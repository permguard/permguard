// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The authorization store: `host/authz/` on the volume.
//!
//! ```text
//! host/authz/
//! ├── journal/          authoritative issue, revoke and expire transitions, segmented
//! ├── snapshot          rebuildable active-grant view at a revision
//! └── bootstrap.cbor    immutable initial recovery principal commitment
//! ```
//!
//! The journal is the truth and is replayed whole at open: a grant store holds tens of records,
//! never millions, so the snapshot is a convenience for a reader without the journal, written
//! after every mutation and checked against the replay at open. Grant ids are permanent, a
//! revocation is a terminal transition, and an expiry is written as one when it is noticed.
//!
//! Mutations append directly to the journal. `TODO(WP-3.6)`: once the Host security-mutation
//! transaction exists, issue and revoke go through it, with compare-and-swap on the revision,
//! idempotency and the operation receipt the Host API promises.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use permguard_core::authz::{AllowSet, Principal, Selector, operations, resource_types};
use permguard_objects::cbor::{self, Value};

use super::record::{
    FRAME_EXPIRE, FRAME_ISSUE, FRAME_REVOKE, GrantId, GrantRecord, RecordError, Status, Transition,
};
use crate::storage::dir::Dir;
use crate::storage::journal::{Journal, Options, Recovery};
use crate::storage::volume::Volume;
use crate::storage::write::{Published, publish_immutable};
use crate::storage::{Rebuildable, StorageError, snapshot};

/// The directory below `host/`.
pub const DIRECTORY: &str = "authz";
const JOURNAL: &str = "journal";
const SNAPSHOT: &str = "snapshot";
const BOOTSTRAP: &str = "bootstrap.cbor";

/// The principal the bootstrap commitment names for a certificate fingerprint.
pub fn bootstrap_principal(fingerprint: &str) -> Result<Principal, AuthzError> {
    let fingerprint = fingerprint.trim().to_ascii_lowercase();
    let hex = fingerprint.strip_prefix("sha256:").unwrap_or(&fingerprint);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AuthzError::Invalid(format!(
            "`{fingerprint}` is not a certificate fingerprint: 64 hex characters, optionally \
             prefixed `sha256:`"
        )));
    }
    Principal::new(format!("cert:sha256:{hex}"))
        .map_err(|error| AuthzError::Invalid(error.to_string()))
}

/// What the store refuses, beyond what the volume does.
#[derive(Debug)]
pub enum AuthzError {
    /// A request that does not name a registered operation or type, a valid principal or
    /// selector, or that would recreate what exists.
    Invalid(String),
    /// A grant id the store does not hold.
    Unknown(GrantId),
    /// A transition the grant's state does not allow: revoking what is already terminal.
    Terminal(GrantId, Status),
    /// The journal or the snapshot could not be read or written.
    Storage(StorageError),
    /// A frame that does not decode: the journal is damaged, and the store does not guess.
    Record(RecordError),
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => f.write_str(detail),
            Self::Unknown(id) => write!(f, "no grant `{id}` is held"),
            Self::Terminal(id, status) => {
                write!(f, "grant `{id}` is {}, which is terminal", status.as_str())
            }
            Self::Storage(error) => write!(f, "{error}"),
            Self::Record(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuthzError {}

impl From<StorageError> for AuthzError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<RecordError> for AuthzError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// What an issue asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub principal: Principal,
    pub operations: Vec<String>,
    pub selector: Selector,
    pub resource_types: Vec<String>,
    pub constraints: BTreeMap<String, String>,
    pub issued_by: String,
    pub expires_at: Option<u64>,
}

/// The bootstrap commitment: the one recovery administrator, written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    pub principal: Principal,
    pub fingerprint: String,
    pub created_at: u64,
}

impl Bootstrap {
    fn encode(&self) -> Result<Vec<u8>, AuthzError> {
        cbor::encode(&Value::Map(vec![
            (
                Value::Int(1),
                Value::Text(self.principal.as_str().to_owned()),
            ),
            (Value::Int(2), Value::Text(self.fingerprint.clone())),
            (
                Value::Int(3),
                Value::Int(i64::try_from(self.created_at).unwrap_or(i64::MAX)),
            ),
        ]))
        .map_err(|error| AuthzError::Record(RecordError::Cbor(error.to_string())))
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let Value::Map(pairs) = cbor::decode_canonical(bytes).ok()? else {
            return None;
        };
        let mut principal = None;
        let mut fingerprint = None;
        let mut created_at = None;
        for (key, value) in pairs {
            match (key, value) {
                (Value::Int(1), Value::Text(text)) => principal = Principal::new(text).ok(),
                (Value::Int(2), Value::Text(text)) => fingerprint = Some(text),
                (Value::Int(3), Value::Int(at)) if at >= 0 => created_at = Some(at as u64),
                _ => return None,
            }
        }
        Some(Self {
            principal: principal?,
            fingerprint: fingerprint?,
            created_at: created_at?,
        })
    }
}

struct State {
    records: BTreeMap<GrantId, GrantRecord>,
    revision: u64,
}

/// The grant store of one volume: the journal, replayed, and what it holds.
pub struct GrantStore {
    dir: Rebuildable<Dir>,
    journal: Mutex<Journal>,
    state: RwLock<State>,
    bootstrap: Mutex<Option<Bootstrap>>,
}

impl std::fmt::Debug for GrantStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantStore")
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

impl GrantStore {
    /// Opens the store of `volume`, replaying the journal and checking the snapshot.
    pub fn open(volume: &Volume) -> Result<(Arc<Self>, Recovery), AuthzError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        let journal_dir = dir.subdir(JOURNAL, true)?;
        let (journal, recovery) =
            Journal::open(journal_dir, volume.journal_options(Options::default()))?;
        let mut state = State {
            records: BTreeMap::new(),
            revision: 0,
        };
        for frame in journal.frames()? {
            apply(&mut state, frame.kind, &frame.payload)?;
        }
        // A record naming what no route checks allows nothing (owner decision); said once here,
        // where an operator reading the start-up log can act on it.
        for record in state.records.values() {
            let unknown: Vec<&String> = record
                .operations
                .iter()
                .filter(|operation| !operations::is_registered(operation))
                .chain(
                    record
                        .resource_types
                        .iter()
                        .filter(|resource_type| !resource_types::is_registered(resource_type)),
                )
                .collect();
            if !unknown.is_empty() {
                tracing::warn!(
                    event.name = "authz.grant_unregistered",
                    component = "host",
                    grant = %record.grant_id,
                    unregistered = ?unknown,
                    "a grant names operations or types outside the registry: they allow nothing"
                );
            }
        }
        let bootstrap = dir
            .read(BOOTSTRAP)?
            .and_then(|bytes| Bootstrap::decode(&bytes));
        let store = Self {
            dir: Rebuildable::new(dir),
            journal: Mutex::new(journal),
            state: RwLock::new(state),
            bootstrap: Mutex::new(bootstrap),
        };
        // A snapshot that disagrees with the journal is rebuilt, never believed.
        let rebuilt = store.snapshot_matches()?;
        if !rebuilt {
            store.write_snapshot()?;
        }
        Ok((Arc::new(store), recovery))
    }

    /// The store revision: the number of transitions applied.
    pub fn revision(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revision
    }

    /// Every record the store holds, active or terminal, by id.
    pub fn records(&self) -> Vec<GrantRecord> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .values()
            .cloned()
            .collect()
    }

    /// The bootstrap commitment, when one was written.
    pub fn bootstrap(&self) -> Option<Bootstrap> {
        self.bootstrap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The active allows at `now`, with the store revision. A record naming an operation or a
    /// type outside the registry contributes nothing (owner decision): what it names is nothing
    /// a route checks.
    pub fn allows_at(&self, now: u64) -> AllowSet {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let allows = state
            .records
            .values()
            .filter(|record| record.is_active_at(now))
            .flat_map(|record| {
                record.allows().into_iter().filter(|allow| {
                    operations::is_registered(&allow.operation)
                        && resource_types::is_registered(&allow.resource_type)
                })
            })
            .collect();
        AllowSet::new(allows, state.revision)
    }

    /// Issues a grant: a direct journal append. `TODO(WP-3.6)`: the security-mutation transaction.
    pub fn issue(&self, issue: Issue, now: u64) -> Result<GrantRecord, AuthzError> {
        if issue.principal.is_anonymous() {
            return Err(AuthzError::Invalid(format!(
                "`{}` is the reserved public principal: what anybody may do is declared in the \
                 configuration's `host.authz.public`, never journaled",
                permguard_core::authz::ANONYMOUS
            )));
        }
        if issue.operations.is_empty() {
            return Err(AuthzError::Invalid(
                "a grant names at least one operation".to_owned(),
            ));
        }
        if let Some(unknown) = issue
            .operations
            .iter()
            .find(|operation| !operations::is_registered(operation))
        {
            return Err(AuthzError::Invalid(format!(
                "`{unknown}` is not a registered operation; the registry is {}",
                operations::ALL.join(", ")
            )));
        }
        if issue.resource_types.is_empty() {
            return Err(AuthzError::Invalid(
                "a grant names at least one resource type".to_owned(),
            ));
        }
        if let Some(unknown) = issue
            .resource_types
            .iter()
            .find(|resource_type| !resource_types::is_registered(resource_type))
        {
            return Err(AuthzError::Invalid(format!(
                "`{unknown}` is not a registered resource type; the registry is {}",
                resource_types::ALL.join(", ")
            )));
        }
        if issue.expires_at.is_some_and(|until| until <= now) {
            return Err(AuthzError::Invalid(
                "the grant would expire before it is issued".to_owned(),
            ));
        }
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = GrantRecord {
            grant_id: fresh_id(&state.records)?,
            principal_id: issue.principal,
            operations: issue.operations,
            selector: issue.selector,
            resource_types: issue.resource_types,
            constraints: issue.constraints,
            revision: state.revision + 1,
            status: Status::Active,
            issued_by: issue.issued_by,
            issued_at: now,
            expires_at: issue.expires_at,
        };
        journal.append(FRAME_ISSUE, &record.encode()?)?;
        state.revision += 1;
        state.records.insert(record.grant_id, record.clone());
        drop(state);
        drop(journal);
        self.write_snapshot()?;
        Ok(record)
    }

    /// Revokes a grant: terminal. `TODO(WP-3.6)`: the security-mutation transaction.
    pub fn revoke(&self, grant_id: GrantId, by: &str, now: u64) -> Result<GrantRecord, AuthzError> {
        self.transition(FRAME_REVOKE, Status::Revoked, grant_id, by, now)
    }

    /// Writes an expire transition for every active grant past its expiry at `now`.
    pub fn expire_due(&self, now: u64) -> Result<Vec<GrantId>, AuthzError> {
        let due: Vec<GrantId> = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .values()
            .filter(|record| {
                record.status == Status::Active
                    && record.expires_at.is_some_and(|until| now >= until)
            })
            .map(|record| record.grant_id)
            .collect();
        for grant_id in &due {
            self.transition(FRAME_EXPIRE, Status::Expired, *grant_id, "expiry", now)?;
        }
        Ok(due)
    }

    /// Writes the bootstrap commitment once and issues the recovery administrator's grant:
    /// `authz.admin` on `host`. A second bootstrap naming the same fingerprint is the first; one
    /// naming another is refused, the file being immutable.
    pub fn bootstrap_recovery_administrator(
        &self,
        fingerprint: &str,
        now: u64,
    ) -> Result<(Bootstrap, Option<GrantRecord>), AuthzError> {
        let principal = bootstrap_principal(fingerprint)?;
        let commitment = Bootstrap {
            principal: principal.clone(),
            fingerprint: fingerprint.trim().to_ascii_lowercase(),
            created_at: now,
        };
        let bytes = commitment.encode()?;
        let same_principal = |existing: &[u8]| {
            Bootstrap::decode(existing).is_some_and(|held| held.principal == principal)
        };
        let published = publish_immutable(
            self.dir.get(),
            BOOTSTRAP,
            &bytes,
            &|content| Bootstrap::decode(content).is_some(),
            &same_principal,
        )
        .map_err(|error| match error {
            StorageError::Corruption(_) => AuthzError::Invalid(format!(
                "{} already commits to another recovery administrator; a bootstrap is written once",
                self.dir.get().child_path(BOOTSTRAP).display()
            )),
            other => AuthzError::Storage(other),
        })?;
        let held = self
            .dir
            .get()
            .read(BOOTSTRAP)?
            .and_then(|bytes| Bootstrap::decode(&bytes))
            .unwrap_or(commitment);
        *self
            .bootstrap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(held.clone());
        // The grant follows the commitment; a crash between the two leaves a committed principal
        // with no grant, so the grant is issued whenever the committed principal holds none.
        let committed = held.principal.clone();
        let holds_admin = self.allows_at(now).permits(
            &committed,
            operations::AUTHZ_ADMIN,
            &permguard_core::authz::Resource::host(),
        );
        let grant = if holds_admin {
            None
        } else {
            Some(self.issue(
                Issue {
                    principal: committed,
                    operations: vec![operations::AUTHZ_ADMIN.to_owned()],
                    selector: Selector::exactly(permguard_core::authz::Resource::host()),
                    resource_types: vec![resource_types::HOST.to_owned()],
                    constraints: BTreeMap::from([(
                        "bootstrap".to_owned(),
                        "recovery administrator".to_owned(),
                    )]),
                    issued_by: "bootstrap".to_owned(),
                    expires_at: None,
                },
                now,
            )?)
        };
        tracing::info!(
            event.name = "authz.bootstrap",
            component = "host",
            fingerprint = %held.fingerprint,
            written = matches!(published, Published::Written),
            granted = grant.is_some(),
            "the recovery administrator is committed"
        );
        Ok((held, grant))
    }

    fn transition(
        &self,
        kind: u16,
        to: Status,
        grant_id: GrantId,
        by: &str,
        now: u64,
    ) -> Result<GrantRecord, AuthzError> {
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = state
            .records
            .get(&grant_id)
            .ok_or(AuthzError::Unknown(grant_id))?;
        if current.status != Status::Active {
            return Err(AuthzError::Terminal(grant_id, current.status));
        }
        let transition = Transition {
            grant_id,
            revision: state.revision + 1,
            at: now,
            by: by.to_owned(),
        };
        journal.append(kind, &transition.encode()?)?;
        state.revision += 1;
        let revision = state.revision;
        let record = state
            .records
            .get_mut(&grant_id)
            .ok_or(AuthzError::Unknown(grant_id))?;
        record.status = to;
        record.revision = revision;
        let record = record.clone();
        drop(state);
        drop(journal);
        self.write_snapshot()?;
        Ok(record)
    }

    fn snapshot_body(&self) -> Result<(u64, Vec<u8>), AuthzError> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut items = Vec::new();
        for record in state.records.values() {
            items.push(Value::Bytes(record.encode()?));
        }
        let body = cbor::encode(&Value::Array(items))
            .map_err(|error| AuthzError::Record(RecordError::Cbor(error.to_string())))?;
        Ok((state.revision, body))
    }

    fn write_snapshot(&self) -> Result<(), AuthzError> {
        let (revision, body) = self.snapshot_body()?;
        snapshot::write(&self.dir, SNAPSHOT, revision, &SOURCE, &body)?;
        Ok(())
    }

    /// Whether the snapshot on disk is the replayed state at its revision.
    fn snapshot_matches(&self) -> Result<bool, AuthzError> {
        let (revision, body) = self.snapshot_body()?;
        Ok(
            snapshot::load(&self.dir, SNAPSHOT, revision, &SOURCE)?
                .is_some_and(|held| held == body),
        )
    }
}

/// The snapshot's source marker: one journal, so one constant; the revision is the variable part.
const SOURCE: [u8; 32] = source_marker();

const fn source_marker() -> [u8; 32] {
    let text = permguard_core::domains::format::AUTHZ_SNAPSHOT_V1.as_bytes();
    assert!(text.len() == 32, "the marker is exactly the checksum width");
    let mut marker = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        marker[index] = text[index];
        index += 1;
    }
    marker
}

fn apply(state: &mut State, kind: u16, payload: &[u8]) -> Result<(), AuthzError> {
    match kind {
        FRAME_ISSUE => {
            let record = GrantRecord::decode(payload)?;
            state.revision = state.revision.max(record.revision);
            state.records.insert(record.grant_id, record);
        }
        FRAME_REVOKE | FRAME_EXPIRE => {
            let transition = Transition::decode(payload)?;
            let record = state
                .records
                .get_mut(&transition.grant_id)
                .ok_or(AuthzError::Unknown(transition.grant_id))?;
            record.status = if kind == FRAME_REVOKE {
                Status::Revoked
            } else {
                Status::Expired
            };
            record.revision = transition.revision;
            state.revision = state.revision.max(transition.revision);
        }
        other => {
            return Err(AuthzError::Storage(StorageError::Corruption(format!(
                "the grant journal holds a frame of unknown kind {other}"
            ))));
        }
    }
    Ok(())
}

fn fresh_id(held: &BTreeMap<GrantId, GrantRecord>) -> Result<GrantId, AuthzError> {
    use ring::rand::SecureRandom as _;

    let rng = ring::rand::SystemRandom::new();
    for _ in 0..8 {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes).map_err(|_| {
            AuthzError::Invalid("the system random source did not answer".to_owned())
        })?;
        let id = GrantId::from_bytes(bytes);
        if !held.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(AuthzError::Invalid(
        "eight fresh identities collided with held grants; the random source is suspect".to_owned(),
    ))
}

/// Seconds since the epoch, now.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::authz::Resource;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-authz-store-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn issue(principal: &str, operation: &str, selector: &str) -> Issue {
        Issue {
            principal: Principal::new(principal).expect("a principal"),
            operations: vec![operation.to_owned()],
            selector: Selector::parse(selector).expect("a selector"),
            resource_types: vec!["*".to_owned()],
            constraints: BTreeMap::new(),
            issued_by: "test".to_owned(),
            expires_at: None,
        }
    }

    #[test]
    fn grants_survive_a_reopen_and_a_revocation_is_terminal() {
        let root = scratch("reopen");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("opens");
        let billing = store
            .issue(
                issue("billing", "catalog.read", "plane/control/zone/billing/*"),
                100,
            )
            .expect("issued");
        let people = store
            .issue(
                issue("people", "catalog.read", "plane/control/zone/people/*"),
                101,
            )
            .expect("issued");
        assert_eq!(store.revision(), 2);
        store.revoke(people.grant_id, "test", 102).expect("revoked");
        assert!(matches!(
            store.revoke(people.grant_id, "test", 103),
            Err(AuthzError::Terminal(_, Status::Revoked))
        ));
        drop(store);
        drop(volume);

        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed again");
        let (store, _) = GrantStore::open(&volume).expect("reopens");
        assert_eq!(store.revision(), 3);
        let allows = store.allows_at(200);
        let own = Resource::ledger("control", "billing", "main");
        assert!(allows.permits(&Principal::new("billing").expect("p"), "catalog.read", &own));
        assert!(!allows.permits(
            &Principal::new("people").expect("p"),
            "catalog.read",
            &Resource::zone("control", "people")
        ));
        assert_eq!(allows.revision(), 3);
        assert_eq!(store.records().len(), 2);
        assert_eq!(
            store
                .records()
                .iter()
                .find(|record| record.grant_id == billing.grant_id)
                .map(|record| record.status),
            Some(Status::Active)
        );
    }

    #[test]
    fn an_expired_grant_allows_nothing_and_is_written_as_expired_when_noticed() {
        let root = scratch("expiry");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("opens");
        let mut short = issue("ops", "catalog.write", "plane/control");
        short.expires_at = Some(500);
        let record = store.issue(short, 100).expect("issued");
        let plane = Resource::plane("control");
        let ops = Principal::new("ops").expect("p");
        assert!(store.allows_at(499).permits(&ops, "catalog.write", &plane));
        assert!(!store.allows_at(500).permits(&ops, "catalog.write", &plane));
        assert_eq!(
            store.expire_due(600).expect("expired"),
            vec![record.grant_id]
        );
        assert_eq!(store.records()[0].status, Status::Expired);
        let mut late = issue("ops", "catalog.write", "plane/control");
        late.expires_at = Some(50);
        assert!(matches!(
            store.issue(late, 100),
            Err(AuthzError::Invalid(_))
        ));
    }

    #[test]
    fn a_grant_to_the_reserved_anonymous_principal_is_refused_at_issue() {
        let root = scratch("anonymous");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("opens");
        assert!(matches!(
            store.issue(issue("anonymous", "catalog.read", "plane/control/*"), 1),
            Err(AuthzError::Invalid(_))
        ));
        assert_eq!(store.revision(), 0);
    }

    #[test]
    fn an_unregistered_operation_is_refused_at_issue() {
        let root = scratch("registry");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("opens");
        assert!(matches!(
            store.issue(issue("x", "catalog.delete", "plane/control"), 1),
            Err(AuthzError::Invalid(_))
        ));
        let mut typed = issue("x", "catalog.read", "plane/control");
        typed.resource_types = vec!["realm".to_owned()];
        assert!(matches!(store.issue(typed, 1), Err(AuthzError::Invalid(_))));
        assert_eq!(store.revision(), 0, "nothing was written");
    }

    #[test]
    fn the_bootstrap_is_written_once_and_grants_authz_admin_on_the_host() {
        let root = scratch("bootstrap");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("opens");
        let fingerprint = "AB".repeat(32);
        let (commitment, grant) = store
            .bootstrap_recovery_administrator(&fingerprint, 10)
            .expect("bootstrapped");
        assert_eq!(
            commitment.principal.as_str(),
            format!("cert:sha256:{}", "ab".repeat(32))
        );
        let grant = grant.expect("the first bootstrap issues the grant");
        assert_eq!(grant.operations, vec!["authz.admin"]);
        assert!(store.allows_at(11).permits(
            &commitment.principal,
            "authz.admin",
            &Resource::host()
        ));
        // The same fingerprint again: the same commitment, no second grant.
        let (again, none) = store
            .bootstrap_recovery_administrator(&format!("sha256:{fingerprint}"), 20)
            .expect("idempotent");
        assert_eq!(again, commitment);
        assert!(none.is_none());
        // Another fingerprint: refused, the file is immutable.
        assert!(matches!(
            store.bootstrap_recovery_administrator(&"cd".repeat(32), 30),
            Err(AuthzError::Invalid(_))
        ));
        assert!(matches!(
            store.bootstrap_recovery_administrator("nonsense", 30),
            Err(AuthzError::Invalid(_))
        ));
        assert_eq!(store.bootstrap(), Some(commitment));
    }

    #[test]
    fn a_damaged_snapshot_is_rebuilt_from_the_journal() {
        let root = scratch("snapshot");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("opens");
        store
            .issue(
                issue("billing", "catalog.read", "plane/control/zone/billing/*"),
                1,
            )
            .expect("issued");
        let path = root.join("host").join(DIRECTORY).join(SNAPSHOT);
        drop(store);
        drop(volume);
        std::fs::write(&path, b"garbage").expect("damaged");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("reopens from the journal");
        assert_eq!(store.revision(), 1);
        assert_ne!(std::fs::read(&path).expect("rewritten"), b"garbage");
    }
}
