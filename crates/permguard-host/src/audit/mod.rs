// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The audit engine (WP-3.5): every audit record the process writes, in a trail per
//! `(class, resource)` under `host/audit/trails/`.
//!
//! ```text
//! caller capability ─▶ registered action schema ─▶ Host attribution and resource
//!   ─▶ bounded facts ─▶ trail(class, resource): seq, previous, digest ─▶ the day file, flushed
//! ```
//!
//! | Class        | Append failure                                                          |
//! | ------------ | ----------------------------------------------------------------------- |
//! | `security`   | the caller is answered the failure: a mutation does not report success |
//! | `operations` | counted, logged and readiness degraded (`audit`); the operation goes on  |
//! | `access`     | a bounded queue; a full queue drops, counts, and a record marks the gap |
//!
//! The action's registration fixes its class, its component, its facts, its size limit and
//! whether it requires a phase: a caller names none of these, so none can be downgraded. An
//! unregistered action, an undeclared fact, a fact of the wrong type or shaped like a token or a
//! key, and a resource outside the action's root are refused before anything is appended.
//!
//! The engine sits behind the core [`AuditSink`], so every recorder and handle of the process
//! writes through it; it forwards each record to the sink `audit.destination` chose as well, the
//! log stream by default (owner decision of 2026-10-07).

pub mod pseudonym;
pub mod record;
pub mod trail;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use permguard_core::Pseudonymizer;
use permguard_core::server::Health;
use permguard_core::{AuditError, AuditEvent, AuditOutcome, AuditSink, BoxFuture, Fact, Subject};
use permguard_objects::digest::Digest;

use crate::storage::Dir;
use crate::storage::volume::Volume;
use crate::time::TimeGuard;

use pseudonym::ResourcePseudonyms;
use record::{AuditRecord, FactValue};
use trail::Trail;

/// The directory below `host/` the trails live in.
pub const DIRECTORY: &str = "audit";
/// The directory below [`DIRECTORY`] holding one directory per class.
pub const TRAILS: &str = "trails";
/// The capability the Host reports degraded when an `operations` record was lost.
pub const CAPABILITY: &str = "audit";
/// How many `access` records may wait for the writer before new ones are dropped.
pub const ACCESS_QUEUE: usize = 4096;

/// The resource roots the Host assigns: its own actions, and each Plane's.
pub const HOST: &str = "host";
pub const CONTROL: &str = "plane/control";
pub const DATA: &str = "plane/data";

/// An audit class and its failure policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    Security,
    Operations,
    Access,
}

impl Class {
    /// The name a trail and a record carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Operations => "operations",
            Self::Access => "access",
        }
    }

    /// The class named `name`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "security" => Some(Self::Security),
            "operations" => Some(Self::Operations),
            "access" => Some(Self::Access),
            _ => None,
        }
    }
}

/// The type of one declared fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactType {
    /// Text of at most this many bytes.
    Text(usize),
    Uint,
    Bool,
}

/// One registered action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionSchema {
    /// `<domain>.<verb>`, more dots allowed.
    pub action: &'static str,
    pub class: Class,
    /// The resource root the Host assigns; a caller may only narrow below it.
    pub root: &'static str,
    /// Every fact a record of the action may carry.
    pub facts: &'static [(&'static str, FactType)],
    /// The largest encoded record.
    pub max_bytes: usize,
    /// Whether every record of the action names its operation and phase.
    pub phases: bool,
}

const fn action(action: &'static str, class: Class, root: &'static str) -> ActionSchema {
    ActionSchema {
        action,
        class,
        root,
        facts: &[],
        max_bytes: 8 * 1024,
        phases: false,
    }
}

/// A `security` action recorded at each phase of a mutation transaction (WP-3.6).
const fn mutation(action: &'static str, root: &'static str) -> ActionSchema {
    ActionSchema {
        phases: true,
        ..self::action(action, Class::Security, root)
    }
}

/// Every action the process records, with its class (owner decisions of 2026-10-07).
pub const REGISTRY: &[ActionSchema] = &[
    // The Host's lifecycle and services.
    action("server.start", Class::Operations, HOST),
    action("server.stop", Class::Operations, HOST),
    action("service.start", Class::Operations, HOST),
    action("service.stop", Class::Operations, HOST),
    // The Host's time guard (WP-2.12).
    action("host.clock_anomaly", Class::Security, HOST),
    action("host.clock_restored", Class::Security, HOST),
    // The grants (WP-2.5), each a phase of one mutation transaction (WP-3.6).
    mutation("host.grant.issued", HOST),
    mutation("host.grant.revoke_planned", HOST),
    mutation("host.grant.revoked", HOST),
    mutation("host.grant.expired", HOST),
    // The Host identity (WP-2.2): its provisioning, and each rotation a mutation.
    action("host.identity.provisioned", Class::Security, HOST),
    mutation("host.identity.rotated", HOST),
    // The key rings (WP-3.1): every journal entry an `operations` record, an operator's
    // rotation and revocation each a mutation.
    ActionSchema {
        action: "host.keys.transition",
        class: Class::Operations,
        root: HOST,
        facts: &[
            ("ring", FactType::Text(32)),
            ("kind", FactType::Text(16)),
            ("epoch", FactType::Uint),
            ("reason", FactType::Text(256)),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    mutation("host.keys.rotated", HOST),
    mutation("host.keys.revoke_planned", HOST),
    mutation("host.keys.revoked", HOST),
    // Peer Host sessions (WP-2.3): each one established or refused.
    ActionSchema {
        action: "host.session.established",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("role", FactType::Text(16)),
            ("epoch", FactType::Uint),
            ("operation", FactType::Text(16)),
            ("declared_assurance", FactType::Text(16)),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    ActionSchema {
        action: "host.session.refused",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("role", FactType::Text(16)),
            ("code", FactType::Text(64)),
            ("reason", FactType::Text(512)),
            ("epoch", FactType::Uint),
            ("operation", FactType::Text(16)),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    // The Control Plane: catalog, NOTP and its sweep.
    action("zone.created", Class::Security, CONTROL),
    action("zone.renamed", Class::Security, CONTROL),
    action("zone.deleted", Class::Security, CONTROL),
    action("zone.create.refused", Class::Security, CONTROL),
    action("zone.rename.refused", Class::Security, CONTROL),
    action("zone.delete.refused", Class::Security, CONTROL),
    action("ledger.created", Class::Security, CONTROL),
    action("ledger.renamed", Class::Security, CONTROL),
    action("ledger.deleted", Class::Security, CONTROL),
    action("ledger.create.refused", Class::Security, CONTROL),
    action("ledger.rename.refused", Class::Security, CONTROL),
    action("ledger.delete.refused", Class::Security, CONTROL),
    action("ledger.pushed", Class::Security, CONTROL),
    action("notp.push.negotiate.refused", Class::Security, CONTROL),
    action("notp.upload.refused", Class::Security, CONTROL),
    action("notp.push.commit.refused", Class::Security, CONTROL),
    action("store.swept", Class::Operations, CONTROL),
    // The Data Plane: decisions and mirrors.
    action("authz.decision", Class::Access, DATA),
    action("ledger.synchronized", Class::Operations, DATA),
    // The engine itself: the mark a gap in an access trail leaves, in that trail.
    ActionSchema {
        action: "audit.access_dropped",
        class: Class::Access,
        root: DATA,
        facts: &[("dropped", FactType::Uint)],
        max_bytes: 8 * 1024,
        phases: false,
    },
];

/// Fact names a schema may never declare: what a fact must never carry.
const FORBIDDEN_FACTS: &[&str] = &[
    "payload",
    "body",
    "token",
    "tokens",
    "credential",
    "proof",
    "policy",
    "key",
    "private_key",
    "apikey",
    "api_key",
    "secret",
    "secret_ref",
    "password",
    "passphrase",
    "bearer",
    "jwt",
    "signature",
    "cookie",
];

/// Refuses a registry with an action named twice, an action that is not `<domain>.<verb>`, a
/// fact named as a forbidden one or a root outside the three the Host assigns.
pub fn check_registry(registry: &[ActionSchema]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for schema in registry {
        if !seen.insert(schema.action) {
            return Err(format!("`{}` is registered twice", schema.action));
        }
        let well_formed = schema.action.split('.').count() >= 2
            && schema.action.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
            });
        if !well_formed {
            return Err(format!("`{}` is not `<domain>.<verb>`", schema.action));
        }
        if schema.max_bytes > record::MAX_RECORD_BYTES {
            return Err(format!(
                "`{}` allows {} bytes, more than any record takes",
                schema.action, schema.max_bytes
            ));
        }
        if ![HOST, CONTROL, DATA].contains(&schema.root) {
            return Err(format!(
                "`{}` names the root `{}`, which the Host does not assign",
                schema.action, schema.root
            ));
        }
        for (name, _) in schema.facts {
            let lower = name.to_ascii_lowercase();
            if FORBIDDEN_FACTS
                .iter()
                .any(|forbidden| lower == *forbidden || lower.ends_with(&format!("_{forbidden}")))
            {
                return Err(format!(
                    "`{}` declares the fact `{name}`, which a record never carries",
                    schema.action
                ));
            }
        }
    }
    Ok(())
}

/// Why the engine did not append.
#[derive(Debug)]
pub enum Refused {
    /// The action is not registered.
    Unregistered(String),
    /// A fact the schema does not declare, of another type, too long or shaped like a secret.
    Fact(String),
    /// A resource outside the action's root.
    Resource(String),
    /// A phase missing where the schema requires one, or present where it does not.
    Phase(String),
    /// The record is larger than the schema allows.
    TooLarge(usize),
    /// The trail could not be written.
    Storage(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unregistered(action) => {
                write!(
                    f,
                    "`{action}` is not a registered audit action; nothing was appended"
                )
            }
            Self::Fact(detail) | Self::Resource(detail) | Self::Phase(detail) => {
                write!(f, "{detail}; nothing was appended")
            }
            Self::TooLarge(bytes) => write!(
                f,
                "the record takes {bytes} bytes, more than its schema allows; nothing was appended"
            ),
            Self::Storage(detail) => write!(f, "the audit trail could not be written: {detail}"),
        }
    }
}

impl std::error::Error for Refused {}

/// The digest of the effective configuration a record names as `config_revision`: SHA-256 over
/// every setting in key order, each as its length-prefixed key, then `1` and its length-prefixed
/// value or `0` when it is unset. The settings carry no secret material (WP-2.9), only
/// references to it.
pub fn config_revision<'a>(
    settings: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
) -> Digest {
    let mut sorted: Vec<(&str, Option<&str>)> = settings.into_iter().collect();
    sorted.sort();
    // Each part length-prefixed, so no key or value can be read as another.
    let mut bytes = Vec::new();
    for (key, value) in sorted {
        bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
        bytes.extend_from_slice(key.as_bytes());
        match value {
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
                bytes.extend_from_slice(value.as_bytes());
            }
            None => bytes.push(0),
        }
    }
    Digest::compute(&bytes)
}

/// What the engine stamps on every record.
#[derive(Debug, Clone)]
pub struct Stamp {
    /// The installation: the volume's identity.
    pub host_id: [u8; 16],
    /// The incarnation: drawn at each start.
    pub boot_id: [u8; 16],
    /// The executable's version.
    pub build: String,
    /// The digest of the effective configuration.
    pub config_revision: Digest,
}

struct Inner {
    trails: Dir,
    registry: &'static [ActionSchema],
    stamp: Stamp,
    time: Arc<TimeGuard>,
    pseudonyms: Option<ResourcePseudonyms>,
    open: Mutex<BTreeMap<(Class, String), Trail>>,
    health: OnceLock<Health>,
    lost: AtomicU64,
    dropped: AtomicU64,
    /// Drops not yet marked, by the resource of the access trail that has the gap.
    pending_drops: Mutex<BTreeMap<String, u64>>,
    /// How long `access` and `operations` day files are kept; `security` ones always are.
    retention: OnceLock<std::time::Duration>,
}

/// The audit engine of one process.
pub struct Engine {
    inner: Arc<Inner>,
    access: Mutex<Option<SyncSender<Box<AuditRecord>>>>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("trails", &self.inner.trails.path())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// The engine of the volume `volume` holds, with the process's registry.
    pub fn open(
        volume: &Volume,
        stamp: Stamp,
        time: Arc<TimeGuard>,
        pseudonyms: Option<ResourcePseudonyms>,
    ) -> Result<Self, Refused> {
        Self::with_registry(volume, REGISTRY, stamp, time, pseudonyms)
    }

    /// Removes `access` and `operations` day files older than `retention` from now on; a
    /// `security` trail keeps every day until WP-3.7's checkpoints (owner decision of 2026-10-07).
    pub fn retain_for(&self, retention: std::time::Duration) {
        let _ = self.inner.retention.set(retention);
    }

    /// The engine over `registry`, for a test that registers its own actions.
    pub fn with_registry(
        volume: &Volume,
        registry: &'static [ActionSchema],
        stamp: Stamp,
        time: Arc<TimeGuard>,
        pseudonyms: Option<ResourcePseudonyms>,
    ) -> Result<Self, Refused> {
        Self::with_queue(volume, registry, stamp, time, pseudonyms, ACCESS_QUEUE)
    }

    pub(crate) fn with_queue(
        volume: &Volume,
        registry: &'static [ActionSchema],
        stamp: Stamp,
        time: Arc<TimeGuard>,
        pseudonyms: Option<ResourcePseudonyms>,
        queue: usize,
    ) -> Result<Self, Refused> {
        check_registry(registry).map_err(Refused::Fact)?;
        let trails = volume
            .host()
            .subdir(DIRECTORY, true)
            .and_then(|dir| dir.subdir(TRAILS, true))
            .map_err(|error| Refused::Storage(error.to_string()))?;
        let inner = Arc::new(Inner {
            trails,
            registry,
            stamp,
            time,
            pseudonyms,
            open: Mutex::new(BTreeMap::new()),
            health: OnceLock::new(),
            lost: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            pending_drops: Mutex::new(BTreeMap::new()),
            retention: OnceLock::new(),
        });
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Box<AuditRecord>>(queue);
        let writer = {
            let inner = Arc::clone(&inner);
            std::thread::Builder::new()
                .name("audit-access".to_owned())
                .spawn(move || {
                    for record in receiver {
                        inner.write_access(*record);
                    }
                    inner.mark_drops();
                })
                .map_err(|error| Refused::Storage(format!("starting the access writer: {error}")))?
        };
        Ok(Self {
            inner,
            access: Mutex::new(Some(sender)),
            writer: Mutex::new(Some(writer)),
        })
    }

    /// Reports `operations` losses on `health`'s Host component, from now on.
    pub fn observe(&self, health: Health) {
        let _ = self.inner.health.set(health);
    }

    /// How many `operations` records could not be written.
    pub fn lost(&self) -> u64 {
        self.inner.lost.load(Ordering::SeqCst)
    }

    /// How many `access` records the full queue dropped.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::SeqCst)
    }

    /// The trail of `(class, resource)`, opened for reading: what a verifier walks.
    pub fn trail_dir(&self, class: Class, resource: &str) -> Result<Dir, Refused> {
        trail::directory(&self.inner.trails, class, resource, false)
            .map_err(|error| Refused::Storage(error.to_string()))
    }

    /// Appends `event`, recorded under `policy` when the engine keeps no pseudonym root of its
    /// own. A `security` failure is answered; an `operations` failure is counted and answered as
    /// written; an `access` record is queued.
    pub fn append(
        &self,
        event: &AuditEvent<'_>,
        policy: Option<&dyn Pseudonymizer>,
    ) -> Result<(), Refused> {
        let schema = self
            .inner
            .registry
            .iter()
            .find(|schema| schema.action == event.action())
            .ok_or_else(|| Refused::Unregistered(event.action().to_owned()))?;
        let record = self.inner.build(schema, event, policy)?;
        match schema.class {
            Class::Security => self.inner.write(record).map_err(Refused::Storage),
            Class::Operations => {
                self.inner.write_or_count(record);
                Ok(())
            }
            Class::Access => {
                let sender = self
                    .access
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                let Some(sender) = sender else {
                    // Closed: the process is stopping, and the record is written here instead.
                    self.inner.write_access(record);
                    return Ok(());
                };
                let resource = record.resource.clone();
                match sender.try_send(Box::new(record)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                        self.inner.dropped.fetch_add(1, Ordering::SeqCst);
                        *self
                            .inner
                            .pending_drops
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .entry(resource)
                            .or_default() += 1;
                    }
                }
                Ok(())
            }
        }
    }

    /// Waits for every queued `access` record and stops the writer.
    pub fn close(&self) {
        drop(
            self.access
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        if let Some(writer) = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = writer.join();
        }
        self.inner.mark_drops();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.close();
    }
}

impl Stamp {
    /// The stamp of this process: `host_id` from the volume, a `boot_id` drawn now.
    pub fn draw(host_id: [u8; 16], build: &str, config_revision: Digest) -> Result<Self, Refused> {
        use ring::rand::SecureRandom as _;
        let mut boot_id = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut boot_id)
            .map_err(|_| Refused::Storage("the system has no source of randomness".to_owned()))?;
        Ok(Self {
            host_id,
            boot_id,
            build: build.to_owned(),
            config_revision,
        })
    }
}

impl Inner {
    fn build(
        &self,
        schema: &'static ActionSchema,
        event: &AuditEvent<'_>,
        policy: Option<&dyn Pseudonymizer>,
    ) -> Result<AuditRecord, Refused> {
        let resource = match event.resource() {
            None => schema.root.to_owned(),
            Some(narrowed)
                if narrowed == schema.root
                    || narrowed.strip_prefix(schema.root).is_some_and(|rest| {
                        rest.strip_prefix('/').is_some_and(|below| {
                            below
                                .split('/')
                                .all(|part| !part.is_empty() && part != "." && part != "..")
                        })
                    }) =>
            {
                narrowed.to_owned()
            }
            Some(other) => {
                return Err(Refused::Resource(format!(
                    "`{}` is recorded under `{}`, and `{other}` is not below it",
                    schema.action, schema.root
                )));
            }
        };
        let facts = facts_of(schema, event.facts())?;
        let (operation_id, phase) = match (event.operation(), schema.phases) {
            (Some((id, phase)), true) => (Some(*id), Some(phase.as_str().to_owned())),
            (None, false) => (None, None),
            (None, true) => {
                return Err(Refused::Phase(format!(
                    "`{}` records the phase of an operation, and this record names none",
                    schema.action
                )));
            }
            (Some(_), false) => {
                return Err(Refused::Phase(format!(
                    "`{}` is a simple observation, and this record names a phase",
                    schema.action
                )));
            }
        };
        let outcome = event
            .outcome()
            .unwrap_or(if schema.action.ends_with(".refused") {
                AuditOutcome::Refused
            } else {
                AuditOutcome::Ok
            });
        if event.target().is_some_and(looks_secret) {
            return Err(Refused::Fact(format!(
                "the target of `{}` is shaped like a token, a key or a proof",
                schema.action
            )));
        }
        let principal = self.principal(event.subject(), &resource, policy)?;
        let component = match schema.root {
            CONTROL => "control-plane",
            DATA => "data-plane",
            _ => "host",
        };
        let record = AuditRecord {
            trail: format!("{}:{resource}", schema.class.as_str()),
            seq: 0,
            operation_id,
            phase,
            host_id: self.stamp.host_id,
            boot_id: self.stamp.boot_id,
            component: component.to_owned(),
            action: schema.action.to_owned(),
            principal,
            resource,
            target: event.target().map(ToOwned::to_owned),
            outcome: outcome.as_str().to_owned(),
            facts,
            build: self.stamp.build.clone(),
            config_revision: self.stamp.config_revision.clone(),
            at: self.time.now_secs(),
            monotonic_offset: u64::try_from(self.time.elapsed().as_nanos()).unwrap_or(u64::MAX),
            previous: Digest::compute(b""),
        };
        let size = match record.encode() {
            Ok(bytes) => bytes.len(),
            Err(record::RecordError::TooLarge(bytes)) => return Err(Refused::TooLarge(bytes)),
            Err(error) => return Err(Refused::Fact(error.to_string())),
        };
        if size > schema.max_bytes {
            return Err(Refused::TooLarge(size));
        }
        Ok(record)
    }

    /// The principal as the record carries it: the resource-derived pseudonym when the engine
    /// keeps a root, and otherwise the subject rendered as every sink renders it, which masks a
    /// person when no pseudonymiser is configured.
    fn principal(
        &self,
        subject: Subject<'_>,
        resource: &str,
        policy: Option<&dyn Pseudonymizer>,
    ) -> Result<String, Refused> {
        match (subject, &self.pseudonyms) {
            (Subject::Principal(value), Some(pseudonyms)) => pseudonyms
                .pseudonym(resource, "principal", value)
                .ok_or_else(|| {
                    Refused::Fact("the principal's pseudonym could not be derived".to_owned())
                }),
            (other, _) => Ok(other.render(policy)),
        }
    }

    /// Appends `record` to its trail, opening the trail on first use.
    fn write(&self, record: AuditRecord) -> Result<(), String> {
        let class = Class::parse(record.trail.split(':').next().unwrap_or_default())
            .ok_or_else(|| format!("`{}` names no class", record.trail))?;
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (class, record.resource.clone());
        let retention = match class {
            Class::Security => None,
            Class::Operations | Class::Access => self.retention.get().copied(),
        };
        if !open.contains_key(&key) {
            let trail = Trail::open(&self.trails, class, &record.resource, retention)
                .map_err(|error| error.to_string())?;
            open.insert(key.clone(), trail);
        }
        let trail = open
            .get_mut(&key)
            .ok_or_else(|| "the trail vanished".to_owned())?;
        let appended = trail.append(record).map_err(|error| error.to_string());
        if appended.is_err() {
            // Reopened at the next record: what a failed append left at the end of the day file
            // is a torn item there, which opening cuts, and the sequence continues from disk.
            open.remove(&key);
        }
        appended
    }

    /// Writes a record whose loss the caller is not answered: counted, logged, and the Host's
    /// readiness degraded.
    fn write_or_count(&self, record: AuditRecord) {
        let action = record.action.clone();
        if let Err(error) = self.write(record) {
            self.count_loss(&action, &error);
        }
    }

    fn count_loss(&self, action: &str, error: &str) {
        let lost = self.lost.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::error!(
            event.name = "audit.record_unwritten",
            component = "host",
            action = %action,
            error = %error,
            "an audit record could not be written; the operation goes on"
        );
        if let Some(health) = self.health.get() {
            health.lifecycle().degrade(
                permguard_core::lifecycle::HOST,
                CAPABILITY,
                format!("{lost} audit records could not be written"),
            );
        }
    }

    fn write_access(&self, record: AuditRecord) {
        self.mark_drops();
        self.write_or_count(record);
    }

    /// Writes, in each access trail that has a gap, the record that marks it.
    fn mark_drops(&self) {
        let pending = std::mem::take(
            &mut *self
                .pending_drops
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let Some(schema) = self
            .registry
            .iter()
            .find(|schema| schema.action == "audit.access_dropped")
        else {
            return;
        };
        for (resource, dropped) in pending {
            let facts = [("dropped", Fact::Uint(dropped))];
            let event = AuditEvent::new("audit.access_dropped", Subject::System("audit"))
                .in_resource(&resource)
                .with_facts(&facts);
            match self.build(schema, &event, None) {
                Ok(record) => self.write_or_count(record),
                Err(error) => self.count_loss("audit.access_dropped", &error.to_string()),
            }
        }
    }
}

fn facts_of(
    schema: &ActionSchema,
    facts: &[(&str, Fact<'_>)],
) -> Result<BTreeMap<String, FactValue>, Refused> {
    let mut out = BTreeMap::new();
    for (name, value) in facts {
        let declared = schema
            .facts
            .iter()
            .find(|(declared, _)| declared == name)
            .map(|(_, kind)| *kind)
            .ok_or_else(|| {
                Refused::Fact(format!("`{}` declares no fact `{name}`", schema.action))
            })?;
        let value = match (declared, value) {
            (FactType::Text(max), Fact::Text(text)) => {
                if text.len() > max {
                    return Err(Refused::Fact(format!(
                        "the fact `{name}` of `{}` is longer than {max} bytes",
                        schema.action
                    )));
                }
                if looks_secret(text) {
                    return Err(Refused::Fact(format!(
                        "the fact `{name}` of `{}` is shaped like a token, a key or a proof",
                        schema.action
                    )));
                }
                FactValue::Text((*text).to_owned())
            }
            (FactType::Uint, Fact::Uint(number)) => FactValue::Uint(*number),
            (FactType::Bool, Fact::Bool(flag)) => FactValue::Bool(*flag),
            _ => {
                return Err(Refused::Fact(format!(
                    "the fact `{name}` of `{}` is not of its declared type",
                    schema.action
                )));
            }
        };
        if out.insert((*name).to_owned(), value).is_some() {
            return Err(Refused::Fact(format!(
                "the fact `{name}` of `{}` is given twice",
                schema.action
            )));
        }
    }
    Ok(out)
}

/// Whether a text looks like what a fact or a target may never carry: an authorization header,
/// a PEM block, a compact JWS, JWT or JWE (detached and unsecured forms included), a PASETO, or a
/// well-known API key. A heuristic over shapes, never a proof of absence.
fn looks_secret(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    let scheme = lower.split_whitespace().next().unwrap_or_default();
    if (matches!(scheme, "bearer" | "basic" | "negotiate")
        && lower.split_whitespace().nth(1).is_some())
        || lower.contains("-----begin")
    {
        return true;
    }
    if ["v1.", "v2.", "v3.", "v4."]
        .iter()
        .any(|version| lower.starts_with(version))
        && (lower[3..].starts_with("local.") || lower[3..].starts_with("public."))
    {
        return true;
    }
    if [
        "ghp_",
        "gho_",
        "ghs_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "sk-",
        "akia",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix) && trimmed.len() >= 16)
    {
        return true;
    }
    let base64url = |part: &str| {
        part.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let parts: Vec<&str> = trimmed.split('.').collect();
    // JOSE compact forms start with a header that decodes to `{"`: base64url `eyJ`.
    if (parts.len() == 3 || parts.len() == 5)
        && parts[0].starts_with("eyJ")
        && parts.iter().all(|part| base64url(part))
    {
        return true;
    }
    // Any other three long base64url parts, when they carry upper case beside lower case or
    // digits, as random bytes do: a host name such as `controlplane.permguard.internal` is not a
    // token.
    parts.len() == 3
        && parts.iter().all(|part| part.len() >= 8 && base64url(part))
        && trimmed.bytes().any(|b| b.is_ascii_uppercase())
        && trimmed
            .bytes()
            .any(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The engine as the process's audit sink: every recorder and handle writes through it, and
/// each record goes to `also`, the sink `audit.destination` chose, too.
pub struct HostAuditSink {
    engine: Arc<Engine>,
    also: Option<Arc<dyn AuditSink>>,
}

impl HostAuditSink {
    /// The engine, forwarding to `also` when the destination names one.
    pub fn new(engine: Arc<Engine>, also: Option<Arc<dyn AuditSink>>) -> Self {
        Self { engine, also }
    }

    /// The engine behind the sink.
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }
}

impl AuditSink for HostAuditSink {
    fn name(&self) -> &'static str {
        "host"
    }

    /// Drains the access queue on a thread of its own, so the caller's shutdown deadline bounds
    /// the wait rather than a blocked worker, then shuts the destination down.
    fn shutdown(&self) -> BoxFuture<'_, Result<(), AuditError>> {
        let engine = Arc::clone(&self.engine);
        Box::pin(async move {
            Closing::start(engine).await;
            match &self.also {
                Some(also) => also.shutdown().await,
                None => Ok(()),
            }
        })
    }

    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            self.engine
                .append(event, policy)
                .map_err(|refused| match refused {
                    Refused::Storage(detail) => AuditError::unavailable(detail),
                    other => AuditError::backend(other.to_string()),
                })?;
            match &self.also {
                Some(also) => also.record(event, policy).await,
                None => Ok(()),
            }
        })
    }
}

/// The engine's close, run on a thread and awaited: completes once the access queue is drained.
struct Closing {
    state: Arc<Mutex<(bool, Option<std::task::Waker>)>>,
}

impl Closing {
    fn start(engine: Arc<Engine>) -> Self {
        let state = Arc::new(Mutex::new((false, None::<std::task::Waker>)));
        let shared = Arc::clone(&state);
        let closing = Arc::clone(&engine);
        let spawned = std::thread::Builder::new()
            .name("audit-close".to_owned())
            .spawn(move || {
                closing.close();
                let mut held = shared.lock().unwrap_or_else(PoisonError::into_inner);
                held.0 = true;
                if let Some(waker) = held.1.take() {
                    waker.wake();
                }
            });
        if spawned.is_err() {
            // No thread to run it on: closed here, which is no worse than before.
            engine.close();
            state.lock().unwrap_or_else(PoisonError::into_inner).0 = true;
        }
        Self { state }
    }
}

impl std::future::Future for Closing {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let mut held = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if held.0 {
            std::task::Poll::Ready(())
        } else {
            held.1 = Some(context.waker().clone());
            std::task::Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests;
