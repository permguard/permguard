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
//!
//! With a [`CheckpointSigner`] registered, every ended day of every trail is sealed by a signed
//! checkpoint (WP-3.7, owner decisions of 2026-10-11): when a record starts a new day, at each
//! [`Engine::sweep`] (at start and every hour) and on demand ([`Engine::checkpoint`]). A
//! checkpoint that cannot be signed leaves the record standing, is logged, degrades
//! `audit_checkpoint`, and is sealed at the next sweep. A registered [`CheckpointWitness`] is
//! asked to co-sign each checkpoint at the sweep and on demand, outside every trail's lock; an
//! unanswered witness degrades `audit_witness` and never holds a checkpoint back. Retention
//! deletes sealed days only, so without a signer nothing is deleted.

pub mod checkpoint;
pub mod jsonl;
pub mod pseudonym;
pub mod query;
pub mod record;
pub mod trail;
pub mod verify;

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

use checkpoint::{CheckpointSigner, CheckpointWitness};
use pseudonym::ResourcePseudonyms;
use query::{CheckpointList, CursorKey, Page, Query, QueryError};
use record::{AuditRecord, FactValue};
use trail::Trail;

/// The directory below `host/` the trails live in.
pub const DIRECTORY: &str = "audit";
/// The directory below [`DIRECTORY`] holding one directory per class.
pub const TRAILS: &str = "trails";
/// The capability the Host reports degraded when an `operations` record was lost.
pub const CAPABILITY: &str = "audit";
/// The capability the Host reports degraded while a checkpoint could not be sealed.
pub const CHECKPOINT_CAPABILITY: &str = "audit_checkpoint";
/// The capability the Host reports degraded while the registered witness does not answer.
pub const WITNESS_CAPABILITY: &str = "audit_witness";
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
    // An approval of a plan (WP-3.9): a mutation of the plan's domain.
    mutation("host.plan.approved", HOST),
    // A plan consumed ahead of its change (WP-3.9): the offline reset's.
    mutation("host.plan.consumed", HOST),
    // The Host identity (WP-2.2): its provisioning, and each rotation a mutation.
    action("host.identity.provisioned", Class::Security, HOST),
    mutation("host.identity.rotated", HOST),
    // Its reset (WP-4.1): planned, then run.
    mutation("host.identity.reset_planned", HOST),
    mutation("host.identity.reset", HOST),
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
    // The memberships (WP-4.1): every change of an invitation or a membership a mutation, on
    // either side; no token, proof or key is ever a fact.
    mutation("host.membership.invited", HOST),
    mutation("host.membership.invite_revoked", HOST),
    mutation("host.membership.enrolled", HOST),
    mutation("host.membership.approved", HOST),
    mutation("host.membership.rejected", HOST),
    mutation("host.membership.suspended", HOST),
    // Dormancy (WP-4.6): a membership silent past its `dormant_after`, suspended by the system.
    mutation("host.membership.dormant", HOST),
    mutation("host.membership.resumed", HOST),
    mutation("host.membership.fenced", HOST),
    mutation("host.membership.revoke_planned", HOST),
    mutation("host.membership.revoked", HOST),
    mutation("host.membership.joined", HOST),
    mutation("host.membership.synced", HOST),
    mutation("host.membership.verified", HOST),
    mutation("host.membership.orphaned", HOST),
    // Task sessions (WP-4.3): every lease issued, every epoch refused, every clone alarm, each
    // a security record of the coordinator; a hold for review a mutation.
    ActionSchema {
        action: "host.membership.lease_issued",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("task", FactType::Text(128)),
            ("epoch", FactType::Uint),
            ("resource", FactType::Text(512)),
            ("member_boot_id", FactType::Text(32)),
            ("coordinator_boot_id", FactType::Text(32)),
            ("expires_at", FactType::Uint),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    ActionSchema {
        action: "host.membership.epoch_stale",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("task", FactType::Text(128)),
            ("presented", FactType::Uint),
            ("current", FactType::Uint),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    ActionSchema {
        action: "host.membership.epoch_unknown",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("task", FactType::Text(128)),
            ("presented", FactType::Uint),
            ("current", FactType::Uint),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    ActionSchema {
        action: "host.membership.clone_alarm",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("task", FactType::Text(128)),
            ("open_boot_id", FactType::Text(32)),
            ("new_boot_id", FactType::Text(32)),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    ActionSchema {
        action: "host.stream.forked",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("task", FactType::Text(128)),
            ("stream", FactType::Text(256)),
            ("at_seq", FactType::Uint),
        ],
        max_bytes: 8 * 1024,
        phases: false,
    },
    mutation("host.membership.held", HOST),
    // The ring re-pin (WP-4.5): the re-pin, the cutover, an acknowledgement and the retiring
    // pin's drop, each a mutation; a rollback or an equivocation an observation.
    mutation("host.membership.repinned", HOST),
    mutation("host.membership.cutover", HOST),
    mutation("host.membership.acknowledged", HOST),
    mutation("host.membership.pin_retired", HOST),
    ActionSchema {
        action: "host.membership.repin_rollback",
        class: Class::Security,
        root: HOST,
        facts: &[("ring", FactType::Text(128)), ("epoch", FactType::Uint)],
        max_bytes: 8 * 1024,
        phases: false,
    },
    ActionSchema {
        action: "host.membership.repin_equivocation",
        class: Class::Security,
        root: HOST,
        facts: &[("ring", FactType::Text(128)), ("epoch", FactType::Uint)],
        max_bytes: 8 * 1024,
        phases: false,
    },
    // Assurance appraisal (WP-4.2): an appraisal a mutation; each operator approval it takes a
    // record of its own inside that operation, with its principal, scope, reason and expiry; no
    // evidence is ever a fact.
    mutation("host.membership.appraised", HOST),
    ActionSchema {
        action: "host.membership.assurance_revoked",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("controls", FactType::Text(1200)),
            ("reason", FactType::Text(512)),
        ],
        max_bytes: 8 * 1024,
        phases: true,
    },
    ActionSchema {
        action: "host.membership.assurance_approved",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("control", FactType::Text(64)),
            ("tasks", FactType::Text(4200)),
            ("reason", FactType::Text(512)),
            ("expires_at", FactType::Uint),
            ("record", FactType::Text(80)),
        ],
        max_bytes: 8 * 1024,
        phases: true,
    },
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
    // A ref update (WP-7.12): a phase of one mutation transaction (WP-3.6).
    mutation("ledger.pushed", CONTROL),
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
    /// How long `access` and `operations` day files are kept.
    retention: OnceLock<std::time::Duration>,
    /// What the export of each trail allows retention to delete (WP-5.9).
    egress: OnceLock<Arc<dyn EgressFloor>>,
    /// How long `security` day files are kept; for ever unless set.
    retention_security: OnceLock<std::time::Duration>,
    signer: OnceLock<Arc<dyn CheckpointSigner>>,
    witness: OnceLock<Arc<dyn CheckpointWitness>>,
    cursors: CursorKey,
    /// The trails whose last seal failed: `audit_checkpoint` is restored once none is left.
    unsealed: Mutex<std::collections::BTreeSet<(Class, String)>>,
    /// The trails the witness left a checkpoint of unanswered: `audit_witness` likewise.
    unwitnessed: Mutex<std::collections::BTreeSet<(Class, String)>>,
}

/// One trail a listing found: its class, its digest, and the resource its `META.cbor` names or
/// why it names none.
type Listed = (Class, String, Result<String, String>);

/// What the export of a trail allows retention to delete (WP-5.9, owner decision of 2026-10-16).
pub trait EgressFloor: Send + Sync {
    /// `None` when no required task exports the trail of `(class, resource)`: retention as
    /// configured. Otherwise the last checkpoint a coordinator acknowledged, by its file name, and
    /// `Some(None)` while none is.
    fn acknowledged(&self, class: Class, resource: &str) -> Option<Option<String>>;
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

    /// Removes the sealed `access` and `operations` day files older than `retention`, from the
    /// trails opened from now on.
    pub fn retain_for(&self, retention: std::time::Duration) {
        let _ = self.inner.retention.set(retention);
    }

    /// Removes the sealed `security` day files older than `retention`, from the trails opened
    /// from now on; without it a `security` trail keeps every day (owner decision of 2026-10-11).
    pub fn retain_security_for(&self, retention: std::time::Duration) {
        let _ = self.inner.retention_security.set(retention);
    }

    /// Bounds retention by the export of each trail from now on (WP-5.9): a day goes only once
    /// the seal that closes it was acknowledged, while a required task exports its trail.
    pub fn gate_retention_with(&self, egress: Arc<dyn EgressFloor>) {
        let _ = self.inner.egress.set(egress);
    }

    /// Seals every ended day of every trail with `signer` from now on.
    pub fn seal_with(&self, signer: Arc<dyn CheckpointSigner>) {
        let _ = self.inner.signer.set(signer);
    }

    /// Asks `witness` to co-sign every checkpoint from now on.
    pub fn witness_with(&self, witness: Arc<dyn CheckpointWitness>) {
        let _ = self.inner.witness.set(witness);
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
            egress: OnceLock::new(),
            retention_security: OnceLock::new(),
            signer: OnceLock::new(),
            witness: OnceLock::new(),
            cursors: CursorKey::draw().ok_or_else(|| {
                Refused::Storage("the system has no source of randomness".to_owned())
            })?,
            unsealed: Mutex::new(std::collections::BTreeSet::new()),
            unwitnessed: Mutex::new(std::collections::BTreeSet::new()),
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

    /// Every trail on the volume, by class and digest, with the resource its `META.cbor` names or
    /// why it names none.
    fn trails(&self) -> Result<Vec<Listed>, Refused> {
        let storage = |error: crate::storage::StorageError| Refused::Storage(error.to_string());
        let mut trails = Vec::new();
        for class_name in self.inner.trails.subdirs().map_err(storage)? {
            let Some(class) = Class::parse(&class_name) else {
                continue;
            };
            let class_dir = self
                .inner
                .trails
                .subdir(&class_name, false)
                .map_err(storage)?;
            for digest in class_dir.subdirs().map_err(storage)? {
                let resource = class_dir
                    .subdir(&digest, false)
                    .and_then(|dir| dir.read(trail::META))
                    .map_err(|error| error.to_string())
                    .and_then(|meta| {
                        record::TrailMeta::decode(&meta.unwrap_or_default())
                            .map_err(|error| error.to_string())
                    })
                    .and_then(|meta| {
                        // A `META.cbor` naming a resource kept elsewhere would open another trail.
                        if trail::resource_digest(&meta.resource) == digest {
                            Ok(meta.resource)
                        } else {
                            Err("its META.cbor names a resource kept under another digest"
                                .to_owned())
                        }
                    });
                trails.push((class, digest, resource));
            }
        }
        Ok(trails)
    }

    /// Seals every ended day of every trail on the volume that no seal closed yet, deletes what
    /// retention allows, and asks the witness for the co-signatures still missing; answers the
    /// checkpoints written. A trail that fails is logged and the others go on.
    pub fn sweep(&self) -> Result<Vec<String>, Refused> {
        let today = trail::day_name(self.inner.time.now_secs());
        let mut written = Vec::new();
        let mut visited = Vec::new();
        for (class, digest, resource) in self.trails()? {
            let resource = match resource {
                Ok(resource) => resource,
                Err(error) => {
                    tracing::error!(
                        event.name = "audit.sweep_failed",
                        component = "host",
                        class = class.as_str(),
                        trail = %digest,
                        error = %error,
                        "an audit trail could not be swept"
                    );
                    continue;
                }
            };
            let mut open = self
                .inner
                .open
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match self.inner.trail(&mut open, class, &resource) {
                Ok(trail) => {
                    written.extend(self.inner.maintain(trail, class, &resource, &today));
                }
                Err(error) => tracing::error!(
                    event.name = "audit.sweep_failed",
                    component = "host",
                    class = class.as_str(),
                    error = %error,
                    "an audit trail could not be swept"
                ),
            }
            drop(open);
            visited.push((class, resource));
        }
        self.inner.ask_witness(&visited);
        Ok(written)
    }

    /// Every trail on the volume, by class and resource (WP-5.9: what an export ships); a trail
    /// whose `META.cbor` cannot be read refuses the listing rather than being skipped.
    pub fn trails_held(&self) -> Result<Vec<(Class, String)>, Refused> {
        self.trails()?
            .into_iter()
            .map(|(class, digest, resource)| {
                resource.map(|resource| (class, resource)).map_err(|error| {
                    Refused::Storage(format!(
                        "the {} trail {digest} cannot be read: {error}",
                        class.as_str()
                    ))
                })
            })
            .collect()
    }

    /// The bytes of the `ANCHOR.cbor` of `(class, resource)`, when retention deleted a prefix.
    pub fn anchor_bytes(&self, class: Class, resource: &str) -> Result<Option<Vec<u8>>, Refused> {
        match trail::directory(&self.inner.trails, class, resource, false) {
            Ok(dir) => dir
                .read(checkpoint::ANCHOR)
                .map_err(|error| Refused::Storage(error.to_string())),
            Err(error) if not_found(&error) => Ok(None),
            Err(error) => Err(Refused::Storage(error.to_string())),
        }
    }

    /// Whether a checkpoint signer is registered: without one this process seals nothing.
    pub fn seals(&self) -> bool {
        self.inner.signer.get().is_some()
    }

    /// Checkpoints every trail on the volume now, as [`Engine::checkpoint`] does one (WP-4.9: the
    /// evidence an identity reset seals before its rings retire); answers the newest checkpoint
    /// of each trail holding records. Refused at the first trail that cannot be checkpointed, a
    /// trail whose `META.cbor` cannot be read included: nothing is skipped. The trails sealed
    /// before it keep their checkpoints, which only add to what a trail proves.
    pub fn checkpoint_all(&self) -> Result<Vec<String>, Refused> {
        let mut written = Vec::new();
        for (class, digest, resource) in self.trails()? {
            let resource = resource.map_err(|error| {
                Refused::Storage(format!(
                    "the {} trail {digest} cannot be checkpointed: {error}",
                    class.as_str()
                ))
            })?;
            written.extend(self.checkpoint(class, &resource)?);
        }
        Ok(written)
    }

    /// Checkpoints the trail of `(class, resource)` now: its ended days sealed, its last day up to
    /// its last record; answers the newest checkpoint's file name, `None` when the trail holds
    /// no record. Refused when no signer is registered or the trail does not exist.
    pub fn checkpoint(&self, class: Class, resource: &str) -> Result<Option<String>, Refused> {
        let signer = self.inner.signer.get().ok_or_else(|| {
            Refused::Storage("no checkpoint signer is registered in this process".to_owned())
        })?;
        self.trail_dir(class, resource)?;
        let today = trail::day_name(self.inner.time.now_secs());
        let newest = {
            let mut open = self
                .inner
                .open
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let trail = self
                .inner
                .trail(&mut open, class, resource)
                .map_err(Refused::Storage)?;
            let sealed = trail.checkpoint_now(
                &today,
                signer.as_ref(),
                self.inner.stamp.host_id,
                self.inner.time.now_secs(),
            );
            match sealed {
                Ok(_) => self.inner.sealed(class, resource),
                Err(error) => {
                    self.inner.seal_failed(class, resource, &error);
                    return Err(Refused::Storage(error));
                }
            }
            trail.newest_checkpoint().map(ToOwned::to_owned)
        };
        self.inner.ask_witness(&[(class, resource.to_owned())]);
        Ok(newest)
    }

    /// One page of the records of `(class, resource)`, with the gaps it cannot show.
    pub fn read(&self, class: Class, resource: &str, query: &Query) -> Result<Page, QueryError> {
        self.page(class, resource, query, false)
    }

    /// One page of the export of `(class, resource)` up to the frontier its first page fixed:
    /// every record, from the first kept, whatever its time.
    pub fn export(&self, class: Class, resource: &str, query: &Query) -> Result<Page, QueryError> {
        self.page(class, resource, query, true)
    }

    /// The checkpoints of `(class, resource)`, of the day `period` alone when it names one.
    pub fn checkpoints(
        &self,
        class: Class,
        resource: &str,
        period: Option<&str>,
    ) -> Result<CheckpointList, QueryError> {
        match trail::directory(&self.inner.trails, class, resource, false) {
            Ok(dir) => query::checkpoints(&dir, period),
            Err(error) if not_found(&error) => Ok(CheckpointList::default()),
            Err(error) => Err(QueryError::Storage(error.to_string())),
        }
    }

    fn page(
        &self,
        class: Class,
        resource: &str,
        query: &Query,
        export: bool,
    ) -> Result<Page, QueryError> {
        let dir = match trail::directory(&self.inner.trails, class, resource, false) {
            Ok(dir) => dir,
            Err(error) if not_found(&error) => {
                if query.cursor.is_some() {
                    // No cursor was issued for a trail that does not exist.
                    return Err(QueryError::Cursor(
                        "the cursor was issued for another query".to_owned(),
                    ));
                }
                return Ok(Page {
                    records: Vec::new(),
                    gaps: Vec::new(),
                    frontier: 0,
                    next: None,
                    anchor: None,
                });
            }
            Err(error) => return Err(QueryError::Storage(error.to_string())),
        };
        let next_seq = {
            let mut open = self
                .inner
                .open
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.inner
                .trail(&mut open, class, resource)
                .map_err(QueryError::Storage)?
                .next_seq()
        };
        query::page(
            &self.inner.cursors,
            &dir,
            class,
            resource,
            next_seq,
            query,
            export,
        )
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

    /// The open trail of `(class, resource)`, opened on first use.
    fn trail<'a>(
        &self,
        open: &'a mut BTreeMap<(Class, String), Trail>,
        class: Class,
        resource: &str,
    ) -> Result<&'a mut Trail, String> {
        let key = (class, resource.to_owned());
        if !open.contains_key(&key) {
            let retention = match class {
                Class::Security => self.retention_security.get().copied(),
                Class::Operations | Class::Access => self.retention.get().copied(),
            };
            let trail = Trail::open(&self.trails, class, resource, retention)
                .map_err(|error| error.to_string())?;
            open.insert(key.clone(), trail);
        }
        open.get_mut(&key)
            .ok_or_else(|| "the trail vanished".to_owned())
    }

    /// Appends `record` to its trail, opening the trail on first use; a record that starts a new
    /// day seals the days before it and deletes what retention allows.
    fn write(&self, record: AuditRecord) -> Result<(), String> {
        let class = Class::parse(record.trail.split(':').next().unwrap_or_default())
            .ok_or_else(|| format!("`{}` names no class", record.trail))?;
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (class, record.resource.clone());
        let trail = self.trail(&mut open, class, &record.resource)?;
        match trail.append(record) {
            Ok(new_day) => {
                if new_day && let Some(today) = trail.last_day().map(ToOwned::to_owned) {
                    self.maintain(trail, class, &key.1, &today);
                }
                Ok(())
            }
            Err(error) => {
                // Reopened at the next record: what a failed append left at the end of the day
                // file is a torn item there, which opening cuts, and the sequence continues from
                // disk.
                open.remove(&key);
                Err(error.to_string())
            }
        }
    }

    /// Seals the days of `trail` before the day file `today` and deletes what its retention
    /// allows; a failure is logged and degrades a capability, and the record that led here
    /// stands. Answers the checkpoints written.
    fn maintain(
        &self,
        trail: &mut Trail,
        class: Class,
        resource: &str,
        today: &str,
    ) -> Vec<String> {
        let mut written = Vec::new();
        if let Some(signer) = self.signer.get() {
            match trail.seal_before(
                today,
                signer.as_ref(),
                self.stamp.host_id,
                self.time.now_secs(),
            ) {
                Ok(names) => {
                    written = names;
                    self.sealed(class, resource);
                }
                Err(error) => self.seal_failed(class, resource, &error),
            }
        }
        let egress = self
            .egress
            .get()
            .and_then(|floor| floor.acknowledged(class, resource));
        if let Err(error) = trail.prune(today, egress.as_ref().map(|held| held.as_deref())) {
            tracing::error!(
                event.name = "audit.retention_failed",
                component = "host",
                error = %error,
                "sealed audit days past their retention could not be deleted; the next sweep retries"
            );
        }
        written
    }

    /// The trail of `(class, resource)` sealed: `audit_checkpoint` is restored once no trail's
    /// seal is failing.
    fn sealed(&self, class: Class, resource: &str) {
        let mut unsealed = self.unsealed.lock().unwrap_or_else(PoisonError::into_inner);
        unsealed.remove(&(class, resource.to_owned()));
        if unsealed.is_empty()
            && let Some(health) = self.health.get()
        {
            health
                .lifecycle()
                .restore(permguard_core::lifecycle::HOST, CHECKPOINT_CAPABILITY);
        }
    }

    fn seal_failed(&self, class: Class, resource: &str, error: &str) {
        self.unsealed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((class, resource.to_owned()));
        tracing::error!(
            event.name = "audit.checkpoint_unsealed",
            component = "host",
            error = %error,
            "an audit checkpoint could not be sealed; the next sweep retries"
        );
        if let Some(health) = self.health.get() {
            health.lifecycle().degrade(
                permguard_core::lifecycle::HOST,
                CHECKPOINT_CAPABILITY,
                format!("an audit checkpoint could not be sealed: {error}"),
            );
        }
    }

    /// Asks the registered witness to co-sign every checkpoint of `trails` that has no
    /// co-signature yet, outside every trail's lock; the first one unanswered stops the round and
    /// leaves the rest to the next sweep. `audit_witness` is degraded while any trail has a
    /// checkpoint the witness left unanswered, and restored once none has.
    fn ask_witness(&self, trails: &[(Class, String)]) {
        let Some(witness) = self.witness.get() else {
            return;
        };
        let mut unanswered = None;
        let mut answered = Vec::new();
        'trails: for (class, resource) in trails {
            let Ok(held) = trail::directory(&self.trails, *class, resource, false)
                .and_then(|dir| dir.subdir(trail::CHECKPOINTS, false))
            else {
                continue;
            };
            let Ok(names) = held.names() else {
                continue;
            };
            for name in checkpoint::ordered(names.iter().cloned()) {
                let cosigned = checkpoint::witness_name(&name);
                if names.contains(&cosigned) {
                    continue;
                }
                let answer = held
                    .read(&name)
                    .map_err(|error| error.to_string())
                    .and_then(|envelope| witness.cosign(&envelope.unwrap_or_default()))
                    .and_then(|signature| {
                        let same = |kept: &[u8]| kept == signature.as_slice();
                        crate::storage::write::publish_immutable(
                            &held, &cosigned, &signature, &same, &same,
                        )
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                    });
                if let Err(error) = answer {
                    unanswered = Some(((*class, resource.clone()), error));
                    break 'trails;
                }
            }
            answered.push((*class, resource.clone()));
        }
        let pending = {
            let mut pending = self
                .unwitnessed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for key in &answered {
                pending.remove(key);
            }
            if let Some((key, _)) = &unanswered {
                pending.insert(key.clone());
            }
            !pending.is_empty()
        };
        let unanswered = unanswered.map(|(_, error)| error);
        let Some(health) = self.health.get() else {
            if let Some(error) = &unanswered {
                tracing::warn!(
                    event.name = "audit.witness_unanswered",
                    component = "host",
                    error = %error,
                    "the audit witness did not co-sign a checkpoint; the next sweep asks again"
                );
            }
            return;
        };
        match unanswered {
            None if pending => {}
            Some(error) => {
                tracing::warn!(
                    event.name = "audit.witness_unanswered",
                    component = "host",
                    error = %error,
                    "the audit witness did not co-sign a checkpoint; the next sweep asks again"
                );
                health.lifecycle().degrade(
                    permguard_core::lifecycle::HOST,
                    WITNESS_CAPABILITY,
                    format!("the audit witness did not co-sign a checkpoint: {error}"),
                );
            }
            None => health
                .lifecycle()
                .restore(permguard_core::lifecycle::HOST, WITNESS_CAPABILITY),
        }
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

fn not_found(error: &crate::storage::StorageError) -> bool {
    matches!(error, crate::storage::StorageError::Io { source, .. }
        if source.kind() == std::io::ErrorKind::NotFound)
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
