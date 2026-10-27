// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's composition core: one implementation of every generic capability, and the typed,
//! least-privilege handles a Plane receives for what it declared (P1).
//!
//! ```text
//! composition (permguard-server)
//!   ─▶ Host::builder()          the rings, the audit recorder, the zone keys: built once
//!   ─▶ host.register(declaration)   per Plane, before its state opens; collisions refused
//!   ─▶ Registration              the Plane's handles, limited to what it declared
//! ```
//!
//! | Handle             | What a Plane can do with it                     | What it cannot reach                     |
//! | ------------------ | ----------------------------------------------- | ---------------------------------------- |
//! | [`Signer<T>`]      | sign with the ring artifact `T` names           | the key manager, another ring, any key   |
//! | [`PublicKeys`]     | read a declared ring's public set               | signing                                  |
//! | [`AuditHandle<T>`] | record the actions schema `T` declares          | another action, the sink, the trail      |
//! | `ZoneHandle`       | a MAC under the zone key of a declared purpose  | any key's bytes, another purpose's keys  |
//! | [`StreamProducer`] | append to a declared stream through the Host's engine (WP-5.1) | another stream, the engine, its files |
//! | [`TaskClient`], [`Authorization`] | declared now; built by their packages | — |
//!
//! Least privilege is a property of the types: no handle has an accessor that returns the key
//! manager, a key's bytes or a Host-private path, so a Plane holding one cannot widen it. A
//! Plane is trusted code in this process, and the handles are not a sandbox; they keep a Plane from
//! signing, recording or reading what it did not declare by mistake — the confused-deputy risk the
//! security architecture names.
//!
//! `TaskClient` and `Authorization` are declared today, and their collisions are refused at
//! startup, but no Plane can build one yet: task routing (WP-4.x) and the authorization model
//! (WP-2.4) build them when they land. `StreamProducer` is built by the Host's stream engine
//! (WP-5.1), handed in by the server as a [`StreamEngine`].

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

#[cfg(test)]
use permguard_core::keys::Signature;
use permguard_core::keys::{Jwk, KeyId, KeyManager, SigningRing};
use permguard_core::server::AuditRecorder;
use permguard_core::{AuditError, AuditEvent, BoxFuture, Subject};

use crate::time::TimeGuard;
use permguard_core::authz::Resource;

/// A key ring the Host holds, by its registered name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RingId(&'static str);

impl RingId {
    /// The ring's registered name.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// The ring the Control Plane signs what it serves with.
pub const CONTROL_ATTEST: RingId = RingId("control.attest");
/// The ring the Data Plane signs its evidence with.
pub const DATA_ATTEST: RingId = RingId("data.attest");
/// The Host's own operations ring: it seals the audit trail, and no Plane is handed it. A Plane
/// may sign under it only [`LedgerExportV1`], whose payload the Host writes (WP-7.10).
pub const HOST_OPERATIONS: RingId = RingId("host.operations");

/// The Plane artifacts allowed on [`HOST_OPERATIONS`]: each a payload the Host writes.
const OPERATIONS_ARTIFACTS: &[&str] = &[permguard_core::domains::protected::LEDGER_EXPORT];

/// An artifact a Plane may sign: its protected type and the ring that signs it.
pub trait Artifact: 'static {
    /// The protected type, or content type, the artifact is signed as.
    const TYPE: &'static str;
    /// The ring that signs it.
    const RING: RingId;
    /// Whether the artifact carries a time a verifier relies on: such an artifact is not signed
    /// while the Host's clock is in anomaly (WP-2.12). Evidence ordered by sequence is not.
    const TIME_SENSITIVE: bool;
}

/// Today's signed NOTP head statement, signed by the Control Plane.
pub struct HeadStatementV1;

impl Artifact for HeadStatementV1 {
    const TYPE: &'static str = permguard_core::domains::protected::NOTP_HEAD;
    const RING: RingId = CONTROL_ATTEST;
    /// `signed_at` is what a verifier judges a head's freshness by.
    const TIME_SENSITIVE: bool = true;
}

/// The coordinator's observation checkpoint of an `events.import` resource, signed by the Control
/// Plane that provides the task (WP-6.2c1).
pub struct ImportCheckpointV1;

/// A ledger or zone export's manifest (WP-7.10): a COSE_Sign1 under `host.operations` whose
/// payload, [`crate::exports::Manifest`], is the Host's to encode, the one Plane artifact on that
/// ring.
pub struct LedgerExportV1;

impl Artifact for LedgerExportV1 {
    const TYPE: &'static str = permguard_core::domains::protected::LEDGER_EXPORT;
    const RING: RingId = HOST_OPERATIONS;
    /// `exported_at` is what an importer reads the archive's age by.
    const TIME_SENSITIVE: bool = true;
}

impl Artifact for ImportCheckpointV1 {
    const TYPE: &'static str = permguard_core::domains::protected::EVENT_IMPORT_CHECKPOINT;
    const RING: RingId = CONTROL_ATTEST;
    /// `issued_at` is what a member's freshness starts from.
    const TIME_SENSITIVE: bool = true;
}

/// A decision batch, signed by the Data Plane that decided.
pub struct DecisionBatchV1;

impl Artifact for DecisionBatchV1 {
    const TYPE: &'static str = permguard_core::domains::protected::DECISION_BATCH;
    const RING: RingId = DATA_ATTEST;
    /// Evidence: ordered by sequence, it keeps shipping through an anomaly.
    const TIME_SENSITIVE: bool = false;
}

/// An event batch, signed by the Data Plane that recorded the history.
pub struct EventBatchV1;

impl Artifact for EventBatchV1 {
    const TYPE: &'static str = permguard_core::domains::protected::EVENT_BATCH;
    const RING: RingId = DATA_ATTEST;
    /// Evidence: ordered by sequence, it keeps shipping through an anomaly.
    const TIME_SENSITIVE: bool = false;
}

/// A native decision response, signed by the Data Plane that decided, when the request asked
/// for it (WP-6.6b).
pub struct DecisionResponseV1;

impl Artifact for DecisionResponseV1 {
    const TYPE: &'static str = permguard_core::domains::protected::DECISION_RESPONSE;
    const RING: RingId = DATA_ATTEST;
    /// `issued_at` and `expires_at` are what a verifier judges it by.
    const TIME_SENSITIVE: bool = true;
}

/// The actions an audit schema lets its holder record.
pub trait AuditSchema: 'static {
    /// The schema's name, unique across Planes.
    const NAME: &'static str;
    /// Every action the holder may record.
    const ACTIONS: &'static [&'static str];
}

/// What a Plane declares before its state opens.
#[derive(Debug, Clone, Default)]
pub struct Declaration {
    plane: String,
    signers: Vec<(&'static str, RingId)>,
    public_rings: Vec<RingId>,
    audit: Vec<(&'static str, &'static [&'static str])>,
    zone_keys: Vec<crate::secrets::ZonePurpose>,
    streams: Vec<String>,
    read_streams: Vec<String>,
    tasks: Vec<crate::membership::record::Capability>,
    scope_schemas: Vec<String>,
    mutations: Vec<&'static str>,
    layouts: Vec<&'static str>,
    reads_holds: bool,
    gc_jobs: Vec<&'static str>,
}

impl Declaration {
    /// A declaration for the Plane `plane`.
    pub fn new(plane: impl Into<String>) -> Self {
        Self {
            plane: plane.into(),
            ..Self::default()
        }
    }

    /// Declares that this Plane signs artifact `T`, with the ring `T` names.
    pub fn signs<T: Artifact>(mut self) -> Self {
        self.signers.push((T::TYPE, T::RING));
        self
    }

    /// Declares that this Plane reads the public set of `ring`, to publish it or verify with it.
    pub fn reads_public_keys(mut self, ring: RingId) -> Self {
        self.public_rings.push(ring);
        self
    }

    /// Declares the audit schema `T`.
    pub fn audits<T: AuditSchema>(mut self) -> Self {
        self.audit.push((T::NAME, T::ACTIONS));
        self
    }

    /// Declares the zone keys of `purpose` this Plane MACs under (WP-3.3): a handle that never
    /// shows a key, and answers no MAC for a zone or scope this Host holds no key for.
    pub fn uses_zone_key(mut self, purpose: crate::secrets::ZonePurpose) -> Self {
        if !self.zone_keys.contains(&purpose) {
            self.zone_keys.push(purpose);
        }
        self
    }

    /// Declares a stream descriptor this Plane produces.
    pub fn produces_stream(mut self, descriptor: impl Into<String>) -> Self {
        self.streams.push(descriptor.into());
        self
    }

    /// Declares a stream this Plane reads as the Host consumes it (WP-6.1): its public reads
    /// answer from the Host's consumer in-process, whichever Plane produces the stream.
    pub fn reads_stream(mut self, descriptor: impl Into<String>) -> Self {
        self.read_streams.push(descriptor.into());
        self
    }

    /// Declares that this Plane provides `task` at `version`: the provider's handler (WP-4.4).
    pub fn handles_task(mut self, task: crate::membership::record::TaskType, version: u64) -> Self {
        self.tasks.push(crate::membership::record::Capability {
            task_type: task,
            version,
            role: crate::membership::record::ContractRole::Provider,
        });
        self
    }

    /// Declares that this Plane consumes `task` at `version`: the consumer's client (WP-4.4).
    pub fn uses_task(mut self, task: crate::membership::record::TaskType, version: u64) -> Self {
        self.tasks.push(crate::membership::record::Capability {
            task_type: task,
            version,
            role: crate::membership::record::ContractRole::Consumer,
        });
        self
    }

    /// The task contracts this declaration registers (WP-4.4).
    pub fn task_contracts(&self) -> &[crate::membership::record::Capability] {
        &self.tasks
    }

    /// Declares a domain of security mutations this Plane applies through the Host's mutation
    /// transaction (WP-3.6): its handle runs and recovers that domain's operations only.
    pub fn mutates(mut self, domain: &'static str) -> Self {
        self.mutations.push(domain);
        self
    }

    /// Declares that this Plane reads the Host's holds (WP-7.3c): what its garbage collection must
    /// not sweep.
    pub fn reads_holds(mut self) -> Self {
        self.reads_holds = true;
        self
    }

    /// Declares that this Plane provides the garbage-collection `job` the Host API plans and runs
    /// (WP-7.11b): one of [`crate::gc::JOBS`], provided by one Plane.
    pub fn provides_gc_job(mut self, job: &'static str) -> Self {
        if !self.gc_jobs.contains(&job) {
            self.gc_jobs.push(job);
        }
        self
    }

    /// Declares a WP-1.9 layout subsystem whose version in force this Plane reads (WP-6.2d): a
    /// legacy store it stops reading once the volume archived it, without touching the volume.
    pub fn reads_layout(mut self, subsystem: &'static str) -> Self {
        self.layouts.push(subsystem);
        self
    }

    /// Declares a resource scope schema this Plane owns.
    pub fn owns_scope_schema(mut self, schema: impl Into<String>) -> Self {
        self.scope_schemas.push(schema.into());
        self
    }

    /// The Plane this declaration is for.
    pub fn plane(&self) -> &str {
        &self.plane
    }
}

/// Why composition refused a declaration or a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionError {
    /// Two declarations claim one thing: a ring's artifact type, an audit schema, a secret purpose,
    /// a stream descriptor, a task type or a scope schema.
    Collision {
        what: &'static str,
        name: String,
        first: String,
        second: String,
    },
    /// A Plane registered twice.
    AlreadyRegistered(String),
    /// A handle asked for something its Plane did not declare.
    Undeclared { plane: String, what: String },
    /// A Plane declared, as its own artifact, a content type only the Host identity signs: the
    /// identity document, a succession, a session or its proof, a ring binding (WP-2.3).
    Reserved { plane: String, artifact: String },
    /// A Plane declared a garbage-collection job the Host does not serve (WP-7.11b).
    UnknownGcJob { plane: String, job: String },
}

/// The content types the Host identity signs and no Plane may declare as its artifact: a verifier
/// of a session proof or a ring binding never meets one a Plane's ring signed (WP-2.3).
pub const HOST_RESERVED: &[&str] = &[
    permguard_core::domains::protected::HOST_IDENTITY,
    permguard_core::domains::protected::HOST_PROOF,
    permguard_core::domains::protected::HOST_SESSION,
    permguard_core::domains::protected::HOST_SUCCESSION,
    permguard_core::domains::protected::HOST_RING_BINDING,
];

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Collision {
                what,
                name,
                first,
                second,
            } => write!(
                f,
                "the {what} `{name}` is declared by both `{first}` and `{second}`; each is \
                 declared once"
            ),
            Self::AlreadyRegistered(plane) => write!(f, "the plane `{plane}` registered twice"),
            Self::Undeclared { plane, what } => write!(
                f,
                "the plane `{plane}` asked for {what}, which it did not declare"
            ),
            Self::UnknownGcJob { plane, job } => write!(
                f,
                "the plane `{plane}` declared the gc job `{job}`, which the Host does not serve: \
                 the jobs are {}",
                crate::gc::JOBS.join(", ")
            ),
            Self::Reserved { plane, artifact } => write!(
                f,
                "the plane `{plane}` declared `{artifact}` as its artifact, which only the Host \
                 identity signs"
            ),
        }
    }
}

impl std::error::Error for CompositionError {}

/// The Host: every generic capability, implemented once.
pub struct Host {
    mutations: Option<Arc<crate::operations::mutation::Mutations>>,
    task_slots: BTreeMap<
        (crate::membership::record::TaskType, u64),
        Arc<crate::membership::task::Deferred>,
    >,
    hub: Option<Arc<crate::membership::watch::Hub>>,
    memberships: Option<Arc<dyn ServingMembers>>,
    mirror_tasks: Option<Arc<dyn MirrorTasks>>,
    holds: Option<Arc<crate::holds::HoldStore>>,
    gc_jobs: Option<Arc<crate::gc::Jobs>>,
    streams: Option<Arc<dyn StreamEngine>>,
    rings: BTreeMap<RingId, Arc<dyn KeyManager>>,
    recorder: Option<AuditRecorder>,
    authorization: Option<Arc<Authorization>>,
    time: Arc<TimeGuard>,
    zone_keys: BTreeMap<crate::secrets::ZonePurpose, Arc<crate::secrets::ZoneHandle>>,
    host_id: Option<[u8; 16]>,
    layouts: BTreeMap<String, u16>,
    claimed: std::sync::Mutex<Claims>,
}

#[derive(Default)]
struct Claims {
    planes: Vec<String>,
    by_kind: BTreeMap<(&'static str, String), String>,
}

/// Builds the [`Host`] from the collaborators composition resolved.
#[derive(Default)]
pub struct HostBuilder {
    mutations: Option<Arc<crate::operations::mutation::Mutations>>,
    task_slots: BTreeMap<
        (crate::membership::record::TaskType, u64),
        Arc<crate::membership::task::Deferred>,
    >,
    hub: Option<Arc<crate::membership::watch::Hub>>,
    memberships: Option<Arc<dyn ServingMembers>>,
    mirror_tasks: Option<Arc<dyn MirrorTasks>>,
    holds: Option<Arc<crate::holds::HoldStore>>,
    gc_jobs: Option<Arc<crate::gc::Jobs>>,
    streams: Option<Arc<dyn StreamEngine>>,
    rings: BTreeMap<RingId, Arc<dyn KeyManager>>,
    recorder: Option<AuditRecorder>,
    authorization: Option<Arc<Authorization>>,
    time: Option<Arc<TimeGuard>>,
    zone_keys: BTreeMap<crate::secrets::ZonePurpose, Arc<crate::secrets::ZoneHandle>>,
    host_id: Option<[u8; 16]>,
    layouts: BTreeMap<String, u16>,
}

impl HostBuilder {
    /// The key manager behind `ring`.
    pub fn ring(mut self, ring: RingId, keys: Arc<dyn KeyManager>) -> Self {
        self.rings.insert(ring, keys);
        self
    }

    /// The audit recorder every Plane's records go through.
    pub fn audit(mut self, recorder: AuditRecorder) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// The Host.
    /// The authorization every registered Plane decides with. A Host built without one hands
    /// out [`Authorization::closed`]: nothing is allowed, which is the fail-closed default.
    pub fn authorization(mut self, authorization: Arc<Authorization>) -> Self {
        self.authorization = Some(authorization);
        self
    }

    /// The time guard every signer of a time-sensitive artifact consults. A Host built without
    /// one guards with the operating system's clocks and the default bound, kept on no volume.
    pub fn time(mut self, time: Arc<TimeGuard>) -> Self {
        self.time = Some(time);
        self
    }

    /// The zone keys of one purpose this Host holds, as coordinator or as a member (WP-3.3).
    pub fn zone_key(mut self, handle: crate::secrets::ZoneHandle) -> Self {
        self.zone_keys.insert(handle.purpose(), Arc::new(handle));
        self
    }

    /// This Host's `host_id`, the salt of every Host-local key a Plane derives from a root of
    /// its own (WP-3.3).
    pub fn host_id(mut self, host_id: [u8; 16]) -> Self {
        self.host_id = Some(host_id);
        self
    }

    /// The Host's stream engine (WP-5.1): a Plane reaches the producer of each stream it
    /// declared through it.
    pub fn streams(mut self, streams: Arc<dyn StreamEngine>) -> Self {
        self.streams = Some(streams);
        self
    }

    /// The Host's security mutation transaction (WP-3.6): a Plane that declared a mutation
    /// domain applies it through a handle over this engine.
    pub fn mutations(mut self, mutations: Arc<crate::operations::mutation::Mutations>) -> Self {
        self.mutations = Some(mutations);
        self
    }

    /// The slot of the handler a Plane provides for `task` at `version`, which the Host's task
    /// sessions already route to (WP-7.12).
    pub fn task_slot(
        mut self,
        task: crate::membership::record::TaskType,
        version: u64,
        slot: Arc<crate::membership::task::Deferred>,
    ) -> Self {
        self.task_slots.insert((task, version), slot);
        self
    }

    /// Where the Host's watches take their hints (WP-4.4): a Plane that provides a task
    /// publishes the hints of its resources there.
    pub fn watch_hub(mut self, hub: Arc<crate::membership::watch::Hub>) -> Self {
        self.hub = Some(hub);
        self
    }

    /// Who serves a resource under this Host's memberships (WP-4.4): handed to the Plane that
    /// provides `policy.mirror`.
    pub fn memberships(mut self, memberships: Arc<dyn ServingMembers>) -> Self {
        self.memberships = Some(memberships);
        self
    }

    /// The member side of `policy.mirror` (WP-7.2a): handed to the Plane that consumes it.
    pub fn mirror_tasks(mut self, tasks: Arc<dyn MirrorTasks>) -> Self {
        self.mirror_tasks = Some(tasks);
        self
    }

    /// The volume's holds (WP-7.3c): handed to a Plane that declared it reads them.
    pub fn holds(mut self, holds: Arc<crate::holds::HoldStore>) -> Self {
        self.holds = Some(holds);
        self
    }

    /// The Host API's garbage-collection jobs (WP-7.11b): a Plane that declared a job provides it
    /// there.
    pub fn gc_jobs(mut self, jobs: Arc<crate::gc::Jobs>) -> Self {
        self.gc_jobs = Some(jobs);
        self
    }

    /// The version in force of every WP-1.9 layout on the volume, as the start left it (WP-6.2d):
    /// a Plane reads those it declared.
    pub fn layouts(mut self, layouts: impl IntoIterator<Item = (String, u16)>) -> Self {
        self.layouts.extend(layouts);
        self
    }

    pub fn build(self) -> Host {
        Host {
            mutations: self.mutations,
            task_slots: self.task_slots,
            hub: self.hub,
            memberships: self.memberships,
            mirror_tasks: self.mirror_tasks,
            holds: self.holds,
            gc_jobs: self.gc_jobs,
            streams: self.streams,
            rings: self.rings,
            recorder: self.recorder,
            authorization: self.authorization,
            time: self.time.unwrap_or_else(|| {
                Arc::new(TimeGuard::system(
                    permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
                ))
            }),
            zone_keys: self.zone_keys,
            host_id: self.host_id,
            layouts: self.layouts,
            claimed: std::sync::Mutex::new(Claims::default()),
        }
    }
}

impl Host {
    /// A builder; only a composition root calls it.
    pub fn builder() -> HostBuilder {
        HostBuilder::default()
    }

    /// Registers a Plane's declaration and answers its handles. A Plane holds no secret: what it
    /// MACs under is a zone key handle the Host holds (WP-3.3).
    ///
    /// Refuses a Plane registered before, and any declaration that collides with one already
    /// registered: an artifact type, a ring signed by two Planes, an audit schema, a stream
    /// descriptor, a task type or a scope schema.
    pub fn register(&self, declaration: Declaration) -> Result<Registration, CompositionError> {
        let plane = declaration.plane.clone();
        if let Some((artifact, _)) = declaration
            .signers
            .iter()
            .find(|(artifact, _)| HOST_RESERVED.contains(artifact))
        {
            return Err(CompositionError::Reserved {
                plane,
                artifact: (*artifact).to_owned(),
            });
        }
        // `host.operations` is the Host's: a Plane signs under it only a payload the Host writes
        // (WP-7.10).
        if let Some((artifact, _)) = declaration.signers.iter().find(|(artifact, ring)| {
            *ring == HOST_OPERATIONS && !OPERATIONS_ARTIFACTS.contains(artifact)
        }) {
            return Err(CompositionError::Reserved {
                plane,
                artifact: (*artifact).to_owned(),
            });
        }
        if let Some(job) = declaration
            .gc_jobs
            .iter()
            .find(|job| !crate::gc::JOBS.contains(job))
        {
            return Err(CompositionError::UnknownGcJob {
                plane,
                job: (*job).to_owned(),
            });
        }
        {
            let mut claims = self
                .claimed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if claims.planes.contains(&plane) {
                return Err(CompositionError::AlreadyRegistered(plane));
            }
            // The Host serves the sides of its own contracts: no Plane claims one (WP-4.7,
            // WP-6.2c1).
            if let Some(contract) = declaration.tasks.iter().find(|contract| {
                crate::membership::contracts::host_side(contract.task_type, contract.role)
            }) {
                return Err(CompositionError::Collision {
                    what: "task contract",
                    name: format!("{} {}", contract.task_type.as_str(), contract.role.as_str()),
                    first: "host".to_owned(),
                    second: plane,
                });
            }
            let mut claimed: Vec<(&'static str, String)> = Vec::new();
            for (artifact, ring) in &declaration.signers {
                claimed.push(("artifact type", (*artifact).to_owned()));
                claimed.push(("signing ring", ring.as_str().to_owned()));
            }
            claimed.extend(
                declaration
                    .audit
                    .iter()
                    .map(|(name, _)| ("audit schema", (*name).to_owned())),
            );
            claimed.extend(
                declaration
                    .streams
                    .iter()
                    .map(|name| ("stream descriptor", name.clone())),
            );
            // One Plane provides a task type, and one consumes it, whatever the versions.
            let mut sides: Vec<(&'static str, String)> = declaration
                .tasks
                .iter()
                .map(|contract| {
                    (
                        "task contract",
                        format!("{} {}", contract.task_type.as_str(), contract.role.as_str()),
                    )
                })
                .collect();
            sides.sort();
            sides.dedup();
            claimed.extend(sides);
            claimed.extend(
                declaration
                    .scope_schemas
                    .iter()
                    .map(|name| ("scope schema", name.clone())),
            );
            claimed.extend(
                declaration
                    .gc_jobs
                    .iter()
                    .map(|job| ("gc job", (*job).to_owned())),
            );
            claimed.extend(
                declaration
                    .mutations
                    .iter()
                    .map(|domain| ("mutation domain", (*domain).to_owned())),
            );
            claimed.sort();
            // A Plane signing two artifacts with one ring claims the ring once; anything else it
            // names twice is a collision with itself.
            claimed.dedup_by(|left, right| left.0 == "signing ring" && left == right);
            for (at, (what, name)) in claimed.iter().enumerate() {
                let first = match claims.by_kind.get(&(*what, name.clone())) {
                    Some(first) => Some(first.clone()),
                    None => claimed[..at]
                        .contains(&(*what, name.clone()))
                        .then(|| plane.clone()),
                };
                if let Some(first) = first {
                    return Err(CompositionError::Collision {
                        what,
                        name: name.clone(),
                        first,
                        second: plane,
                    });
                }
            }
            for (what, name) in claimed {
                claims.by_kind.insert((what, name), plane.clone());
            }
            claims.planes.push(plane.clone());
        }

        let owned = |stream: &&String| {
            stream
                .split_once('/')
                .is_some_and(|(owner, _)| owner == plane)
        };
        let producers = declaration
            .streams
            .iter()
            // A Plane reaches the producers of its own streams only, `<plane>/<type>`.
            .filter(owned)
            .filter_map(|stream| {
                self.streams
                    .as_ref()
                    .and_then(|engine| engine.producer(stream))
                    .map(|producer| (stream.clone(), producer))
            })
            .collect();
        let consumers = declaration
            .read_streams
            .iter()
            .filter_map(|stream| {
                self.streams
                    .as_ref()
                    .and_then(|engine| engine.consumer(stream))
                    .map(|consumer| (stream.clone(), consumer))
            })
            .collect();
        let provided: Vec<(crate::membership::record::TaskType, u64)> = declaration
            .tasks
            .iter()
            .filter(|contract| contract.role == crate::membership::record::ContractRole::Provider)
            .map(|contract| (contract.task_type, contract.version))
            .collect();
        Ok(Registration {
            task_slots: provided
                .iter()
                .filter_map(|key| {
                    self.task_slots
                        .get(key)
                        .map(|slot| (*key, Arc::clone(slot)))
                })
                .collect(),
            hints: self.hub.as_ref().map(|hub| Hints {
                hub: Arc::clone(hub),
                tasks: provided.iter().map(|(task, _)| *task).collect(),
            }),
            provided,
            mutations: self.mutations.as_ref().map(Arc::clone),
            declared_mutations: declaration.mutations.clone(),
            plane,
            signers: declaration
                .signers
                .iter()
                .filter_map(|(artifact, ring)| {
                    self.rings
                        .get(ring)
                        .map(|keys| (*artifact, (*ring, Arc::clone(keys))))
                })
                .collect(),
            declared_signers: declaration
                .signers
                .iter()
                .map(|(artifact, _)| *artifact)
                .collect(),
            public: declaration
                .public_rings
                .iter()
                .filter_map(|ring| self.rings.get(ring).map(|keys| (*ring, Arc::clone(keys))))
                .collect(),
            declared_public: declaration.public_rings.clone(),
            audit: declaration.audit.iter().map(|(name, _)| *name).collect(),
            recorder: self.recorder.clone(),
            zone_keys: declaration
                .zone_keys
                .iter()
                .filter_map(|purpose| {
                    self.zone_keys
                        .get(purpose)
                        .map(|handle| (*purpose, Arc::clone(handle)))
                })
                .collect(),
            declared_zone_keys: declaration.zone_keys.clone(),
            producers,
            declared_streams: declaration.streams.clone(),
            consumers,
            declared_reads: declaration.read_streams.clone(),
            host_id: self.host_id,
            layouts: declaration
                .layouts
                .iter()
                .map(|subsystem| (*subsystem, self.layouts.get(*subsystem).copied()))
                .collect(),
            authorization: self
                .authorization
                .clone()
                .unwrap_or_else(|| Arc::new(Authorization::closed())),
            time: Arc::clone(&self.time),
            memberships: declaration
                .tasks
                .iter()
                .any(|contract| {
                    matches!(
                        contract.task_type,
                        crate::membership::record::TaskType::PolicyMirror
                            | crate::membership::record::TaskType::EventsImport
                    ) && contract.role == crate::membership::record::ContractRole::Provider
                })
                .then(|| self.memberships.clone())
                .flatten(),
            mirror_tasks: declaration
                .tasks
                .iter()
                .any(|contract| {
                    contract.task_type == crate::membership::record::TaskType::PolicyMirror
                        && contract.role == crate::membership::record::ContractRole::Consumer
                })
                .then(|| self.mirror_tasks.clone())
                .flatten(),
            holds: declaration
                .reads_holds
                .then(|| self.holds.clone())
                .flatten(),
            gc_jobs: (!declaration.gc_jobs.is_empty())
                .then(|| self.gc_jobs.clone())
                .flatten(),
            declared_gc_jobs: declaration.gc_jobs.clone(),
        })
    }
}

/// A Plane's handles: what its declaration granted, and nothing else.
pub struct Registration {
    task_slots: BTreeMap<
        (crate::membership::record::TaskType, u64),
        Arc<crate::membership::task::Deferred>,
    >,
    provided: Vec<(crate::membership::record::TaskType, u64)>,
    hints: Option<Hints>,
    mutations: Option<Arc<crate::operations::mutation::Mutations>>,
    declared_mutations: Vec<&'static str>,
    plane: String,
    signers: BTreeMap<&'static str, (RingId, Arc<dyn KeyManager>)>,
    declared_signers: Vec<&'static str>,
    public: BTreeMap<RingId, Arc<dyn KeyManager>>,
    declared_public: Vec<RingId>,
    audit: Vec<&'static str>,
    recorder: Option<AuditRecorder>,
    zone_keys: BTreeMap<crate::secrets::ZonePurpose, Arc<crate::secrets::ZoneHandle>>,
    declared_zone_keys: Vec<crate::secrets::ZonePurpose>,
    producers: BTreeMap<String, Arc<dyn StreamAppender>>,
    declared_streams: Vec<String>,
    consumers: BTreeMap<String, Arc<dyn StreamConsumerReads>>,
    declared_reads: Vec<String>,
    host_id: Option<[u8; 16]>,
    layouts: BTreeMap<&'static str, Option<u16>>,
    authorization: Arc<Authorization>,
    time: Arc<TimeGuard>,
    memberships: Option<Arc<dyn ServingMembers>>,
    mirror_tasks: Option<Arc<dyn MirrorTasks>>,
    holds: Option<Arc<crate::holds::HoldStore>>,
    gc_jobs: Option<Arc<crate::gc::Jobs>>,
    declared_gc_jobs: Vec<&'static str>,
}

/// Who serves a resource under this Host's memberships, and what was observed of them: the Host
/// API answers it (WP-4.4).
pub trait ServingMembers: Send + Sync {
    /// The members this Host coordinates whose `policy.mirror` task covers `resource`.
    fn serving_members(
        &self,
        resource: &permguard_core::authz::Resource,
    ) -> Vec<crate::api::members::ServingMemberView>;

    /// The required origins of `resource` for `events.import` (WP-6.2c1, owner decision of
    /// 2026-10-19): the members this Host coordinates whose `events.ship` task covers it.
    fn import_origins(
        &self,
        resource: &permguard_core::authz::Resource,
    ) -> Result<crate::membership::import::OriginSet, String> {
        let _ = resource;
        Ok(crate::membership::import::OriginSet::default())
    }
}

/// One `policy.mirror` task this Host holds as a member, as a mirror round snapshots it (WP-7.2a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorTask {
    pub membership_id: [u8; 16],
    pub task_id: String,
    /// The coordinator: the authority of every ledger the task serves.
    pub coordinator: [u8; 16],
    /// The epoch of the manifest the task was read from: the task's revision.
    pub revision: u64,
    /// The resource the task's selector covers, which a session reads under.
    pub resource: String,
    /// Whether the coordinator marked the task required: what the plane's readiness waits for.
    pub required: bool,
    /// The largest message the signed task lets a session carry.
    pub max_body_bytes: u64,
}

/// A `control.attest` set as a membership pins it (WP-7.2b): its epoch, the digest of its keys,
/// the identity-signed binding the pin names, and the keys, each the RFC 7517 JSON the statement
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRing {
    pub epoch: u64,
    pub key_set_digest: [u8; 32],
    /// The exact `COSE_Sign1` binding of the set under the coordinator's identity.
    pub binding: Vec<u8>,
    pub keys: Vec<String>,
}

/// A refusal on a `policy.mirror` session: the stable code, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRefusal {
    pub code: String,
    pub reason: String,
}

impl std::fmt::Display for MirrorRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

/// An open `policy.mirror` task session (WP-7.2a): one message, one answer, in order.
pub trait MirrorSession: Send {
    fn call(&mut self, body: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, MirrorRefusal>>;

    /// The coordinator's `control.attest` set the membership pins as the session opened, its
    /// binding verified under the coordinator's identity the session proved (WP-7.2b): what the
    /// ledgers' head statements verify under, never a ring the coordinator hands over. `None`
    /// when the manifest in force pins none, its statement is not held, or the binding does not
    /// verify.
    fn ring(&self) -> Option<PinnedRing>;

    /// Reports `resources`, one per ledger the task mirrors, as this session's task progress
    /// (WP-7.2d, `policy.mirror` progress): one bounded snapshot, numbered in this incarnation,
    /// which the coordinator keeps as member-reported state.
    fn report(
        &mut self,
        resources: Vec<crate::membership::record::ProgressResource>,
    ) -> BoxFuture<'_, Result<(), MirrorRefusal>>;
}

/// A `policy.mirror` watch (WP-7.2c, `WatchRefs`): the hints the coordinator sends as refs move.
pub trait MirrorWatch: Send {
    /// The next hints, each `(zone_id/ledger_id/ref, counter)` of a ref that moved past what the
    /// member holds; none for a heartbeat. A refusal ends the watch: lost, overflowed, fenced or
    /// silent past its bound.
    fn next(&mut self) -> BoxFuture<'_, Result<Vec<(String, u64)>, MirrorRefusal>>;
}

/// The member side of `policy.mirror` (WP-7.2a): the tasks this Host holds, and a session on
/// one. The member opens every session; the coordinator never dials.
pub trait MirrorTasks: Send + Sync {
    /// The active `policy.mirror` tasks of every membership this Host holds as a member.
    fn mirror_tasks(&self) -> Vec<MirrorTask>;

    /// Opens a task session over `task`'s resource, its lease verified and kept.
    fn open_mirror<'a>(
        &'a self,
        task: &'a MirrorTask,
    ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>>;

    /// Opens a session over `task`'s resource and turns it into a watch from `positions`, the
    /// counter held per `zone_id/ledger_id/ref` (WP-7.2c).
    fn watch_mirror<'a>(
        &'a self,
        task: &'a MirrorTask,
        positions: Vec<(String, u64)>,
    ) -> BoxFuture<'a, Result<Box<dyn MirrorWatch>, MirrorRefusal>>;
}

impl MirrorTasks for crate::api::HostApi {
    fn mirror_tasks(&self) -> Vec<MirrorTask> {
        crate::api::HostApi::mirror_tasks(self)
    }

    fn open_mirror<'a>(
        &'a self,
        task: &'a MirrorTask,
    ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
        Box::pin(crate::api::HostApi::open_mirror(self, task))
    }

    fn watch_mirror<'a>(
        &'a self,
        task: &'a MirrorTask,
        positions: Vec<(String, u64)>,
    ) -> BoxFuture<'a, Result<Box<dyn MirrorWatch>, MirrorRefusal>> {
        Box::pin(crate::api::HostApi::watch_mirror(self, task, positions))
    }
}

impl ServingMembers for crate::api::HostApi {
    fn serving_members(
        &self,
        resource: &permguard_core::authz::Resource,
    ) -> Vec<crate::api::members::ServingMemberView> {
        crate::api::HostApi::serving_members(self, resource)
    }

    fn import_origins(
        &self,
        resource: &permguard_core::authz::Resource,
    ) -> Result<crate::membership::import::OriginSet, String> {
        crate::api::HostApi::import_origins(self, resource)
    }
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("plane", &self.plane)
            .field("signers", &self.declared_signers)
            .field("public", &self.declared_public)
            .field("audit", &self.audit)
            .field("zone_keys", &self.declared_zone_keys)
            .finish()
    }
}

impl Registration {
    /// The signer for artifact `T`: `None` when its ring is not composed in this deployment.
    pub fn signer<T: Artifact>(&self) -> Result<Option<Signer<T>>, CompositionError> {
        if !self.declared_signers.contains(&T::TYPE) {
            return Err(self.undeclared(format!("a signer for `{}`", T::TYPE)));
        }
        Ok(self.signers.get(T::TYPE).map(|(_, keys)| Signer {
            keys: Arc::clone(keys),
            time: Arc::clone(&self.time),
            artifact: PhantomData,
        }))
    }

    /// The producer of `stream`, which the Plane declared (WP-5.1): `None` when no stream engine
    /// is composed in this deployment, or it has no producer of that stream.
    pub fn stream_producer(
        &self,
        stream: &str,
    ) -> Result<Option<StreamProducer>, CompositionError> {
        if !self
            .declared_streams
            .iter()
            .any(|declared| declared == stream)
        {
            return Err(self.undeclared(format!("the producer of stream `{stream}`")));
        }
        Ok(self.producers.get(stream).map(|appender| StreamProducer {
            appender: Arc::clone(appender),
        }))
    }

    /// The Host's consumer of `stream`, which the Plane declared it reads (WP-6.1): `None` when no
    /// stream engine is composed, or it consumes no such stream.
    pub fn stream_consumer(
        &self,
        stream: &str,
    ) -> Result<Option<StreamConsumer>, CompositionError> {
        if !self
            .declared_reads
            .iter()
            .any(|declared| declared == stream)
        {
            return Err(self.undeclared(format!("the consumer of stream `{stream}`")));
        }
        Ok(self.consumers.get(stream).map(|reads| StreamConsumer {
            reads: Arc::clone(reads),
        }))
    }

    /// The public set of `ring`: `None` when the ring is not composed in this deployment.
    pub fn public_keys(&self, ring: RingId) -> Result<Option<PublicKeys>, CompositionError> {
        if !self.declared_public.contains(&ring) {
            return Err(self.undeclared(format!("the public keys of `{}`", ring.as_str())));
        }
        Ok(self.public.get(&ring).map(|keys| PublicKeys {
            ring,
            keys: Arc::clone(keys),
        }))
    }

    /// The audit handle for schema `T`: `None` when no audit recorder is composed.
    pub fn audit<T: AuditSchema>(&self) -> Result<Option<AuditHandle<T>>, CompositionError> {
        if !self.audit.contains(&T::NAME) {
            return Err(self.undeclared(format!("the audit schema `{}`", T::NAME)));
        }
        Ok(self.recorder.clone().map(|recorder| AuditHandle {
            recorder,
            schema: PhantomData,
        }))
    }

    /// The Host's authorization, which every Plane decides with: deny by default, and closed
    /// when the Host built none.
    pub fn authorization(&self) -> Arc<Authorization> {
        Arc::clone(&self.authorization)
    }

    /// The zone keys of `purpose`: `None` when this Host holds none (no coordinator root and
    /// nothing delivered), never another purpose's.
    pub fn zone_key(
        &self,
        purpose: crate::secrets::ZonePurpose,
    ) -> Result<Option<Arc<crate::secrets::ZoneHandle>>, CompositionError> {
        if !self.declared_zone_keys.contains(&purpose) {
            return Err(self.undeclared(format!("the zone keys of `{}`", purpose.as_str())));
        }
        Ok(self.zone_keys.get(&purpose).cloned())
    }

    /// Serves `task` at `version`, which the Plane declared it provides, with `handler`: the
    /// Host's task sessions route its messages there from now on. Answers whether the Host
    /// routes the task at all; one without task sessions does not.
    pub fn serve_task(
        &self,
        task: crate::membership::record::TaskType,
        version: u64,
        handler: Arc<dyn crate::membership::task::TaskHandler>,
    ) -> Result<bool, CompositionError> {
        if !self.provided.contains(&(task, version)) {
            return Err(self.undeclared(format!(
                "the provider of `{}` version {version}",
                task.as_str()
            )));
        }
        match self.task_slots.get(&(task, version)) {
            Some(slot) => {
                slot.fill(handler)
                    .map(|()| true)
                    .map_err(|error| CompositionError::Collision {
                        what: "task handler",
                        name: format!("{} {version}: {error}", task.as_str()),
                        first: "an earlier registration".to_owned(),
                        second: self.plane.clone(),
                    })
            }
            None => Ok(false),
        }
    }

    /// Where this Plane publishes the watch hints of the tasks it provides, when the Host keeps
    /// watches.
    pub fn hints(&self) -> Option<Hints> {
        self.hints.clone()
    }

    /// The handle to the mutation transaction for `domain`, which the Plane declared: `None`
    /// when this Host composes no mutation engine.
    pub fn mutations(
        &self,
        domain: &'static str,
    ) -> Result<Option<MutationHandle>, CompositionError> {
        if !self.declared_mutations.contains(&domain) {
            return Err(self.undeclared(format!("the mutation domain `{domain}`")));
        }
        Ok(self.mutations.as_ref().map(|engine| MutationHandle {
            engine: Arc::clone(engine),
            domain,
        }))
    }

    /// The version in force of the layout `subsystem` on the volume, `None` when it is not laid
    /// out (WP-6.2d); refused for a layout this Plane did not declare.
    pub fn layout(&self, subsystem: &str) -> Result<Option<u16>, CompositionError> {
        self.layouts
            .get(subsystem)
            .copied()
            .ok_or_else(|| self.undeclared(format!("the layout `{subsystem}`")))
    }

    /// This Host's `host_id`, when the composition knows it: public, the salt of a Host-local
    /// key a Plane derives from its own root.
    pub fn host_id(&self) -> Option<[u8; 16]> {
        self.host_id
    }

    /// The Host's holds (WP-7.3c): `None` for a Plane that did not declare it reads them, or a
    /// Host that composes none.
    pub fn holds(&self) -> Option<Arc<crate::holds::HoldStore>> {
        self.holds.clone()
    }

    /// Provides the garbage-collection `job` this Plane declared with `handler` (WP-7.11b): the
    /// Host API plans and runs it from now on. Answers whether the Host serves the jobs at all;
    /// one without a Host API does not.
    pub fn provide_gc_job(
        &self,
        job: &'static str,
        handler: Arc<dyn crate::gc::GcJob>,
    ) -> Result<bool, CompositionError> {
        if !self.declared_gc_jobs.contains(&job) {
            return Err(self.undeclared(format!("the gc job `{job}`")));
        }
        match &self.gc_jobs {
            Some(jobs) => jobs
                .provide(job, &self.plane, handler)
                .map(|()| true)
                .map_err(|error| CompositionError::Collision {
                    what: "gc job",
                    name: format!("{job}: {error}"),
                    first: "an earlier registration".to_owned(),
                    second: self.plane.clone(),
                }),
            None => Ok(false),
        }
    }

    /// The member side of `policy.mirror` (WP-7.2a): `None` for a Plane that does not consume
    /// it, or a Host that holds no memberships.
    pub fn mirror_tasks(&self) -> Option<Arc<dyn MirrorTasks>> {
        self.mirror_tasks.clone()
    }

    /// The members serving `resource` (WP-4.4): empty for a Plane that does not provide
    /// `policy.mirror`, or a Host without memberships.
    pub fn serving_members(
        &self,
        resource: &permguard_core::authz::Resource,
    ) -> Vec<crate::api::members::ServingMemberView> {
        if !self.provides(crate::membership::record::TaskType::PolicyMirror) {
            return Vec::new();
        }
        self.memberships
            .as_ref()
            .map(|memberships| memberships.serving_members(resource))
            .unwrap_or_default()
    }

    /// The required origins of `resource` (WP-6.2c1): `None` for a Plane that does not provide
    /// `events.import`, or a Host without memberships.
    pub fn import_origins(
        &self,
        resource: &permguard_core::authz::Resource,
    ) -> Option<Result<crate::membership::import::OriginSet, String>> {
        if !self.provides(crate::membership::record::TaskType::EventsImport) {
            return None;
        }
        self.memberships
            .as_ref()
            .map(|memberships| memberships.import_origins(resource))
    }

    /// Whether the Plane declared it provides `task`, at any version.
    fn provides(&self, task: crate::membership::record::TaskType) -> bool {
        self.provided.iter().any(|(provided, _)| *provided == task)
    }

    fn undeclared(&self, what: String) -> CompositionError {
        CompositionError::Undeclared {
            plane: self.plane.clone(),
            what,
        }
    }
}

/// Signs artifact `T`, and nothing else, with the ring `T` names.
pub struct Signer<T: Artifact> {
    keys: Arc<dyn KeyManager>,
    time: Arc<TimeGuard>,
    artifact: PhantomData<fn() -> T>,
}

impl<T: Artifact> Clone for Signer<T> {
    fn clone(&self) -> Self {
        Self {
            keys: Arc::clone(&self.keys),
            time: Arc::clone(&self.time),
            artifact: PhantomData,
        }
    }
}

impl<T: Artifact> std::fmt::Debug for Signer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer<{}>({})", T::TYPE, T::RING.as_str())
    }
}

mod sealed {
    /// Only the Host implements [`super::Payload`]: what reaches a ring is framed here.
    pub trait Sealed {}
}

/// What a typed signer signs: an artifact's payload, in the canonical form its format fixes
/// (WP-3.2, owner decision of 2026-10-08). A Plane holds a [`Signer<T>`] and hands it a payload;
/// it never reaches a `sign(bytes)`. Sealed: the Host writes every signing input — the head
/// statement's COSE structure, a batch's protected header — so no implementation outside it can
/// hand a ring bytes of its own choosing.
///
/// ```compile_fail
/// use permguard_host::composition::{DecisionBatchV1, Payload};
///
/// struct Forged;
///
/// impl Payload for Forged {
///     type Artifact = DecisionBatchV1;
///     type Signed = ();
///
///     fn sign_with(
///         &self,
///         _: &dyn permguard_core::keys::SigningRing,
///     ) -> permguard_core::keys::Result<()> {
///         Ok(())
///     }
/// }
/// ```
pub trait Payload: sealed::Sealed {
    /// The artifact the payload is the content of: a `Signer<Self::Artifact>` signs it.
    type Artifact: Artifact;
    /// The signed artifact, as its format writes it.
    type Signed;
    /// Signs `self` with `keys`, the ring of [`Self::Artifact`], as the artifact's format does:
    /// the protected header naming the ring's active key, the canonical signing input.
    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Self::Signed>;
}

impl<T: Artifact> Signer<T> {
    /// Signs `payload`, a payload of `T` and of nothing else; refused while the Host's clock is in
    /// anomaly for an artifact that carries a time (WP-2.12).
    pub fn sign<P: Payload<Artifact = T>>(
        &self,
        payload: &P,
    ) -> permguard_core::keys::Result<P::Signed> {
        if T::TIME_SENSITIVE
            && let Err(anomaly) = self.time.trusted_now()
        {
            return Err(permguard_core::KeyError::ClockAnomaly {
                detail: anomaly.to_string(),
            });
        }
        payload.sign_with(self.keys.as_ref())
    }

    /// Whether a payload of `T` could be signed now: the clock trusted for an artifact that
    /// carries a time, and an active key. What a caller asks before committing to work whose
    /// answer needs the signature (WP-6.6b).
    pub fn ready(&self) -> permguard_core::keys::Result<()> {
        if T::TIME_SENSITIVE
            && let Err(anomaly) = self.time.trusted_now()
        {
            return Err(permguard_core::KeyError::ClockAnomaly {
                detail: anomaly.to_string(),
            });
        }
        self.keys.active_key_id().map(|_| ())
    }

    /// The key that signs now.
    pub fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        self.keys.active_key_id()
    }

    /// The time an artifact signed now carries: the Host's time guard (WP-2.12).
    pub fn signing_time(&self) -> i64 {
        self.time.now()
    }
}

/// A NOTP head statement is the payload of [`HeadStatementV1`]: a COSE_Sign1 under the ring's
/// active key, its `kid` the key's, refused when the ring rotated mid-signature.
impl sealed::Sealed for permguard_objects::statement::HeadStatement {}

impl Payload for permguard_objects::statement::HeadStatement {
    type Artifact = HeadStatementV1;
    type Signed = Vec<u8>;

    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Vec<u8>> {
        // The ring's epoch and set, bound into the statement, and its suite (WP-7.1).
        let set = keys.key_set()?;
        let suite = permguard_objects::crypto::suite::Suite::from_jws_alg(set.algorithm)
            .ok_or_else(|| {
                permguard_core::KeyError::backend(format!(
                    "the ring signs with `{}`, no suite of a head statement",
                    set.algorithm
                ))
            })?;
        let statement = permguard_objects::statement::HeadStatement {
            ring_epoch: set.epoch,
            key_set_digest: permguard_objects::digest::Digest::from_raw(set.digest),
            ..self.clone()
        };
        let kid = keys.active_key_id()?;
        let failed = std::cell::RefCell::new(None::<permguard_core::KeyError>);
        let signed = permguard_objects::statement::SignedHead::sign_with(
            &statement,
            suite,
            kid.as_str().as_bytes(),
            |bytes| {
                let signature = keys.sign(bytes).map_err(|error| {
                    let detail = error.to_string();
                    *failed.borrow_mut() = Some(error);
                    permguard_objects::statement::StatementError::Signer(detail)
                })?;
                if signature.key_id() != &kid {
                    return Err(permguard_objects::statement::StatementError::Signer(
                        "the signing key rotated mid-signature".to_owned(),
                    ));
                }
                // The set the statement binds is the one in force once the signature is made:
                // a ring that moved its epoch or set in between names another, refused.
                if keys.key_set().ok() != Some(set) {
                    return Err(permguard_objects::statement::StatementError::Signer(
                        "the ring's key set moved mid-signature".to_owned(),
                    ));
                }
                Ok(signature.bytes().to_vec())
            },
        )
        .map_err(|error| {
            failed.take().unwrap_or_else(|| {
                permguard_core::KeyError::backend(format!("signing the head statement: {error}"))
            })
        })?;
        signed.encode().map_err(|error| {
            permguard_core::KeyError::backend(format!("encoding the head statement: {error}"))
        })
    }
}

/// An import checkpoint is the payload of [`ImportCheckpointV1`]: a COSE_Sign1 under the ring's
/// active key, binding the ring's epoch and key set, refused when the ring moved mid-signature.
impl sealed::Sealed for crate::exports::Manifest {}

/// An export manifest is the payload of [`LedgerExportV1`]: a COSE_Sign1 under the ring's active
/// key, refused when the key rotated mid-signature.
impl Payload for crate::exports::Manifest {
    type Artifact = LedgerExportV1;
    type Signed = Vec<u8>;

    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Vec<u8>> {
        let set = keys.key_set()?;
        let suite = permguard_objects::crypto::suite::Suite::from_jws_alg(set.algorithm)
            .ok_or_else(|| {
                permguard_core::KeyError::backend(format!(
                    "the ring signs with `{}`, no suite of an export manifest",
                    set.algorithm
                ))
            })?;
        let payload = self.encode().map_err(|error| {
            permguard_core::KeyError::backend(format!("encoding the export manifest: {error}"))
        })?;
        let kid = keys.active_key_id()?;
        let failed = std::cell::RefCell::new(None::<permguard_core::KeyError>);
        let signed = permguard_objects::cose::Sign1::sign_with(
            suite,
            LedgerExportV1::TYPE,
            kid.as_str().as_bytes(),
            payload,
            |bytes| {
                let signature = keys.sign(bytes).map_err(|error| {
                    let detail = error.to_string();
                    *failed.borrow_mut() = Some(error);
                    detail
                })?;
                if signature.key_id() != &kid {
                    return Err("the signing key rotated mid-signature".to_owned());
                }
                Ok(signature.bytes().to_vec())
            },
        )
        .map_err(|error| {
            failed.take().unwrap_or_else(|| {
                permguard_core::KeyError::backend(format!("signing the export manifest: {error}"))
            })
        })?;
        signed.encode().map_err(|error| {
            permguard_core::KeyError::backend(format!("encoding the export manifest: {error}"))
        })
    }
}

impl sealed::Sealed for crate::membership::import::Checkpoint {}

impl Payload for crate::membership::import::Checkpoint {
    type Artifact = ImportCheckpointV1;
    type Signed = Vec<u8>;

    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Vec<u8>> {
        let set = keys.key_set()?;
        let suite = permguard_objects::crypto::suite::Suite::from_jws_alg(set.algorithm)
            .ok_or_else(|| {
                permguard_core::KeyError::backend(format!(
                    "the ring signs with `{}`, no suite of an import checkpoint",
                    set.algorithm
                ))
            })?;
        let checkpoint = crate::membership::import::Checkpoint {
            ring_epoch: set.epoch,
            key_set_digest: set.digest,
            ..self.clone()
        };
        let payload = checkpoint.encode().map_err(|error| {
            permguard_core::KeyError::backend(format!("encoding the import checkpoint: {error}"))
        })?;
        let kid = keys.active_key_id()?;
        let failed = std::cell::RefCell::new(None::<permguard_core::KeyError>);
        let signed = permguard_objects::cose::Sign1::sign_with(
            suite,
            ImportCheckpointV1::TYPE,
            kid.as_str().as_bytes(),
            payload,
            |bytes| {
                let signature = keys.sign(bytes).map_err(|error| {
                    let detail = error.to_string();
                    *failed.borrow_mut() = Some(error);
                    detail
                })?;
                if signature.key_id() != &kid {
                    return Err("the signing key rotated mid-signature".to_owned());
                }
                if keys.key_set().ok() != Some(set) {
                    return Err("the ring's key set moved mid-signature".to_owned());
                }
                Ok(signature.bytes().to_vec())
            },
        )
        .map_err(|error| {
            failed.take().unwrap_or_else(|| {
                permguard_core::KeyError::backend(format!("signing the import checkpoint: {error}"))
            })
        })?;
        signed.encode().map_err(|error| {
            permguard_core::KeyError::backend(format!("encoding the import checkpoint: {error}"))
        })
    }
}

/// An artifact signed as a JWS whose protected header the Host writes (WP-3.2). Sealed: the
/// framings are the Host's, so no Plane makes a JWS of its own on its ring.
pub trait JwsArtifact: Artifact + sealed::Sealed {
    /// The algorithm the header declares, and the only one the signature may be made with.
    const ALGORITHM: &'static str;
    /// Whether the header declares [`Artifact::TYPE`] as its `typ`.
    const DECLARES_TYPE: bool;
    /// Whether the header is written in its JCS form, members sorted (`alg`, `kid`, `typ`): what
    /// a signed decision response's contract fixes (WP-6.6b). The batches keep the bytes they
    /// were always signed with.
    const CANONICAL_HEADER: bool = false;
}

impl sealed::Sealed for DecisionBatchV1 {}
impl sealed::Sealed for EventBatchV1 {}
impl sealed::Sealed for DecisionResponseV1 {}

/// A signed decision response's header is the closed JCS `{"alg","kid","typ"}`.
impl JwsArtifact for DecisionResponseV1 {
    const ALGORITHM: &'static str = "EdDSA";
    const DECLARES_TYPE: bool = true;
    const CANONICAL_HEADER: bool = true;
}

/// A decision batch's header is `{"alg","kid"}`.
impl JwsArtifact for DecisionBatchV1 {
    const ALGORITHM: &'static str = "EdDSA";
    const DECLARES_TYPE: bool = false;
}

/// An event batch's header is `{"alg","typ","kid"}`.
impl JwsArtifact for EventBatchV1 {
    const ALGORITHM: &'static str = "EdDSA";
    const DECLARES_TYPE: bool = true;
}

/// A JWS payload of `T`: the canonical bytes its format fixes. The Host writes the protected
/// header and the signing input `protected || "." || payload`.
pub struct Jws<'a, T> {
    payload: &'a [u8],
    artifact: PhantomData<T>,
}

impl<'a, T: JwsArtifact> Jws<'a, T> {
    /// The payload `bytes`, to be signed as `T`.
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            payload,
            artifact: PhantomData,
        }
    }
}

/// A signed JWS's three parts, base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsParts {
    /// The protected header the Host wrote.
    pub protected: String,
    /// The payload.
    pub payload: String,
    /// The signature over `protected || "." || payload`.
    pub signature: String,
}

/// Why a JWS was not signed.
#[derive(Debug)]
pub enum JwsError {
    /// The ring did not sign.
    Key(permguard_core::KeyError),
    /// The ring signed with an algorithm the artifact's header does not declare.
    Algorithm(String),
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(error) => write!(f, "{error}"),
            Self::Algorithm(found) => write!(f, "the ring signed with `{found}`"),
        }
    }
}

impl std::error::Error for JwsError {}

#[derive(serde::Serialize)]
struct JwsHeader<'a> {
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
    kid: &'a str,
}

/// The JCS header: members in code-point order, every one present.
#[derive(serde::Serialize)]
struct CanonicalJwsHeader<'a> {
    alg: &'a str,
    kid: &'a str,
    typ: &'a str,
}

/// Signs `payload` as a JWS of `T` under `keys`' active key: the one framing of a batch, used by
/// the Host's [`Signer<T>`] and by a tool that holds a ring itself.
pub fn sign_jws<T: JwsArtifact>(
    payload: &[u8],
    keys: &dyn permguard_core::keys::Sign,
) -> Result<JwsParts, JwsError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    let kid = keys.active_key_id().map_err(JwsError::Key)?;
    let header = if T::CANONICAL_HEADER {
        serde_json::to_vec(&CanonicalJwsHeader {
            alg: T::ALGORITHM,
            kid: kid.as_str(),
            typ: T::TYPE,
        })
    } else {
        serde_json::to_vec(&JwsHeader {
            alg: T::ALGORITHM,
            typ: T::DECLARES_TYPE.then_some(T::TYPE),
            kid: kid.as_str(),
        })
    }
    .map_err(|error| {
        JwsError::Key(permguard_core::KeyError::backend(format!(
            "writing the protected header: {error}"
        )))
    })?;
    let protected = B64.encode(header);
    let payload = B64.encode(payload);
    let signature = keys
        .sign(format!("{protected}.{payload}").as_bytes())
        .map_err(JwsError::Key)?;
    if signature.algorithm() != T::ALGORITHM {
        return Err(JwsError::Algorithm(signature.algorithm().to_owned()));
    }
    if signature.key_id() != &kid {
        return Err(JwsError::Key(permguard_core::KeyError::backend(
            "the signing key rotated mid-signature",
        )));
    }
    Ok(JwsParts {
        protected,
        payload,
        signature: B64.encode(signature.bytes()),
    })
}

impl<T: JwsArtifact> sealed::Sealed for Jws<'_, T> {}

impl<T: JwsArtifact> Payload for Jws<'_, T> {
    type Artifact = T;
    type Signed = JwsParts;

    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<JwsParts> {
        sign_jws::<T>(self.payload, keys).map_err(|error| match error {
            JwsError::Key(error) => error,
            JwsError::Algorithm(_) => permguard_core::KeyError::backend(error.to_string()),
        })
    }
}

impl<T: Artifact> permguard_core::keys::PublicSet for Signer<T> {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        self.keys.public_keys()
    }

    fn key_set(&self) -> permguard_core::keys::Result<permguard_core::keys::KeySetView> {
        self.keys.key_set()
    }
}

/// A ring's public set: read, never signed with.
#[derive(Clone)]
pub struct PublicKeys {
    ring: RingId,
    keys: Arc<dyn KeyManager>,
}

impl std::fmt::Debug for PublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKeys({})", self.ring.as_str())
    }
}

impl permguard_core::keys::PublicSet for PublicKeys {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        self.keys.public_keys()
    }

    fn key_set(&self) -> permguard_core::keys::Result<permguard_core::keys::KeySetView> {
        self.keys.key_set()
    }
}

/// The watch hints of the tasks one Plane provides (WP-4.4): a hint grants nothing, it schedules
/// the member's ordinary round.
#[derive(Clone)]
pub struct Hints {
    hub: Arc<crate::membership::watch::Hub>,
    tasks: Vec<crate::membership::record::TaskType>,
}

impl std::fmt::Debug for Hints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hints")
            .field("tasks", &self.tasks)
            .finish_non_exhaustive()
    }
}

impl Hints {
    /// Offers `hint` about `resource` to the live watches of `task`; a task this Plane does not
    /// provide reaches no one.
    pub fn publish(
        &self,
        task: crate::membership::record::TaskType,
        resource: &permguard_core::authz::Resource,
        hint: &crate::membership::record::WatchHint,
    ) {
        if self.tasks.contains(&task) {
            self.hub.publish(task, resource, hint);
        }
    }
}

/// The mutation transaction of one declared domain (WP-3.6): it runs and recovers that domain's
/// operations, and no other domain's.
#[derive(Clone)]
pub struct MutationHandle {
    engine: Arc<crate::operations::mutation::Mutations>,
    domain: &'static str,
}

impl std::fmt::Debug for MutationHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MutationHandle({})", self.domain)
    }
}

impl MutationHandle {
    /// A handle over `engine` for `domain`, for a test or a composition that holds the engine
    /// itself.
    pub fn new(engine: Arc<crate::operations::mutation::Mutations>, domain: &'static str) -> Self {
        Self { engine, domain }
    }

    /// The domain it applies.
    pub fn domain(&self) -> &'static str {
        self.domain
    }

    /// [`crate::operations::mutation::Mutations::run_checked`], for an operation of this domain;
    /// one of another domain is refused before anything is written.
    pub fn run_checked<T, E>(
        &self,
        begin: crate::operations::mutation::Begin,
        check: impl FnOnce() -> Result<(), E>,
        apply: impl FnOnce(
            &crate::operations::mutation::Applying<'_>,
        ) -> Result<
            crate::operations::mutation::Applied<T>,
            crate::operations::mutation::Failure<E>,
        >,
    ) -> Result<
        crate::operations::mutation::Outcome<T>,
        crate::operations::mutation::MutationError<E>,
    >
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        if begin.domain != self.domain {
            return Err(crate::operations::mutation::MutationError::Unavailable(
                format!(
                    "this handle applies `{}`, not `{}`",
                    self.domain, begin.domain
                ),
            ));
        }
        self.engine.run_checked(begin, check, apply)
    }

    /// [`crate::operations::mutation::Mutations::replayed`], for a request of this domain: the
    /// answer a retry learns before the caller resolves anything; one of another domain is
    /// refused.
    pub fn replayed<T, E>(
        &self,
        begin: &crate::operations::mutation::Begin,
    ) -> Result<
        Option<crate::operations::mutation::Outcome<T>>,
        crate::operations::mutation::MutationError<E>,
    >
    where
        T: serde::de::DeserializeOwned,
    {
        if begin.domain != self.domain {
            return Err(crate::operations::mutation::MutationError::Unavailable(
                format!(
                    "this handle applies `{}`, not `{}`",
                    self.domain, begin.domain
                ),
            ));
        }
        self.engine.replayed(begin)
    }

    /// Resolves the open operations this domain left at a crash.
    pub fn recover(
        &self,
        domain: &dyn crate::operations::mutation::Domain,
    ) -> Result<crate::operations::mutation::Recovered, crate::storage::StorageError> {
        if domain.name() != self.domain {
            return Err(crate::storage::StorageError::Refused(format!(
                "this handle recovers `{}`, not `{}`",
                self.domain,
                domain.name()
            )));
        }
        self.engine.recover(domain)
    }
}

/// Records the actions schema `T` declares, and refuses any other.
pub struct AuditHandle<T: AuditSchema> {
    recorder: AuditRecorder,
    schema: PhantomData<fn() -> T>,
}

impl<T: AuditSchema> Clone for AuditHandle<T> {
    fn clone(&self) -> Self {
        Self {
            recorder: self.recorder.clone(),
            schema: PhantomData,
        }
    }
}

impl<T: AuditSchema> std::fmt::Debug for AuditHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuditHandle<{}>", T::NAME)
    }
}

/// Why an audit handle did not record.
#[derive(Debug)]
pub enum AuditRefusal {
    /// The action is not one the handle's schema declares: nothing was recorded.
    Undeclared {
        schema: &'static str,
        action: String,
    },
    /// The sink refused or could not be reached.
    Sink(AuditError),
}

impl std::fmt::Display for AuditRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undeclared { schema, action } => write!(
                f,
                "the action `{action}` is not in the audit schema `{schema}`; nothing was recorded"
            ),
            Self::Sink(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuditRefusal {}

impl<T: AuditSchema> AuditHandle<T> {
    fn check(action: &str) -> Result<(), AuditRefusal> {
        if T::ACTIONS.contains(&action) {
            Ok(())
        } else {
            Err(AuditRefusal::Undeclared {
                schema: T::NAME,
                action: action.to_owned(),
            })
        }
    }

    /// The privacy policy the Host records subjects under, for a Plane that tokenises identifiers
    /// before they leave it: a capability that pseudonymises, never its key.
    pub fn pseudonymizer(&self) -> Option<Arc<dyn permguard_core::Pseudonymizer>> {
        self.recorder.pseudonymizer()
    }

    /// Records `action`, one of the schema's.
    pub async fn record(&self, action: &str, subject: Subject<'_>) -> Result<(), AuditRefusal> {
        Self::check(action)?;
        self.recorder
            .record(action, subject)
            .await
            .map_err(AuditRefusal::Sink)
    }

    /// Records `action`, one of the schema's, naming what it was done to.
    pub async fn record_on(
        &self,
        action: &str,
        subject: Subject<'_>,
        target: &str,
    ) -> Result<(), AuditRefusal> {
        Self::check(action)?;
        self.recorder
            .record_on(action, subject, target)
            .await
            .map_err(AuditRefusal::Sink)
    }

    /// Records `event`, whose action is one of the schema's, as built: a resource narrowed below
    /// the root the Host assigns the Plane, an outcome, facts or an operation's phase.
    pub async fn record_event(&self, event: &AuditEvent<'_>) -> Result<(), AuditRefusal> {
        Self::check(event.action())?;
        self.recorder
            .record_event(event)
            .await
            .map_err(AuditRefusal::Sink)
    }
}

/// What appending a record answers: the run and the sequence it took (WP-5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamReceipt {
    pub run_id: [u8; 16],
    pub seq: u64,
}

/// Where the next record of a stream lands (WP-6.1): its run, its sequence and the digest of the
/// record before it in the run, zeros at sequence 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPosition {
    pub run_id: [u8; 16],
    pub seq: u64,
    pub prev: [u8; 32],
}

/// The records a Plane builds from a stream's next position: consecutive sequences from it.
pub type BuildRecords<'a> = &'a mut dyn FnMut(StreamPosition) -> Result<Vec<Vec<u8>>, String>;

/// One stream's producer as the Host's engine serves it: a record's bytes, checked by the codec
/// the stream registered, appended durably (WP-5.1).
pub trait StreamAppender: Send + Sync {
    fn append(&self, resource: &Resource, record: &[u8]) -> Result<StreamReceipt, String>;

    /// Appends the records `build` makes from the stream's next position, called once under the
    /// lock that gives sequences: what a record naming its own place needs (WP-6.1). Answers the
    /// last record's receipt once it is durable.
    fn append_with(
        &self,
        resource: &Resource,
        build: BuildRecords<'_>,
    ) -> Result<StreamReceipt, String>;

    /// Whether the stream of `resource` holds more than `max_bytes` or older than `max_age_secs`
    /// that no required subscription acknowledged: the code naming which, or `None` (WP-6.1).
    fn pressure(
        &self,
        resource: &Resource,
        max_bytes: u64,
        max_age_secs: u64,
    ) -> Result<Option<&'static str>, String>;

    /// The runs of `resource`'s stream, in the order the producer opened them; none for a stream
    /// it never opened (WP-6.2a).
    fn runs(&self, resource: &Resource) -> Result<Vec<ProducedRun>, String> {
        let _ = resource;
        Err("this producer reads nothing back".to_owned())
    }

    /// The records of `run` from sequence `from`, at most `limit`, as their bytes; a read below
    /// what the run deleted answers from its low watermark, which the page names (WP-6.2a).
    fn records(
        &self,
        resource: &Resource,
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<ConsumedPage, String> {
        let _ = (resource, run, from, limit);
        Err("this producer reads nothing back".to_owned())
    }

    /// Keeps the `history` streams of this producer above `floor` from now on (WP-6.2a).
    fn retain_above(&self, floor: Arc<dyn StreamFloor>) -> Result<(), String> {
        let _ = floor;
        Err("this producer keeps no floor".to_owned())
    }
}

/// One run of a stream its producer holds (WP-6.2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProducedRun {
    pub run: [u8; 16],
    /// The last sequence it holds; zero before its first record.
    pub last_seq: u64,
    /// The first sequence still held: past a deleted prefix, 1 otherwise.
    pub low_watermark: u64,
    pub ended: bool,
}

/// The `history` floor a Plane registers on a stream it produces (WP-6.2a, after WP-5.6b): per
/// resource and run, the last sequence no loaded contract reads any more; `None` keeps the run
/// whole.
pub trait StreamFloor: Send + Sync {
    fn retention_safe(&self, resource: &str, run: &[u8; 16]) -> Option<u64>;
}

/// The streams this Host signs under a member ring, as a re-pin cuts them over to the ring's new
/// key (WP-4.5, WP-5.2): the engine lives in `permguard-stream`, the membership side here.
pub trait StreamCutovers: Send + Sync {
    /// `(stream, from_seq)` of every stream fenced by `membership_id` whose batches `ring`
    /// signs, from the first sequence its key `kid` seals: each recorded pending until journaled.
    /// An error means the streams are unknown, never that there are none.
    fn due(
        &self,
        membership_id: &[u8; 16],
        ring: &str,
        kid: &str,
    ) -> Result<Vec<(String, u64)>, String>;

    /// The coordinator journaled the cutover of `streams` to `ring`'s key `kid`: each seals under
    /// it from its `from_seq`.
    fn journaled(&self, ring: &str, kid: &str, streams: &[(String, u64)]) -> Result<(), String>;
}

/// One subscription a member ships under: its membership's task, as the manifest holds it
/// (WP-5.4, owner decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscribed<'a> {
    pub membership_id: [u8; 16],
    pub task_type: crate::membership::record::TaskType,
    pub task_id: &'a str,
    /// Whether the manifest makes it required: only a required subscription blocks deletion.
    pub required: bool,
    /// The membership's epoch: a subscription paused on `unverifiable` resumes once it moves.
    pub epoch: u64,
    /// The task's selector: a stream it covers whose run is not fenced by this subscription rolls
    /// over to one that is (WP-6.1).
    pub selector: &'a permguard_core::authz::Selector,
    /// The coordinator boot id of the session it ships on, `None` outside one (WP-7.9b): an
    /// answer below the acknowledgement under another incarnation is a restored coordinator's.
    pub coordinator_boot_id: Option<[u8; 16]>,
}

/// A message the engine has ready to ship, and what it ships.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shipment {
    /// Fresh for each delivery, so a resend is answered afresh.
    pub request_id: String,
    pub body: Vec<u8>,
    pub run: [u8; 16],
    pub first_seq: u64,
    pub last_seq: u64,
}

/// What shipping a stream's batches to a coordinator needs of the engine (WP-5.4, owner
/// decision): the member's pass drives the task sessions, the engine keeps the subscriptions.
pub trait StreamShipping: Send + Sync {
    /// The resources of the streams `subscription` ships now: a paused subscription whose epoch
    /// moved resumes; one backing off or stopped is not due.
    fn due(&self, subscription: &Subscribed<'_>) -> Result<Vec<String>, String>;

    /// The next message to ship on `resource`, within `max_bytes`; `None` when nothing is due.
    fn next(
        &self,
        subscription: &Subscribed<'_>,
        resource: &str,
        max_bytes: u64,
    ) -> Result<Option<Shipment>, String>;

    /// The coordinator answered `answer` to `shipment`: whether to ship on.
    fn answered(
        &self,
        subscription: &Subscribed<'_>,
        resource: &str,
        shipment: &Shipment,
        answer: &[u8],
    ) -> Result<bool, String>;

    /// The coordinator could not keep a batch now: the subscription backs off.
    fn deferred(&self, subscription: &Subscribed<'_>, resource: &str) -> Result<(), String>;

    /// The ship tasks `membership_id`'s manifest still holds: every other subscription of it
    /// is dropped, which only a signed manifest revision does.
    fn retain(&self, membership_id: &[u8; 16], task_ids: &[String]) -> Result<(), String>;

    /// The streams a required subscription is behind on now, with the mark each would take
    /// (WP-5.8): what a drain still has to ship.
    fn behind(&self) -> Result<Vec<Unshipped>, String> {
        Ok(Vec::new())
    }

    /// Marks every stream behind in its STATE, as an incomplete drain leaves it, and answers the
    /// marks (WP-5.8).
    fn mark_unshipped(&self) -> Result<Vec<Unshipped>, String> {
        Ok(Vec::new())
    }

    /// Removes the mark of every stream no longer behind, and answers the marks that remain
    /// (WP-5.8).
    fn settle_unshipped(&self) -> Result<Vec<Unshipped>, String> {
        Ok(Vec::new())
    }

    /// The mark of `resource`'s stream that `subscription`'s task ships, settled first: `None`
    /// when it holds none, or no longer needs one (WP-5.8).
    fn unshipped_on(
        &self,
        subscription: &Subscribed<'_>,
        resource: &str,
    ) -> Result<Option<Unshipped>, String> {
        let _ = (subscription, resource);
        Ok(None)
    }

    /// Every subscription the coordinator's answers left paused or stopped (F-08): what keeps a
    /// stream from shipping until its membership moves or an operator acts, so health can name
    /// it rather than let shipping stop silently. Required of every engine: one that forgot it
    /// would report nothing, which is the silence this exists to end.
    fn refused(&self) -> Result<Vec<RefusedShipping>, String>;
}

/// A subscription that does not ship now because the coordinator refused it (F-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedShipping {
    /// The membership whose ship task the subscription is.
    pub membership_id: [u8; 16],
    /// `<plane>/<type>`, as the Plane declared the stream.
    pub stream: String,
    /// The resource the stream is of.
    pub resource: String,
    /// The ship task the subscription is of.
    pub task_id: String,
    /// `paused at epoch <n>` until the membership's epoch moves, or `stopped: <reason>` until an
    /// operator acts.
    pub state: String,
}

/// A stream an incomplete drain left behind its required subscriptions (WP-5.8, owner decision
/// of 2026-10-15): the last sequence of its newest run still behind, and that run's
/// `truncate_safe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unshipped {
    /// `<plane>/<type>`, as the Plane declared the stream.
    pub stream: String,
    /// The resource the stream is of.
    pub resource: String,
    pub tail: u64,
    pub truncate_safe: u64,
}

/// The Host's stream engine as composition reaches it (WP-5.1, interpretation): the engine lives
/// in `permguard-stream`, which depends on this crate, so the server hands it in through this.
pub trait StreamEngine: Send + Sync {
    /// The producer of `stream`, as the Plane declared it.
    fn producer(&self, stream: &str) -> Option<Arc<dyn StreamAppender>>;

    /// The consumer of `stream` (WP-6.1): `None` when the engine consumes no such stream.
    fn consumer(&self, _stream: &str) -> Option<Arc<dyn StreamConsumerReads>> {
        None
    }
}

/// One producer run the Host's consumer holds (WP-6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedRun {
    pub producer: [u8; 16],
    pub run: [u8; 16],
    /// The highest contiguous sequence held.
    pub acked: u64,
    /// The first sequence still held; below it a deleted prefix.
    pub oldest_retained: u64,
}

/// One consumed run's signers (WP-6.2b): from which sequence each key signed, by `kid`, with its
/// public JWK as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedSigners {
    pub producer: [u8; 16],
    pub run: [u8; 16],
    pub acked: u64,
    /// `(from_seq, kid, jwk)`, in sequence order.
    pub spans: Vec<(u64, String, String)>,
}

/// A page of a run's records, as their bytes: read from a consumer, or from a producer (WP-6.2a).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsumedPage {
    pub records: Vec<(u64, Vec<u8>)>,
    /// When the read started below what the run still holds: where it holds from.
    pub low_watermark: Option<u64>,
}

/// The origin a batch is imported from (WP-6.2c2a): its membership with the coordinator, the
/// manifest epoch it was verified at, its `host_id` and the `data.attest` pins that manifest holds.
#[derive(Debug, Clone, Copy)]
pub struct ImportOrigin<'a> {
    pub membership_id: [u8; 16],
    pub epoch: u64,
    pub host_id: [u8; 16],
    pub pins: &'a [crate::membership::record::RingPin],
}

/// What importing one batch came to, as the engine's ingest answered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Imported {
    /// Kept, or already held: the run is acknowledged through `acked`.
    Admitted { acked: u64 },
    /// Not contiguous with what is held: the next sequence wanted is `acked + 1`.
    OutOfOrder { acked: u64 },
    /// Below what the run still holds and not the batch that went.
    Gone { acked: u64 },
    /// The origin's stream differs from what is held, in `run` from `at`: it is closed here,
    /// every later batch of the origin answered so.
    Fork { run: [u8; 16], at: u64 },
    /// It did not verify under the origin's pins.
    Unverifiable,
}

/// What the member Host's `events.import` needs of its consumer of the event stream (WP-6.2c2a,
/// owner decisions of 2026-10-19): the runs it holds, the ingest of an origin's batch as the
/// origin shipped it, and the import's state per ledger, kept beside the runs.
pub trait StreamImport: Send + Sync {
    /// The last sequence held of `origin`'s run `run` over `resource`; 0 when none.
    fn held(&self, resource: &Resource, origin: &[u8; 16], run: &[u8; 16]) -> Result<u64, String>;

    /// Ingests `body`, a `ship_message` as `origin` shipped it, into `origin`'s own run.
    fn import(
        &self,
        resource: &Resource,
        origin: &ImportOrigin<'_>,
        body: &[u8],
    ) -> Result<Imported, String>;

    /// The import's state of `resource`, when one was kept.
    fn import_state(
        &self,
        resource: &Resource,
    ) -> Result<Option<crate::membership::import::State>, String>;

    /// Replaces the import's state of `resource`, durably.
    fn keep_import_state(
        &self,
        resource: &Resource,
        state: &crate::membership::import::State,
    ) -> Result<(), String>;
}

/// What a Plane reads of a stream the Host consumes (WP-6.1, owner decision of 2026-10-18): the
/// public reads answer from the consumer in-process, one copy.
pub trait StreamConsumerReads: Send + Sync {
    /// The runs held over `resource`, by producer and then the order they opened.
    fn runs(&self, resource: &Resource) -> Result<Vec<ConsumedRun>, String>;

    /// The resource over which `producer`'s run `run` is held, when it is.
    fn locate(&self, producer: &[u8; 16], run: &[u8; 16]) -> Result<Option<Resource>, String>;

    /// At most `limit` records of `producer`'s run `run` over `resource` from `from`.
    fn records(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<ConsumedPage, String>;

    /// The batch file, as admitted, covering `seq` of `producer`'s run `run` over `resource`.
    fn batch(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        seq: u64,
    ) -> Result<Option<Vec<u8>>, String>;

    /// The signing-key spans of each run over `resource` the consumer holds, with what it
    /// acknowledged (WP-6.2b): what a verifier checks a run's batches against.
    fn signers(&self, resource: &Resource) -> Result<Vec<ConsumedSigners>, String> {
        let _ = resource;
        Ok(Vec::new())
    }

    /// The ring statement, as its producer shipped it, under which the batches signed by `kid`
    /// of `producer`'s run `run` were verified (WP-6.2c1): what `events.import` forwards.
    fn statement(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        kid: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let _ = (resource, producer, run, kid);
        Ok(None)
    }

    /// The consumer's own time it admitted the last batch of `producer`'s run `run` at, in
    /// seconds (WP-6.2c1): the coordinator's receipt time a checkpoint names.
    fn admitted_at(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
    ) -> Result<Option<u64>, String> {
        let _ = (resource, producer, run);
        Ok(None)
    }

    /// The member Host's import state of `resource` (WP-6.2c2b1): the checkpoint it last verified,
    /// when, and the gaps it keeps; `None` when it imports nothing of it.
    fn import_state(
        &self,
        resource: &Resource,
    ) -> Result<Option<crate::membership::import::State>, String> {
        let _ = resource;
        Ok(None)
    }

    /// Keeps the consumer's `history` runs above `floor` (WP-6.2c2b1): what a loaded window still
    /// reads of the imported origins. A consumer that keeps no floor refuses.
    fn retain_above(&self, floor: Arc<dyn StreamFloor>) -> Result<(), String> {
        let _ = floor;
        Err("this consumer keeps no floor".to_owned())
    }

    /// Every resource the consumer holds a run of (WP-6.2c2b1, after the review): what a floor is
    /// measured over, read or not.
    fn resources(&self) -> Result<Vec<Resource>, String> {
        Ok(Vec::new())
    }
}

/// Reads a stream the Plane declared, as the Host's engine consumes it (WP-6.1).
#[derive(Clone)]
pub struct StreamConsumer {
    reads: Arc<dyn StreamConsumerReads>,
}

impl std::fmt::Debug for StreamConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamConsumer").finish_non_exhaustive()
    }
}

impl StreamConsumer {
    /// A handle over `reads`, for a test composing no Host.
    #[doc(hidden)]
    pub fn over(reads: Arc<dyn StreamConsumerReads>) -> Self {
        Self { reads }
    }

    pub fn runs(&self, resource: &Resource) -> Result<Vec<ConsumedRun>, String> {
        self.reads.runs(resource)
    }

    /// The signers of each run over `resource` (WP-6.2b).
    pub fn signers(&self, resource: &Resource) -> Result<Vec<ConsumedSigners>, String> {
        self.reads.signers(resource)
    }

    /// The ring statement the batches `kid` signed of a run were verified under (WP-6.2c1).
    pub fn statement(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        kid: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        self.reads.statement(resource, producer, run, kid)
    }

    /// The member Host's import state of `resource` (WP-6.2c2b1).
    pub fn import_state(
        &self,
        resource: &Resource,
    ) -> Result<Option<crate::membership::import::State>, String> {
        self.reads.import_state(resource)
    }

    /// Keeps the consumer's `history` runs above `floor` (WP-6.2c2b1).
    pub fn retain_above(&self, floor: Arc<dyn StreamFloor>) -> Result<(), String> {
        self.reads.retain_above(floor)
    }

    /// Every resource the consumer holds a run of.
    pub fn resources(&self) -> Result<Vec<Resource>, String> {
        self.reads.resources()
    }

    /// When the consumer admitted a run's last batch (WP-6.2c1).
    pub fn admitted_at(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
    ) -> Result<Option<u64>, String> {
        self.reads.admitted_at(resource, producer, run)
    }

    pub fn locate(&self, producer: &[u8; 16], run: &[u8; 16]) -> Result<Option<Resource>, String> {
        self.reads.locate(producer, run)
    }

    pub fn records(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<ConsumedPage, String> {
        self.reads.records(resource, producer, run, from, limit)
    }

    pub fn batch(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        seq: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        self.reads.batch(resource, producer, run, seq)
    }
}

/// Appends to a stream the Plane declared, through the Host's engine (WP-5.1).
#[derive(Clone)]
pub struct StreamProducer {
    appender: Arc<dyn StreamAppender>,
}

impl std::fmt::Debug for StreamProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamProducer").finish_non_exhaustive()
    }
}

impl StreamProducer {
    /// A handle over `appender`, for a test composing no Host.
    #[doc(hidden)]
    pub fn over(appender: Arc<dyn StreamAppender>) -> Self {
        Self { appender }
    }

    /// Appends `record` to the stream of `resource`; answers once it is durable.
    pub fn append(&self, resource: &Resource, record: &[u8]) -> Result<StreamReceipt, String> {
        self.appender.append(resource, record)
    }

    /// Appends the records `build` makes from the stream's next position; answers once the last
    /// is durable (WP-6.1).
    pub fn append_with(
        &self,
        resource: &Resource,
        build: BuildRecords<'_>,
    ) -> Result<StreamReceipt, String> {
        self.appender.append_with(resource, build)
    }

    /// Whether the stream of `resource` holds more unacknowledged than the bounds allow (WP-6.1).
    pub fn pressure(
        &self,
        resource: &Resource,
        max_bytes: u64,
        max_age_secs: u64,
    ) -> Result<Option<&'static str>, String> {
        self.appender.pressure(resource, max_bytes, max_age_secs)
    }

    /// The runs of `resource`'s stream, oldest first (WP-6.2a).
    pub fn runs(&self, resource: &Resource) -> Result<Vec<ProducedRun>, String> {
        self.appender.runs(resource)
    }

    /// The records of `run` from `from`, at most `limit` (WP-6.2a).
    pub fn records(
        &self,
        resource: &Resource,
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<ConsumedPage, String> {
        self.appender.records(resource, run, from, limit)
    }

    /// Keeps this producer's `history` streams above `floor` (WP-6.2a).
    pub fn retain_above(&self, floor: Arc<dyn StreamFloor>) -> Result<(), String> {
        self.appender.retain_above(floor)
    }
}

/// Calls a task on a peer Host the Plane declared: built by task routing (WP-4.x).
#[derive(Debug)]
pub struct TaskClient {
    _unbuildable: PhantomData<()>,
}

/// Authorizes a request against Host grants: the handle of [`crate::authz::Authorization`], one
/// per Host, handed to every registered Plane (WP-2.4).
pub use crate::authz::Authorization;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::keys::Maintenance;

    /// A ring that signs with a fixed tag, so a test can tell which ring signed.
    struct TaggedRing(&'static str);

    impl KeyManager for TaggedRing {
        fn name(&self) -> &'static str {
            "tagged"
        }
        fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
            Ok(Maintenance::default())
        }
    }

    impl permguard_core::keys::Sign for TaggedRing {
        fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
            Ok(KeyId::new(self.0))
        }

        fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
            let mut bytes = self.0.as_bytes().to_vec();
            bytes.extend_from_slice(payload);
            Ok(Signature::new(KeyId::new(self.0), "EdDSA", bytes))
        }
    }

    impl permguard_core::keys::PublicSet for TaggedRing {
        fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
            Ok(vec![Jwk::okp(self.0, "Ed25519", "EdDSA", "x")])
        }
    }

    /// WP-6.6b: a signed decision response's header is the closed JCS `{alg, kid, typ}`, while a
    /// batch keeps the header bytes it was always signed with.
    #[test]
    fn a_decision_response_header_is_jcs_and_a_batch_header_keeps_its_bytes() {
        use base64::Engine as _;
        let decode = |part: &str| {
            String::from_utf8(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(part)
                    .expect("base64url"),
            )
            .expect("UTF-8")
        };
        let ring = TaggedRing("k-1");
        let response = sign_jws::<DecisionResponseV1>(b"{}", &ring).expect("signed");
        assert_eq!(
            decode(&response.protected),
            r#"{"alg":"EdDSA","kid":"k-1","typ":"permguard.decision.response.v1"}"#
        );
        assert_eq!(decode(&response.payload), "{}");
        let batch = sign_jws::<EventBatchV1>(b"{}", &ring).expect("signed");
        assert_eq!(
            decode(&batch.protected),
            format!(
                r#"{{"alg":"EdDSA","typ":"{}","kid":"k-1"}}"#,
                permguard_core::domains::protected::EVENT_BATCH
            )
        );
    }
    /// A ring whose key set reads epoch 5, or, `moving`, a later epoch at every read: a rotation
    /// landing while a head statement is signed.
    struct EpochRing {
        moving: bool,
        reads: std::sync::atomic::AtomicU64,
    }

    impl KeyManager for EpochRing {
        fn name(&self) -> &'static str {
            "epoch"
        }
        fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
            Ok(Maintenance::default())
        }
    }

    impl permguard_core::keys::Sign for EpochRing {
        fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
            Ok(KeyId::new("control"))
        }
        fn sign(&self, _payload: &[u8]) -> permguard_core::keys::Result<Signature> {
            Ok(Signature::new(KeyId::new("control"), "EdDSA", vec![0; 64]))
        }
    }

    impl permguard_core::keys::PublicSet for EpochRing {
        fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
            Ok(vec![Jwk::okp("control", "Ed25519", "EdDSA", "x")])
        }
        fn key_set(&self) -> permguard_core::keys::Result<permguard_core::keys::KeySetView> {
            let read = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(permguard_core::keys::KeySetView {
                epoch: if self.moving { 5 + read } else { 5 },
                digest: [0x5a; 32],
                algorithm: "EdDSA",
            })
        }
    }

    /// WP-7.12: a mutation handle runs and recovers its own domain's operations, never
    /// another's, and refuses before anything is written.
    #[test]
    fn a_mutation_handle_applies_its_own_domain_only() {
        use crate::operations::journal::Initiator;
        use crate::operations::mutation::{Applied, Begin, Domain, Mutations, Observed};

        struct Other;
        impl Domain for Other {
            fn name(&self) -> &'static str {
                "other"
            }
            fn observe(
                &self,
                _: &crate::operations::journal::OperationId,
                _: Option<&str>,
            ) -> Option<Observed> {
                None
            }
        }

        let root =
            std::env::temp_dir().join(format!("permguard-handle-domain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let volume = crate::storage::volume::Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let engine = Arc::new(Mutations::open_offline(&volume, "test").expect("opens"));
        let handle = MutationHandle::new(Arc::clone(&engine), "mine");
        let applied = std::cell::Cell::new(false);
        let refused = handle.run_checked(
            Begin {
                domain: "other",
                operation: "other.change",
                action: "host.grant.issued",
                initiator: Initiator::System("test".to_owned()),
                request: None,
                target: None,
            },
            || Ok::<(), String>(()),
            |_| {
                applied.set(true);
                Ok(Applied {
                    revision: 1,
                    target: None,
                    value: (),
                })
            },
        );
        assert!(refused.is_err(), "another domain's operation is refused");
        assert!(!applied.get(), "and nothing of it was applied");
        assert!(engine.open_intents().is_empty(), "nor written");
        assert!(
            handle.recover(&Other).is_err(),
            "nor another domain recovered"
        );
    }

    /// A task context of `resource`, for the deferred handler's tests.
    fn task_context(resource: &str) -> crate::membership::task::TaskContext {
        crate::membership::task::TaskContext {
            selector: permguard_core::authz::Selector::under(
                permguard_core::authz::Resource::host(),
            ),
            membership_id: [1; 16],
            task_id: "mirror".to_owned(),
            task_type: crate::membership::record::TaskType::PolicyMirror,
            version: 1,
            epoch: 1,
            resource: resource.to_owned(),
            member: [2; 16],
            request_id: "r".to_owned(),
            limits: crate::membership::record::Limits {
                max_body_bytes: 1024,
                max_concurrency: 1,
                max_rate_per_minute: 60,
                max_batch_records: 10,
                retention_seconds: 60,
            },
            channel_binding: [3; 32],
        }
    }

    struct Echo;

    impl crate::membership::task::TaskHandler for Echo {
        fn handle(
            &self,
            _context: &crate::membership::task::TaskContext,
            body: &[u8],
        ) -> Result<Vec<u8>, crate::session::Refusal> {
            Ok(body.to_vec())
        }
    }

    /// WP-7.12: the Host routes a task to a slot before the Plane that provides it is composed;
    /// the slot answers `not_served_yet` until that Plane fills it, once, and only a Plane that
    /// declared the task may.
    #[test]
    fn a_task_slot_is_served_once_by_the_plane_that_declared_it() {
        use crate::membership::record::TaskType;
        use crate::membership::task::TaskHandler as _;

        let slot = Arc::new(crate::membership::task::Deferred::default());
        let host = Host::builder()
            .task_slot(TaskType::PolicyMirror, 1, Arc::clone(&slot))
            .build();
        let context = task_context("plane/control");
        assert_eq!(
            slot.handle(&context, b"x")
                .expect_err("nothing serves it yet")
                .code,
            permguard_core::codes::host::NOT_SERVED_YET
        );

        let stranger = host
            .register(Declaration::new("data").uses_task(TaskType::PolicyMirror, 1))
            .expect("registers");
        assert!(
            stranger
                .serve_task(TaskType::PolicyMirror, 1, Arc::new(Echo))
                .is_err(),
            "a consumer does not serve the task"
        );
        let provider = host
            .register(Declaration::new("control").handles_task(TaskType::PolicyMirror, 1))
            .expect("registers");
        assert_eq!(
            provider.serve_task(TaskType::PolicyMirror, 1, Arc::new(Echo)),
            Ok(true)
        );
        assert_eq!(slot.handle(&context, b"x").expect("served"), b"x");
        assert!(
            provider
                .serve_task(TaskType::PolicyMirror, 1, Arc::new(Echo))
                .is_err(),
            "the slot is filled once"
        );
    }

    /// WP-7.2a: the member side of `policy.mirror` goes to the Plane that consumes it, and to no
    /// other: not the provider, not a Plane that declared neither side.
    #[test]
    fn the_member_side_of_policy_mirror_is_granted_to_its_consumer_only() {
        use crate::membership::record::TaskType;

        struct NoTasks;

        impl MirrorTasks for NoTasks {
            fn mirror_tasks(&self) -> Vec<MirrorTask> {
                Vec::new()
            }

            fn open_mirror<'a>(
                &'a self,
                _task: &'a MirrorTask,
            ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
                Box::pin(std::future::ready(Err(MirrorRefusal {
                    code: "unavailable".to_owned(),
                    reason: "none".to_owned(),
                })))
            }

            fn watch_mirror<'a>(
                &'a self,
                _task: &'a MirrorTask,
                _positions: Vec<(String, u64)>,
            ) -> BoxFuture<'a, Result<Box<dyn MirrorWatch>, MirrorRefusal>> {
                Box::pin(std::future::ready(Err(MirrorRefusal {
                    code: "unavailable".to_owned(),
                    reason: "none".to_owned(),
                })))
            }
        }

        let host = Host::builder().mirror_tasks(Arc::new(NoTasks)).build();
        let consumer = host
            .register(Declaration::new("data").uses_task(TaskType::PolicyMirror, 1))
            .expect("registers");
        assert!(consumer.mirror_tasks().is_some());
        let provider = host
            .register(Declaration::new("control").handles_task(TaskType::PolicyMirror, 1))
            .expect("registers");
        assert!(
            provider.mirror_tasks().is_none(),
            "the provider never dials"
        );
        let bystander = host
            .register(Declaration::new("other").uses_task(TaskType::DecisionsShip, 1))
            .expect("registers");
        assert!(bystander.mirror_tasks().is_none());
        let unconsumed = Host::builder()
            .build()
            .register(Declaration::new("data").uses_task(TaskType::PolicyMirror, 1))
            .expect("registers");
        assert!(
            unconsumed.mirror_tasks().is_none(),
            "a Host holding no memberships hands out none"
        );
    }

    /// WP-7.12: a Plane publishes the hints of the tasks it provides, and of no other; a Host
    /// without watches hands out none.
    #[test]
    fn hints_reach_the_watches_of_a_task_the_plane_provides() {
        use crate::membership::record::{Lease, Limits, TaskType, WatchHint, WatchRequest};

        let hub = Arc::new(crate::membership::watch::Hub::default());
        let host = Host::builder().watch_hub(Arc::clone(&hub)).build();
        let provider = host
            .register(Declaration::new("control").handles_task(TaskType::PolicyMirror, 1))
            .expect("registers");
        let other = host
            .register(Declaration::new("data").handles_task(TaskType::EventsShip, 1))
            .expect("registers");
        let lease = Lease {
            membership_id: [1; 16],
            task_id: "mirror".to_owned(),
            epoch: 1,
            coordinator: [2; 16],
            member: [3; 16],
            coordinator_boot_id: [4; 16],
            member_boot_id: [5; 16],
            selector: permguard_core::authz::Selector::parse("plane/control/*")
                .expect("a selector"),
            resource: "plane/control/zone/z".to_owned(),
            limits: Limits {
                max_body_bytes: 1024,
                max_concurrency: 1,
                max_rate_per_minute: 60,
                max_batch_records: 10,
                retention_seconds: 60,
            },
            issued_at: 0,
            expires_at: 60,
            channel_binding: [6; 32],
            binding_digest: None,
        };
        let queue = hub
            .subscribe(
                TaskType::PolicyMirror,
                &lease,
                &WatchRequest {
                    positions: Vec::new(),
                },
            )
            .expect("subscribes");
        let resource = permguard_core::authz::Resource::ledger("control", "z", "l");
        let hint = |counter| WatchHint {
            key: "z/l/main".to_owned(),
            head: "sha256:00".to_owned(),
            counter,
        };
        other
            .hints()
            .expect("hints")
            .publish(TaskType::PolicyMirror, &resource, &hint(1));
        assert_eq!(
            queue.take(),
            Some(Vec::new()),
            "another Plane's task reaches no one"
        );
        let hints = provider.hints().expect("hints");
        hints.publish(TaskType::PolicyMirror, &resource, &hint(1));
        hints.publish(TaskType::PolicyMirror, &resource, &hint(3));
        hints.publish(TaskType::PolicyMirror, &resource, &hint(2));
        assert_eq!(
            queue.take(),
            Some(vec![hint(3)]),
            "coalesced, the newest counter wins"
        );

        assert!(
            Host::builder()
                .build()
                .register(Declaration::new("control").handles_task(TaskType::PolicyMirror, 1))
                .expect("registers")
                .hints()
                .is_none()
        );
    }

    /// WP-7.1: a head statement binds the epoch and set of the ring it is signed under, and a
    /// ring whose set moves while it signs is refused rather than named wrongly.
    #[test]
    fn a_head_statement_binds_the_ring_and_refuses_one_that_moves_while_signing() {
        let statement = permguard_objects::statement::HeadStatement {
            zone: "zone".into(),
            ledger: "ledger".into(),
            r#ref: "main".into(),
            digest: permguard_objects::digest::Digest::compute(b"head"),
            counter: 1,
            signed_at: 1_800_000_000,
            authority_host_id: [1; 16],
            ref_digest: permguard_objects::digest::Digest::compute(b"state"),
            ring_epoch: 0,
            key_set_digest: permguard_objects::digest::Digest::from_raw([0; 32]),
        };
        let signer = |moving| {
            Host::builder()
                .ring(
                    CONTROL_ATTEST,
                    Arc::new(EpochRing {
                        moving,
                        reads: std::sync::atomic::AtomicU64::new(0),
                    }),
                )
                .build()
                .register(Declaration::new("control").signs::<HeadStatementV1>())
                .expect("registers")
                .signer::<HeadStatementV1>()
                .expect("declared")
                .expect("composed")
        };

        let signed = signer(false).sign(&statement).expect("a steady ring signs");
        let bound = permguard_objects::statement::SignedHead::decode(&signed)
            .expect("decodes")
            .statement_unverified()
            .expect("a statement");
        assert_eq!(bound.ring_epoch, 5);
        assert_eq!(*bound.key_set_digest.raw(), [0x5a; 32]);

        assert!(
            signer(true).sign(&statement).is_err(),
            "a ring that moved mid-signature is refused"
        );
    }

    /// A payload of `T` whose signed form is the raw signature over its bytes, for the tests.
    struct Probe<T>(&'static [u8], PhantomData<T>);

    impl<T> Probe<T> {
        fn new(bytes: &'static [u8]) -> Self {
            Self(bytes, PhantomData)
        }
    }

    impl<T> sealed::Sealed for Probe<T> {}

    impl<T: Artifact> Payload for Probe<T> {
        type Artifact = T;
        type Signed = Signature;

        fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Signature> {
            keys.sign(self.0)
        }
    }

    /// WP-3.2: a Plane's signer signs payloads only. Resolved by autoref: the method of the
    /// `Sign` probe wins only where the type implements `Sign`.
    #[test]
    fn a_plane_signer_has_no_signature_over_bytes() {
        struct Probe<T>(PhantomData<T>);
        trait ViaSign {
            fn signs_bytes(&self) -> bool {
                true
            }
        }
        impl<T: permguard_core::keys::Sign> ViaSign for Probe<T> {}
        trait Otherwise {
            fn signs_bytes(&self) -> bool {
                false
            }
        }
        impl<T> Otherwise for &Probe<T> {}

        assert!(!(&Probe::<Signer<HeadStatementV1>>(PhantomData)).signs_bytes());
        assert!(!(&Probe::<Signer<DecisionBatchV1>>(PhantomData)).signs_bytes());
        assert!(!(&Probe::<Signer<EventBatchV1>>(PhantomData)).signs_bytes());
        // The probe tells: a ring does sign bytes.
        assert!(Probe::<TaggedRing>(PhantomData).signs_bytes());
    }

    struct Discard;

    impl permguard_core::AuditSink for Discard {
        fn name(&self) -> &'static str {
            "discard"
        }
        fn record<'a>(
            &'a self,
            _: &'a permguard_core::AuditEvent<'a>,
            _: Option<&'a dyn permguard_core::pseudonym::Pseudonymizer>,
        ) -> permguard_core::BoxFuture<'a, Result<(), AuditError>> {
            permguard_core::ready(Ok(()))
        }
    }

    struct CatalogActions;
    impl AuditSchema for CatalogActions {
        const NAME: &'static str = "catalog.v1";
        const ACTIONS: &'static [&'static str] = &["zone.created", "zone.deleted"];
    }

    fn host() -> Host {
        Host::builder()
            .ring(CONTROL_ATTEST, Arc::new(TaggedRing("control")))
            .ring(DATA_ATTEST, Arc::new(TaggedRing("data")))
            .ring(HOST_OPERATIONS, Arc::new(TaggedRing("operations")))
            .build()
    }

    /// WP-3.2: the Host writes a batch's protected header and signing input; the Plane supplies
    /// the payload only, and a ring signing with another algorithm is refused.
    #[test]
    fn the_host_frames_a_batch_and_the_plane_supplies_its_payload() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let registration = host()
            .register(
                Declaration::new("data")
                    .signs::<DecisionBatchV1>()
                    .signs::<EventBatchV1>(),
            )
            .expect("registers");
        let events = registration
            .signer::<EventBatchV1>()
            .expect("declared")
            .expect("composed");
        let decisions = registration
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("composed");

        let event = events
            .sign(&Jws::<EventBatchV1>::new(b"{}"))
            .expect("signs");
        assert_eq!(
            B64.decode(&event.protected).expect("base64url"),
            br#"{"alg":"EdDSA","typ":"permguard.event.batch.v1","kid":"data"}"#
        );
        assert_eq!(event.payload, B64.encode(b"{}"));
        assert_eq!(
            B64.decode(&event.signature).expect("base64url"),
            format!("data{}.{}", event.protected, event.payload).into_bytes()
        );
        let decision = decisions
            .sign(&Jws::<DecisionBatchV1>::new(b"{}"))
            .expect("signs");
        assert_eq!(
            B64.decode(&decision.protected).expect("base64url"),
            br#"{"alg":"EdDSA","kid":"data"}"#
        );

        struct Es256;
        impl permguard_core::keys::Sign for Es256 {
            fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
                Ok(KeyId::new("p256"))
            }
            fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
                Ok(Signature::new(
                    KeyId::new("p256"),
                    "ES256",
                    payload.to_vec(),
                ))
            }
        }
        assert!(matches!(
            sign_jws::<DecisionBatchV1>(b"{}", &Es256),
            Err(JwsError::Algorithm(found)) if found == "ES256"
        ));
    }

    /// WP-7.10: a Plane signs under `host.operations` only the export manifest, whose payload the
    /// Host writes; any other artifact on that ring is refused at registration.
    #[test]
    fn a_plane_signs_under_host_operations_only_an_export_manifest() {
        struct Sealer;
        impl Artifact for Sealer {
            const TYPE: &'static str = "test.operations.sealer";
            const RING: RingId = HOST_OPERATIONS;
            const TIME_SENSITIVE: bool = false;
        }
        let refused = host()
            .register(Declaration::new("control").signs::<Sealer>())
            .expect_err("another artifact on host.operations");
        assert!(
            matches!(&refused, CompositionError::Reserved { artifact, .. } if artifact == Sealer::TYPE),
            "{refused}"
        );

        let registration = host()
            .register(Declaration::new("control").signs::<LedgerExportV1>())
            .expect("registers");
        // The capability, never the ring: what it signs is the Host's payload (signed for real in
        // `api::backups::tests::an_export_manifest_verifies_from_the_sources_bundle_and_pin`).
        assert!(
            registration
                .signer::<LedgerExportV1>()
                .expect("declared")
                .is_some()
        );
    }

    #[test]
    fn a_plane_signs_what_it_declared_with_the_ring_the_artifact_names() {
        let host = host();
        let data = host
            .register(
                Declaration::new("data")
                    .signs::<DecisionBatchV1>()
                    .signs::<EventBatchV1>(),
            )
            .expect("registers");
        let signer = data
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("the ring is composed");
        assert!(
            signer
                .sign(&Probe::<DecisionBatchV1>::new(b"x"))
                .expect("signs")
                .bytes()
                .starts_with(b"data")
        );
        let refused = data.signer::<HeadStatementV1>().expect_err("not declared");
        assert!(
            matches!(refused, CompositionError::Undeclared { .. }),
            "{refused}"
        );
        let refused = data.public_keys(CONTROL_ATTEST).expect_err("not declared");
        assert!(
            matches!(refused, CompositionError::Undeclared { .. }),
            "{refused}"
        );
    }

    /// WP-2.12: a backward jump beyond the bound stops the time-sensitive signatures — a head
    /// statement's `signed_at` — and leaves evidence signing, which orders by sequence.
    #[test]
    fn a_clock_anomaly_stops_time_sensitive_signatures_and_leaves_evidence_signing() {
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

        let wall = Arc::new(ManualClock::at(1_800_000_000));
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            Arc::new(ManualMonotonic::default()),
            std::time::Duration::from_secs(30),
        ));
        let host = Host::builder()
            .ring(CONTROL_ATTEST, Arc::new(TaggedRing("control")))
            .ring(DATA_ATTEST, Arc::new(TaggedRing("data")))
            .time(time)
            .build();
        let control = host
            .register(Declaration::new("control").signs::<HeadStatementV1>())
            .expect("registers");
        let data = host
            .register(Declaration::new("data").signs::<DecisionBatchV1>())
            .expect("registers");
        let heads = control
            .signer::<HeadStatementV1>()
            .expect("declared")
            .expect("composed");
        let batches = data
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("composed");
        let head = Probe::<HeadStatementV1>::new(b"head");
        let batch = Probe::<DecisionBatchV1>::new(b"batch");
        heads.sign(&head).expect("a sound clock signs");

        wall.jump(-31);
        let refused = heads.sign(&head).expect_err("in anomaly");
        assert!(
            matches!(refused, permguard_core::KeyError::ClockAnomaly { .. }),
            "{refused}"
        );
        assert!(refused.is_retryable());
        batches.sign(&batch).expect("evidence keeps signing");

        wall.jump(31);
        heads.sign(&head).expect("the wall clock caught up");
    }

    /// WP-6.6b: a signed decision response carries the times a verifier judges it by, so a clock
    /// in anomaly stops it, and `ready` says so before anything is signed.
    #[test]
    fn a_clock_anomaly_stops_a_signed_decision_response() {
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

        let wall = Arc::new(ManualClock::at(1_800_000_000));
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            Arc::new(ManualMonotonic::default()),
            std::time::Duration::from_secs(30),
        ));
        let host = Host::builder()
            .ring(DATA_ATTEST, Arc::new(TaggedRing("data")))
            .time(time)
            .build();
        let data = host
            .register(Declaration::new("data").signs::<DecisionResponseV1>())
            .expect("registers");
        let responses = data
            .signer::<DecisionResponseV1>()
            .expect("declared")
            .expect("composed");
        let payload = Jws::<DecisionResponseV1>::new(b"{}");
        responses.ready().expect("a sound clock");
        responses.sign(&payload).expect("signs");

        wall.jump(-31);
        assert!(matches!(
            responses.ready().expect_err("in anomaly"),
            permguard_core::KeyError::ClockAnomaly { .. }
        ));
        assert!(matches!(
            responses.sign(&payload).expect_err("in anomaly"),
            permguard_core::KeyError::ClockAnomaly { .. }
        ));
    }

    #[test]
    fn colliding_declarations_fail_registration() {
        let host = host();
        host.register(Declaration::new("data").signs::<DecisionBatchV1>())
            .expect("first");
        for (second, what) in [
            (
                Declaration::new("other").signs::<DecisionBatchV1>(),
                "artifact type",
            ),
            (
                Declaration::new("other").signs::<EventBatchV1>(),
                "signing ring",
            ),
        ] {
            let refused = host.register(second).expect_err("collides");
            assert!(
                matches!(&refused, CompositionError::Collision { what: found, .. } if *found == what),
                "{refused}"
            );
        }
        let host = self::host();
        host.register(
            Declaration::new("control")
                .produces_stream("permguard.decisions")
                .handles_task(crate::membership::record::TaskType::PolicyMirror, 1)
                .owns_scope_schema("zone")
                .audits::<CatalogActions>(),
        )
        .expect("first");
        for (second, what) in [
            (
                Declaration::new("data").produces_stream("permguard.decisions"),
                "stream descriptor",
            ),
            (
                Declaration::new("data")
                    .handles_task(crate::membership::record::TaskType::PolicyMirror, 2),
                "task contract",
            ),
            (
                Declaration::new("data").owns_scope_schema("zone"),
                "scope schema",
            ),
            (
                Declaration::new("data").audits::<CatalogActions>(),
                "audit schema",
            ),
        ] {
            let refused = host.register(second).expect_err("collides");
            assert!(
                matches!(&refused, CompositionError::Collision { what: found, .. } if *found == what),
                "{refused}"
            );
        }
        let refused = host
            .register(Declaration::new("control"))
            .expect_err("twice");
        assert!(matches!(refused, CompositionError::AlreadyRegistered(_)));
        let refused = self::host()
            .register(
                Declaration::new("data")
                    .produces_stream("s")
                    .produces_stream("s"),
            )
            .expect_err("a Plane colliding with itself");
        assert!(
            matches!(refused, CompositionError::Collision { .. }),
            "{refused}"
        );
    }

    #[tokio::test]
    async fn an_audit_handle_records_only_its_schemas_actions() {
        let recorder = AuditRecorder::new(Arc::new(Discard));
        let host = Host::builder().audit(recorder).build();
        let control = host
            .register(Declaration::new("control").audits::<CatalogActions>())
            .expect("registers");
        let audit = control
            .audit::<CatalogActions>()
            .expect("declared")
            .expect("composed");
        audit
            .record("zone.created", Subject::System("catalog"))
            .await
            .expect("declared action");
        let refused = audit
            .record("key.exported", Subject::System("catalog"))
            .await
            .expect_err("not in the schema");
        assert!(
            matches!(refused, AuditRefusal::Undeclared { .. }),
            "{refused}"
        );
    }

    /// A Plane narrows its records below the root the Host assigns it, through its handle, and the
    /// engine writes them in the narrowed resource's own trail (WP-3.5).
    #[tokio::test]
    async fn a_plane_narrows_its_resource_through_its_handle() {
        use crate::audit::{Class, Engine, HostAuditSink, Stamp, trail};
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};
        use permguard_core::assurance::AssuranceProfile;

        let root = std::env::temp_dir().join(format!(
            "permguard-host-composition-narrow-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = crate::storage::volume::Volume::claim(&root, AssuranceProfile::Development)
            .expect("claimed");
        let time = Arc::new(TimeGuard::new(
            Arc::new(ManualClock::at(1_800_000_000)),
            Arc::new(ManualMonotonic::default()),
            std::time::Duration::from_secs(30),
        ));
        let stamp = Stamp {
            host_id: [1; 16],
            boot_id: [2; 16],
            build: "9.9.9".to_owned(),
            config_revision: permguard_objects::digest::Digest::compute(b"settings"),
        };
        let engine = Arc::new(Engine::open(&volume, stamp, time, None).expect("opens"));
        let sink = Arc::new(HostAuditSink::new(Arc::clone(&engine), None));
        let host = Host::builder().audit(AuditRecorder::new(sink)).build();
        let audit = host
            .register(Declaration::new("control").audits::<CatalogActions>())
            .expect("registers")
            .audit::<CatalogActions>()
            .expect("declared")
            .expect("composed");
        audit
            .record_event(
                &AuditEvent::new("zone.created", Subject::System("catalog"))
                    .in_resource("plane/control/zone/z1"),
            )
            .await
            .expect("narrowed below the Plane's root");
        let narrowed = engine
            .trail_dir(Class::Security, "plane/control/zone/z1")
            .expect("its own trail");
        assert_eq!(trail::verify(&narrowed).expect("verifies"), 1);
        let refused = audit
            .record_event(
                &AuditEvent::new("zone.created", Subject::System("catalog")).in_resource("host"),
            )
            .await
            .expect_err("not below the Plane's root");
        assert!(refused.to_string().contains("not below it"), "{refused}");
        let refused = audit
            .record_event(&AuditEvent::new("key.exported", Subject::System("catalog")))
            .await
            .expect_err("not in the schema");
        assert!(
            matches!(refused, AuditRefusal::Undeclared { .. }),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Each side of a task type is one Plane's (WP-4.4): the provider of `policy.mirror` and its
    /// consumer may be two Planes, a second provider may not, and a Plane declaring two versions
    /// of its side claims it once.
    #[test]
    fn a_task_contract_is_declared_by_one_plane_alone() {
        use crate::membership::record::{Capability, ContractRole, TaskType};

        let host = self::host();
        let control = Declaration::new("control")
            .handles_task(TaskType::PolicyMirror, 1)
            .handles_task(TaskType::PolicyMirror, 2)
            .uses_task(TaskType::DecisionsShip, 1);
        assert_eq!(
            control.task_contracts()[2],
            Capability {
                task_type: TaskType::DecisionsShip,
                version: 1,
                role: ContractRole::Consumer,
            }
        );
        host.register(control)
            .expect("one Plane, two versions of its side");
        host.register(
            Declaration::new("data")
                .uses_task(TaskType::PolicyMirror, 1)
                .handles_task(TaskType::DecisionsShip, 1),
        )
        .expect("the other sides");
        let refused = host
            .register(Declaration::new("audit").handles_task(TaskType::PolicyMirror, 3))
            .expect_err("a second provider");
        assert!(
            matches!(&refused, CompositionError::Collision { what: "task contract", name, .. } if name == "policy.mirror provider"),
            "{refused}"
        );
    }

    /// WP-5.1: a Plane reaches, through the Host's engine, the producer of a stream it declared,
    /// and of no other; without an engine composed it gets none.
    #[test]
    fn a_plane_receives_the_producer_of_a_stream_it_declared() {
        struct Engine;
        struct Appender;
        impl StreamAppender for Appender {
            fn append(&self, _: &Resource, record: &[u8]) -> Result<StreamReceipt, String> {
                Ok(StreamReceipt {
                    run_id: [1; 16],
                    seq: record.len() as u64,
                })
            }
            fn append_with(
                &self,
                _: &Resource,
                _: BuildRecords<'_>,
            ) -> Result<StreamReceipt, String> {
                Err("not in this test".to_owned())
            }
            fn pressure(
                &self,
                _: &Resource,
                _: u64,
                _: u64,
            ) -> Result<Option<&'static str>, String> {
                Ok(None)
            }
        }
        impl StreamEngine for Engine {
            fn producer(&self, stream: &str) -> Option<Arc<dyn StreamAppender>> {
                (stream == "data/decisions").then(|| Arc::new(Appender) as Arc<dyn StreamAppender>)
            }
        }
        let host = Host::builder().streams(Arc::new(Engine)).build();
        let registration = host
            .register(Declaration::new("data").produces_stream("data/decisions"))
            .expect("registered");
        let producer = registration
            .stream_producer("data/decisions")
            .expect("declared")
            .expect("served by the engine");
        assert_eq!(
            producer
                .append(&Resource::plane("data"), b"abc")
                .expect("appended"),
            StreamReceipt {
                run_id: [1; 16],
                seq: 3
            }
        );
        assert!(matches!(
            registration.stream_producer("data/events"),
            Err(CompositionError::Undeclared { .. })
        ));
        // Another Plane naming the Data Plane's stream reaches nothing.
        let other = Host::builder()
            .streams(Arc::new(Engine))
            .build()
            .register(Declaration::new("control").produces_stream("data/decisions"))
            .expect("registered");
        assert!(
            other
                .stream_producer("data/decisions")
                .expect("declared")
                .is_none()
        );
        let bare = self::host()
            .register(Declaration::new("data").produces_stream("data/decisions"))
            .expect("registered");
        assert!(
            bare.stream_producer("data/decisions")
                .expect("declared")
                .is_none()
        );
    }

    /// WP-6.1: a Plane reads the Host's consumer of a stream it declared it reads, whichever
    /// Plane produces it, and of no other; without an engine consuming it, it gets none.
    #[test]
    fn a_plane_reads_only_the_stream_it_declared() {
        struct Engine;
        struct Reads;
        impl StreamConsumerReads for Reads {
            fn runs(&self, _: &Resource) -> Result<Vec<ConsumedRun>, String> {
                Ok(vec![ConsumedRun {
                    producer: [1; 16],
                    run: [2; 16],
                    acked: 3,
                    oldest_retained: 1,
                }])
            }
            fn locate(&self, _: &[u8; 16], _: &[u8; 16]) -> Result<Option<Resource>, String> {
                Ok(None)
            }
            fn records(
                &self,
                _: &Resource,
                _: &[u8; 16],
                _: &[u8; 16],
                _: u64,
                _: usize,
            ) -> Result<ConsumedPage, String> {
                Ok(ConsumedPage::default())
            }
            fn batch(
                &self,
                _: &Resource,
                _: &[u8; 16],
                _: &[u8; 16],
                _: u64,
            ) -> Result<Option<Vec<u8>>, String> {
                Ok(None)
            }
        }
        impl StreamEngine for Engine {
            fn producer(&self, _: &str) -> Option<Arc<dyn StreamAppender>> {
                None
            }
            fn consumer(&self, stream: &str) -> Option<Arc<dyn StreamConsumerReads>> {
                (stream == "data/decisions")
                    .then(|| Arc::new(Reads) as Arc<dyn StreamConsumerReads>)
            }
        }
        let registration = Host::builder()
            .streams(Arc::new(Engine))
            .build()
            .register(Declaration::new("control").reads_stream("data/decisions"))
            .expect("registered");
        let consumer = registration
            .stream_consumer("data/decisions")
            .expect("declared")
            .expect("composed");
        assert_eq!(
            consumer
                .runs(&Resource::ledger("data", "z", "l"))
                .expect("runs")[0]
                .acked,
            3
        );
        assert!(matches!(
            registration.stream_consumer("data/events"),
            Err(CompositionError::Undeclared { .. })
        ));
        assert!(matches!(
            Host::builder()
                .streams(Arc::new(Engine))
                .build()
                .register(Declaration::new("control"))
                .expect("registered")
                .stream_consumer("data/decisions"),
            Err(CompositionError::Undeclared { .. })
        ));
        let bare = self::host()
            .register(Declaration::new("control").reads_stream("data/decisions"))
            .expect("registered");
        assert!(
            bare.stream_consumer("data/decisions")
                .expect("declared")
                .is_none()
        );
    }

    /// WP-4.7: the Host serves both sides of `audit.checkpoints` and `zone.secrets`; a Plane
    /// claiming either side is refused, and registers nothing.
    #[test]
    fn no_plane_claims_a_contract_the_host_serves() {
        use crate::membership::record::TaskType;

        let host = self::host();
        for declaration in [
            Declaration::new("data").uses_task(TaskType::ZoneSecrets, 1),
            Declaration::new("data").handles_task(TaskType::ZoneSecrets, 1),
            Declaration::new("data").handles_task(TaskType::AuditCheckpoints, 1),
            Declaration::new("data")
                .handles_task(TaskType::DecisionsShip, 1)
                .uses_task(TaskType::AuditCheckpoints, 1),
        ] {
            let refused = host.register(declaration).expect_err("the Host serves it");
            assert!(
                matches!(&refused, CompositionError::Collision { what: "task contract", first, .. } if first == "host"),
                "{refused}"
            );
        }
        // Nothing was claimed: the Plane registers its own sides afterwards.
        host.register(Declaration::new("data").handles_task(TaskType::DecisionsShip, 1))
            .expect("the Plane's own side");
    }

    #[test]
    fn a_layout_is_answered_only_when_declared() {
        let host = Host::builder()
            .layouts([("events-legacy".to_owned(), 2), ("keys".to_owned(), 1)])
            .build();
        let data = host
            .register(
                Declaration::new("data")
                    .reads_layout("events-legacy")
                    .reads_layout("decisions-legacy"),
            )
            .expect("registered");
        assert_eq!(data.layout("events-legacy").expect("declared"), Some(2));
        // Declared and not laid out on this volume.
        assert_eq!(data.layout("decisions-legacy").expect("declared"), None);
        // Laid out, and not this Plane's to read.
        assert!(matches!(
            data.layout("keys"),
            Err(CompositionError::Undeclared { .. })
        ));
        let control = host
            .register(Declaration::new("control"))
            .expect("registered");
        assert!(control.layout("events-legacy").is_err());
    }

    struct NoJob;

    impl crate::gc::GcJob for NoJob {
        fn plan(
            &self,
            _: &permguard_core::authz::Resource,
        ) -> Result<crate::gc::Report, crate::gc::GcError> {
            Ok(crate::gc::Report::default())
        }

        fn run(
            &self,
            _: &permguard_core::authz::Resource,
            _: &str,
        ) -> Result<crate::gc::Report, crate::gc::GcError> {
            Ok(crate::gc::Report::default())
        }
    }

    /// WP-7.11b: a gc job is one the Host serves, declared and provided by one Plane.
    #[test]
    fn a_gc_job_is_provided_once_by_the_plane_that_declared_it() {
        let jobs = Arc::new(crate::gc::Jobs::default());
        let host = Host::builder().gc_jobs(Arc::clone(&jobs)).build();
        let refused = host
            .register(Declaration::new("other").provides_gc_job("everything"))
            .expect_err("not a job the Host serves");
        assert!(
            matches!(&refused, CompositionError::UnknownGcJob { job, .. } if job == "everything"),
            "{refused:?}"
        );
        let control = host
            .register(Declaration::new("control").provides_gc_job(crate::gc::OBJECTS))
            .expect("registered");
        let refused = host
            .register(Declaration::new("data").provides_gc_job(crate::gc::OBJECTS))
            .expect_err("one Plane provides a job");
        assert!(
            matches!(&refused, CompositionError::Collision { what: "gc job", .. }),
            "{refused:?}"
        );
        assert!(jobs.get(crate::gc::OBJECTS).is_none(), "not provided yet");
        assert!(
            control
                .provide_gc_job(crate::gc::OBJECTS, Arc::new(NoJob))
                .expect("provided")
        );
        let (plane, _) = jobs.get(crate::gc::OBJECTS).expect("provided");
        assert_eq!(plane, "control");
        assert!(
            control
                .provide_gc_job(crate::gc::OBJECTS, Arc::new(NoJob))
                .is_err(),
            "provided once"
        );
        // A Plane that did not declare it provides nothing.
        let quiet = host
            .register(Declaration::new("quiet"))
            .expect("registered");
        assert!(matches!(
            quiet.provide_gc_job(crate::gc::OBJECTS, Arc::new(NoJob)),
            Err(CompositionError::Undeclared { .. })
        ));
        // A Host without a Host API serves no job, and says so.
        let bare = Host::builder().build();
        let control = bare
            .register(Declaration::new("control").provides_gc_job(crate::gc::OBJECTS))
            .expect("registered");
        assert!(
            !control
                .provide_gc_job(crate::gc::OBJECTS, Arc::new(NoJob))
                .expect("answered")
        );
    }
}
