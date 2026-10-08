// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The security mutation transaction (WP-3.6): one operation id across the intent, the domain
//! state and the audit projection, in `host/audit/mutations/`.
//!
//! ```text
//! 1 authorize and validate                       the caller, before `run`
//! 2 append INTENT; flush                         mutation.intent_written
//! 3 audit intent; flush                          mutation.intent_audited
//! 4 apply, carrying the operation id; flush      mutation.applied
//! 5 append COMMIT with the revision; flush       mutation.committed
//! 6 audit applied; flush                         mutation.applied_audited
//!   append PROJECTED; flush                      mutation.projected
//! 7 reply
//! ```
//!
//! | Crash or failure                   | Recovery                                                                           |
//! | ---------------------------------- | ---------------------------------------------------------------------------------- |
//! | before the domain applied          | the domain does not show the id: FAILED and an audit `failed` record               |
//! | after the domain applied           | the domain shows the id and its revision: COMMIT and an audit `reconciled` record   |
//! | after COMMIT, before the reply     | a retry with the same request id is answered from the COMMIT                       |
//! | the audit intent fails             | FAILED, nothing applied, refused as audit unavailable                              |
//! | the audit outcome record fails     | the COMMIT stands, never rolled back; answered as unrecorded; projected again later |
//!
//! While an outcome record is pending, every new mutation first projects it; one that still
//! cannot be written refuses the mutation, and the Host reports `degraded: security_mutations`
//! (owner decisions of 2026-10-07). Reads and decisions go on.
//!
//! A domain's mutators take an [`Applying`], which only this module builds, inside step 4: the
//! engine is the only way to them, and `task check:mutations` keeps it so.
//!
//! An operation is idempotent per `(principal, request id)` inside [`WINDOW`]: a retry with the
//! same request learns the stored answer, the same id under another request is refused, and a
//! retry of an operation that FAILED applies anew under a new operation id. The intent's audit
//! record is not written again at recovery: the outcome record carries the operation id.
//!
//! An outcome record is written at least once (owner decision of 2026-10-08): a crash after it
//! reaches the trail and before its PROJECTED mark writes it again at the next start, with the
//! same operation id and phase.
//!
//! A write to the journal that fails stops the journal until the next start, as the storage
//! library's journal does: what reached the file is uncertain, and an operation it left open
//! may have been applied. Until then a retry of that operation is answered unrecorded, never
//! "nothing was applied", and every new mutation is refused. A domain write whose own failure
//! leaves it uncertain ([`Failure::Indeterminate`]) leaves the intent open the same way; the
//! next start asks the domain.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use permguard_core::server::Health;
use permguard_core::{AuditEvent, AuditOutcome, AuditPhase, Subject};

use super::journal::{Commit, Entry, Initiator, Intent, MAX_ENTRY_BYTES, OperationId, RequestKey};
use crate::storage::crash;
use crate::storage::volume::Volume;
use crate::storage::{Dir, StorageError, sequence, write};
use crate::time::TimeGuard;

/// The directory below `host/audit/`.
pub const DIRECTORY: &str = "mutations";
/// The journal file.
pub const JOURNAL: &str = "journal.cborseq";
/// The snapshot file.
pub const SNAPSHOT: &str = "snapshot.cbor";
/// The capability the Host reports degraded while an outcome record is pending.
pub const CAPABILITY: &str = "security_mutations";
/// How long a committed answer is kept for a retry.
pub const WINDOW: Duration = Duration::from_secs(10 * 60);
/// How many entries the journal takes before it is folded into the snapshot.
const COMPACT_AFTER: usize = 1024;

/// The Host's audit engine with the privacy policy and the destination sink every other record
/// of the process goes through (WP-3.5): the engine writes the trail, failure answered; the
/// destination, the log stream by default, hears of each record too, best effort.
pub struct HostProjection {
    engine: Arc<crate::audit::Engine>,
    policy: Option<Arc<dyn permguard_core::Pseudonymizer>>,
    also: Option<Arc<dyn permguard_core::AuditSink>>,
}

impl HostProjection {
    /// Over `engine`, rendering principals under `policy` and forwarding to `also`.
    pub fn new(
        engine: Arc<crate::audit::Engine>,
        policy: Option<Arc<dyn permguard_core::Pseudonymizer>>,
        also: Option<Arc<dyn permguard_core::AuditSink>>,
    ) -> Self {
        Self {
            engine,
            policy,
            also,
        }
    }
}

impl Projection for HostProjection {
    fn project(&self, event: &AuditEvent<'_>) -> Result<(), String> {
        self.engine
            .append(event, self.policy.as_deref())
            .map_err(|refused| refused.to_string())?;
        if let Some(also) = &self.also {
            // The destination sinks answer at once (the log stream); one that would wait is not
            // waited for, since the trail already holds the record.
            let mut forwarded = also.record(event, self.policy.as_deref());
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            match forwarded.as_mut().poll(&mut context) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(error)) => tracing::warn!(
                    event.name = "host.audit_forward_failed",
                    component = "host",
                    error = %error,
                    "a mutation record is in the trail and did not reach the audit destination"
                ),
                std::task::Poll::Pending => tracing::warn!(
                    event.name = "host.audit_forward_pending",
                    component = "host",
                    "a mutation record is in the trail and its audit destination did not answer at once"
                ),
            }
        }
        Ok(())
    }
}

/// Where the engine writes the audit record of each phase: the Host's audit engine, whose
/// `security` failure is answered (WP-3.5).
pub trait Projection: Send + Sync {
    /// Writes `event` durably, or says why it could not.
    fn project(&self, event: &AuditEvent<'_>) -> Result<(), String>;
}

impl Projection for crate::audit::Engine {
    fn project(&self, event: &AuditEvent<'_>) -> Result<(), String> {
        self.append(event, None)
            .map_err(|refused| refused.to_string())
    }
}

/// What a domain shows of an operation it applied: the revision it produced and what it changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub revision: u64,
    pub target: Option<String>,
}

/// A domain whose mutations go through the engine.
pub trait Domain {
    /// The name intents carry: `grants`.
    fn name(&self) -> &'static str;
    /// What the domain shows of `operation_id`, when it applied it; `target` is what the intent
    /// named, for a domain whose state records the outcome rather than the operation id.
    fn observe(&self, operation_id: &OperationId, target: Option<&str>) -> Option<Observed>;
}

/// The proof that the engine is applying an operation: a domain mutator takes one, and only this
/// module builds one.
pub struct Applying<'a> {
    operation_id: OperationId,
    _engine: PhantomData<&'a Mutations>,
}

impl Applying<'_> {
    /// The operation being applied: what the domain writes beside its change.
    pub fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

#[cfg(test)]
impl Applying<'static> {
    /// A token for the unit tests of a domain's mutators, which run them without the engine.
    pub(crate) fn for_tests(byte: u8) -> Self {
        Self {
            operation_id: OperationId::from_bytes([byte; 16]),
            _engine: PhantomData,
        }
    }
}

impl std::fmt::Debug for Applying<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Applying({})", self.operation_id)
    }
}

/// What an operation is, before it is applied.
#[derive(Debug, Clone)]
pub struct Begin {
    /// The domain that applies it.
    pub domain: &'static str,
    /// The operation: `grants.create`.
    pub operation: &'static str,
    /// The registered `security` audit action its records carry.
    pub action: &'static str,
    pub initiator: Initiator,
    /// The idempotency key, for an operation a caller may retry.
    pub request: Option<RequestKey>,
    /// What it is done to, when known before it is applied.
    pub target: Option<String>,
}

/// Why a domain did not apply an operation.
#[derive(Debug)]
pub enum Failure<E> {
    /// Refused: nothing was applied.
    Refused(E),
    /// Its own write failed in a way that may still have applied it, or may after a restart: a
    /// flush that failed, a frame the journal keeps. The intent stays open for recovery.
    Indeterminate(E),
}

/// What a domain answers when it applied an operation.
#[derive(Debug)]
pub struct Applied<T> {
    pub revision: u64,
    pub target: Option<String>,
    /// The answer, which a retry learns.
    pub value: T,
}

/// How an operation ended for its caller.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    /// Applied now, its outcome record durable.
    Applied(T),
    /// A retry inside the window: the answer the first attempt committed.
    Replayed(T),
    /// A retry of an operation recovery committed after a crash: the domain applied it at
    /// `revision`, and the caller rebuilds its answer from the domain's state.
    Reconciled {
        operation_id: OperationId,
        revision: u64,
        target: Option<String>,
    },
}

/// Why an operation did not end applied.
#[derive(Debug)]
pub enum MutationError<E> {
    /// The domain refused it: nothing was applied.
    Refused(E),
    /// The request id is in flight, or names another request inside the window.
    RequestIdReused(&'static str),
    /// An audit record could not be written before anything was applied: nothing was.
    AuditUnavailable(String),
    /// Applied, or possibly applied, and its commit or its outcome record could not be written:
    /// the caller reads the state before it retries.
    Unrecorded(String),
    /// The domain could not say whether it applied: the caller reads the state before it
    /// retries, and the next start resolves the operation.
    Indeterminate(E),
    /// The journal could not be written before anything was applied: nothing was.
    Unavailable(String),
}

impl<E: std::fmt::Display> std::fmt::Display for MutationError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(error) => write!(f, "{error}"),
            Self::RequestIdReused(detail) => f.write_str(detail),
            Self::AuditUnavailable(detail) => {
                write!(
                    f,
                    "the audit trail is unavailable; nothing was applied: {detail}"
                )
            }
            Self::Unrecorded(detail) => write!(
                f,
                "the mutation may have been applied and its record could not be written: {detail}"
            ),
            Self::Indeterminate(error) => write!(
                f,
                "the mutation may have been applied; it is resolved at the next start: {error}"
            ),
            Self::Unavailable(detail) => write!(
                f,
                "the mutation journal is unavailable; nothing was applied: {detail}"
            ),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for MutationError<E> {}

/// One operation as the journal holds it.
#[derive(Debug, Clone)]
struct Operation {
    /// The order its intent was met in: the snapshot keeps it.
    order: u64,
    intent: Intent,
    end: Option<End>,
    projected: bool,
}

#[derive(Debug, Clone)]
enum End {
    Commit(Commit),
    Failed { at: u64, reason: String },
}

#[derive(Default)]
struct State {
    operations: BTreeMap<OperationId, Operation>,
    /// The latest operation of each `(principal, request id)`.
    requests: BTreeMap<(String, String), OperationId>,
    /// Entries appended since the journal was last folded.
    appended: usize,
    /// The order the next intent gets.
    next: u64,
}

impl State {
    /// Folds `entry` in: monotonic, so an entry met twice (the snapshot and the journal both
    /// holding it, after a crash mid-compaction) changes nothing the second time.
    fn apply(&mut self, entry: Entry) {
        match entry {
            Entry::Intent(intent) => {
                if let (Initiator::Principal(principal), Some(request)) =
                    (&intent.initiator, &intent.request)
                {
                    self.requests.insert(
                        (principal.clone(), request.request_id.clone()),
                        intent.operation_id,
                    );
                }
                let order = self.next;
                self.operations
                    .entry(intent.operation_id)
                    .or_insert_with(|| Operation {
                        order,
                        intent,
                        end: None,
                        projected: false,
                    });
                self.next += 1;
            }
            Entry::Commit(commit) => {
                if let Some(operation) = self.operations.get_mut(&commit.operation_id)
                    && operation.end.is_none()
                {
                    operation.end = Some(End::Commit(commit));
                }
            }
            Entry::Failed {
                operation_id,
                at,
                reason,
            } => {
                if let Some(operation) = self.operations.get_mut(&operation_id)
                    && operation.end.is_none()
                {
                    operation.end = Some(End::Failed { at, reason });
                }
            }
            Entry::Projected { operation_id, .. } => {
                if let Some(operation) = self.operations.get_mut(&operation_id) {
                    operation.projected = true;
                }
            }
        }
    }

    /// The entries that rebuild what is still live at `now`: open intents, outcomes not yet
    /// projected, and commits a retry may still ask for.
    fn live(&self, now: u64) -> Vec<Entry> {
        let mut entries = Vec::new();
        let mut operations: Vec<&Operation> = self.operations.values().collect();
        operations.sort_by_key(|operation| operation.order);
        for operation in operations {
            let keep = match &operation.end {
                None => true,
                Some(_) if !operation.projected => true,
                Some(End::Commit(commit)) => {
                    operation.intent.request.is_some()
                        && commit.at.saturating_add(WINDOW.as_secs()) >= now
                }
                Some(End::Failed { .. }) => false,
            };
            if !keep {
                continue;
            }
            entries.push(Entry::Intent(operation.intent.clone()));
            match &operation.end {
                Some(End::Commit(commit)) => entries.push(Entry::Commit(commit.clone())),
                Some(End::Failed { at, reason }) => entries.push(Entry::Failed {
                    operation_id: operation.intent.operation_id,
                    at: *at,
                    reason: reason.clone(),
                }),
                None => {}
            }
            if operation.projected {
                entries.push(Entry::Projected {
                    operation_id: operation.intent.operation_id,
                    at: now,
                });
            }
        }
        entries
    }

    fn rebuild(entries: Vec<Entry>) -> Self {
        let mut state = Self::default();
        for entry in entries {
            state.apply(entry);
        }
        state
    }
}

/// What [`Mutations::recover`] did for one domain.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// Intents the domain showed applied: committed and recorded as reconciled.
    pub reconciled: Vec<OperationId>,
    /// Intents the domain did not show: marked failed.
    pub failed: Vec<OperationId>,
}

/// The mutation engine of one volume.
pub struct Mutations {
    dir: Dir,
    state: Mutex<State>,
    /// Held while pending outcome records are projected, so two callers never write one twice.
    settling: Mutex<()>,
    /// The `(principal, request id)` pairs with an operation in flight.
    in_flight: Mutex<BTreeSet<(String, String)>>,
    /// The operations between their intent and their answer in this process: recovery leaves
    /// them alone.
    running: Mutex<BTreeSet<OperationId>>,
    /// Why the journal stopped taking writes, after one failed.
    stopped: Mutex<Option<String>>,
    projection: Arc<dyn Projection>,
    time: Arc<TimeGuard>,
    health: OnceLock<Health>,
    compact_after: usize,
}

/// Why pending work could not be finished.
#[derive(Debug)]
enum Halt {
    /// The audit trail did not take a record.
    Audit(String),
    /// The journal did not take an entry, or an operation is unresolved until the next start.
    Journal(String),
}

impl Halt {
    fn detail(self) -> String {
        match self {
            Self::Audit(detail) | Self::Journal(detail) => detail,
        }
    }
}

/// One operation running; dropping it lets recovery see it again.
struct Running<'a> {
    engine: &'a Mutations,
    operation_id: OperationId,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.engine
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.operation_id);
    }
}

impl std::fmt::Debug for Mutations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mutations")
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

/// One operation in flight; dropping it lets the next arrival with the same pair in.
struct InFlight<'a> {
    engine: &'a Mutations,
    key: Option<(String, String)>,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.engine
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&key);
        }
    }
}

impl Mutations {
    /// Opens `host/audit/mutations/` on `volume`: the snapshot, then the journal with a torn
    /// final entry cut, folded into a fresh snapshot. Open intents stay open until
    /// [`Mutations::recover`] meets their domain.
    pub fn open(
        volume: &Volume,
        projection: Arc<dyn Projection>,
        time: Arc<TimeGuard>,
    ) -> Result<Self, StorageError> {
        let dir = volume
            .host()
            .subdir(crate::audit::DIRECTORY, true)?
            .subdir(DIRECTORY, true)?;
        dir.sweep_temps()?;
        let mut entries = match dir.read(SNAPSHOT)? {
            Some(bytes) => super::journal::decode_snapshot(&bytes)
                .map_err(|error| StorageError::Corruption(error.to_string()))?,
            None => Vec::new(),
        };
        for item in sequence::recover(&dir, JOURNAL, MAX_ENTRY_BYTES)?.items {
            entries.push(
                Entry::from_value(item)
                    .map_err(|error| StorageError::Corruption(error.to_string()))?,
            );
        }
        let engine = Self {
            dir,
            state: Mutex::new(State::rebuild(entries)),
            settling: Mutex::new(()),
            in_flight: Mutex::new(BTreeSet::new()),
            running: Mutex::new(BTreeSet::new()),
            stopped: Mutex::new(None),
            projection,
            time,
            health: OnceLock::new(),
            compact_after: COMPACT_AFTER,
        };
        {
            let mut state = engine.state.lock().unwrap_or_else(PoisonError::into_inner);
            engine.compact(&mut state)?;
        }
        Ok(engine)
    }

    /// Opens the engine over an audit engine of its own on `volume`, with a stamp drawn here and
    /// the system clock: what a process that runs no server uses, the offline CLI. Its records
    /// land in the same trails a server writes.
    pub fn open_offline(volume: &Volume, build: &str) -> Result<Self, String> {
        Self::open_offline_as(volume, build, None)
    }

    /// [`Mutations::open_offline`], its records stamped with `identity`'s `host_id` and
    /// `boot_id`; without one, with the volume's id and a boot id drawn here, as a volume
    /// provisioned before WP-2.2 is.
    pub fn open_offline_as(
        volume: &Volume,
        build: &str,
        identity: Option<&crate::identity::Identity>,
    ) -> Result<Self, String> {
        let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
        let revision = crate::audit::config_revision(std::iter::empty());
        let stamp = match identity {
            Some(identity) => crate::audit::Stamp {
                host_id: identity.host_id(),
                boot_id: identity.boot_id(),
                build: build.to_owned(),
                config_revision: revision,
            },
            None => crate::audit::Stamp::draw(volume.id(), build, revision)
                .map_err(|error| error.to_string())?,
        };
        let audit = crate::audit::Engine::open(volume, stamp, Arc::clone(&time), None)
            .map_err(|error| error.to_string())?;
        Self::open(volume, Arc::new(audit), time).map_err(|error| error.to_string())
    }

    /// Reports pending outcome records on `health`'s Host component, from now on.
    pub fn observe(&self, health: Health) {
        let _ = self.health.set(health);
        self.report();
    }

    /// The operations whose intent has neither a commit nor a failure.
    pub fn open_intents(&self) -> Vec<OperationId> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .operations
            .values()
            .filter(|operation| operation.end.is_none())
            .map(|operation| operation.intent.operation_id)
            .collect()
    }

    /// How many operations wait: outcome records not yet written, and intents left open by a
    /// failed write that only the next start resolves.
    pub fn pending(&self) -> usize {
        let (ended, open) = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let ended = state
                .operations
                .values()
                .filter(|operation| operation.end.is_some() && !operation.projected)
                .count();
            let open: Vec<OperationId> = state
                .operations
                .values()
                .filter(|operation| operation.end.is_none())
                .map(|operation| operation.intent.operation_id)
                .collect();
            (ended, open)
        };
        let running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        ended
            + open
                .iter()
                .filter(|operation_id| !running.contains(operation_id))
                .count()
    }

    /// Folds the journal after this many entries instead of [`COMPACT_AFTER`].
    #[cfg(test)]
    pub(crate) fn folding_after(mut self, entries: usize) -> Self {
        self.compact_after = entries;
        self
    }

    /// Resolves the open intents of `domain`: committed when the domain shows the operation,
    /// failed when it does not; then writes every pending outcome record it can.
    pub fn recover(&self, domain: &dyn Domain) -> Result<Recovered, StorageError> {
        let open: Vec<(OperationId, Option<String>)> = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .operations
            .values()
            .filter(|operation| operation.end.is_none() && operation.intent.domain == domain.name())
            .map(|operation| {
                (
                    operation.intent.operation_id,
                    operation.intent.target.clone(),
                )
            })
            .collect();
        // An operation of this process between its intent and its answer is not a crash's.
        let open: Vec<(OperationId, Option<String>)> = {
            let running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
            open.into_iter()
                .filter(|(operation_id, _)| !running.contains(operation_id))
                .collect()
        };
        let mut recovered = Recovered::default();
        for (operation_id, target) in open {
            let now = self.time.now_secs();
            match domain.observe(&operation_id, target.as_deref()) {
                Some(observed) => {
                    self.append(Entry::Commit(Commit {
                        operation_id,
                        at: now,
                        revision: observed.revision,
                        target: observed.target,
                        result: None,
                        reconciled: true,
                    }))?;
                    recovered.reconciled.push(operation_id);
                }
                None => {
                    self.append(Entry::Failed {
                        operation_id,
                        at: now,
                        reason: "found open at recovery, and the domain shows no trace of it"
                            .to_owned(),
                    })?;
                    recovered.failed.push(operation_id);
                }
            }
        }
        if !recovered.reconciled.is_empty() || !recovered.failed.is_empty() {
            tracing::warn!(
                event.name = "host.mutations_recovered",
                component = "host",
                domain = domain.name(),
                reconciled = recovered.reconciled.len(),
                failed = recovered.failed.len(),
                "open mutation intents were resolved at recovery"
            );
        }
        let _ = self.settle();
        Ok(recovered)
    }

    /// Runs one operation through the protocol. `apply` is the domain mutation: it is given the
    /// [`Applying`] its mutators take, and answers the revision, the target and the answer.
    pub fn run<T, E>(
        &self,
        begin: Begin,
        apply: impl FnOnce(&Applying<'_>) -> Result<Applied<T>, Failure<E>>,
    ) -> Result<Outcome<T>, MutationError<E>>
    where
        T: Serialize + DeserializeOwned,
    {
        self.run_checked(begin, || Ok(()), apply)
    }

    /// [`Mutations::run`], with `check` the caller's validation (step 1): run after a retry is
    /// answered from the window and before the intent, so a request the domain would refuse
    /// leaves no intent and no audit record, and a retry of an applied one still learns it.
    pub fn run_checked<T, E>(
        &self,
        begin: Begin,
        check: impl FnOnce() -> Result<(), E>,
        apply: impl FnOnce(&Applying<'_>) -> Result<Applied<T>, Failure<E>>,
    ) -> Result<Outcome<T>, MutationError<E>>
    where
        T: Serialize + DeserializeOwned,
    {
        let key = match (&begin.initiator, &begin.request) {
            (Initiator::Principal(principal), Some(request)) => {
                Some((principal.clone(), request.request_id.clone()))
            }
            _ => None,
        };
        let _in_flight = self.take(key.clone())?;
        if let Some(key) = &key
            && let Some(answer) = self.lookup(key, &begin)?
        {
            // A success is answered only once its outcome record is durable, a retry's too.
            self.settle()
                .map_err(|halt| MutationError::Unrecorded(halt.detail()))?;
            return Ok(answer);
        }
        // An outcome record still pending is written before anything new is applied.
        self.settle().map_err(|halt| match halt {
            Halt::Audit(detail) => MutationError::AuditUnavailable(detail),
            Halt::Journal(detail) => MutationError::Unavailable(detail),
        })?;
        // 1: the caller's validation.
        check().map_err(MutationError::Refused)?;

        // 2: the intent.
        let operation_id = OperationId::mint().ok_or_else(|| {
            MutationError::Unavailable("the OS random source refused an operation id".to_owned())
        })?;
        let intent = Intent {
            operation_id,
            at: self.time.now_secs(),
            domain: begin.domain.to_owned(),
            operation: begin.operation.to_owned(),
            action: begin.action.to_owned(),
            initiator: begin.initiator.clone(),
            request: begin.request.clone(),
            target: begin.target.clone(),
        };
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(operation_id);
        let running = Running {
            engine: self,
            operation_id,
        };
        self.append(Entry::Intent(intent.clone()))
            .map_err(|error| MutationError::Unavailable(error.to_string()))?;
        crash::point("mutation.intent_written");

        // 3: its audit record.
        if let Err(error) = self.project_phase(&intent, AuditPhase::Intent, None) {
            self.fail(
                operation_id,
                format!("the audit intent was not written: {error}"),
            );
            return Err(MutationError::AuditUnavailable(error));
        }
        crash::point("mutation.intent_audited");

        // 4: the domain.
        let token = Applying {
            operation_id,
            _engine: PhantomData,
        };
        let applied = match apply(&token) {
            Ok(applied) => applied,
            Err(Failure::Refused(refused)) => {
                self.fail(operation_id, "refused by the domain".to_owned());
                let _ = self.settle();
                return Err(MutationError::Refused(refused));
            }
            Err(Failure::Indeterminate(error)) => {
                // Left open: the next start asks the domain whether it applied.
                drop(running);
                self.report();
                return Err(MutationError::Indeterminate(error));
            }
        };
        crash::point("mutation.applied");

        // 5: the commit, with the answer a retry learns. An answer that does not serialize, or
        // is too large for an entry, is committed without it: a retry rebuilds it from the
        // domain, as after a crash.
        let mut commit = Commit {
            operation_id,
            at: self.time.now_secs(),
            revision: applied.revision,
            target: applied.target.clone(),
            result: serde_json::to_vec(&applied.value).ok(),
            reconciled: false,
        };
        if Entry::Commit(commit.clone()).encode().is_err() {
            commit.result = None;
        }
        if let Err(error) = self.append(Entry::Commit(commit)) {
            drop(running);
            self.report();
            return Err(MutationError::Unrecorded(error.to_string()));
        }
        crash::point("mutation.committed");

        // 6: the outcome record, then the mark that it is written.
        drop(running);
        self.settle()
            .map_err(|halt| MutationError::Unrecorded(halt.detail()))?;
        Ok(Outcome::Applied(applied.value))
    }

    /// Takes `(principal, request id)` for one operation, or refuses a second arrival.
    fn take<E>(&self, key: Option<(String, String)>) -> Result<InFlight<'_>, MutationError<E>> {
        if let Some(key) = &key {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !in_flight.insert(key.clone()) {
                return Err(MutationError::RequestIdReused(
                    "a mutation with this request id is in flight; retry once it has answered",
                ));
            }
        }
        Ok(InFlight { engine: self, key })
    }

    /// The answer a retry of `key` learns, when the window holds one.
    fn lookup<T: DeserializeOwned, E>(
        &self,
        key: &(String, String),
        begin: &Begin,
    ) -> Result<Option<Outcome<T>>, MutationError<E>> {
        let now = self.time.now_secs();
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(operation) = state
            .requests
            .get(key)
            .and_then(|id| state.operations.get(id))
        else {
            return Ok(None);
        };
        let same = operation.intent.operation == begin.operation
            && operation
                .intent
                .request
                .as_ref()
                .map(|request| &request.digest)
                == begin.request.as_ref().map(|request| &request.digest);
        match &operation.end {
            Some(End::Failed { .. }) => Ok(None),
            Some(End::Commit(commit)) if commit.at.saturating_add(WINDOW.as_secs()) < now => {
                Ok(None)
            }
            _ if !same => Err(MutationError::RequestIdReused(
                "this request id was already used for a different mutation inside the replay window",
            )),
            Some(End::Commit(commit)) => match &commit.result {
                Some(bytes) => serde_json::from_slice(bytes)
                    .map(|value| Some(Outcome::Replayed(value)))
                    .map_err(|error| {
                        MutationError::Unrecorded(format!(
                            "the operation was applied and its committed answer does not read: \
                             {error}"
                        ))
                    }),
                None => Ok(Some(Outcome::Reconciled {
                    operation_id: commit.operation_id,
                    revision: commit.revision,
                    target: commit.target.clone(),
                })),
            },
            None => Err(MutationError::Unrecorded(
                "an earlier attempt with this request id may have been applied and is unresolved \
                 until the next start"
                    .to_owned(),
            )),
        }
    }

    /// Marks `operation_id` failed, best effort: an unwritten FAILED leaves an open intent, which
    /// recovery resolves the same way.
    fn fail(&self, operation_id: OperationId, reason: String) {
        if let Err(error) = self.append(Entry::Failed {
            operation_id,
            at: self.time.now_secs(),
            reason,
        }) {
            tracing::error!(
                event.name = "host.mutation_failure_unwritten",
                component = "host",
                operation_id = %operation_id,
                error = %error,
                "a failed mutation could not be marked; recovery resolves it"
            );
        }
        self.report();
    }

    /// Writes every pending outcome record and marks each written; says why one could not be,
    /// or that an operation stays unresolved until the next start.
    fn settle(&self) -> Result<(), Halt> {
        let _settling = self.settling.lock().unwrap_or_else(PoisonError::into_inner);
        // Read, and the guard released, before `report` takes it again.
        let stopped = self
            .stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(reason) = stopped {
            self.report();
            return Err(Halt::Journal(reason));
        }
        let pending: Vec<(Intent, End)> = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state
                .operations
                .values()
                .filter(|operation| !operation.projected)
                .filter_map(|operation| {
                    operation
                        .end
                        .clone()
                        .map(|end| (operation.intent.clone(), end))
                })
                .collect()
        };
        let mut outcome = Ok(());
        for (intent, end) in pending {
            let (phase, target) = match &end {
                End::Commit(commit) if commit.reconciled => {
                    (AuditPhase::Reconciled, commit.target.clone())
                }
                End::Commit(commit) => (AuditPhase::Applied, commit.target.clone()),
                End::Failed { .. } => (AuditPhase::Failed, intent.target.clone()),
            };
            if let Err(error) = self.project_phase(&intent, phase, target.as_deref()) {
                outcome = Err(Halt::Audit(error));
                break;
            }
            crash::point("mutation.applied_audited");
            if let Err(error) = self.append(Entry::Projected {
                operation_id: intent.operation_id,
                at: self.time.now_secs(),
            }) {
                outcome = Err(Halt::Journal(error.to_string()));
                break;
            }
            crash::point("mutation.projected");
        }
        // An intent left open by an uncertain domain write waits for the next start.
        if outcome.is_ok() && self.pending() > 0 {
            outcome = Err(Halt::Journal(
                "an earlier mutation may have been applied and is unresolved until the next start"
                    .to_owned(),
            ));
        }
        self.report();
        outcome
    }

    /// Writes the audit record of `intent` at `phase`.
    fn project_phase(
        &self,
        intent: &Intent,
        phase: AuditPhase,
        target: Option<&str>,
    ) -> Result<(), String> {
        let subject = match &intent.initiator {
            Initiator::Principal(name) => Subject::Principal(name),
            Initiator::System(name) => Subject::System(name),
        };
        let mut event = AuditEvent::new(&intent.action, subject)
            .in_operation(intent.operation_id.as_bytes(), phase)
            .with_outcome(match phase {
                AuditPhase::Failed => AuditOutcome::Failed,
                AuditPhase::Intent | AuditPhase::Applied | AuditPhase::Reconciled => {
                    AuditOutcome::Ok
                }
            });
        if let Some(target) = target.or(intent.target.as_deref()) {
            event = event.on(target);
        }
        self.projection.project(&event)
    }

    /// Appends `entry`, flushed, and folds it into the state; folds the journal into the
    /// snapshot once it has grown.
    fn append(&self, entry: Entry) -> Result<(), StorageError> {
        let bytes = entry
            .encode()
            .map_err(|error| StorageError::Corruption(error.to_string()))?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut stopped = self.stopped.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(reason) = stopped.as_ref() {
            return Err(StorageError::Refused(reason.clone()));
        }
        if let Err(error) = sequence::append(&self.dir, JOURNAL, &bytes) {
            tracing::error!(
                event.name = "host.mutations_stopped",
                component = "host",
                error = %error,
                "the mutation journal refused a write and takes none until the next start"
            );
            *stopped = Some(format!(
                "the mutation journal refused a write and takes none until the next start: {error}"
            ));
            return Err(error);
        }
        drop(stopped);
        state.apply(entry);
        state.appended += 1;
        if state.appended >= self.compact_after {
            // A failed fold leaves the journal as it was, which is still the truth.
            if let Err(error) = self.compact(&mut state) {
                tracing::warn!(
                    event.name = "host.mutations_compaction_failed",
                    component = "host",
                    error = %error,
                    "the mutation journal could not be folded into its snapshot"
                );
            }
        }
        Ok(())
    }

    /// Writes the live entries as the snapshot, then empties the journal. A crash between the
    /// two leaves both holding the same entries, which fold to the same state.
    fn compact(&self, state: &mut State) -> Result<(), StorageError> {
        let now = self.time.now_secs();
        let live = state.live(now);
        let bytes = super::journal::encode_snapshot(now, &live)
            .map_err(|error| StorageError::Corruption(error.to_string()))?;
        write::replace_bytes(&self.dir, SNAPSHOT, &bytes)?;
        crash::point("mutation.snapshot_written");
        write::replace_bytes(&self.dir, JOURNAL, &[])?;
        *state = State::rebuild(live);
        Ok(())
    }

    /// Degrades or restores the Host's `security_mutations` capability.
    fn report(&self) {
        let Some(health) = self.health.get() else {
            return;
        };
        let pending = self.pending();
        let stopped = self
            .stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if pending == 0 && !stopped {
            health
                .lifecycle()
                .restore(permguard_core::lifecycle::HOST, CAPABILITY);
        } else {
            health.lifecycle().degrade(
                permguard_core::lifecycle::HOST,
                CAPABILITY,
                if stopped {
                    "the mutation journal refused a write; it takes none until the next start"
                        .to_owned()
                } else {
                    format!(
                        "{pending} mutation operations wait for the audit trail or the next start"
                    )
                },
            );
        }
    }
}

#[cfg(test)]
mod tests;
