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
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

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
/// What holds readiness while a recovery stopped on a domain that could not say.
pub const RECOVERY_HOLD: &str = "security_mutations.recovery";
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
        self.project_recorded(event).map(|_| ())
    }

    fn project_recorded(
        &self,
        event: &AuditEvent<'_>,
    ) -> Result<Option<crate::audit::Recorded>, String> {
        let recorded = self
            .engine
            .record(event, self.policy.as_deref())
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
        Ok(recorded)
    }
}

/// Where the engine writes the audit record of each phase: the Host's audit engine, whose
/// `security` failure is answered (WP-3.5).
pub trait Projection: Send + Sync {
    /// Writes `event` durably, or says why it could not.
    fn project(&self, event: &AuditEvent<'_>) -> Result<(), String>;

    /// Writes `event` as [`Projection::project`] does, and answers where the trail recorded it
    /// when the projection knows (BUG-0095).
    fn project_recorded(
        &self,
        event: &AuditEvent<'_>,
    ) -> Result<Option<crate::audit::Recorded>, String> {
        self.project(event).map(|()| None)
    }
}

impl Projection for crate::audit::Engine {
    fn project(&self, event: &AuditEvent<'_>) -> Result<(), String> {
        self.append(event, None)
            .map_err(|refused| refused.to_string())
    }

    fn project_recorded(
        &self,
        event: &AuditEvent<'_>,
    ) -> Result<Option<crate::audit::Recorded>, String> {
        self.record(event, None)
            .map_err(|refused| refused.to_string())
    }
}

/// How many operations' intent records [`Mutations::intent_recorded`] remembers: far more than
/// are ever in flight, so every receipt of this process finds its own.
const RECENT_INTENTS: usize = 4096;

/// Where the intent records of the latest operations were written, oldest first out.
#[derive(Debug, Default)]
struct RecentIntents {
    order: std::collections::VecDeque<OperationId>,
    by_operation: BTreeMap<OperationId, crate::audit::Recorded>,
}

impl RecentIntents {
    fn remember(&mut self, operation_id: OperationId, recorded: crate::audit::Recorded) {
        if self.by_operation.insert(operation_id, recorded).is_none() {
            self.order.push_back(operation_id);
        }
        while self.order.len() > RECENT_INTENTS {
            if let Some(oldest) = self.order.pop_front() {
                self.by_operation.remove(&oldest);
            }
        }
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
    ///
    /// `Ok(None)` is an answer: the domain read its state and the operation is not in it. A
    /// domain that could not read its state says so with `Err`, and never with `None`: recovery
    /// records an operation the domain does not show as failed, and an operation the domain
    /// applied and could not be asked about must not be (decision E17 of iteration 03).
    fn observe(
        &self,
        operation_id: &OperationId,
        target: Option<&str>,
    ) -> Result<Option<Observed>, String>;
}

/// The proof that the engine is applying an operation: a domain mutator takes one, and only this
/// module builds one.
pub struct Applying<'a> {
    operation_id: OperationId,
    /// The unit of work the operation runs in, on an engine that has one.
    unit: Option<&'a (dyn std::any::Any + Send + Sync)>,
    _engine: PhantomData<&'a Mutations>,
}

impl<'a> Applying<'a> {
    /// The operation being applied: what the domain writes beside its change.
    pub fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// The unit of work the operation runs in, when the engine applying it has one of the kind
    /// `T` (iteration 03, decision E23): a store of that engine's backend makes its change
    /// inside it, so the change, the operation's record and its audit record are kept together
    /// or not at all. The file engine has none: its unit of work is the protocol around the
    /// domain write, and a store of the file backend never asks.
    pub fn unit<T: 'static>(&self) -> Option<&'a T> {
        self.unit.and_then(|unit| unit.downcast_ref())
    }

    /// The token of `operation_id` applied inside `unit`. An engine's alone: it is the proof a
    /// domain mutator takes that an engine is applying the operation, and
    /// `task check:mutations` finds any file that asks for one and is not an engine
    /// `mutations.json` names.
    pub fn within(operation_id: OperationId, unit: &'a (dyn std::any::Any + Send + Sync)) -> Self {
        Self {
            operation_id,
            unit: Some(unit),
            _engine: PhantomData,
        }
    }
}

#[cfg(test)]
impl Applying<'static> {
    /// A token for the unit tests of a domain's mutators, which run them without the engine.
    pub(crate) fn for_tests(byte: u8) -> Self {
        Self {
            operation_id: OperationId::from_bytes([byte; 16]),
            unit: None,
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
    /// The request id names another request inside the window.
    RequestIdReused(&'static str),
    /// The same request id is in flight: the same request succeeds, or learns the first answer,
    /// once that one has answered (BUG-0169).
    InFlight(&'static str),
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
    /// A backup barrier holds new mutations (WP-7.8): nothing was applied, and the same request
    /// succeeds once the backup is finalized or aborted.
    Quiesced(String),
}

/// What a domain answered an engine when it applied an operation: [`Applied`], its answer as
/// the bytes a retry is given back.
#[derive(Debug)]
pub struct AppliedBytes {
    pub revision: u64,
    pub target: Option<String>,
    /// The answer, serialized; `None` when it does not serialize, and a retry then rebuilds it
    /// from the domain.
    pub result: Option<Vec<u8>>,
}

/// Why a domain did not apply an operation, as an engine needs it: [`Failure`] without the
/// domain's own reason, which the caller of the engine keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declined {
    Refused,
    Indeterminate,
}

/// How an operation ended, as an engine says it: [`Outcome`] with a replayed answer still in
/// the bytes it was kept in.
#[derive(Debug)]
pub enum Ended {
    Applied,
    Replayed(Vec<u8>),
    Reconciled {
        operation_id: OperationId,
        revision: u64,
        target: Option<String>,
    },
}

/// Why an operation did not end applied, as an engine says it: [`MutationError`] without the
/// domain's own reason.
#[derive(Debug)]
pub enum Stopped {
    /// The caller's validation refused it, before any intent.
    Unchecked,
    /// The domain refused it: nothing was applied.
    Refused,
    /// The domain could not say whether it applied.
    Indeterminate,
    RequestIdReused(&'static str),
    InFlight(&'static str),
    AuditUnavailable(String),
    Unrecorded(String),
    Unavailable(String),
    Quiesced(String),
}

/// A mutation engine (iteration 03, decision E23): what runs a security mutation as one unit
/// of work. A domain asks it to run an operation and is handed the [`Applying`] that carries
/// the unit; what the unit is, is the engine's. On files it is the protocol of this module,
/// intent, apply, commit and their recovery; on a database it is a transaction.
///
/// The trait speaks in bytes so that it can be asked through a reference to any engine; the
/// typed calls every domain makes, [`run_checked_on`] and [`replayed_on`], are written once
/// over it.
pub trait Engine: Send + Sync {
    /// Runs one operation: `check` is the caller's validation and answers whether it passed,
    /// `apply` the domain's write. See [`Mutations::run_checked`] for the rules an engine keeps.
    fn run_bytes(
        &self,
        begin: Begin,
        check: &mut dyn FnMut() -> bool,
        apply: &mut dyn FnMut(&Applying<'_>) -> Result<AppliedBytes, Declined>,
    ) -> Result<Ended, Stopped>;

    /// The answer a retry of `begin`'s request learns without a new mutation; `None` when the
    /// engine holds none.
    fn replayed_bytes(&self, begin: &Begin) -> Result<Option<Ended>, Stopped>;

    /// Resolves the operations `domain` left open, where the engine can leave one open. An
    /// engine whose unit of work is a transaction leaves none and answers that nothing was
    /// resolved.
    fn recover(&self, domain: &dyn Domain) -> Result<Recovered, String>;

    /// The gate of the subsystem `name`, one per name for the life of the engine.
    fn subsystem(&self, name: &str) -> Subsystem;

    /// Whether a backup barrier holds new mutations now. An engine of a backend with no volume
    /// has no barrier, and answers that none holds.
    fn quiesced(&self) -> bool {
        false
    }
}

/// The typed form of [`Engine::run_bytes`]: what every domain calls, on any engine.
pub fn run_checked_on<T, E>(
    engine: &dyn Engine,
    begin: Begin,
    check: impl FnMut() -> Result<(), E>,
    apply: impl FnMut(&Applying<'_>) -> Result<Applied<T>, Failure<E>>,
) -> Result<Outcome<T>, MutationError<E>>
where
    T: Serialize + DeserializeOwned,
{
    // The domain's own answer and reason stay here: the engine is told that there is one. An
    // engine that runs the write again, because its unit of work kept nothing of the first run,
    // is answered by the last run alone.
    let refusal: std::cell::RefCell<Option<E>> = std::cell::RefCell::new(None);
    let mut value: Option<T> = None;
    let (mut check, mut apply) = (check, apply);
    let ended = engine.run_bytes(
        begin,
        &mut || match check() {
            Ok(()) => true,
            Err(refused) => {
                *refusal.borrow_mut() = Some(refused);
                false
            }
        },
        &mut |applying| match apply(applying) {
            Ok(applied) => {
                let result = serde_json::to_vec(&applied.value).ok();
                value = Some(applied.value);
                Ok(AppliedBytes {
                    revision: applied.revision,
                    target: applied.target,
                    result,
                })
            }
            Err(Failure::Refused(refused)) => {
                *refusal.borrow_mut() = Some(refused);
                Err(Declined::Refused)
            }
            Err(Failure::Indeterminate(error)) => {
                *refusal.borrow_mut() = Some(error);
                Err(Declined::Indeterminate)
            }
        },
    );
    let lost = || {
        MutationError::Unrecorded(
            "the engine answered for a domain write it did not run".to_owned(),
        )
    };
    match ended {
        Ok(Ended::Applied) => value.map(Outcome::Applied).ok_or_else(lost),
        Ok(ended) => typed(ended),
        Err(Stopped::Unchecked | Stopped::Refused) => Err(refusal
            .into_inner()
            .map(MutationError::Refused)
            .unwrap_or_else(lost)),
        Err(Stopped::Indeterminate) => Err(refusal
            .into_inner()
            .map(MutationError::Indeterminate)
            .unwrap_or_else(lost)),
        Err(stopped) => Err(untyped(stopped)),
    }
}

/// The typed form of [`Engine::replayed_bytes`].
pub fn replayed_on<T, E>(
    engine: &dyn Engine,
    begin: &Begin,
) -> Result<Option<Outcome<T>>, MutationError<E>>
where
    T: DeserializeOwned,
{
    match engine.replayed_bytes(begin) {
        Ok(None) => Ok(None),
        Ok(Some(ended)) => typed(ended).map(Some),
        Err(stopped) => Err(untyped(stopped)),
    }
}

/// An engine's answer for a retry, read back as the domain's.
fn typed<T: DeserializeOwned, E>(ended: Ended) -> Result<Outcome<T>, MutationError<E>> {
    match ended {
        Ended::Replayed(bytes) => serde_json::from_slice(&bytes)
            .map(Outcome::Replayed)
            .map_err(|error| {
                MutationError::Unrecorded(format!(
                    "the operation was applied and its committed answer does not read: {error}"
                ))
            }),
        Ended::Reconciled {
            operation_id,
            revision,
            target,
        } => Ok(Outcome::Reconciled {
            operation_id,
            revision,
            target,
        }),
        Ended::Applied => Err(MutationError::Unrecorded(
            "the engine answered applied for an operation it did not run".to_owned(),
        )),
    }
}

/// An engine's own stop, as the caller is told it.
fn untyped<E>(stopped: Stopped) -> MutationError<E> {
    match stopped {
        Stopped::RequestIdReused(detail) => MutationError::RequestIdReused(detail),
        Stopped::InFlight(detail) => MutationError::InFlight(detail),
        Stopped::AuditUnavailable(detail) => MutationError::AuditUnavailable(detail),
        Stopped::Unrecorded(detail) => MutationError::Unrecorded(detail),
        Stopped::Unavailable(detail) => MutationError::Unavailable(detail),
        Stopped::Quiesced(detail) => MutationError::Quiesced(detail),
        Stopped::Unchecked | Stopped::Refused | Stopped::Indeterminate => {
            MutationError::Unrecorded(
                "the engine answered for the domain without the domain's reason".to_owned(),
            )
        }
    }
}

impl<E: std::fmt::Display> std::fmt::Display for MutationError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(error) => write!(f, "{error}"),
            Self::RequestIdReused(detail) | Self::InFlight(detail) => f.write_str(detail),
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
            Self::Quiesced(detail) => write!(f, "nothing was applied: {detail}"),
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

/// The gate of one subsystem (iteration 03, decision E26): the stores of a subsystem change
/// together under it, and what must be read as they stand together is read under it.
///
/// An operation whose domain write spans two stores of one subsystem, an account and its
/// tokens, holds the gate from the first write to the last, so no other operation of the
/// subsystem and no gated read falls between the two. It is the file backend's unit of work
/// over those stores; a backend with transactions has one instead.
///
/// The gate is taken before any lock of a store and never while one is held, and never by the
/// code it already holds: an operation's domain write does not start another gated operation.
#[derive(Clone)]
pub struct Subsystem {
    gate: Arc<dyn SubsystemGate>,
}

/// What holds a subsystem: the engine's, of the kind its backend has. On files it is a lock of
/// the process; on a database it is a row every holder takes inside its unit of work.
pub trait SubsystemGate: Send + Sync {
    /// Runs `work` while nothing else of the subsystem changes or reads under the gate, on any
    /// instance the gate reaches. `Err` when the gate could not be taken, and `work` was then
    /// not run, or when what `work` did under it could not be kept, and nothing of it is.
    ///
    /// Asked from inside an operation the engine is applying, the gate is taken in the
    /// operation's own unit of work and `work` is always run: a gate that could not be taken
    /// there fails the unit, and the operation with it.
    fn hold(&self, work: &mut dyn FnMut()) -> Result<(), String>;
}

/// The gate of one process: a lock.
#[derive(Default)]
struct ProcessGate(Mutex<()>);

impl SubsystemGate for ProcessGate {
    fn hold(&self, work: &mut dyn FnMut()) -> Result<(), String> {
        let _held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        work();
        Ok(())
    }
}

impl Default for Subsystem {
    fn default() -> Self {
        Self {
            gate: Arc::new(ProcessGate::default()),
        }
    }
}

impl std::fmt::Debug for Subsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Subsystem")
    }
}

impl Subsystem {
    /// The subsystem `gate` holds: what an engine of another backend answers for its own.
    pub fn over(gate: Arc<dyn SubsystemGate>) -> Self {
        Self { gate }
    }

    /// Runs `work` while nothing else of the subsystem changes or reads under the gate. `Err`
    /// as [`SubsystemGate::hold`] says: the work was not run, or nothing of it was kept.
    pub fn hold<R>(&self, work: impl FnOnce() -> R) -> Result<R, String> {
        let mut work = Some(work);
        let mut answer = None;
        self.gate.hold(&mut || {
            if let Some(work) = work.take() {
                answer = Some(work());
            }
        })?;
        answer.ok_or_else(|| "the subsystem's gate did not run the work".to_owned())
    }
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
    /// The domains whose recovery stopped because they could not say, and what each said: the
    /// process is not ready while one is here.
    unanswered: Mutex<BTreeMap<String, String>>,
    projection: Arc<dyn Projection>,
    time: Arc<TimeGuard>,
    health: OnceLock<Health>,
    compact_after: usize,
    /// The backup barrier (WP-7.8) and the operations it waits for.
    gate: Mutex<Gate>,
    /// Where the intent records of the latest operations were written (BUG-0095).
    intents: Mutex<RecentIntents>,
    /// Signalled whenever an operation leaves, so a barrier waiting for them wakes.
    drained: Condvar,
    /// The gate of each subsystem that asked for one, by name.
    subsystems: Mutex<BTreeMap<String, Subsystem>>,
}

/// The backup barrier (WP-7.8, application-consistent snapshot): while it is held, every new
/// operation of another domain than [`BARRIER_DOMAIN`] is refused, and a barrier is raised only once
/// the operations already past it have ended.
#[derive(Debug, Default)]
struct Gate {
    /// Until when the barrier holds: past it, the barrier no longer refuses anything.
    held: Option<Instant>,
    /// The operations admitted and not yet answered.
    active: usize,
}

impl Gate {
    fn holds(&self, now: Instant) -> bool {
        self.held.is_some_and(|until| now < until)
    }
}

/// Whether a backup barrier holds now, for a writer outside the mutation transaction that holds
/// with it (BUG-0207): read from the engine, never copied, so it lowers when the barrier does.
#[derive(Debug, Clone)]
pub struct BarrierView(std::sync::Weak<Mutations>);

impl BarrierView {
    /// Whether the barrier holds now; never once the engine is gone.
    pub fn holds(&self) -> bool {
        self.0.upgrade().is_some_and(|engine| engine.quiesced())
    }
}

impl crate::keys::ring::MaintenanceHold for BarrierView {
    fn holds(&self) -> bool {
        BarrierView::holds(self)
    }
}

/// The domain a backup barrier lets through: the backup's own prepare, finalize and abort.
pub const BARRIER_DOMAIN: &str = "backup";
/// The operations of [`BARRIER_DOMAIN`] the barrier lets through, and no other.
pub const BARRIER_OPERATIONS: [&str; 3] = ["backup.prepare", "backup.finalize", "backup.abort"];

/// An operation admitted past the barrier; dropping it lets a waiting barrier go on.
struct Admitted<'a> {
    engine: &'a Mutations,
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        let mut gate = self
            .engine
            .gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        gate.active = gate.active.saturating_sub(1);
        self.engine.drained.notify_all();
    }
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

impl Engine for Mutations {
    fn run_bytes(
        &self,
        begin: Begin,
        check: &mut dyn FnMut() -> bool,
        apply: &mut dyn FnMut(&Applying<'_>) -> Result<AppliedBytes, Declined>,
    ) -> Result<Ended, Stopped> {
        self.run_protocol(begin, check, apply)
    }

    fn replayed_bytes(&self, begin: &Begin) -> Result<Option<Ended>, Stopped> {
        self.replayed_protocol(begin)
    }

    fn recover(&self, domain: &dyn Domain) -> Result<Recovered, String> {
        Mutations::recover(self, domain).map_err(|error| error.to_string())
    }

    fn subsystem(&self, name: &str) -> Subsystem {
        Mutations::subsystem(self, name)
    }

    fn quiesced(&self) -> bool {
        Mutations::quiesced(self)
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
            unanswered: Mutex::new(BTreeMap::new()),
            projection,
            time,
            health: OnceLock::new(),
            compact_after: COMPACT_AFTER,
            gate: Mutex::new(Gate::default()),
            intents: Mutex::new(RecentIntents::default()),
            drained: Condvar::new(),
            subsystems: Mutex::new(BTreeMap::new()),
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

    /// The gate of the subsystem `name`: one per name for the life of the engine, so every
    /// handle of a subsystem holds the same one.
    pub fn subsystem(&self, name: &str) -> Subsystem {
        self.subsystems
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(name.to_owned())
            .or_default()
            .clone()
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

    /// The intents no running call will end: left open by an uncertain domain write or an
    /// unwritten commit, resolved only at the next start.
    fn unresolved(&self) -> usize {
        // Both read under one hold of the state: an operation that commits and leaves `running`
        // between two separate reads would be counted open and not running.
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .operations
            .values()
            .filter(|operation| operation.end.is_none())
            .filter(|operation| !running.contains(&operation.intent.operation_id))
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
    ///
    /// A domain that cannot say stops the recovery: the operation it was asked about stays open,
    /// nothing is recorded of it, and the caller does not serve the domain. The operations met
    /// before it keep the outcome they were given, and the next start asks again. The process is
    /// not ready from then until a recovery of that domain ends.
    pub fn recover(&self, domain: &dyn Domain) -> Result<Recovered, StorageError> {
        let outcome = self.recover_open(domain);
        {
            let mut unanswered = self
                .unanswered
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match &outcome {
                Ok(_) => unanswered.remove(domain.name()),
                Err(error) => unanswered.insert(domain.name().to_owned(), error.to_string()),
            };
        }
        self.report();
        outcome
    }

    fn recover_open(&self, domain: &dyn Domain) -> Result<Recovered, StorageError> {
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
            let shown = domain
                .observe(&operation_id, target.as_deref())
                .map_err(|error| {
                    tracing::error!(
                        event.name = "host.mutations_recovery_stopped",
                        component = "host",
                        domain = domain.name(),
                        operation_id = %operation_id,
                        error = %error,
                        "a domain could not say whether it applied an operation a crash left open"
                    );
                    StorageError::Refused(format!(
                        "the domain `{}` could not say whether it applied the operation \
                         {operation_id}, which stays open: {error}",
                        domain.name()
                    ))
                })?;
            match shown {
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

    /// Writes a record of an operation's own facts beside its phases, through the same audit
    /// projection, failure answered: what a phase record cannot carry (WP-4.2: an operator
    /// approval's principal, scope, reason and expiry).
    pub fn project(&self, event: &AuditEvent<'_>) -> Result<(), String> {
        self.projection.project(event)
    }

    /// Admits one operation of `domain` past the backup barrier, or refuses it while the barrier
    /// holds.
    fn admit(&self, domain: &str, operation: &str) -> Result<Admitted<'_>, String> {
        let mut gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
        let exempt = domain == BARRIER_DOMAIN && BARRIER_OPERATIONS.contains(&operation);
        if !exempt && gate.holds(Instant::now()) {
            return Err(
                "a backup is being prepared: mutations resume when it is finalized or aborted"
                    .to_owned(),
            );
        }
        gate.active += 1;
        Ok(Admitted { engine: self })
    }

    /// Raises the backup barrier until `until` (WP-7.8): every new operation of another domain is
    /// refused from now on, and this answers once the operations already admitted have ended. One
    /// still running after `wait` lowers the barrier again and refuses it; so does a barrier
    /// already held.
    pub fn quiesce(&self, until: Instant, wait: Duration) -> Result<(), String> {
        let started = Instant::now();
        let mut gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
        if gate.holds(started) {
            return Err("a backup barrier is already held".to_owned());
        }
        gate.held = Some(until);
        while gate.active > 0 {
            let left = wait.saturating_sub(started.elapsed());
            if left.is_zero() {
                gate.held = None;
                return Err(format!(
                    "{} operations were still running after {}s: the barrier is lowered",
                    gate.active,
                    wait.as_secs()
                ));
            }
            gate = self
                .drained
                .wait_timeout(gate, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Ok(())
    }

    /// Lowers the backup barrier: mutations resume.
    pub fn release(&self) {
        self.gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .held = None;
    }

    /// The order the next intent gets: how many operations the transaction has begun, what a
    /// snapshot manifest names as the `mutations` revision (WP-7.8).
    pub fn order(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .next
    }

    /// A view of the backup barrier for the writers outside the transaction that must hold with
    /// it: the key rings' maintenance (BUG-0207). It keeps no engine alive.
    pub fn barrier(self: &Arc<Self>) -> BarrierView {
        BarrierView(Arc::downgrade(self))
    }

    /// Whether a backup barrier refuses new mutations now.
    pub fn quiesced(&self) -> bool {
        self.gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .holds(Instant::now())
    }

    /// Runs one operation through the protocol. `apply` is the domain mutation: it is given the
    /// [`Applying`] its mutators take, and answers the revision, the target and the answer.
    pub fn run<T, E>(
        &self,
        begin: Begin,
        apply: impl FnMut(&Applying<'_>) -> Result<Applied<T>, Failure<E>>,
    ) -> Result<Outcome<T>, MutationError<E>>
    where
        T: Serialize + DeserializeOwned,
    {
        self.run_checked(begin, || Ok(()), apply)
    }

    /// Looks up and validates a completed request without starting a new mutation. Callers whose
    /// domain work needs external I/O use this before that I/O, so a retry or a reused request id
    /// never contacts the external system again.
    pub fn replayed<T, E>(&self, begin: &Begin) -> Result<Option<Outcome<T>>, MutationError<E>>
    where
        T: DeserializeOwned,
    {
        replayed_on(self, begin)
    }

    /// [`Mutations::run`], with `check` the caller's validation (step 1): run after a retry is
    /// answered from the window and before the intent, so a request the domain would refuse
    /// leaves no intent and no audit record, and a retry of an applied one still learns it.
    pub fn run_checked<T, E>(
        &self,
        begin: Begin,
        check: impl FnMut() -> Result<(), E>,
        apply: impl FnMut(&Applying<'_>) -> Result<Applied<T>, Failure<E>>,
    ) -> Result<Outcome<T>, MutationError<E>>
    where
        T: Serialize + DeserializeOwned,
    {
        run_checked_on(self, begin, check, apply)
    }

    /// The protocol of [`Mutations::run_checked`], as [`Engine::run_bytes`] asks it.
    fn run_protocol(
        &self,
        begin: Begin,
        check: &mut dyn FnMut() -> bool,
        apply: &mut dyn FnMut(&Applying<'_>) -> Result<AppliedBytes, Declined>,
    ) -> Result<Ended, Stopped> {
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
                .map_err(|halt| Stopped::Unrecorded(halt.detail()))?;
            return Ok(answer);
        }
        // An outcome record still pending is written before anything new is applied.
        self.settle().map_err(|halt| match halt {
            Halt::Audit(detail) => Stopped::AuditUnavailable(detail),
            Halt::Journal(detail) => Stopped::Unavailable(detail),
        })?;
        // 1: the caller's validation.
        if !check() {
            return Err(Stopped::Unchecked);
        }
        // A backup barrier refuses what is new; what was admitted before it runs to its answer.
        let _admitted = self
            .admit(begin.domain, begin.operation)
            .map_err(Stopped::Quiesced)?;

        // 2: the intent.
        let operation_id = OperationId::mint().ok_or_else(|| {
            Stopped::Unavailable("the OS random source refused an operation id".to_owned())
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
            .map_err(|error| Stopped::Unavailable(error.to_string()))?;
        crash::point("mutation.intent_written");

        // 3: its audit record.
        match self.project_phase(&intent, AuditPhase::Intent, None) {
            Ok(Some(recorded)) => self
                .intents
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remember(operation_id, recorded),
            Ok(None) => {}
            Err(error) => {
                self.fail(
                    operation_id,
                    format!("the audit intent was not written: {error}"),
                );
                return Err(Stopped::AuditUnavailable(error));
            }
        }
        crash::point("mutation.intent_audited");

        // 4: the domain.
        let token = Applying {
            operation_id,
            unit: None,
            _engine: PhantomData,
        };
        let applied = match apply(&token) {
            Ok(applied) => applied,
            Err(Declined::Refused) => {
                self.fail(operation_id, "refused by the domain".to_owned());
                let _ = self.settle();
                return Err(Stopped::Refused);
            }
            Err(Declined::Indeterminate) => {
                // Left open: the next start asks the domain whether it applied.
                drop(running);
                self.report();
                return Err(Stopped::Indeterminate);
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
            result: applied.result,
            reconciled: false,
        };
        if Entry::Commit(commit.clone()).encode().is_err() {
            commit.result = None;
        }
        if let Err(error) = self.append(Entry::Commit(commit)) {
            drop(running);
            self.report();
            return Err(Stopped::Unrecorded(error.to_string()));
        }
        crash::point("mutation.committed");

        // 6: the outcome record, then the mark that it is written.
        drop(running);
        self.settle()
            .map_err(|halt| Stopped::Unrecorded(halt.detail()))?;
        Ok(Ended::Applied)
    }

    /// The lookup of [`Mutations::replayed`], as [`Engine::replayed_bytes`] asks it.
    fn replayed_protocol(&self, begin: &Begin) -> Result<Option<Ended>, Stopped> {
        let key = match (&begin.initiator, &begin.request) {
            (Initiator::Principal(principal), Some(request)) => {
                Some((principal.clone(), request.request_id.clone()))
            }
            _ => None,
        };
        let _in_flight = self.take(key.clone())?;
        let Some(key) = &key else {
            return Ok(None);
        };
        let Some(answer) = self.lookup(key, begin)? else {
            return Ok(None);
        };
        self.settle()
            .map_err(|halt| Stopped::Unrecorded(halt.detail()))?;
        Ok(Some(answer))
    }

    /// Takes `(principal, request id)` for one operation, or refuses a second arrival.
    fn take(&self, key: Option<(String, String)>) -> Result<InFlight<'_>, Stopped> {
        if let Some(key) = &key {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !in_flight.insert(key.clone()) {
                return Err(Stopped::InFlight(
                    "a mutation with this request id is in flight; retry once it has answered",
                ));
            }
        }
        Ok(InFlight { engine: self, key })
    }

    /// The answer a retry of `key` learns, when the window holds one.
    fn lookup(&self, key: &(String, String), begin: &Begin) -> Result<Option<Ended>, Stopped> {
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
            _ if !same => Err(Stopped::RequestIdReused(
                "this request id was already used for a different mutation inside the replay window",
            )),
            Some(End::Commit(commit)) => match &commit.result {
                Some(bytes) => Ok(Some(Ended::Replayed(bytes.clone()))),
                None => Ok(Some(Ended::Reconciled {
                    operation_id: commit.operation_id,
                    revision: commit.revision,
                    target: commit.target.clone(),
                })),
            },
            None => Err(Stopped::Unrecorded(
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
        // An intent left open by an uncertain domain write waits for the next start. An operation
        // that ended while this one settled is not one: its outcome is written by its own call's
        // settle or, when that call does not settle, by the next mutation's.
        if outcome.is_ok() && self.unresolved() > 0 {
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
    ) -> Result<Option<crate::audit::Recorded>, String> {
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
        self.projection.project_recorded(&event)
    }

    /// Where the intent record of `operation_id` was written, when this process wrote it
    /// recently: what a receipt names (BUG-0095). An operation reconciled after a restart has
    /// none here.
    pub fn intent_recorded(&self, operation_id: &OperationId) -> Option<crate::audit::Recorded> {
        self.intents
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_operation
            .get(operation_id)
            .cloned()
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
        // A recovery that stopped holds readiness: what the domain holds of an operation is not
        // known, and nothing is served on a guess.
        let unanswered = self
            .unanswered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .next()
            .cloned();
        match unanswered {
            Some(reason) => {
                health
                    .lifecycle()
                    .hold_as(RECOVERY_HOLD, CAPABILITY, reason);
                return;
            }
            None => health.lifecycle().release_as(RECOVERY_HOLD, CAPABILITY),
        }
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
