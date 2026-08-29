// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The writing half: a decision becomes a record, at the position the chain
//! demands, on a disk that will still have it after a restart.
//!
//! # What happens per decision
//!
//! ```text
//! sampled out? ──► nothing is written, and nothing is claimed
//!      │           (a sampled permit was never a record, so it leaves no hole)
//!      ▼
//! build ──► append (durable) ──► pressure? ──► end the stream, start its successor
//! ```
//!
//! # Where the epochs come from
//!
//! Some facts are properties of a *range* of records rather than of each one:
//! the sampling rate, the build that decided, the commitment key in use. They
//! are written once as a `marker`, at the start of every stream and whenever
//! any of them changes, and exactly one marker governs any record — the most
//! recent at or before its sequence. That is what makes a completeness claim
//! unambiguous: "permits sampled at 0.5" is true of a range, and the range has
//! a beginning and an end that are both in the chain.
//!
//! # What is deliberately not recorded
//!
//! Policy text (it is in the ledger, addressed by the commit), the entity
//! graph itself, and any caller attribute nobody named in `include`. A
//! decision log is not a request archive. What is always kept is a **keyed
//! commitment** over the caller's context and partition inputs: it proves what the
//! decision saw, and lets two decisions be compared, without keeping either.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};

use permguard_core::Metrics;
use permguard_decisions::record::{
    ActionRef, Body, Build, Commitments, DecisionBody, DiscontinuityBody, Inputs, Lost, MarkerBody,
    Party, Predecessor, Reason, Record, Sampling, StoreRef, Stream, Trace, VERSION,
};
use permguard_decisions::spool::{Already, Bounds, Spool, SpoolError, Terminal};
use permguard_decisions::{Commitment, commitment};
use serde_json::Value;
use tracing::{info, warn};

use super::measure;

const COMPONENT: &str = "data-plane";

/// What one decision has to say about itself, in the vocabulary of the
/// decision path rather than of the record.
#[derive(Debug, Clone, Default)]
pub struct Decided<'a> {
    /// The handle the caller was given back.
    pub id: &'a str,
    /// When, RFC 3339 in UTC.
    pub at: String,
    /// The zone that owns the ledger.
    pub zone: &'a str,
    /// The ledger that answered.
    pub ledger: &'a str,
    /// The exact commit it answered from.
    pub commit: &'a str,
    /// Where that commit stood in the ledger's history.
    pub counter: u64,
    /// Which profile was asked for.
    pub profile: &'a str,
    /// Who asked, already pseudonymised.
    pub subject: (String, String),
    /// The subject attributes the deployment named in `include`.
    pub subject_properties: Option<serde_json::Map<String, Value>>,
    /// About what.
    pub resource: (String, String),
    /// The resource attributes the deployment named in `include`.
    pub resource_properties: Option<serde_json::Map<String, Value>>,
    /// The context members the deployment named in `include`.
    pub included_context: Option<serde_json::Map<String, Value>>,
    /// To do what.
    pub action: String,
    /// On whose behalf, where the request said so — pseudonymised.
    pub principal: Option<(String, String)>,
    /// The caller's context, for the commitment.
    pub context: Option<Value>,
    /// The entity graph, for the commitment.
    pub partition_inputs: Option<Value>,
    /// The answer.
    pub permit: bool,
    /// Which policies decided.
    pub policies: Vec<String>,
    /// The class of the outcome.
    pub reason: String,
    /// The trace the request belonged to.
    pub trace: Option<(String, String)>,
    /// The caller's own correlation handle.
    pub request_id: Option<String>,
    /// How long it took.
    pub latency_us: u64,
    /// The occurrence this decision was made about, for a temporal one.
    pub event: Option<permguard_decisions::record::EventRef>,
}

/// The members that say *what* was decided, as opposed to the occasion of
/// writing it down.
///
/// An allow-list rather than a deny-list, and deliberately: a member added to
/// the record later is excluded until somebody decides it is part of the
/// decision's identity, which fails towards answering a retry rather than
/// towards refusing one over a field that describes the write.
///
/// `pdp`, `latency_us`, `trace`, `request_id` and `context` are all left out.
/// The first three describe the occasion — which build, how long, which trace —
/// and the last two are correlation the caller chose; none of them changes what
/// was asked or what was answered. The context itself is still covered, because
/// `inputs` commits to the whole of it.
const DECIDES: [&str; 10] = [
    "id",
    "store",
    "subject",
    "resource",
    "action",
    "principal",
    "inputs",
    "decision",
    "policies",
    "reason",
];

/// How a decision record names the logical write it is.
///
/// Returns `None` for anything that is not a decision — a marker, a stream's
/// terminal record — because those are not retried under a caller's key and
/// have no identity to be idempotent about.
fn decision_identity(record: &serde_json::Value) -> Option<permguard_decisions::spool::Identity> {
    // `Body` is flattened into the record, so the decision's members sit beside
    // the envelope's rather than under a `body` of their own.
    let record = record.as_object()?;
    if record.get("kind").and_then(serde_json::Value::as_str) != Some("decision") {
        return None;
    }
    let id = record.get("id")?.as_str()?.to_owned();

    let mut decides = serde_json::Map::new();
    for member in DECIDES {
        if let Some(value) = record.get(member) {
            decides.insert((*member).to_owned(), value.clone());
        }
    }
    let fingerprint =
        permguard_decisions::record::digest_of(&serde_json::Value::Object(decides)).ok()?;

    Some(permguard_decisions::spool::Identity { id, fingerprint })
}

fn identity_conflict(id: &str, seq: u64) -> SpoolError {
    SpoolError::Malformed(format!(
        "the decision `{id}` is already recorded at sequence {seq} and this record decides \
         something else under the same identity: refusing to write a second record nothing could \
         tell apart"
    ))
}

/// What writing one record established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// A record was appended and is durable.
    Recorded {
        /// Where it sits.
        seq: u64,
    },
    /// Nothing was written, deliberately: sampling. No hole, and no claim.
    SampledOut,
    /// The spool reached a bound, so the stream ended and a new one began.
    ///
    /// The decision itself was still answered — this is the `open` behaviour.
    Discontinued {
        /// How many written records were discarded.
        lost: u64,
    },
    /// Nothing was written because this decision is already durable here.
    ///
    /// A retry of a decision the journal already holds, answered from the
    /// record it holds rather than by appending a second one under the same
    /// identity.
    AlreadyRecorded {
        /// Where the record that answers it sits.
        seq: u64,
    },
    /// Nothing was written and nothing could be: the plane is configured to
    /// refuse rather than decide unrecorded, and the caller must be refused.
    Refused(String),
}

/// The epoch a stream is currently in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    /// This plane's released version.
    pub version: String,
    /// The digest of the binary, where a deployment attests it.
    pub build: Option<String>,
    /// Engine versions, by language.
    pub engines: BTreeMap<String, String>,
    /// The rate at which permits are recorded.
    pub sampling: String,
}

/// How the journal behaves when the spool reaches a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenFull {
    /// Keep answering: the stream ends with a signed discontinuity.
    Open,
    /// Refuse to decide rather than decide unrecorded.
    Closed,
}

/// The group-commit rendezvous: who is waiting for the disk, and where the
/// disk stands.
///
/// # Why a group, and what it does not change
///
/// One decision, one fsync is the most expensive way to buy durability: the
/// flush costs the same whether it settles one record or forty, and a flush
/// per record serialises the whole plane behind a single disk operation. So
/// appends land in the segment immediately (cheap, under the spool lock) and
/// **one** flush settles every record appended before it — the group.
///
/// What does not change is the contract: **no caller is answered before its
/// record is durable.** A writer waits until the flushed high-water mark
/// covers its own sequence, and a flush that fails is an error handed to
/// every writer it stranded — before any of their answers leave. This is not
/// asynchronous logging; it is the same promise, paid for once per group
/// instead of once per record.
struct GroupCommit {
    state: Mutex<FlushState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct FlushState {
    /// Which stream incarnation these marks describe. Bumped by a stream end,
    /// **after** everything requested under the old one was settled — which is
    /// what lets a waiter treat "the generation moved" as "mine was settled
    /// before it did". Without this, a discontinuity would reset the sequence
    /// to one while `durable` still held the old stream's high-water mark, and
    /// every successor record would skip its wait: answered before durable,
    /// silently, forever.
    generation: u64,
    /// The highest sequence somebody has appended and wants settled.
    requested: u64,
    /// The highest sequence the disk has confirmed.
    durable: u64,
    /// The highest sequence a flush has *attempted*, successfully or not.
    attempted: u64,
    /// What the last failed flush said, for the writers it stranded.
    failed: Option<String>,
    /// Set when the journal is going away, so no writer waits forever.
    stopped: bool,
}

impl GroupCommit {
    fn new(durable: u64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FlushState {
                generation: 1,
                requested: durable,
                durable,
                attempted: durable,
                failed: None,
                stopped: false,
            }),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FlushState> {
        match self.state.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Records that `seq` wants settling and wakes the flusher. Answers the
    /// generation the request belongs to — what [`Self::wait_for`] needs to
    /// tell "not yet settled" apart from "settled, and the stream then ended".
    ///
    /// Called **under the spool lock**, deliberately: the sequence and the
    /// generation must describe the same incarnation, and the spool lock is
    /// what a stream end holds while it settles one and resets the other.
    fn request(&self, seq: u64) -> u64 {
        let mut state = self.lock();
        // A record may already be appended because the flush that first
        // covered it failed. A retry of that logical write must re-arm the
        // flusher; merely waiting would immediately replay the old error and
        // `next_target` would see nothing newer than `attempted` to try.
        if state.failed.is_some() && state.attempted >= seq {
            state.attempted = seq.saturating_sub(1);
            state.failed = None;
        }
        state.requested = state.requested.max(seq);
        self.changed.notify_all();

        state.generation
    }

    /// The current incarnation — read under the spool lock, for the same
    /// reason [`Self::request`] is called there.
    fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// Blocks until `seq` of `generation` is durable, or returns what stopped
    /// it from being.
    ///
    /// A generation that moved on is an `Ok`: a stream end settles everything
    /// requested under the old generation **before** bumping it, so "the
    /// generation moved" and "mine was durable" are the same fact — even when
    /// the discontinuity then discarded the record, which is the documented,
    /// counted loss of the `open` mode, not a silent one.
    fn wait_for(&self, generation: u64, seq: u64) -> Result<(), SpoolError> {
        let mut state = self.lock();
        loop {
            if state.generation != generation || state.durable >= seq {
                return Ok(());
            }
            if state.attempted >= seq
                && let Some(failed) = &state.failed
            {
                return Err(SpoolError::Malformed(format!(
                    "the group flush covering this record failed: {failed}"
                )));
            }
            if state.stopped {
                return Err(SpoolError::Malformed(
                    "the journal is shutting down before this record was settled".to_owned(),
                ));
            }
            state = match self.changed.wait(state) {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn durable(&self) -> u64 {
        self.lock().durable
    }

    /// Publishes the outcome of one flush that covered up to `covered` of
    /// `generation`. A stale generation is dropped: its stream has ended, and
    /// its marks no longer describe anything.
    fn settled(&self, generation: u64, covered: u64, outcome: Result<(), String>) {
        let mut state = self.lock();
        if state.generation != generation {
            return;
        }
        state.attempted = state.attempted.max(covered);
        match outcome {
            Ok(()) => {
                state.durable = state.durable.max(covered);
                state.failed = None;
            }
            Err(failed) => state.failed = Some(failed),
        }
        self.changed.notify_all();
    }

    /// Opens the next incarnation's sequence space. Only a stream end calls
    /// this, under the spool lock, after settling everything requested.
    fn reset(&self) {
        let mut state = self.lock();
        state.generation += 1;
        state.requested = 0;
        state.durable = 0;
        state.attempted = 0;
        state.failed = None;
        self.changed.notify_all();
    }

    /// Blocks the flusher until there is work, or the journal is going away.
    /// Answers the target to flush to, or `None` on shutdown.
    fn next_target(&self) -> Option<u64> {
        let mut state = self.lock();
        loop {
            if state.stopped {
                return None;
            }
            if state.requested > state.attempted {
                return Some(state.requested);
            }
            state = match self.changed.wait(state) {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn stop(&self) {
        self.lock().stopped = true;
        self.changed.notify_all();
    }
}

/// The writing half of the decision log.
pub struct Journal {
    /// This plane's name — half of every stream identity.
    pdp_id: String,
    epoch: Epoch,
    when_full: WhenFull,
    /// The permit sampling rate, parsed once.
    permit_rate: f64,
    commitment: Commitment,
    metrics: Metrics,
    /// One writer, so the sequence is one sequence.
    state: Arc<Mutex<Spool>>,
    /// The rendezvous between writers and the one flush that settles them.
    group: Arc<GroupCommit>,
    /// The flusher, joined on drop so a test tears down cleanly.
    flusher: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        self.group.stop();
        if let Some(flusher) = self.flusher.take() {
            let _ = flusher.join();
        }
    }
}

impl Journal {
    /// Opens the journal, writing the marker that opens its stream.
    ///
    /// A marker at the start of every stream is not bookkeeping: without it,
    /// the records that follow describe themselves with no declared sampling
    /// rate, build or commitment key, and a reader cannot say what the log
    /// claims to be complete about.
    pub fn open(
        directory: impl AsRef<std::path::Path>,
        pdp_id: impl Into<String>,
        epoch: Epoch,
        when_full: WhenFull,
        bounds: Bounds,
        commitment: Commitment,
        metrics: Metrics,
    ) -> Result<Self, SpoolError> {
        let opened = Spool::open_indexed(directory, bounds, Some(decision_identity))?;
        let durable = opened.seq();
        let spool = Arc::new(Mutex::new(opened));
        let group = GroupCommit::new(durable);
        let flusher = std::thread::Builder::new()
            .name("decision-journal-flush".to_owned())
            .spawn({
                let spool = Arc::clone(&spool);
                let group = Arc::clone(&group);
                move || flush_loop(&spool, &group)
            })
            .map_err(|error| SpoolError::Malformed(format!("starting the flusher: {error}")))?;
        let journal = Self {
            pdp_id: pdp_id.into(),
            permit_rate: epoch.sampling.parse().unwrap_or(1.0),
            epoch,
            when_full,
            commitment,
            metrics,
            state: spool,
            group,
            flusher: Some(flusher),
        };
        journal.mark(None)?;
        journal.publish();

        Ok(journal)
    }

    /// The live stream identity.
    pub fn stream(&self) -> Option<Stream> {
        self.state
            .lock()
            .ok()
            .map(|spool| Stream::new(self.pdp_id.clone(), spool.instance()))
    }

    /// Whether a decision that cannot be recorded must be refused.
    pub fn refuses_unrecorded(&self) -> bool {
        self.when_full == WhenFull::Closed
    }

    /// Records one decision.
    ///
    /// Never returns before the record is durable, and never touches the
    /// network. The caller is on the decision path, so everything here is a
    /// local append and a wait for the **group flush** that settles it — one
    /// `fsync` per group of concurrent decisions, not one per decision, and
    /// still deliberately blocking: the alternative is a decision the
    /// deployment believes was logged and was not.
    pub fn record(&self, decided: &Decided<'_>) -> Result<Written, SpoolError> {
        // Denies and errors are never sampled, whatever the rate says: a log
        // that drops refusals is not an audit trail.
        if decided.permit && !self.keep_permit(decided.id) {
            self.metrics.count(&measure::SAMPLED_OUT, &[]);
            return Ok(Written::SampledOut);
        }

        if let Some(reason) = self.under_pressure()? {
            match self.when_full {
                WhenFull::Closed => {
                    return Ok(Written::Refused(reason.to_owned()));
                }
                WhenFull::Open => {
                    let lost = self.end_stream(reason)?;
                    // The decision is still answered, and it is recorded in
                    // the successor: ending the stream is what makes room.
                    self.write_decision(decided)?;

                    return Ok(Written::Discontinued { lost });
                }
            }
        }

        let (seq, already) = self.write_decision(decided)?;
        if already {
            self.metrics
                .count(&measure::WRITTEN, &[("kind", "decision_retry")]);

            return Ok(Written::AlreadyRecorded { seq });
        }
        self.metrics
            .count(&measure::WRITTEN, &[("kind", "decision")]);

        Ok(Written::Recorded { seq })
    }

    /// Appends one decision and returns when it is durable — the group-commit
    /// path.
    ///
    /// Everything that fixes the record's place — reading the position,
    /// building the record, appending it, registering the wait — happens under
    /// **one** hold of the spool lock: read-position-then-append as two
    /// acquisitions would let two concurrent decisions build for the same
    /// sequence, and the loser's record would never be written. The wait is
    /// the only part outside the lock, and it is the point: many writers, one
    /// flush.
    /// Returns where the record sits, and whether this call is what put it
    /// there: a retry is answered from the journal, and the caller has to be
    /// able to say so rather than reporting a write it did not make.
    fn write_decision(&self, decided: &Decided<'_>) -> Result<(u64, bool), SpoolError> {
        let (generation, seq, already) = {
            let mut spool = self.state.lock().map_err(poisoned)?;
            let record = self.decision_record(&spool, decided)?;
            // Asked under the same lock that assigns the sequence. Reading the
            // index and then appending as two acquisitions would let two
            // recoveries of one decision each find nothing and each append.
            if let Some(identity) = decision_identity(&record) {
                match spool.already_written(&identity) {
                    Some(Already::Same(held)) => return Ok((held.seq, true)),
                    Some(Already::Conflict(held)) => {
                        return Err(identity_conflict(&identity.id, held.seq));
                    }
                    None => {}
                }

                // An append waiting for the group fsync is not durable yet, so
                // it cannot answer the retry immediately. It does reserve the
                // identity: join the first writer's wait instead of appending a
                // second indistinguishable audit record. The generation is read
                // under the spool lock, the same lock that stream rollover uses.
                match spool.pending_write(&identity) {
                    Some(Already::Same(held)) => (self.group.request(held.seq), held.seq, true),
                    Some(Already::Conflict(held)) => {
                        return Err(identity_conflict(&identity.id, held.seq));
                    }
                    None => {
                        let seq = spool.append_unsynced(&record)?.seq;
                        (self.group.request(seq), seq, false)
                    }
                }
            } else {
                let seq = spool.append_unsynced(&record)?.seq;
                (self.group.request(seq), seq, false)
            }
        };
        self.group.wait_for(generation, seq)?;
        self.publish();

        Ok((seq, already))
    }

    /// Declares a new epoch, when the build or the sampling rate changes.
    ///
    /// A rate declared only in a batch envelope would leave the records that
    /// straddle a reload describing themselves two ways.
    pub fn re_mark(&mut self, epoch: Epoch) -> Result<(), SpoolError> {
        if epoch == self.epoch {
            return Ok(());
        }
        self.permit_rate = epoch.sampling.parse().unwrap_or(1.0);
        self.epoch = epoch;
        self.mark(None)?;

        Ok(())
    }

    /// The head the next batch continues — `digest(acked)`, from disk.
    ///
    /// Read from the spool rather than remembered, and that is the whole point:
    /// a producer that restarts must continue the receiver's chain, and an
    /// in-memory value would have it claim to start a new one. While a closed
    /// stream is still shipping its terminal record, this is *that* stream's
    /// head — the live spool has already reset to the successor's genesis.
    pub fn previous_head(&self) -> String {
        let Ok(spool) = self.state.lock() else {
            return permguard_decisions::record::GENESIS.to_owned();
        };
        match spool.closing() {
            Some(closing) => closing.previous_head.clone(),
            None => spool.acked_digest().to_owned(),
        }
    }

    /// The digest of the record at `seq`, when the spool still holds it.
    ///
    /// Needed when a store acknowledges further than the batch just shipped —
    /// a spool restored from a backup, say. The head recorded must be the
    /// digest *at* the acknowledged point, and this is where that record still
    /// is.
    pub fn digest_at(&self, seq: u64) -> Result<Option<String>, SpoolError> {
        let spool = self.state.lock().map_err(poisoned)?;
        let Some(record) = spool
            .read_from(seq.saturating_sub(1), 1)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        if record.get("seq").and_then(Value::as_u64) != Some(seq) {
            return Ok(None);
        }

        Ok(Some(
            permguard_decisions::record::digest_of(&record)
                .map_err(|error| SpoolError::Malformed(error.to_string()))?,
        ))
    }

    /// The records the shipper should send next, and where it stands.
    pub fn pending(&self, limit: usize) -> Result<Vec<Value>, SpoolError> {
        let spool = self.state.lock().map_err(poisoned)?;
        // The terminal record of a stream that ended goes first: everything
        // else belongs to the successor, and a reader must see them in that
        // order or the closure looks like it never happened.
        if let Some(terminal) = spool.terminal()? {
            return Ok(vec![terminal]);
        }
        let acked = spool.acked();

        let durable = self.group.durable();
        Ok(spool
            .read_from(acked, limit)?
            .into_iter()
            .filter(|record| {
                record
                    .get("seq")
                    .and_then(Value::as_u64)
                    .is_some_and(|seq| seq <= durable)
            })
            .collect())
    }

    /// Records what the control plane confirmed durable.
    pub fn acknowledge(&self, acked: u64, digest: &str) -> Result<(), SpoolError> {
        {
            let mut spool = self.state.lock().map_err(poisoned)?;
            if spool.closing().is_some() {
                // The closed stream is finished with; the successor's own
                // acknowledgements start from its own genesis.
                spool.close_finished()?;
            } else {
                spool.acknowledge(acked, digest)?;
            }
        }
        self.publish();

        Ok(())
    }

    fn under_pressure(&self) -> Result<Option<&'static str>, SpoolError> {
        self.state.lock().map_err(poisoned)?.pressure()
    }

    /// Ends the live stream and opens its successor's.
    ///
    /// One hold of the spool lock covers the whole transition, and the order
    /// inside it is the invariant:
    ///
    /// 1. **settle the old stream** — flush, and tell the group, so every
    ///    writer already waiting is released with the truth (durable, then
    ///    counted among the lost: the documented `open` loss, never a hang);
    /// 2. discontinue, which resets the sequence space;
    /// 3. **reset the group** to the successor's generation — without this,
    ///    the old high-water mark would cover every new sequence and the
    ///    successor's records would be answered before they were durable;
    /// 4. write the successor's opening marker, before the lock is released,
    ///    so no decision can slot in front of it.
    fn end_stream(&self, reason: &str) -> Result<u64, SpoolError> {
        let (ended, lost) = {
            let mut spool = self.state.lock().map_err(poisoned)?;

            // 1. Settle what the old stream still owes its writers.
            let owed = spool.seq();
            let outcome = spool.sync_open();
            self.group.settled(
                self.group.generation(),
                owed,
                outcome.as_ref().map(|_| ()).map_err(ToString::to_string),
            );
            outcome?;

            let lost = spool.seq().saturating_sub(spool.acked());
            // 2. The stream ends; the spool's sequence space starts over.
            let ended = spool.discontinue(reason, |terminal| self.terminal_record(&terminal))?;
            // 3. So the group's marks must too.
            self.group.reset();

            // 4. The successor opens with its marker, atomically with the
            //    switch: a decision cannot claim sequence one first.
            let marker = self.marker_record(
                &spool,
                Some(Predecessor {
                    instance: ended.closed.clone(),
                    last_seq: Some(ended.terminal_seq),
                    reason: reason.to_owned(),
                }),
            )?;
            let seq = spool.append(&marker)?.seq;
            self.group.settled(self.group.generation(), seq, Ok(()));

            (ended, lost)
        };

        self.metrics.count(&measure::DROPPED, &[]);
        self.metrics
            .count(&measure::DISCONTINUITIES, &[("reason", reason)]);
        self.metrics.count(&measure::WRITTEN, &[("kind", "marker")]);
        self.publish();
        warn!(
            event.name = "decisions.discontinued",
            component = COMPONENT,
            reason,
            closed = ended.closed.as_str(),
            successor = ended.successor.as_str(),
            terminal_seq = ended.terminal_seq,
            lost,
            "the decision stream ended and a new incarnation began: records were lost"
        );

        Ok(lost)
    }

    /// Writes the marker that governs the records after it.
    fn mark(&self, predecessor: Option<Predecessor>) -> Result<(), SpoolError> {
        {
            let mut spool = self.state.lock().map_err(poisoned)?;
            let record = self.marker_record(&spool, predecessor)?;
            let seq = spool.append(&record)?.seq;
            self.group.settled(self.group.generation(), seq, Ok(()));
        }
        self.publish();
        self.metrics.count(&measure::WRITTEN, &[("kind", "marker")]);
        info!(
            event.name = "decisions.marked",
            component = COMPONENT,
            sampling = self.epoch.sampling.as_str(),
            "a decision-log epoch begins"
        );

        Ok(())
    }

    /// Builds the marker at the position `spool` — already held — dictates.
    fn marker_record(
        &self,
        spool: &Spool,
        predecessor: Option<Predecessor>,
    ) -> Result<Value, SpoolError> {
        let (seq, prev) = spool.next_position();

        Record {
            v: VERSION,
            stream: Stream::new(self.pdp_id.clone(), spool.instance().to_owned()),
            seq,
            prev,
            at: now(),
            body: Body::Marker(Box::new(MarkerBody {
                predecessor,
                pdp: self.build(),
                sampling: Sampling {
                    permits: self.epoch.sampling.clone(),
                },
                commitments: Commitments {
                    alg: commitment::COMMITMENT_ALGORITHM.to_owned(),
                    key_version: self.commitment.version().to_owned(),
                },
            })),
        }
        .to_value()
        .map_err(|error| SpoolError::Malformed(error.to_string()))
    }

    /// Builds the record at the position `spool` — already held by the caller
    /// — dictates. Taking the guard is what makes position and append one
    /// atomic step; a version that locked for the position and again for the
    /// append let two concurrent decisions claim one sequence.
    fn decision_record(&self, spool: &Spool, decided: &Decided<'_>) -> Result<Value, SpoolError> {
        let (seq, prev) = spool.next_position();
        let instance = spool.instance().to_owned();

        Record {
            v: VERSION,
            stream: Stream::new(self.pdp_id.clone(), instance),
            seq,
            prev,
            at: decided.at.clone(),
            body: Body::Decision(Box::new(DecisionBody {
                id: decided.id.to_owned(),
                pdp: Build {
                    version: self.epoch.version.clone(),
                    build: None,
                    engines: None,
                },
                store: StoreRef {
                    zone: decided.zone.to_owned(),
                    ledger: decided.ledger.to_owned(),
                    commit: decided.commit.to_owned(),
                    counter: decided.counter,
                    profile: decided.profile.to_owned(),
                },
                subject: party(
                    &decided.subject,
                    Self::normalized_map(decided.subject_properties.clone()),
                ),
                resource: party(
                    &decided.resource,
                    Self::normalized_map(decided.resource_properties.clone()),
                ),
                action: ActionRef {
                    name: decided.action.clone(),
                },
                principal: decided
                    .principal
                    .as_ref()
                    .map(|principal| party(principal, None)),
                inputs: Inputs {
                    context: self.commit_to(decided.context.as_ref()),
                    partition_inputs: self.commit_to(decided.partition_inputs.as_ref()),
                    external: Vec::new(),
                },
                decision: decided.permit,
                policies: decided.policies.clone(),
                reason: Reason {
                    code: decided.reason.clone(),
                },
                trace: decided.trace.as_ref().map(|(trace_id, span_id)| Trace {
                    trace_id: trace_id.clone(),
                    span_id: span_id.clone(),
                }),
                request_id: decided.request_id.clone(),
                context: Self::normalized_map(decided.included_context.clone()),
                latency_us: decided.latency_us,
                event: decided.event.clone(),
            })),
        }
        .to_value()
        .map_err(|error| SpoolError::Malformed(error.to_string()))
    }

    fn terminal_record(&self, terminal: &Terminal) -> Result<Value, SpoolError> {
        Record {
            v: VERSION,
            stream: Stream::new(self.pdp_id.clone(), terminal.instance.clone()),
            seq: terminal.seq,
            prev: terminal.prev.clone(),
            at: now(),
            body: Body::Discontinuity(Box::new(DiscontinuityBody {
                reason: terminal.reason.clone(),
                lost: Lost {
                    from_seq: terminal.lost_from,
                    count_estimate: terminal.lost_count,
                },
                successor: terminal.successor.clone(),
            })),
        }
        .to_value()
        .map_err(|error| SpoolError::Malformed(error.to_string()))
    }

    fn build(&self) -> Build {
        Build {
            version: self.epoch.version.clone(),
            build: self.epoch.build.clone(),
            engines: if self.epoch.engines.is_empty() {
                None
            } else {
                Some(self.epoch.engines.clone())
            },
        }
    }

    /// Commits to a caller-supplied value, whatever it carries.
    ///
    /// Normalised first, so the commitment is **total**: a caller who put a
    /// float in the context must not be able to make the record silently
    /// non-committal about what the decision saw — that would hand whoever is
    /// being audited a way to degrade their own audit trail.
    fn commit_to(&self, value: Option<&Value>) -> Option<String> {
        value.and_then(|value| {
            self.commitment
                .commit(&permguard_decisions::jcs::normalized(value))
                .ok()
        })
    }

    /// A caller-supplied map, made canonicalisable.
    ///
    /// The `include`d cleartext fields travel inside the record, and the
    /// record is digested canonically: a float among them would otherwise fail
    /// the append — a refusal (`closed`) or an unrecorded decision (`open`)
    /// that the caller chose the trigger for.
    fn normalized_map(
        map: Option<serde_json::Map<String, Value>>,
    ) -> Option<serde_json::Map<String, Value>> {
        map.map(|map| {
            map.into_iter()
                .map(|(key, value)| {
                    let value = permguard_decisions::jcs::normalized(&value);
                    (key, value)
                })
                .collect()
        })
    }

    /// Whether this permit is one of the recorded ones.
    ///
    /// Derived from the decision's own handle rather than from a random draw,
    /// so the same decision is sampled the same way wherever the question is
    /// asked again — and so a plane cannot be made to record more by retrying.
    fn keep_permit(&self, id: &str) -> bool {
        if self.permit_rate >= 1.0 {
            return true;
        }
        if self.permit_rate <= 0.0 {
            return false;
        }
        let bucket = id.bytes().fold(0u64, |hash, byte| {
            hash.wrapping_mul(31).wrapping_add(u64::from(byte))
        });

        (bucket % 10_000) < (self.permit_rate * 10_000.0) as u64
    }

    fn publish(&self) {
        let Ok(spool) = self.state.lock() else {
            return;
        };
        self.metrics
            .set(&measure::SEQUENCE, &[], spool.seq() as f64);
        self.metrics.set(&measure::ACKED, &[], spool.acked() as f64);
        self.metrics.set(
            &measure::UNSHIPPED,
            &[],
            spool.seq().saturating_sub(spool.acked()) as f64,
        );
        if let Ok(bytes) = spool.bytes() {
            self.metrics.set(&measure::SPOOL_BYTES, &[], bytes as f64);
        }
    }
}

/// The flusher: one thread, one flush per group, however many writers.
///
/// It takes the target under the group lock, snapshots the open segment under
/// the spool lock, flushes without holding that lock, then publishes the
/// durable high-water mark named by the token. Writers that arrive during the
/// flush keep appending and are picked up by a later group; the filesystem may
/// have settled their bytes already, but the journal only claims what it can
/// prove from one locked snapshot.
fn flush_loop(spool: &Mutex<Spool>, group: &GroupCommit) {
    while let Some(target) = group.next_target() {
        // Generation, coverage and the segment handle are read under the spool
        // lock, so they describe the same incarnation — but the flush itself
        // happens **after** the lock is released. A flush inside the lock
        // would stop every append for its whole duration, and the group would
        // never grow past whatever slipped between two flushes: the entire
        // point of the group is that appends keep landing while the disk
        // settles the previous batch.
        let (generation, token) = {
            let spool = match spool.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            (group.generation(), spool.flush_token())
        };
        match token {
            Ok(Some((covered, handle))) => {
                let outcome = handle.sync_data().map_err(|error| error.to_string());
                if outcome.is_ok() {
                    // The disk took them, so the keys they carry may now answer
                    // a retry. Taken back under the lock, and only for what the
                    // flush actually covered.
                    let mut spool = match spool.lock() {
                        Ok(held) => held,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    spool.promote_through(covered);
                }
                group.settled(generation, covered, outcome);
            }
            // Nothing open: nothing unsettled either.
            Ok(None) => {}
            Err(error) => {
                // The coverage is unknowable without a token, so nothing is
                // claimed durable: the writers up to the current target hear
                // about it, and the next request makes the flusher try again.
                group.settled(generation, target, Err(error.to_string()));
            }
        }
    }
}

fn party(pair: &(String, String), properties: Option<serde_json::Map<String, Value>>) -> Party {
    Party {
        kind: pair.0.clone(),
        id: pair.1.clone(),
        properties: properties.filter(|properties| !properties.is_empty()),
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> SpoolError {
    SpoolError::Malformed(
        "the journal's writer panicked and its sequence cannot be trusted".to_owned(),
    )
}

fn now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();

    permguard_core::time::to_rfc3339(seconds)
}
