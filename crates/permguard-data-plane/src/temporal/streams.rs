// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event log this plane writes: one stream per tenant ledger on the Host's producer, and
//! what the plane remembers about each (WP-6.2a, owner decisions of 2026-10-18).
//!
//! # One stream per ledger, not one per process
//!
//! A cryptographic stream is owned by one producer and one tenant ledger, so a plane serving
//! three ledgers writes three streams. Not one shared stream: a shared stream would make a
//! tenant's history depend on another tenant's writes, so verifying one would require reading the
//! other, and shipping one would leak that the other exists.
//!
//! The producer identity is the Host's, never taken from a caller nor configured: a record names
//! the `host_id` and the run the Host's producer gives it, its sequence and the digest before it,
//! filled under the lock that hands sequences out (see [`super::host`]).
//!
//! # The legacy journal
//!
//! A ledger an earlier release journalled keeps that journal: the first part of the ledger's
//! history, shipped by the old shipper until it is empty and evicted as before, never appended
//! to. The Host runs' local ordinals follow its last sequence.
//!
//! # One flush for a batch, never one receipt before its flush
//!
//! An `fsync` costs about the same for one record as for a hundred, and the durable-before-observed
//! rule means every submission pays for one. So submissions that overlap in time are written
//! together and flushed once: the first to arrive leads, whoever arrives while it is writing joins
//! its batch, and none of them is answered until the single append covering all of them returns.
//! What is amortised is the cost; what is never relaxed is the rule.
//!
//! # Who an occurrence is
//!
//! `(resource, source, event_id)`: the authenticated principal that submitted it and the id it
//! chose. The same id from another source is another occurrence. An entry of the legacy journal,
//! which names no source, matches its id from any source, as it did before the upgrade.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use permguard_core::Metrics;
use permguard_events::journal::{Bounds, Journal, JournalError, KnownOccurrence};
use permguard_events::record::{PRODUCER_CLASS_DATA_PLANE, Producer, Record};
use permguard_host::composition::{StreamFloor, StreamProducer};

use super::host::HostLedger;

/// How long a measure of a stream's pressure is trusted before it is taken again.
const PRESSURE_FOR: Duration = Duration::from_secs(1);

/// What happened to an occurrence this ledger had already seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// This occurrence is new here.
    Fresh,
    /// The same occurrence: one logical occurrence, and the stored position.
    Idempotent { seq: u64 },
    /// The same key carrying different content. Never resolved by choosing one.
    Conflict { seq: u64, stored_digest: String },
}

/// One ledger's streams, and what this process remembers about them.
struct Held {
    /// The journal an earlier release wrote, read only.
    legacy: Option<Journal>,
    host: HostLedger,
    /// The stream's pressure as last measured, and when.
    pressure: Option<(Instant, Option<&'static str>)>,
    /// The `observed_at` of the last record appended, in epoch seconds: no later record is
    /// observed before it. Read from the stream's tail on the first append after opening.
    last_observed: Option<i64>,
}

/// The largest number of records one flush covers.
///
/// Not a throughput knob: a bound on how long one leader may hold a ledger, so a burst cannot turn
/// into a single writer that never lets go. Whatever does not fit is the next batch's, which forms
/// while this one flushes.
const MAX_BATCH: usize = 1_024;

/// One submission waiting to be written, and the ticket its writer will collect an answer by.
type Waiting = (u64, Record);

/// What one writer collects: what the append did, and the record it did it to.
///
/// The record comes back because the append fills part of it in — the sequence, the link to the
/// record before it, and the stream identity, none of which a caller may choose — and its writer
/// goes on to log and answer from exactly what was written rather than from what it proposed.
pub type Answered = (Written, Record);

/// One ledger's group-commit gate: who is forming a batch, and what has been written for whom.
///
/// Separate from the ledger's own lock on purpose. If forming a batch and writing it were under
/// one lock, nobody could join a batch while it was being written — which is the whole of what
/// group commit is.
#[derive(Default)]
struct Batch {
    /// Submissions that have arrived and not yet been written, in arrival order.
    waiting: Vec<Waiting>,
    /// Whether somebody is currently forming or flushing a batch.
    leading: bool,
    /// What each ticket's write produced, until its writer collects it.
    done: BTreeMap<u64, Result<Answered, Failed>>,
    /// The next ticket to hand out.
    next: u64,
}

/// A ledger's batch, and the signal that it moved.
#[derive(Default)]
struct Gate {
    batch: Mutex<Batch>,
    moved: Condvar,
}

impl Gate {
    /// The batch, poisoning and all: a writer that panicked mid-batch is answered for by
    /// [`Leadership`], so what is behind this lock is always consistent.
    fn batch(&self) -> MutexGuard<'_, Batch> {
        match self.batch.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Leadership of one batch, which is always given back.
///
/// The tickets a leader took are its responsibility: whoever holds them is the only one who can
/// answer them, and their writers are asleep until somebody does. So if the leader unwinds between
/// taking a batch and publishing it, this hands every ticket in it a failure rather than leaving
/// its writer waiting for an answer that is no longer coming.
struct Leadership {
    gate: Arc<Gate>,
    tickets: Vec<u64>,
}

impl Leadership {
    /// Publishes each ticket's answer and steps down, returning this leader's own.
    fn publish(
        mut self,
        results: Vec<(u64, Result<Answered, Failed>)>,
        mine: u64,
    ) -> Option<Result<Answered, Failed>> {
        let mut answer = None;
        let mut batch = self.gate.batch();
        for (ticket, result) in results {
            if ticket == mine {
                answer = Some(result);
            } else {
                batch.done.insert(ticket, result);
            }
        }
        batch.leading = false;
        // Everything published at once: a follower wakes to find its answer already there.
        self.gate.moved.notify_all();
        drop(batch);
        self.tickets.clear();

        answer
    }
}

impl Drop for Leadership {
    fn drop(&mut self) {
        if self.tickets.is_empty() {
            return;
        }
        let mut batch = self.gate.batch();
        for ticket in self.tickets.drain(..) {
            batch.done.entry(ticket).or_insert_with(|| {
                Err(Failed::Journal(JournalError::Io(
                    "the writer holding this batch failed before it was written".to_owned(),
                )))
            });
        }
        batch.leading = false;
        self.gate.moved.notify_all();
    }
}

/// One ledger's open streams, shared by everything that writes to or reads them.
type OpenLedger = Arc<Mutex<Held>>;

/// Every ledger this plane has open, by `(zone, ledger)`.
type OpenLedgers = Mutex<BTreeMap<(String, String), OpenLedger>>;

/// The gate one ledger's first opener holds while it opens.
type Opening = Arc<Mutex<()>>;

/// The Host's side of the event log: its producer of `data/events` and its id.
#[derive(Debug, Clone)]
pub struct HostSide {
    pub producer: StreamProducer,
    pub host_id: [u8; 16],
}

/// The floor this plane registers on `data/events`: per resource and run, the last sequence no
/// loaded window reads any more, as the plane last measured it; a run it has not measured is kept
/// whole. Read by the Host's garbage collection without touching a ledger's lock.
#[derive(Debug, Default)]
pub struct Floors(Mutex<BTreeMap<(String, [u8; 16]), u64>>);

impl StreamFloor for Floors {
    fn retention_safe(&self, resource: &str, run: &[u8; 16]) -> Option<u64> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(resource.to_owned(), *run))
            .copied()
    }
}

/// Every ledger this plane has open.
pub struct Streams {
    /// Where the legacy journals are.
    root: PathBuf,
    /// Whether they are read: not once the volume archived them (WP-6.2d), their old generation
    /// waiting in `root` for `migrate finalize`, never opened.
    legacy: bool,
    /// Where the plane keeps what it remembers of each ledger on the Host.
    planes: PathBuf,
    host: HostSide,
    floors: Arc<Floors>,
    bounds: Bounds,
    open: OpenLedgers,
    /// One group-commit gate per ledger, created with its streams.
    gates: Mutex<BTreeMap<(String, String), Arc<Gate>>>,
    /// One turn-taker per ledger, created with its streams.
    ///
    /// Created here rather than on first use, and this is not tidiness: its starting mark is "every
    /// record this ledger holds has been applied", which is only true at the moment the ledger is
    /// opened. A sequencer created later would take its mark from a ledger that had already moved,
    /// and the sequences in flight would never be ordered against each other.
    sequencers: crate::temporal::sequencer::Sequencers,
    /// One opener per ledger.
    ///
    /// A legacy journal takes an exclusive lock on its own directory when it is opened. Two
    /// threads that both find a ledger closed cannot both open it: the second would be refused by
    /// the lock the first is holding. So the first opens and the rest wait for it, per ledger,
    /// leaving other ledgers' first requests free to proceed in parallel.
    opening: Mutex<BTreeMap<(String, String), Opening>>,
    /// What the streams count about themselves — flushes, and how many records each covered.
    metrics: Metrics,
    /// How long a leader may keep a batch open once submissions are demonstrably overlapping.
    ///
    /// Zero means "never wait": batches still form — from whatever arrives while the previous
    /// flush is in flight — but no submission ever waits for one to fill.
    group_commit_max_delay: Duration,
}

/// How an occurrence was routed when it was answered.
///
/// Recorded beside the answer so a retry can be checked against it: the same identifier arriving
/// under a different profile or a different event type is a routing conflict, not a retry, and
/// answering it from the first would be answering a question nobody asked.
#[derive(Debug, Clone, Copy)]
pub struct Routed<'a> {
    /// The profile that routed it.
    pub profile: &'a str,
    /// The event type it was recorded as.
    pub kind: &'a str,
}

impl Streams {
    /// The ledgers whose legacy journals are under `root`, recorded on `host`'s producer with
    /// what the plane remembers under `planes`; the floor is registered on the producer, so a
    /// producer that keeps none refuses.
    pub fn new(
        root: PathBuf,
        planes: PathBuf,
        host: HostSide,
        bounds: Bounds,
    ) -> Result<Self, JournalError> {
        Self::with_group_commit(root, planes, host, bounds, Duration::ZERO)
    }

    /// The same, told how long a batch may keep forming.
    pub fn with_group_commit(
        root: PathBuf,
        planes: PathBuf,
        host: HostSide,
        bounds: Bounds,
        group_commit_max_delay: Duration,
    ) -> Result<Self, JournalError> {
        let floors = Arc::new(Floors::default());
        host.producer
            .retain_above(Arc::clone(&floors) as Arc<dyn StreamFloor>)
            .map_err(|error| {
                JournalError::Io(format!(
                    "the Host's event producer keeps no floor, so it would delete history a \
                     loaded window still reads: {error}"
                ))
            })?;
        Ok(Self {
            root,
            legacy: true,
            planes,
            host,
            floors,
            bounds,
            open: Mutex::new(BTreeMap::new()),
            gates: Mutex::new(BTreeMap::new()),
            sequencers: crate::temporal::sequencer::Sequencers::default(),
            opening: Mutex::new(BTreeMap::new()),
            metrics: Metrics::none(),
            group_commit_max_delay,
        })
    }

    /// The same ledgers with no legacy journal: the volume archived them (WP-6.2d), and none is
    /// opened, shipped or evicted.
    pub fn without_legacy(mut self) -> Self {
        self.legacy = false;

        self
    }

    /// The same ledgers, recording what they do to the deployment's metrics.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;

        self
    }

    /// Where this plane keeps its legacy event journals.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The producer identity this plane writes as: the Host's id, the run filled per record.
    pub fn producer(&self) -> Producer {
        Producer {
            class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
            id: self
                .host
                .host_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            instance: String::new(),
        }
    }

    /// The floor this plane registered on the Host's producer, as last measured.
    pub fn floors(&self) -> &Arc<Floors> {
        &self.floors
    }

    /// The bounds the streams here are held to.
    pub fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// The streams of one ledger, opening them on first use.
    fn held(&self, zone: &str, ledger: &str) -> Result<OpenLedger, JournalError> {
        let key = (zone.to_owned(), ledger.to_owned());
        if let Some(held) = self.already_open(&key)? {
            return Ok(held);
        }

        // Closed, as far as this thread has seen. One thread per ledger does the opening; the rest
        // wait here and find it open below. The registry's own lock is *not* held across the open:
        // a ledger slow to recover would otherwise stall every other ledger's requests, which only
        // need that lock for a moment.
        let opening = {
            let mut opening = match self.opening.lock() {
                Ok(opening) => opening,
                Err(poisoned) => poisoned.into_inner(),
            };

            Arc::clone(opening.entry(key.clone()).or_default())
        };
        let _first = match opening.lock() {
            Ok(first) => first,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(held) = self.already_open(&key)? {
            return Ok(held);
        }

        let legacy = self.legacy_journal(zone, ledger)?;
        let legacy_through = legacy
            .as_ref()
            .map_or(0, |journal| journal.next_position().0.saturating_sub(1));
        let host = HostLedger::open(
            self.host.producer.clone(),
            self.host.host_id,
            zone,
            ledger,
            super::host::directory(&self.planes, zone, ledger),
            legacy_through,
        )?;
        // The ledger owns the durable order, so new submissions start after its recovered tail.
        // Engine histories are rebuilt lazily by `Submitter::ensure_history` before an occurrence
        // is applied; opening a ledger must not claim that policy state has already been replayed.
        let _ = self.sequencers.of(zone, ledger, host.last());

        let mut open = self
            .open
            .lock()
            .map_err(|_| JournalError::Io("the ledger registry is poisoned".to_owned()))?;

        Ok(Arc::clone(open.entry(key).or_insert_with(|| {
            Arc::new(Mutex::new(Held {
                last_observed: None,
                legacy,
                host,
                pressure: None,
            }))
        })))
    }

    /// The legacy journal of one ledger, when an earlier release wrote one: never created here.
    fn legacy_journal(&self, zone: &str, ledger: &str) -> Result<Option<Journal>, JournalError> {
        if !self.legacy {
            return Ok(None);
        }
        let directory = self.root.join(zone).join(ledger);
        if !directory
            .join(permguard_events::journal::STATE_FILE)
            .exists()
        {
            return Ok(None);
        }
        let stream = permguard_events::journal::stream_of(&directory)?;
        Journal::open(&directory, stream, self.bounds).map(Some)
    }

    /// The streams of one ledger if this process already has them open.
    fn already_open(&self, key: &(String, String)) -> Result<Option<OpenLedger>, JournalError> {
        let open = self
            .open
            .lock()
            .map_err(|_| JournalError::Io("the ledger registry is poisoned".to_owned()))?;

        Ok(open.get(key).map(Arc::clone))
    }

    /// Appends one record durably, unless its occurrence was already seen here.
    ///
    /// The whole write is under the ledger's own lock, so two concurrent submissions of one
    /// occurrence cannot both find it fresh: the second sees the first's, and answers
    /// idempotently.
    ///
    /// # One flush, several records
    ///
    /// Submissions that overlap in time are written together and flushed once. The first to arrive
    /// leads; whoever arrives while it is leading joins its batch and sleeps until the leader has
    /// an answer for them. Nobody is answered before the flush that covers their record returns —
    /// what a batch amortises is the cost of the flush, never the rule that a receipt follows it.
    pub fn append(&self, zone: &str, ledger: &str, record: Record) -> Result<Answered, Failed> {
        let held = self.held(zone, ledger).map_err(Failed::Journal)?;
        let gate = self.gate(zone, ledger).map_err(Failed::Journal)?;

        let ticket = {
            let mut batch = gate.batch();
            let ticket = batch.next;
            batch.next = batch.next.saturating_add(1);
            batch.waiting.push((ticket, record));
            // A leader that is holding a batch open is told somebody joined, so a batch that has
            // reached its bound is written now rather than sitting out the rest of its delay.
            gate.moved.notify_all();

            if batch.leading {
                // Somebody is already writing. Wait for them to answer this ticket — or, if they
                // stepped down without having taken it, take the lead in turn.
                loop {
                    if let Some(answer) = batch.done.remove(&ticket) {
                        return answer;
                    }
                    if !batch.leading {
                        break;
                    }
                    batch = match gate.moved.wait(batch) {
                        Ok(held) => held,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                }
            }
            batch.leading = true;

            ticket
        };

        self.lead(&held, &gate, ticket)
    }

    /// Forms one batch, writes it, flushes it once, and answers everybody in it.
    fn lead(&self, held: &OpenLedger, gate: &Arc<Gate>, ticket: u64) -> Result<Answered, Failed> {
        let taken = self.form(gate);
        let leadership = Leadership {
            gate: Arc::clone(gate),
            tickets: taken.iter().map(|(ticket, _)| *ticket).collect(),
        };
        let results = self.write(held, taken);

        match leadership.publish(results, ticket) {
            Some(answer) => answer,
            // Unreachable: this writer queued its own ticket before taking the lead, and a leader
            // takes the whole queue. Answered rather than asserted, because a caller waiting for a
            // receipt that never comes is worse than a caller told the write did not happen.
            None => Err(Failed::Journal(JournalError::Io(
                "this submission was lost from its own batch".to_owned(),
            ))),
        }
    }

    /// Takes the queued submissions, keeping the batch open only while it is demonstrably worth it.
    ///
    /// A leader that finds itself alone writes immediately: waiting for a second submission that
    /// may never arrive would be latency spent on nothing. A leader that finds company waits up to
    /// the configured delay for more, because under concurrent load that delay buys one flush
    /// where there would have been one per record.
    fn form(&self, gate: &Arc<Gate>) -> Vec<Waiting> {
        let mut batch = gate.batch();
        if !self.group_commit_max_delay.is_zero() && batch.waiting.len() > 1 {
            let deadline = Instant::now() + self.group_commit_max_delay;
            while batch.waiting.len() < MAX_BATCH {
                let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                if left.is_zero() {
                    break;
                }
                let (held, timed_out) = match gate.moved.wait_timeout(batch, left) {
                    Ok(waited) => waited,
                    Err(poisoned) => poisoned.into_inner(),
                };
                batch = held;
                if timed_out.timed_out() {
                    break;
                }
            }
        }

        let keep = batch.waiting.len().min(MAX_BATCH);
        // Whatever does not fit stays queued and is the next batch's, which forms while this one
        // is being flushed.
        batch.waiting.drain(..keep).collect()
    }

    /// Writes a whole batch under the ledger's lock, in one append to the Host's producer.
    fn write(
        &self,
        held: &OpenLedger,
        taken: Vec<Waiting>,
    ) -> Vec<(u64, Result<Answered, Failed>)> {
        let covered = taken.len();
        let mut results = Vec::with_capacity(taken.len());
        let mut held = match held.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };

        // A stream past its bounds takes nothing: temporal history is never dropped to make room,
        // so the submission is refused rather than recorded somewhere it cannot be kept.
        if let Some(code) = self.pressure_of(&mut held) {
            tracing::warn!(
                event.name = "temporal.stream_pressure",
                component = "temporal",
                code,
                "the event stream holds more than its bounds allow unacknowledged: submissions \
                 are refused until it is shipped"
            );
            return taken
                .into_iter()
                .map(|(ticket, _)| (ticket, Err(Failed::Journal(JournalError::Full))))
                .collect();
        }

        // Records an earlier append made durable without their entries are caught up first:
        // checked against entries that lag, a retry of them would be appended again.
        if let Err(error) = held.host.repaired() {
            let reason = error.to_string();
            return taken
                .into_iter()
                .map(|(ticket, _)| {
                    (
                        ticket,
                        Err(Failed::Journal(JournalError::Io(format!(
                            "the ledger's entries cannot be caught up with its stream: {reason}"
                        )))),
                    )
                })
                .collect();
        }

        let mut fresh: Vec<(u64, Record)> = Vec::new();
        // The same occurrence twice in this batch: the second is the first's retry, answered with
        // the position the first is given; `(ticket, record, index of the first in fresh)`.
        let mut retries: Vec<(u64, Record, usize)> = Vec::new();
        for (ticket, record) in taken {
            if let Some(first) = fresh.iter().position(|(_, first)| {
                first.event_id == record.event_id && first.source == record.source
            }) {
                if fresh[first].1.occurrence_digest == record.occurrence_digest {
                    retries.push((ticket, record, first));
                } else {
                    let stored_digest = fresh[first].1.occurrence_digest.clone();
                    results.push((
                        ticket,
                        Err(Failed::Conflict {
                            seq: 0,
                            stored_digest,
                        }),
                    ));
                }
                continue;
            }
            let already = match seen(
                &held,
                record.source.as_deref(),
                &record.event_id,
                &record.occurrence_digest,
            ) {
                Ok(already) => already,
                Err(error) => {
                    // The volume could not be asked whether this is a retry. Refused rather than
                    // assumed fresh: assuming fresh is how one occurrence gets counted twice.
                    results.push((ticket, Err(Failed::Journal(error))));
                    continue;
                }
            };
            match already {
                Seen::Fresh => fresh.push((ticket, record)),
                Seen::Idempotent { seq } => {
                    results.push((ticket, Ok((Written::Idempotent { seq }, record))));
                }
                Seen::Conflict { seq, stored_digest } => {
                    results.push((ticket, Err(Failed::Conflict { seq, stored_digest })));
                }
            }
        }
        if fresh.is_empty() {
            return results;
        }

        let (tickets, mut records): (Vec<u64>, Vec<Record>) = fresh.into_iter().unzip();
        // Observation follows the sequence. Each submission stamped its `observed_at` when it
        // arrived, before it had a sequence, so two of them racing across a second boundary could
        // be sequenced in the opposite order of their observation, and the later one would sort
        // before the earlier one already applied: refused out of order for nothing it did. Here,
        // under the ledger's lock and in sequence order, no record is observed before the one
        // ahead of it by the width of that race; an instant is only ever moved forward, to the
        // instant of that record, and never across a clock that moved further than a race could.
        let floor = observed_floor(&held, &mut records);
        let max_record_bytes = u32::try_from(self.bounds.max_record_bytes)
            .unwrap_or(u32::MAX)
            .min(permguard_events::stream::descriptor().max_record_bytes);
        match held.host.append(records, max_record_bytes) {
            Ok(placed) => {
                held.last_observed = floor;
                self.metrics.count(&super::measure::FLUSHES, &[]);
                self.metrics
                    .observe(&super::measure::BATCH_RECORDS, &[], covered as f64);
                for (ticket, record, first) in retries {
                    let seq = placed.get(first).map_or(0, |(placed, _)| placed.ordinal);
                    results.push((ticket, Ok((Written::Idempotent { seq }, record))));
                }
                for (ticket, (placed, record)) in tickets.into_iter().zip(placed) {
                    results.push((
                        ticket,
                        Ok((
                            Written::Appended {
                                seq: placed.ordinal,
                                digest: placed.digest,
                                instance: placed.run,
                            },
                            record,
                        )),
                    ));
                }
            }
            Err(error) => {
                let reason = error.to_string();
                for ticket in tickets
                    .into_iter()
                    .chain(retries.into_iter().map(|(ticket, ..)| ticket))
                {
                    results.push((
                        ticket,
                        Err(Failed::Journal(JournalError::Io(format!(
                            "the Host's event stream refused the append: {reason}"
                        )))),
                    ));
                }
            }
        }

        results
    }

    /// The pressure of `held`'s stream, measured again once the last measure is old.
    fn pressure_of(&self, held: &mut Held) -> Option<&'static str> {
        if let Some((at, pressure)) = held.pressure
            && at.elapsed() < PRESSURE_FOR
        {
            return pressure;
        }
        let measured = match self.host.producer.pressure(
            held.host.resource(),
            self.bounds.max_bytes,
            u64::MAX,
        ) {
            Ok(pressure) => pressure,
            Err(error) => {
                tracing::warn!(
                    event.name = "temporal.pressure_unknown",
                    component = "temporal",
                    error = error.as_str(),
                    "the event stream's pressure cannot be measured: its submissions are refused \
                     until it can"
                );
                Some(permguard_core::codes::stream::STORE_UNAVAILABLE)
            }
        };
        held.pressure = Some((Instant::now(), measured));
        measured
    }

    /// One ledger's group-commit gate, created on first use.
    fn gate(&self, zone: &str, ledger: &str) -> Result<Arc<Gate>, JournalError> {
        let key = (zone.to_owned(), ledger.to_owned());
        let mut gates = match self.gates.lock() {
            Ok(gates) => gates,
            Err(poisoned) => poisoned.into_inner(),
        };

        Ok(Arc::clone(gates.entry(key).or_default()))
    }

    /// This ledger's turn-taker, so its histories observe the ledger's order.
    ///
    /// Opening the ledger is part of the ask: the sequencer's starting mark comes from it, and a
    /// caller that had not opened it yet would be handed one starting from nothing.
    pub fn sequencer(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<Arc<crate::temporal::sequencer::Sequencer>, JournalError> {
        let held = self.held(zone, ledger)?;
        let applied_through = lock(&held)?.host.last();

        Ok(self.sequencers.of(zone, ledger, applied_through))
    }

    /// The run this ledger's stream last wrote in, or the legacy journal's instance before it.
    pub fn instance(&self, zone: &str, ledger: &str) -> Result<String, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = lock(&held)?;
        Ok(held.host.current_run().unwrap_or_else(|| {
            held.legacy
                .as_ref()
                .map(|journal| journal.stream().producer.instance.clone())
                .unwrap_or_default()
        }))
    }

    /// How many bytes one ledger's legacy journal holds.
    pub fn bytes(&self, zone: &str, ledger: &str) -> Result<u64, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = lock(&held)?;
        held.legacy.as_ref().map_or(Ok(0), Journal::bytes)
    }

    /// The records after local position `after`, the legacy journal's first: the ledger's
    /// history in its local order. A record's own `seq` is its place on its stream — the legacy
    /// journal's, which is also its local position, or its Host run's, which is not past the
    /// first run: what orders them here is the local position.
    pub fn read_from(
        &self,
        zone: &str,
        ledger: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = lock(&held)?;
        let mut records = match &held.legacy {
            Some(journal) if after < held.host.legacy_through() => {
                journal.read_from(after, limit)?
            }
            _ => Vec::new(),
        };
        if records.len() < limit {
            records.extend(
                held.host
                    .read_from(after, limit - records.len())?
                    .into_iter()
                    .map(|(_, record)| record),
            );
        }
        Ok(records)
    }

    /// The legacy journal's records after `after`, for its shipper and its eviction.
    pub fn legacy_read_from(
        &self,
        zone: &str,
        ledger: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, JournalError> {
        self.with_legacy(zone, ledger, |journal| journal.read_from(after, limit))
    }

    /// The record at one exact local position, for completing an interrupted idempotent
    /// submission.
    pub fn record_at(
        &self,
        zone: &str,
        ledger: &str,
        sequence: u64,
    ) -> Result<serde_json::Value, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = lock(&held)?;
        let found = if sequence <= held.host.legacy_through() {
            match &held.legacy {
                Some(journal) => journal
                    .read_from(sequence.saturating_sub(1), 1)?
                    .into_iter()
                    .next()
                    .filter(|record| {
                        record.get("seq").and_then(serde_json::Value::as_u64) == Some(sequence)
                    }),
                None => None,
            }
        } else {
            held.host.record_at(sequence)?
        };
        found.ok_or_else(|| {
            JournalError::Corrupt(format!(
                "the occurrence entry names position {sequence}, but the ledger does not hold it"
            ))
        })
    }

    /// The records one temporal question needs, by their local positions.
    ///
    /// A range scan over the indexes rather than a read of the ledger: one history partition, one
    /// event type, one time range. What makes deciding against a history cost what the history's
    /// relevant part costs, rather than what the tenant's whole traffic costs.
    pub fn scan(
        &self,
        zone: &str,
        ledger: &str,
        query: &permguard_events::index::Query,
    ) -> Result<Vec<(u64, serde_json::Value)>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = lock(&held)?;
        let mut found = match &held.legacy {
            Some(journal) => journal
                .scan(query)?
                .into_iter()
                .filter_map(|record| {
                    let seq = record.get("seq").and_then(serde_json::Value::as_u64)?;
                    Some((seq, record))
                })
                .collect(),
            None => Vec::new(),
        };
        found.extend(held.host.scan(query)?);
        Ok(found)
    }

    /// Runs `read` on one ledger's legacy journal; a ledger without one answers as an empty one
    /// would be refused.
    fn with_legacy<T>(
        &self,
        zone: &str,
        ledger: &str,
        read: impl FnOnce(&mut Journal) -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        let held = self.held(zone, ledger)?;
        let mut held = lock(&held)?;
        match held.legacy.as_mut() {
            Some(journal) => read(journal),
            None => Err(JournalError::Io(format!(
                "`{zone}/{ledger}` holds no legacy journal"
            ))),
        }
    }

    /// Marks the legacy journal's records through `seq` as covered by a signed batch.
    pub fn mark_signed(&self, zone: &str, ledger: &str, through: u64) -> Result<(), JournalError> {
        self.with_legacy(zone, ledger, |journal| journal.mark_signed(through))
    }

    /// Persists the signed checkpoint covering a legacy batch, and marks that range signed.
    pub fn checkpoint(
        &self,
        zone: &str,
        ledger: &str,
        first_seq: u64,
        last_seq: u64,
        jws: &str,
    ) -> Result<(), JournalError> {
        self.with_legacy(zone, ledger, |journal| {
            journal.checkpoint(first_seq, last_seq, jws)
        })
    }

    /// Records which key signed the legacy checkpoint starting at `first_seq`.
    pub fn note_signer(
        &self,
        zone: &str,
        ledger: &str,
        first_seq: u64,
        kid: &str,
        jwk: &serde_json::Value,
    ) -> Result<(), JournalError> {
        self.with_legacy(zone, ledger, |journal| {
            journal.note_signer(first_seq, kid, jwk)
        })
    }

    /// Which key signed which stretch of one ledger's legacy journal.
    pub fn signers(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<permguard_stream::Signers, JournalError> {
        self.with_legacy(zone, ledger, |journal| Ok(journal.signers().clone()))
    }

    /// Keeps the answer given for one occurrence, so a retry is answered rather than refused.
    ///
    /// The entry already exists — the write path made it durable before this record was
    /// acknowledged, because that is what makes the retry *recognisable*. This fills in the answer
    /// that was not known yet at that point. A legacy journal's entry is copied beside the Host
    /// stream's with its answer: the legacy journal is never written.
    pub fn record_outcome(
        &self,
        zone: &str,
        ledger: &str,
        source: &str,
        event_id: &str,
        routed: Routed<'_>,
        response: &serde_json::Value,
    ) -> Result<(), JournalError> {
        let held = self.held(zone, ledger)?;
        let mut held = lock(&held)?;
        let Some(mut known) = known_in(&held, source, event_id)? else {
            return Err(JournalError::Io(format!(
                "`{event_id}` has no entry to keep an answer in"
            )));
        };
        known.response = response.clone();
        // Written with the answer rather than with the record: these are what let a *completed*
        // retry be recognised without loading the profile it was decided under, and an incomplete
        // entry has no answer to recognise.
        known.profile = Some(routed.profile.to_owned());
        known.kind = Some(routed.kind.to_owned());
        // A response may leave only after the idempotency answer is durable. Otherwise a crash
        // can occur after the caller saw success but before the outcome reaches disk, and a retry
        // is then recognised as the same event without being able to reproduce its answer.
        held.host.keep_occurrence(&known)
    }

    /// Settles which directory a ledger's legacy journal lives in when its identifiers changed
    /// shape.
    ///
    /// # Why this exists
    ///
    /// A journal was kept under the pair the caller named, and a caller may name a ledger by its
    /// identifier or by its display name — both resolve to one mirror. Keying storage by whichever
    /// arrived first therefore let one ledger own *two* journals: two sequences, two histories, two
    /// idempotency indexes, each invisible to the other. Storage is keyed canonically now, and this
    /// is what stands between an existing name-keyed journal and being silently abandoned.
    ///
    /// Idempotent by construction: once the canonical directory exists there is nothing to do, so
    /// every later call is a stat.
    pub fn adopt(
        &self,
        canonical: (&str, &str),
        display: (&str, &str),
    ) -> Result<(), JournalError> {
        // An archived legacy (WP-6.2d) is an old generation nothing moves inside, and a pair of
        // journals there is no longer read, so no longer ambiguous.
        if !self.legacy || canonical == display {
            return Ok(());
        }
        let target = self.root.join(canonical.0).join(canonical.1);
        let legacy = self.root.join(display.0).join(display.1);
        // The conflict is tested first, and that ordering is the whole check: asking "is the
        // canonical one already there?" first answers yes in exactly the case that also has a
        // legacy one, and returns before noticing. Two journals for one ledger would then coexist
        // in silence, which is the outcome this exists to refuse.
        if target.exists() && legacy.exists() {
            return Err(JournalError::Io(format!(
                "`{}` holds a journal under both its identifiers and its names ({} and {}). Two \
                 journals for one ledger are two histories, two sequences and two idempotency \
                 indexes: refusing rather than choosing one, because the wrong choice drops events \
                 without saying so. Merge or remove one by hand",
                canonical.1,
                target.display(),
                legacy.display()
            )));
        }
        if target.exists() || !legacy.exists() {
            // Already canonical, or nothing recorded under the old shape.
            return Ok(());
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                JournalError::Io(format!("preparing {}: {error}", parent.display()))
            })?;
        }
        // Moved through the storage library (WP-1.11): both directories flushed, so the adoption
        // survives a crash whole.
        let adopting = |error: permguard_host::storage::StorageError| {
            JournalError::Io(format!(
                "adopting {} as {}: {error}",
                legacy.display(),
                target.display()
            ))
        };
        let (from_dir, from) = legacy
            .parent()
            .zip(legacy.file_name().and_then(|name| name.to_str()))
            .ok_or_else(|| JournalError::Io(format!("{} has no name", legacy.display())))?;
        let (into_dir, to) = target
            .parent()
            .zip(target.file_name().and_then(|name| name.to_str()))
            .ok_or_else(|| JournalError::Io(format!("{} has no name", target.display())))?;
        let source = permguard_host::storage::Dir::open(from_dir).map_err(adopting)?;
        let into = permguard_host::storage::Dir::open(into_dir).map_err(adopting)?;
        source.move_to(from, &into, to).map_err(adopting)?;
        tracing::info!(
            event.name = "temporal.journal_adopted",
            component = "temporal",
            from = %legacy.display(),
            to = %target.display(),
            "a ledger's journal was keyed by its display names and is now keyed by its identifiers"
        );

        Ok(())
    }

    /// The durable entry for one occurrence, when this ledger holds one.
    ///
    /// The whole entry rather than only its answer: a completed retry is checked against what was
    /// recorded — the bytes, the routing — and those live beside the answer, not in it.
    pub fn known(
        &self,
        zone: &str,
        ledger: &str,
        source: &str,
        event_id: &str,
    ) -> Result<Option<KnownOccurrence>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = lock(&held)?;
        known_in(&held, source, event_id)
    }

    /// The answer given for one occurrence, when this ledger still holds it.
    pub fn outcome(
        &self,
        zone: &str,
        ledger: &str,
        source: &str,
        event_id: &str,
    ) -> Result<Option<serde_json::Value>, JournalError> {
        Ok(self
            .known(zone, ledger, source, event_id)?
            .map(|known| known.response)
            .filter(|response| !response.is_null()))
    }

    /// Reserves and durably keeps the one decision identity of an occurrence.
    pub fn decision_id(
        &self,
        zone: &str,
        ledger: &str,
        source: &str,
        event_id: &str,
    ) -> Result<String, JournalError> {
        let held = self.held(zone, ledger)?;
        let mut held = lock(&held)?;
        let Some(mut known) = known_in(&held, source, event_id)? else {
            return Err(JournalError::Corrupt(format!(
                "`{event_id}` has no occurrence entry from which to reserve a decision id"
            )));
        };
        if let Some(decision_id) = &known.decision_id {
            return Ok(decision_id.clone());
        }

        let decision_id = permguard_decisions::instance::mint();
        known.decision_id = Some(decision_id.clone());
        held.host.keep_occurrence(&known)?;

        Ok(decision_id)
    }

    /// The signed checkpoints one ledger's legacy journal holds.
    pub fn checkpoints(&self, zone: &str, ledger: &str) -> Result<Vec<PathBuf>, JournalError> {
        self.with_legacy(zone, ledger, |journal| {
            Ok(journal
                .checkpoints()?
                .into_iter()
                .map(|(_, path)| path)
                .collect())
        })
    }

    /// Marks the legacy journal's records through `seq` as accepted by the control plane.
    pub fn acknowledge(&self, zone: &str, ledger: &str, through: u64) -> Result<(), JournalError> {
        self.with_legacy(zone, ledger, |journal| journal.acknowledge(through))
    }

    /// The watermarks one ledger's legacy journal is at.
    pub fn state(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<permguard_events::journal::State, JournalError> {
        self.with_legacy(zone, ledger, |journal| Ok(journal.state().clone()))
    }

    /// The digest of the legacy journal's record at `seq`, which its next batch must name as its
    /// predecessor.
    ///
    /// Genesis for `0`, which is where a stream begins. Read from the journal rather than kept in
    /// memory, because it is asked for once per shipping round and a number this plane cached
    /// could be a number the journal has since recovered past.
    pub fn head_at(&self, zone: &str, ledger: &str, seq: u64) -> Result<String, JournalError> {
        if seq == 0 {
            return Ok(permguard_events::GENESIS.to_owned());
        }
        let records = self.legacy_read_from(zone, ledger, seq.saturating_sub(1), 1)?;
        let Some(record) = records.first() else {
            return Err(JournalError::Malformed(format!(
                "sequence {seq} is acknowledged and no longer here to be digested"
            )));
        };

        permguard_events::digest_of(record).map_err(JournalError::Digest)
    }

    /// Evicts from the legacy journal what both the control plane has and no loaded policy could
    /// still read.
    ///
    /// Two bounds, and the stricter wins. `retention_safe_through` is the policy-derived one: the
    /// last sequence whose occurrence is older than the retention every loaded partition's
    /// `max_window` requires. The journal applies the acknowledgement bound on top.
    pub fn evict(
        &self,
        zone: &str,
        ledger: &str,
        retention_safe_through: u64,
    ) -> Result<u64, JournalError> {
        self.with_legacy(zone, ledger, |journal| {
            let deletable = journal.deletable_through(retention_safe_through);
            journal.evict(deletable)
        })
    }

    /// The ledgers this plane has legacy journals for, whether or not they are open.
    ///
    /// Read off the filesystem rather than from what this process happens to have opened: after a
    /// restart the shipper has to find every journal with unshipped records, including the ones no
    /// request has touched yet.
    pub fn ledgers(&self) -> Vec<(String, String)> {
        if !self.legacy {
            return Vec::new();
        }
        children_holding(&self.root, permguard_events::journal::STATE_FILE)
    }

    /// The ledgers this plane has recorded on the Host's producer, whether or not they are open.
    pub fn host_ledgers(&self) -> Vec<(String, String)> {
        children_holding(&self.planes, super::host::LEGACY_MARK)
    }

    /// Measures, for every ledger on the Host, the floor no loaded window reads below — what was
    /// observed before `horizon` (epoch seconds) — and what the producer deleted is forgotten:
    /// what the Host's garbage collection then reads, without touching a ledger.
    pub fn refresh_floors(&self, horizon: i64) -> Result<(), JournalError> {
        for (zone, ledger) in self.host_ledgers() {
            let held = self.held(&zone, &ledger)?;
            let mut held = lock(&held)?;
            held.host.forget_deleted()?;
            let resource = held.host.resource().to_string();
            let safe = held.host.retention_safe(horizon)?;
            let mut floors = self
                .floors
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            floors.retain(|(held, _), _| held != &resource);
            for (run, through) in safe {
                floors.insert((resource.clone(), run), through);
            }
        }
        Ok(())
    }
}

/// What an append did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// Newly durable at this position.
    Appended {
        seq: u64,
        digest: String,
        instance: String,
    },
    /// Already here, byte for byte. The caller retried; nothing was written again.
    Idempotent { seq: u64 },
}

/// Why an append did not happen.
#[derive(Debug)]
pub enum Failed {
    /// The same event id carrying different content.
    ///
    /// Never resolved by choosing one of the two: an id is the caller's claim that two submissions
    /// are the same occurrence, and two different occurrences under one id means either a client
    /// bug or somebody replaying an id with new content. Both are worth stopping for.
    Conflict {
        seq: u64,
        stored_digest: String,
    },
    Journal(JournalError),
    Digest(permguard_events::record::DigestError),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { seq, stored_digest } => write!(
                formatter,
                "this event id is already recorded at sequence {seq} with the occurrence \
                 {stored_digest}, and this submission carries different content"
            ),
            Self::Journal(error) => write!(formatter, "{error}"),
            Self::Digest(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for Failed {}

/// Whether this occurrence has been seen here, and whether it carried the same content.
///
/// The Host stream's entries first, keyed by source and id; then a legacy journal's, which name no
/// source and match the id from any, as they did before the upgrade. A miss in both is new; a
/// read that fails is an error, never a miss: assuming fresh is how one occurrence gets counted
/// twice.
fn seen(
    held: &Held,
    source: Option<&str>,
    event_id: &str,
    digest: &str,
) -> Result<Seen, JournalError> {
    let known = match source {
        Some(source) => known_in(held, source, event_id)?,
        None => held.host.occurrence(None, event_id)?,
    };
    let Some(known) = known else {
        return Ok(Seen::Fresh);
    };

    Ok(if known.occurrence_digest == digest {
        Seen::Idempotent { seq: known.seq }
    } else {
        Seen::Conflict {
            seq: known.seq,
            stored_digest: known.occurrence_digest,
        }
    })
}

/// The local half of the logical index (WP-6.4b): this plane's own records, as the import reads
/// them.
impl super::imported::Local for Streams {
    fn copy(
        &self,
        zone: &str,
        ledger: &str,
        source: &str,
        event_id: &str,
    ) -> Result<Option<serde_json::Value>, JournalError> {
        match self.known(zone, ledger, source, event_id)? {
            // Recorded under exactly that source: a legacy entry, or one nobody vouched for, keys by
            // this plane's origin instead and is another occurrence.
            Some(known) if known.source.as_deref() == Some(source) => {
                self.record_at(zone, ledger, known.seq).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Read under the ledger's lock, as `read_from` is. A legacy journal is read from its start
    /// per page; only a rebuilt logical index reads it whole, once.
    fn after(
        &self,
        zone: &str,
        ledger: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<(u64, serde_json::Value)>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = lock(&held)?;
        let mut records: Vec<(u64, serde_json::Value)> = match &held.legacy {
            // A legacy record's own sequence is its local position.
            Some(journal) if after < held.host.legacy_through() => journal
                .read_from(after, limit)?
                .into_iter()
                .filter_map(|record| {
                    let position = record.get("seq").and_then(serde_json::Value::as_u64)?;
                    Some((position, record))
                })
                .collect(),
            _ => Vec::new(),
        };
        if records.len() < limit {
            records.extend(held.host.read_from(after, limit - records.len())?);
        }
        Ok(records)
    }
}

/// The entry of `event_id` from `source`: the Host stream's, then a legacy entry kept beside it,
/// then the legacy journal's.
fn known_in(
    held: &Held,
    source: &str,
    event_id: &str,
) -> Result<Option<KnownOccurrence>, JournalError> {
    if let Some(known) = held.host.occurrence(Some(source), event_id)? {
        return Ok(Some(known));
    }
    if let Some(known) = held.host.occurrence(None, event_id)? {
        return Ok(Some(known));
    }
    match &held.legacy {
        Some(journal) => journal.occurrence(event_id),
        None => Ok(None),
    }
}

fn lock(held: &OpenLedger) -> Result<MutexGuard<'_, Held>, JournalError> {
    held.lock()
        .map_err(|_| JournalError::Io("the ledger is poisoned".to_owned()))
}

/// The `<zone>/<ledger>` directories below `root` holding `marker`.
fn children_holding(root: &Path, marker: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let Ok(zones) = std::fs::read_dir(root) else {
        return found;
    };
    for zone in zones.flatten() {
        let Ok(name) = zone.file_name().into_string() else {
            continue;
        };
        let Ok(ledgers) = std::fs::read_dir(zone.path()) else {
            continue;
        };
        for ledger in ledgers.flatten() {
            if !ledger.path().join(marker).exists() {
                continue;
            }
            if let Ok(held) = ledger.file_name().into_string() {
                found.push((name.clone(), held));
            }
        }
    }
    found.sort();

    found
}

/// How far an `observed_at` is moved forward to follow the record sequenced ahead of it: the
/// width of the race between a submission's stamp and its sequence, which is the time a request
/// spends between arriving and joining a batch. A record ahead by more than this is not a race but
/// a clock that moved, and nothing is carried forward from it: the submission keeps its own stamp
/// and is judged against the history as it stands.
const OBSERVED_LIFT_SECS: i64 = 30;

/// Moves each record's `observed_at` forward to the latest one ahead of it where it is earlier by
/// no more than [`OBSERVED_LIFT_SECS`], in the order the records are about to be sequenced, and
/// answers the latest instant.
///
/// The floor starts at the last record this process appended, or, on the first append after
/// opening, at the stream's tail as stored. An instant that cannot be read is left as it is: the
/// record's own validation refuses it.
fn observed_floor(held: &Held, records: &mut [Record]) -> Option<i64> {
    let mut floor = held.last_observed.or_else(|| {
        let tail = held.host.last();
        (tail > 0)
            .then(|| held.host.record_at(tail).ok().flatten())
            .flatten()
            .and_then(|record| {
                record
                    .get("observed_at")
                    .and_then(serde_json::Value::as_str)
                    .and_then(permguard_events::index::epoch_seconds)
            })
    });
    for record in records.iter_mut() {
        let Some(at) = permguard_events::index::epoch_seconds(&record.observed_at) else {
            continue;
        };
        match floor {
            Some(before) if at < before => {
                if before - at <= OBSERVED_LIFT_SECS
                    && let Some(moved) = permguard_events::index::render_epoch_seconds(before)
                {
                    record.observed_at = moved;
                }
            }
            _ => floor = Some(at),
        }
    }
    floor
}

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_core::Recorder;
    use permguard_core::metrics::Reading;
    use permguard_events::record::Stream;
    use serde_json::json;

    /// Streams over a producer in memory, under a directory nothing else is using.
    fn on_host(tag: &str, delay: Duration) -> Streams {
        let root = scratch(tag);
        Streams::with_group_commit(
            root.join("events"),
            root.join("planes"),
            HostSide {
                producer: StreamProducer::over(Arc::new(
                    crate::temporal::testing::MemoryProducer::default(),
                )),
                host_id: [0xab; 16],
            },
            Bounds::default(),
            delay,
        )
        .expect("the floor is registered")
    }

    /// A directory nothing else is using.
    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-streams-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch directory is created");

        path
    }

    /// One submission, identified by `id` and carrying `id` as its content.
    fn occurrence(id: u64) -> Record {
        let at = permguard_events::index::render_epoch_seconds(1_700_000_000 + id as i64)
            .expect("an instant");

        let event = json!({"event_id": format!("e-{id}"), "kind": "response"});
        Record {
            v: 1,
            record_type: permguard_events::RECORD_TYPE.to_owned(),
            // Overwritten by the journal, which owns the stream identity.
            stream: Stream {
                producer: Producer {
                    class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
                    id: String::new(),
                    instance: String::new(),
                },
                zone: "acme".to_owned(),
                ledger: "main".to_owned(),
            },
            seq: 0,
            prev: String::new(),
            event_type: "permguard.dogwood.event.v1".to_owned(),
            event_id: format!("e-{id}"),
            source: None,
            occurrence_digest: permguard_events::occurrence_digest_of(&event).expect("a digest"),
            kind: "response".to_owned(),
            profile: "temporal".to_owned(),
            policy_partitions: vec!["governance".to_owned()],
            commit: "sha256:commit".to_owned(),
            history_key: None,
            occurred_at: at.clone(),
            observed_at: at,
            event,
        }
    }

    /// What one metric adds up to across every series it has.
    fn total(registry: &permguard_std::metrics::Registry, name: &str) -> f64 {
        registry
            .snapshot()
            .into_iter()
            .filter(|sample| sample.metric.name() == name)
            .map(|sample| match sample.reading {
                Reading::Value(value) => value,
                Reading::Distribution { count, .. } => count as f64,
            })
            .sum()
    }

    /// Sixty submissions arriving together are written together and flushed far fewer times.
    ///
    /// # What this is actually about
    ///
    /// An `fsync` costs about the same for one record as for a hundred, and the durable-before-
    /// observed rule means no submission may be acknowledged before one returns. Without group
    /// commit that is one barrier per submission, and the ledger's throughput is one over the
    /// disk's flush latency no matter how many callers there are.
    ///
    /// So the invariants are both halves at once: strictly fewer flushes than records, *and* every
    /// record durable, in one unbroken chain, each answered with the position it actually got.
    #[test]
    fn submissions_that_overlap_share_a_flush_and_none_of_them_is_lost() {
        let registry = Arc::new(permguard_std::metrics::Registry::new());
        let streams = Arc::new(
            on_host("batched", Duration::from_millis(20))
                .with_metrics(Metrics::new(Arc::clone(&registry) as Arc<dyn Recorder>)),
        );

        // Every writer waits for every other before submitting, so "concurrent" is a property of
        // the test rather than a hope about how fast threads happen to start.
        let ready = Arc::new(std::sync::Barrier::new(60));
        let mut writers = Vec::new();
        for id in 0..60u64 {
            let streams = Arc::clone(&streams);
            let ready = Arc::clone(&ready);
            writers.push(std::thread::spawn(move || {
                ready.wait();
                streams
                    .append("acme", "main", occurrence(id))
                    .expect("every submission is durable")
            }));
        }
        let mut positions: Vec<u64> = writers
            .into_iter()
            .map(|writer| match writer.join().expect("the writer finishes") {
                (Written::Appended { seq, .. }, record) => {
                    assert_eq!(
                        record.seq, seq,
                        "the record carries the position it was given"
                    );
                    assert!(
                        !record.stream.producer.instance.is_empty(),
                        "and the stream identity the journal owns"
                    );
                    seq
                }
                (Written::Idempotent { seq }, _) => {
                    panic!("sixty distinct occurrences, one answered as a retry at {seq}")
                }
            })
            .collect();
        positions.sort_unstable();

        assert_eq!(
            positions,
            (1..=60).collect::<Vec<u64>>(),
            "sixty submissions occupy sixty consecutive positions, with no gap and no collision"
        );
        let records = streams
            .read_from("acme", "main", 0, 100)
            .expect("the journal reads back");
        assert_eq!(records.len(), 60, "and all sixty are on disk");
        permguard_events::chain::verify(&records, None).expect("in one unbroken chain");

        let flushes = total(&registry, "permguard_temporal_flushes_total");
        assert!(
            flushes <= 10.0,
            "sixty submissions released together cost {flushes} flushes: they are not sharing them"
        );
        assert!(flushes >= 1.0, "and at least one, or nothing was flushed");
    }

    /// With no delay configured, nobody waits — and the records are still all there.
    ///
    /// Zero is not "group commit off": batches still form from whatever arrived while the previous
    /// flush was in flight. What zero removes is any submission ever *waiting* for a batch to fill,
    /// which is the latency a deployment buys the amortisation with.
    #[test]
    fn a_zero_delay_still_writes_everything_exactly_once() {
        let streams = Arc::new(on_host("unbatched", Duration::ZERO));

        let mut writers = Vec::new();
        for id in 0..20u64 {
            let streams = Arc::clone(&streams);
            writers.push(std::thread::spawn(move || {
                streams
                    .append("acme", "main", occurrence(id))
                    .expect("every submission is durable")
            }));
        }
        for writer in writers {
            writer.join().expect("the writer finishes");
        }

        let records = streams
            .read_from("acme", "main", 0, 100)
            .expect("the journal reads back");
        assert_eq!(records.len(), 20);
        permguard_events::chain::verify(&records, None).expect("in one unbroken chain");
    }

    /// The same occurrence submitted twice inside one batch is written once.
    ///
    /// Deduplication happens where the batch is written, under the journal's own lock, so two
    /// copies of one occurrence in a single batch cannot both find themselves fresh — the second
    /// sees the first's record, in the same pass, before either is flushed.
    #[test]
    fn one_occurrence_twice_in_a_batch_is_recorded_once() {
        let streams = Arc::new(on_host("retried", Duration::from_millis(20)));

        let mut writers = Vec::new();
        for _ in 0..8 {
            let streams = Arc::clone(&streams);
            writers.push(std::thread::spawn(move || {
                streams
                    .append("acme", "main", occurrence(7))
                    .expect("a retry is an answer, not a failure")
                    .0
            }));
        }
        let answers: Vec<Written> = writers
            .into_iter()
            .map(|writer| writer.join().expect("the writer finishes"))
            .collect();

        let appended = answers
            .iter()
            .filter(|answer| matches!(answer, Written::Appended { .. }))
            .count();
        assert_eq!(
            appended, 1,
            "eight submissions of one occurrence wrote {appended} records"
        );
        assert_eq!(
            answers.len() - appended,
            7,
            "and the other seven were answered as the retries they are"
        );
        let records = streams
            .read_from("acme", "main", 0, 100)
            .expect("the journal reads back");
        assert_eq!(records.len(), 1, "one occurrence, one record");
    }

    /// One event id carrying different content is a conflict, and does not take the batch with it.
    #[test]
    fn a_conflict_fails_alone_and_the_rest_of_its_batch_is_written() {
        let streams = on_host("conflict", Duration::ZERO);

        streams
            .append("acme", "main", occurrence(1))
            .expect("the first is durable");

        // The same id, different content.
        let mut impostor = occurrence(1);
        impostor.event["kind"] = json!("request");
        impostor.occurrence_digest =
            permguard_events::occurrence_digest_of(&impostor.event).expect("a digest");
        let refused = streams
            .append("acme", "main", impostor)
            .expect_err("one id, two occurrences, is never resolved by choosing one");
        assert!(matches!(refused, Failed::Conflict { seq: 1, .. }));

        streams
            .append("acme", "main", occurrence(2))
            .expect("and the ledger goes on accepting");
        let records = streams
            .read_from("acme", "main", 0, 100)
            .expect("the journal reads back");
        assert_eq!(records.len(), 2, "the conflict was refused, not recorded");
    }

    /// Streams over `producer`, under a directory nothing else is using.
    fn over(tag: &str, producer: &Arc<crate::temporal::testing::MemoryProducer>) -> Streams {
        let root = scratch(tag);
        Streams::new(
            root.join("events"),
            root.join("planes"),
            HostSide {
                producer: StreamProducer::over(
                    Arc::clone(producer) as Arc<dyn permguard_host::composition::StreamAppender>
                ),
                host_id: [0xab; 16],
            },
            Bounds::default(),
        )
        .expect("the floor is registered")
    }

    /// A stream past its bounds takes nothing, and neither does one whose pressure cannot be
    /// measured; the measure is trusted a second, then taken again.
    #[test]
    fn a_stream_under_pressure_or_unmeasured_refuses_and_records_nothing() {
        let producer = Arc::new(crate::temporal::testing::MemoryProducer::default());
        let streams = over("pressure", &producer);
        *producer.pressure.lock().expect("the lock") =
            Some(permguard_core::codes::stream::SPOOL_FULL);
        let refused = streams
            .append("acme", "main", occurrence(1))
            .expect_err("past its bounds");
        assert!(
            matches!(refused, Failed::Journal(JournalError::Full)),
            "{refused}"
        );
        // Relieved, and still refused while the measure is trusted.
        *producer.pressure.lock().expect("the lock") = None;
        assert!(streams.append("acme", "main", occurrence(1)).is_err());
        std::thread::sleep(PRESSURE_FOR + Duration::from_millis(100));
        streams
            .append("acme", "main", occurrence(1))
            .expect("measured again");

        let producer = Arc::new(crate::temporal::testing::MemoryProducer::default());
        let streams = over("pressure-unknown", &producer);
        *producer.pressure_error.lock().expect("the lock") = Some("no ring".to_owned());
        let refused = streams
            .append("acme", "main", occurrence(1))
            .expect_err("unmeasured is refused");
        assert!(
            matches!(refused, Failed::Journal(JournalError::Full)),
            "{refused}"
        );
        assert!(
            streams
                .read_from("acme", "main", 0, 10)
                .expect("read")
                .is_empty(),
            "nothing recorded"
        );
    }

    /// Records an append made durable without their entries are caught up before the next write,
    /// so a retry of them is the stored position rather than a second record.
    #[test]
    fn a_retry_after_entries_failed_is_recognised_not_recorded_twice() {
        let producer = Arc::new(crate::temporal::testing::MemoryProducer::default());
        let root = scratch("entries-failed");
        let streams = Streams::new(
            root.join("events"),
            root.join("planes"),
            HostSide {
                producer: StreamProducer::over(
                    Arc::clone(&producer) as Arc<dyn permguard_host::composition::StreamAppender>
                ),
                host_id: [0xab; 16],
            },
            Bounds::default(),
        )
        .expect("the floor is registered");
        // The ledger open, so what fails below is the entries of a durable record.
        streams
            .append("acme", "main", occurrence(0))
            .expect("durable");
        {
            let _failing = permguard_core::fault::inject(
                root.join("planes"),
                permguard_core::fault::Fault::WriteFails,
            );
            streams
                .append("acme", "main", occurrence(1))
                .expect_err("durable on the stream, its entries not");
        }
        let (retried, _) = streams
            .append("acme", "main", occurrence(1))
            .expect("the retry is answered");
        assert_eq!(retried, Written::Idempotent { seq: 2 });
        assert_eq!(
            streams
                .read_from("acme", "main", 0, 10)
                .expect("read")
                .len(),
            2,
            "one record per occurrence"
        );
    }

    /// One id from two sources in one batch is two occurrences, both recorded; the same id from
    /// the same source twice is the first's retry.
    #[test]
    fn one_id_from_two_sources_in_a_batch_is_two_occurrences() {
        let streams = on_host("two-sources", Duration::ZERO);
        let held = streams.held("acme", "main").expect("opened");
        let from = |source: &str| {
            let mut record = occurrence(7);
            record.source = Some(source.to_owned());
            record
        };
        let results = streams.write(
            &held,
            vec![(0, from("alice")), (1, from("bob")), (2, from("alice"))],
        );
        let written: Vec<Written> = results
            .into_iter()
            .map(|(_, result)| result.expect("each is an answer").0)
            .collect();
        assert!(
            written
                .iter()
                .filter(|written| matches!(written, Written::Appended { .. }))
                .count()
                == 2,
            "{written:?}"
        );
        assert!(
            written
                .iter()
                .any(|written| matches!(written, Written::Idempotent { .. })),
            "{written:?}"
        );
        assert_eq!(
            streams
                .read_from("acme", "main", 0, 10)
                .expect("read")
                .len(),
            2
        );
    }
}
