// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The journals this plane writes: one per tenant ledger, and what each one remembers.
//!
//! # One stream per ledger, not one per process
//!
//! A cryptographic stream is owned by one producer instance and one tenant ledger, so a plane
//! serving three ledgers writes three chains. Not one shared chain: a shared chain would make a
//! tenant's history depend on another tenant's writes, so verifying one would require reading the
//! other, and shipping one would leak that the other exists.
//!
//! The producer identity is bound **server-side** and never taken from a caller. In this release
//! the class is the data plane's own and the id is this plane's configured identity; the instance
//! is minted when a journal is first created and kept in its state from then on, so a restart that
//! can prove continuation keeps its sequence and one that cannot gets a new instance rather than
//! reusing a sequence.
//!
//! # One flush for a batch, never one receipt before its flush
//!
//! An `fsync` costs about the same for one record as for a hundred, and the durable-before-observed
//! rule means every submission pays for one. So submissions that overlap in time are written
//! together and flushed once: the first to arrive leads, whoever arrives while it is writing joins
//! its batch, and none of them is answered until the single flush covering all of them returns.
//! What is amortised is the cost; what is never relaxed is the rule.
//!
//! # What is kept in memory, and what is not
//!
//! The journal itself is on disk and is the authority. What is held here is a small index of the
//! event ids seen recently in each ledger, which is what makes a client retry idempotent without a
//! disk scan — bounded, and rebuilt from the journal's tail when a journal is opened, so a restart
//! does not turn a retry into a duplicate.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use permguard_core::Metrics;
use permguard_events::journal::{Bounds, Journal, JournalError};
use permguard_events::record::{PRODUCER_CLASS_DATA_PLANE, Producer, Record, Stream};

/// How many recent event ids one ledger keeps in memory, as a cache and not as the horizon.
///
/// A client retry usually arrives within seconds of its original, so this covers the common case
/// without touching the disk. It is bounded because it is memory a caller can grow: an index that
/// kept every id would be a way to make a plane allocate by sending events.
///
/// It is **not** how long a retry stays recognisable. It used to be, and that was a silent
/// double-count waiting to happen: an id repeated after a few thousand others fell out of the
/// window, was read as a new occurrence, and was counted a second time by a history whose whole
/// purpose is counting occurrences. Recognition now lives on the volume, keyed by the id, and
/// lasts exactly as long as the record does — see [`permguard_events::journal::KnownOccurrence`].
pub const RECENT_EVENT_IDS: usize = 4096;

/// What happened to an occurrence this ledger had already seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// This id is new here.
    Fresh,
    /// The same id and the same occurrence: one logical occurrence, and the stored position.
    Idempotent { seq: u64 },
    /// The same id carrying different content. Never resolved by choosing one.
    Conflict { seq: u64, stored_digest: String },
}

/// One ledger's journal, and what this process remembers about it.
struct Held {
    journal: Journal,
    /// Recently seen `(event_id, occurrence_digest, seq)`, newest last.
    recent: VecDeque<(String, String, u64)>,
}

/// The largest number of records one flush covers.
///
/// Not a throughput knob: a bound on how long one leader may hold a ledger's journal, so a burst
/// cannot turn into a single writer that never lets go. Whatever does not fit is the next batch's,
/// which forms while this one flushes.
const MAX_BATCH: usize = 1_024;

/// One submission waiting to be written, and the ticket its writer will collect an answer by.
type Waiting = (u64, Record);

/// What one writer collects: what the journal did, and the record it did it to.
///
/// The record comes back because the journal fills part of it in — the sequence, the link to the
/// record before it, and the stream identity, none of which a caller may choose — and its writer
/// goes on to log and answer from exactly what was written rather than from what it proposed.
pub type Answered = (Written, Record);

/// One ledger's group-commit gate: who is forming a batch, and what has been written for whom.
///
/// Separate from the journal's own lock on purpose. If forming a batch and writing it were under
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

/// One ledger's open journal, shared by everything that writes to or reads it.
type OpenJournal = Arc<Mutex<Held>>;

/// Every journal this plane has open, by `(zone, ledger)`.
type OpenJournals = Mutex<BTreeMap<(String, String), OpenJournal>>;

/// The gate one ledger's first opener holds while it opens.
type Opening = Arc<Mutex<()>>;

/// Every journal this plane has open, by ledger.
pub struct Streams {
    root: PathBuf,
    producer: Producer,
    bounds: Bounds,
    open: OpenJournals,
    /// One group-commit gate per ledger, created with its journal.
    gates: Mutex<BTreeMap<(String, String), Arc<Gate>>>,
    /// One turn-taker per ledger, created with its journal.
    ///
    /// Created here rather than on first use, and this is not tidiness: its starting mark is "every
    /// record this journal holds has been applied", which is only true at the moment the journal is
    /// opened. A sequencer created later would take its mark from a journal that had already moved,
    /// and the sequences in flight would never be ordered against each other.
    sequencers: crate::temporal::sequencer::Sequencers,
    /// One opener per ledger.
    ///
    /// A journal takes an exclusive lock on its own directory when it is opened — that is what
    /// makes "one writer per stream" a property of the filesystem rather than of this process's
    /// discipline. It also means two threads that both find a ledger closed cannot both open it:
    /// the second would be refused by the lock the first is holding, and a first request that
    /// happened to arrive alongside another would fail for no reason a caller could act on. So the
    /// first opens and the rest wait for it, per ledger, leaving other ledgers' first requests
    /// free to proceed in parallel.
    opening: Mutex<BTreeMap<(String, String), Opening>>,
    /// What the journals count about themselves — flushes, and how many records each covered.
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
    /// The journals under `<volume>/data/events`, written as this producer.
    pub fn new(root: PathBuf, producer_id: String, bounds: Bounds) -> Self {
        Self::with_group_commit(root, producer_id, bounds, Duration::ZERO)
    }

    /// The same journals, told how long a batch may keep forming.
    pub fn with_group_commit(
        root: PathBuf,
        producer_id: String,
        bounds: Bounds,
        group_commit_max_delay: Duration,
    ) -> Self {
        Self {
            root,
            producer: Producer {
                class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
                id: producer_id,
                // Minted per process start. A journal that recovers its own instance from `STATE`
                // keeps that one; this is what a fresh journal is created with.
                instance: permguard_decisions::instance::mint(),
            },
            bounds,
            open: Mutex::new(BTreeMap::new()),
            gates: Mutex::new(BTreeMap::new()),
            sequencers: crate::temporal::sequencer::Sequencers::default(),
            opening: Mutex::new(BTreeMap::new()),
            metrics: Metrics::none(),
            group_commit_max_delay,
        }
    }

    /// The same journals, recording what they do to the deployment's metrics.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;

        self
    }

    /// Where this plane keeps its event journals.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The producer identity this plane writes as.
    pub fn producer(&self) -> &Producer {
        &self.producer
    }

    /// The bounds every journal here is opened with.
    pub fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// The journal for one ledger, opening it on first use.
    ///
    /// Opened once and kept: the journal holds an exclusive lock on its directory for as long as
    /// it lives, which is what makes "one writer per stream" a property of the filesystem rather
    /// than of this process's discipline.
    fn held(&self, zone: &str, ledger: &str) -> Result<OpenJournal, JournalError> {
        let key = (zone.to_owned(), ledger.to_owned());
        if let Some(held) = self.already_open(&key)? {
            return Ok(held);
        }

        // Closed, as far as this thread has seen. One thread per ledger does the opening; the rest
        // wait here and find it open below. The registry's own lock is *not* held across the open:
        // a ledger whose journal is slow to recover would otherwise stall every other ledger's
        // requests, which only need that lock for a moment.
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

        let stream = Stream {
            producer: self.producer.clone(),
            zone: zone.to_owned(),
            ledger: ledger.to_owned(),
        };
        // One directory per stream, named by what the stream is. A tenant's history is separable
        // by construction, so exporting or deleting one ledger's events never touches another's.
        let directory = self.root.join(zone).join(ledger);
        let journal = Journal::open(&directory, stream, self.bounds)?;
        let recent = recent_of(&journal)?;
        // The journal owns the durable order, so new submissions start after its recovered tail.
        // Engine histories are rebuilt lazily by `Submitter::ensure_history` before an occurrence
        // is applied; opening a journal must not claim that policy state has already been replayed.
        let (next, _) = journal.next_position();
        let _ = self.sequencers.of(zone, ledger, next.saturating_sub(1));

        let mut open = self
            .open
            .lock()
            .map_err(|_| JournalError::Io("the journal registry is poisoned".to_owned()))?;

        Ok(Arc::clone(open.entry(key).or_insert_with(|| {
            Arc::new(Mutex::new(Held { journal, recent }))
        })))
    }

    /// The journal for one ledger if this process already has it open.
    fn already_open(&self, key: &(String, String)) -> Result<Option<OpenJournal>, JournalError> {
        let open = self
            .open
            .lock()
            .map_err(|_| JournalError::Io("the journal registry is poisoned".to_owned()))?;

        Ok(open.get(key).map(Arc::clone))
    }

    /// Appends one record durably, unless its id was already seen here.
    ///
    /// The whole write is under the ledger's own lock, so two concurrent submissions of one id
    /// cannot both find it fresh: the second sees the first's record, and answers idempotently.
    ///
    /// # One flush, several records
    ///
    /// Submissions that overlap in time are written together and flushed once. The first to arrive
    /// leads; whoever arrives while it is leading joins its batch and sleeps until the leader has
    /// an answer for them. Nobody is answered before the flush that covers their record returns —
    /// what a batch amortises is the cost of the flush, never the rule that a receipt follows it.
    pub fn append(&self, zone: &str, ledger: &str, record: Record) -> Result<Answered, Failed> {
        let journal = self.held(zone, ledger).map_err(Failed::Journal)?;
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

        self.lead(&journal, &gate, zone, ledger, ticket)
    }

    /// Forms one batch, writes it, flushes it once, and answers everybody in it.
    fn lead(
        &self,
        journal: &OpenJournal,
        gate: &Arc<Gate>,
        zone: &str,
        ledger: &str,
        ticket: u64,
    ) -> Result<Answered, Failed> {
        let taken = self.form(gate);
        let leadership = Leadership {
            gate: Arc::clone(gate),
            tickets: taken.iter().map(|(ticket, _)| *ticket).collect(),
        };
        let results = self.write(journal, zone, ledger, taken);

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

    /// Writes a whole batch under one journal lock, then flushes it once.
    fn write(
        &self,
        journal: &OpenJournal,
        zone: &str,
        ledger: &str,
        taken: Vec<Waiting>,
    ) -> Vec<(u64, Result<Answered, Failed>)> {
        let labels = [("zone", zone), ("ledger", ledger)];
        let covered = taken.len();
        let mut results = Vec::with_capacity(taken.len());
        let mut held = match journal.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut wrote = false;
        for (ticket, mut record) in taken {
            let already = match seen(
                &held.journal,
                &held.recent,
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
                Seen::Fresh => {}
                Seen::Idempotent { seq } => {
                    results.push((ticket, Ok((Written::Idempotent { seq }, record))));
                    continue;
                }
                Seen::Conflict { seq, stored_digest } => {
                    results.push((ticket, Err(Failed::Conflict { seq, stored_digest })));
                    continue;
                }
            }

            // Read for each record in turn, not once for the batch: a record that is refused
            // leaves the journal exactly where it was, so the next one takes the position the
            // refused one would have had rather than a gap.
            let (seq, prev) = held.journal.next_position();
            record.seq = seq;
            record.prev = prev;
            // The instance is the journal's, not this process's guess: a journal that recovered an
            // earlier incarnation continues that one, and a record claiming otherwise would break
            // the chain it is being appended to.
            record.stream = held.journal.stream().clone();

            let value = match record.to_value() {
                Ok(value) => value,
                Err(error) => {
                    results.push((ticket, Err(Failed::Digest(error))));
                    continue;
                }
            };
            match held.journal.append_unsynced(&value) {
                Ok(appended) => {
                    // The journal tail has advanced even if the addressed occurrence entry below
                    // cannot be written. Keep the id in the in-process dedup window first, so a
                    // retry before restart cannot append the same logical occurrence again. On a
                    // restart `Journal::open` reconciles this durable tail into the addressed
                    // index before accepting traffic.
                    held.recent.push_back((
                        record.event_id.clone(),
                        record.occurrence_digest.clone(),
                        appended.seq,
                    ));
                    while held.recent.len() > RECENT_EVENT_IDS {
                        held.recent.pop_front();
                    }
                    // What makes the retry recognisable, on the volume rather than only in this
                    // process's window. Written before the flush below, so a record that becomes
                    // durable is never durable without the entry that identifies it.
                    if let Err(error) = held.journal.record_occurrence(
                        &permguard_events::journal::KnownOccurrence {
                            event_id: record.event_id.clone(),
                            seq: appended.seq,
                            occurrence_digest: record.occurrence_digest.clone(),
                            decision_id: None,
                            // Not answered yet, so nothing to recognise a completed retry by:
                            // both are filled in with the outcome.
                            profile: None,
                            kind: None,
                            // The answer is not known yet; it is filled in once given.
                            response: serde_json::Value::Null,
                        },
                    ) {
                        results.push((ticket, Err(Failed::Journal(error))));
                        continue;
                    }
                    wrote = true;
                    let written = Written::Appended {
                        seq: appended.seq,
                        digest: appended.digest,
                        instance: record.stream.producer.instance.clone(),
                    };
                    results.push((ticket, Ok((written, record))));
                }
                Err(error) => results.push((ticket, Err(Failed::Journal(error)))),
            }
        }

        // One flush for the whole batch, before anybody in it is told anything.
        if wrote {
            self.metrics.count(&super::measure::FLUSHES, &labels);
            self.metrics
                .observe(&super::measure::BATCH_RECORDS, &labels, covered as f64);
        }
        if wrote && let Err(error) = held.journal.sync() {
            let reason = error.to_string();
            for (_, result) in results.iter_mut() {
                if matches!(result, Ok((Written::Appended { .. }, _))) {
                    // On disk but not proven to be: this record is not durable, and a submission
                    // that is not durable is refused rather than acknowledged.
                    *result = Err(Failed::Journal(JournalError::Io(format!(
                        "the batch containing this record could not be flushed: {reason}"
                    ))));
                }
            }

            return results;
        }
        // Commit the addressed idempotency entries after the journal. There is no atomic rename
        // spanning both paths; journal-first makes the append-only record authoritative, and
        // `Journal::open` repairs any occurrence-index tail left behind by a crash here.
        if wrote && let Err(error) = held.journal.sync_occurrences() {
            let reason = error.to_string();
            for (_, result) in results.iter_mut() {
                if matches!(result, Ok((Written::Appended { .. }, _))) {
                    *result = Err(Failed::Journal(JournalError::Io(format!(
                        "this record's retry entry could not be flushed: {reason}"
                    ))));
                }
            }
        }

        results
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

    /// This ledger's turn-taker, so its histories observe the journal's order.
    ///
    /// Opening the journal is part of the ask: the sequencer's starting mark comes from the
    /// journal, and a caller that had not opened it yet would be handed one starting from nothing.
    pub fn sequencer(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<Arc<crate::temporal::sequencer::Sequencer>, JournalError> {
        let held = self.held(zone, ledger)?;
        let applied_through = {
            let held = held
                .lock()
                .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;
            let (next, _) = held.journal.next_position();
            next.saturating_sub(1)
        };

        Ok(self.sequencers.of(zone, ledger, applied_through))
    }

    /// The instance this ledger's journal is writing as.
    pub fn instance(&self, zone: &str, ledger: &str) -> Result<String, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        Ok(held.journal.stream().producer.instance.clone())
    }

    /// How many bytes one ledger's journal holds.
    pub fn bytes(&self, zone: &str, ledger: &str) -> Result<u64, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.bytes()
    }

    /// The records after `seq`, for the shipper and for replay.
    pub fn read_from(
        &self,
        zone: &str,
        ledger: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.read_from(after, limit)
    }

    /// The record at one exact sequence, for completing an interrupted idempotent submission.
    pub fn record_at(
        &self,
        zone: &str,
        ledger: &str,
        sequence: u64,
    ) -> Result<serde_json::Value, JournalError> {
        let records = self.read_from(zone, ledger, sequence.saturating_sub(1), 1)?;
        let record = records.into_iter().next().ok_or_else(|| {
            JournalError::Corrupt(format!(
                "the occurrence index names sequence {sequence}, but the journal does not hold it"
            ))
        })?;
        if record.get("seq").and_then(serde_json::Value::as_u64) != Some(sequence) {
            return Err(JournalError::Corrupt(format!(
                "the occurrence index names sequence {sequence}, but the next retained record is \
                 at {}",
                record
                    .get("seq")
                    .and_then(serde_json::Value::as_u64)
                    .map_or_else(|| "no sequence".to_owned(), |held| held.to_string())
            )));
        }

        Ok(record)
    }

    /// The records one temporal question needs, by their coordinates in this ledger's journal.
    ///
    /// A range scan over the index rather than a read of the ledger: one history partition, one
    /// event type, one time range. What makes deciding against a history cost what the history's
    /// relevant part costs, rather than what the tenant's whole traffic costs.
    pub fn scan(
        &self,
        zone: &str,
        ledger: &str,
        query: &permguard_events::index::Query,
    ) -> Result<Vec<serde_json::Value>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.scan(query)
    }

    /// Marks records through `seq` as covered by a signed batch.
    pub fn mark_signed(&self, zone: &str, ledger: &str, through: u64) -> Result<(), JournalError> {
        let held = self.held(zone, ledger)?;
        let mut held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.mark_signed(through)
    }

    /// Persists the signed checkpoint covering a batch, and marks that range signed.
    pub fn checkpoint(
        &self,
        zone: &str,
        ledger: &str,
        first_seq: u64,
        last_seq: u64,
        jws: &str,
    ) -> Result<(), JournalError> {
        let held = self.held(zone, ledger)?;
        let mut held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.checkpoint(first_seq, last_seq, jws)
    }

    /// Records which key signed the checkpoint starting at `first_seq`, beside the journal.
    pub fn note_signer(
        &self,
        zone: &str,
        ledger: &str,
        first_seq: u64,
        kid: &str,
        jwk: &serde_json::Value,
    ) -> Result<(), JournalError> {
        let held = self.held(zone, ledger)?;
        let mut held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.note_signer(first_seq, kid, jwk)
    }

    /// Which key signed which stretch of one stream, as recorded so far.
    pub fn signers(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<permguard_stream::Signers, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        Ok(held.journal.signers().clone())
    }

    /// Keeps the answer given for one occurrence, so a retry is answered rather than refused.
    ///
    /// The entry already exists — the write path made it durable before this record was
    /// acknowledged, because that is what makes the retry *recognisable*. This fills in the answer
    /// that was not known yet at that point.
    pub fn record_outcome(
        &self,
        zone: &str,
        ledger: &str,
        event_id: &str,
        routed: Routed<'_>,
        response: &serde_json::Value,
    ) -> Result<(), JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        let Some(mut known) = held.journal.occurrence(event_id)? else {
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

        held.journal.record_occurrence(&known)?;
        // A response may leave only after the idempotency answer is durable. Otherwise a crash
        // can occur after the caller saw success but before the outcome index reaches disk, and a
        // retry is then recognised as the same event without being able to reproduce its answer.
        held.journal.sync_occurrences()
    }

    /// Settles which directory a ledger's journal lives in when its identifiers changed shape.
    ///
    /// # Why this exists
    ///
    /// A journal is kept under the pair the caller named, and a caller may name a ledger by its
    /// identifier or by its display name — both resolve to one mirror. Keying storage by whichever
    /// arrived first therefore let one ledger own *two* journals: two sequences, two histories, two
    /// idempotency indexes, each invisible to the other. Storage is keyed canonically now, and this
    /// is what stands between an existing name-keyed journal and being silently abandoned for an
    /// empty one under the identifier.
    ///
    /// Idempotent by construction: once the canonical directory exists there is nothing to do, so
    /// every later call is a stat.
    pub fn adopt(
        &self,
        canonical: (&str, &str),
        display: (&str, &str),
    ) -> Result<(), JournalError> {
        if canonical == display {
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
        std::fs::rename(&legacy, &target).map_err(|error| {
            JournalError::Io(format!(
                "adopting {} as {}: {error}",
                legacy.display(),
                target.display()
            ))
        })?;
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
        event_id: &str,
    ) -> Result<Option<permguard_events::journal::KnownOccurrence>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.occurrence(event_id)
    }

    /// The answer given for one occurrence, when this ledger still holds it.
    pub fn outcome(
        &self,
        zone: &str,
        ledger: &str,
        event_id: &str,
    ) -> Result<Option<serde_json::Value>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        Ok(held
            .journal
            .occurrence(event_id)?
            .map(|known| known.response)
            .filter(|response| !response.is_null()))
    }

    /// Reserves and durably keeps the one decision identity of an occurrence.
    pub fn decision_id(
        &self,
        zone: &str,
        ledger: &str,
        event_id: &str,
    ) -> Result<String, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;
        let Some(mut known) = held.journal.occurrence(event_id)? else {
            return Err(JournalError::Corrupt(format!(
                "`{event_id}` has no occurrence entry from which to reserve a decision id"
            )));
        };
        if let Some(decision_id) = &known.decision_id {
            return Ok(decision_id.clone());
        }

        let decision_id = permguard_decisions::instance::mint();
        known.decision_id = Some(decision_id.clone());
        held.journal.record_occurrence(&known)?;
        held.journal.sync_occurrences()?;

        Ok(decision_id)
    }

    /// The signed checkpoints one ledger's journal holds.
    pub fn checkpoints(&self, zone: &str, ledger: &str) -> Result<Vec<PathBuf>, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        Ok(held
            .journal
            .checkpoints()?
            .into_iter()
            .map(|(_, path)| path)
            .collect())
    }

    /// Marks records through `seq` as accepted by the control plane.
    pub fn acknowledge(&self, zone: &str, ledger: &str, through: u64) -> Result<(), JournalError> {
        let held = self.held(zone, ledger)?;
        let mut held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        held.journal.acknowledge(through)
    }

    /// The watermarks one ledger's journal is at.
    pub fn state(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<permguard_events::journal::State, JournalError> {
        let held = self.held(zone, ledger)?;
        let held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        Ok(held.journal.state().clone())
    }

    /// The digest of the record at `seq`, which the next batch must name as its predecessor.
    ///
    /// Genesis for `0`, which is where a stream begins. Read from the journal rather than kept in
    /// memory, because it is asked for once per shipping round and a number this plane cached
    /// could be a number the journal has since recovered past.
    pub fn head_at(&self, zone: &str, ledger: &str, seq: u64) -> Result<String, JournalError> {
        if seq == 0 {
            return Ok(permguard_events::GENESIS.to_owned());
        }
        let records = self.read_from(zone, ledger, seq.saturating_sub(1), 1)?;
        let Some(record) = records.first() else {
            return Err(JournalError::Malformed(format!(
                "sequence {seq} is acknowledged and no longer here to be digested"
            )));
        };

        permguard_events::digest_of(record).map_err(JournalError::Digest)
    }

    /// Evicts what both the control plane has and no loaded policy could still read.
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
        let held = self.held(zone, ledger)?;
        let mut held = held
            .lock()
            .map_err(|_| JournalError::Io("the journal is poisoned".to_owned()))?;

        let deletable = held.journal.deletable_through(retention_safe_through);

        held.journal.evict(deletable)
    }

    /// The ledgers this plane has journals for, whether or not they are open.
    ///
    /// Read off the filesystem rather than from what this process happens to have opened: after a
    /// restart the shipper has to find every stream with unshipped records, including the ones no
    /// request has touched yet.
    pub fn ledgers(&self) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let Ok(zones) = std::fs::read_dir(&self.root) else {
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
                if !ledger
                    .path()
                    .join(permguard_events::journal::STATE_FILE)
                    .exists()
                {
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

/// Whether this id has been seen here, and whether it carried the same occurrence.
///
/// Two places are consulted, and the order is the point. The in-memory window answers the common
/// case — a retry arrives seconds after its original — without touching the disk. The volume
/// answers everything else, and it is the authority: recognition used to *end* at the window, so
/// an id repeated after a few thousand others was accepted as a new occurrence and counted twice.
/// A silent double-count is the one outcome a temporal history must never produce, so a miss in
/// the window is a question for the volume rather than an answer.
fn seen(
    journal: &Journal,
    recent: &VecDeque<(String, String, u64)>,
    event_id: &str,
    digest: &str,
) -> Result<Seen, JournalError> {
    // Newest first: a retry matches its own original, and an id reused after a very long time
    // matches the most recent use of it.
    for (held_id, held_digest, seq) in recent.iter().rev() {
        if held_id != event_id {
            continue;
        }

        return Ok(if held_digest == digest {
            Seen::Idempotent { seq: *seq }
        } else {
            Seen::Conflict {
                seq: *seq,
                stored_digest: held_digest.clone(),
            }
        });
    }

    let Some(known) = journal.occurrence(event_id)? else {
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

/// The dedup index, rebuilt from the journal's tail.
///
/// Without this a restart turns every in-flight retry into a duplicate: the client resends an id
/// the journal already holds, this process has no memory of it, and the same occurrence is
/// recorded twice under one id — which is exactly the state the conflict rule exists to make
/// impossible.
fn recent_of(journal: &Journal) -> Result<VecDeque<(String, String, u64)>, JournalError> {
    let (next, _) = journal.next_position();
    let after = next.saturating_sub(RECENT_EVENT_IDS as u64);
    let records = journal.read_from(after, RECENT_EVENT_IDS)?;

    Ok(records
        .iter()
        .filter_map(|record| {
            Some((
                record.get("event_id")?.as_str()?.to_owned(),
                record.get("occurrence_digest")?.as_str()?.to_owned(),
                record.get("seq")?.as_u64()?,
            ))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_core::Recorder;
    use permguard_core::metrics::Reading;
    use serde_json::json;

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
            occurrence_digest: format!("sha256:{id:064x}"),
            kind: "response".to_owned(),
            profile: "temporal".to_owned(),
            policy_partitions: vec!["governance".to_owned()],
            commit: "sha256:commit".to_owned(),
            history_key: None,
            occurred_at: at.clone(),
            observed_at: at,
            event: json!({"event_id": format!("e-{id}"), "kind": "response"}),
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
            Streams::with_group_commit(
                scratch("batched"),
                "plane-1".to_owned(),
                Bounds::default(),
                Duration::from_millis(20),
            )
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
        let streams = Arc::new(Streams::new(
            scratch("unbatched"),
            "plane-1".to_owned(),
            Bounds::default(),
        ));

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
        let streams = Arc::new(Streams::with_group_commit(
            scratch("retried"),
            "plane-1".to_owned(),
            Bounds::default(),
            Duration::from_millis(20),
        ));

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
        let streams = Streams::with_group_commit(
            scratch("conflict"),
            "plane-1".to_owned(),
            Bounds::default(),
            Duration::ZERO,
        );

        streams
            .append("acme", "main", occurrence(1))
            .expect("the first is durable");

        // The same id, different content.
        let mut impostor = occurrence(1);
        impostor.occurrence_digest = format!("sha256:{:064x}", 99);
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
}
