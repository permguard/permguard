// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The consumer side: one directory per producer run, `consumer/<sha256(resource)>/<producer-host>/
//! <run>/`, its records kept contiguous from sequence 1 (WP-5.1), and the ingest that admits them
//! (WP-5.3; owner decisions of 2026-10-14).
//!
//! ```text
//! consumer/<sha256(resource)>/<producer-host>/
//! ├── FORKED                         {1 run, 2 at_seq}: every later batch answered `fork`
//! └── <run>/
//!     ├── records/                   the records verbatim, the authority on `acked`
//!     ├── batches/<first>-<last>.jws the batch files verbatim
//!     ├── signers.cbor               the spans of the keys the batches were verified under
//!     └── STATE                      {1 acked, 2 oldest_retained}
//! ```
//!
//! Ingest checks in the blueprint's order: the message's bounds, the producer's fork mark, the
//! ring pin and the key, the signature and the batch's own commitments, the task the batch names,
//! the records' codec, then the range against what is held. A batch's files are written in the
//! order batch file, span, records, STATE, and the answer follows them all: a crash between them
//! leaves what the next delivery of the batch finds and completes.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use permguard_core::authz::Resource;
use permguard_host::membership::record::{RingPin, RingStatement};
use permguard_host::storage::journal::{Journal, Options};
use permguard_host::storage::write::{Published, publish_immutable, read_view, replace_view};
use permguard_host::storage::{Dir, StorageError, format};
use permguard_objects::cbor::Value;

use super::batch::{GENESIS_HEAD, KeyView, SealedBatch, digest_string};
use super::codec::{Map, encode, uint};
use super::ingest::{Answer, Forked, Outcome, Ship, Shipping};
use super::producer::{RECORDS, Span, Spans, canonical_jwk, decode_group};
use super::{Descriptor, RecordCodec, StreamError, StreamKey, hex};

const FORKED: &str = "FORKED";
const STATE: &str = "STATE";
const SIGNERS: &str = "signers.cbor";
const BATCHES: &str = "batches";
const RECORDS_DIR: &str = "records";
/// The most bytes a consumer's STATE and FORKED take.
pub const MAX_VIEW_BYTES: usize = 256;

/// A consumer run's STATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumerState {
    /// The highest contiguous sequence held.
    pub acked: u64,
    /// The oldest sequence whose bytes are held; below it a range is `gone` (WP-5.6 moves it).
    pub oldest_retained: u64,
}

impl ConsumerState {
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        encode(vec![
            (1, uint(self.acked)?),
            (2, uint(self.oldest_retained)?),
        ])
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_VIEW_BYTES {
            return Err(StreamError::Invalid(
                "a consumer STATE is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a consumer STATE")?;
        let state = Self {
            acked: map.uint(1)?,
            oldest_retained: map.uint(2)?,
        };
        map.finish()?;
        if state.oldest_retained == 0 {
            return Err(StreamError::Invalid(
                "a consumer STATE retains from sequence 1 or later".to_owned(),
            ));
        }
        Ok(state)
    }
}

/// A producer's stream found forked: the run and the first sequence that differed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkMark {
    pub run: [u8; 16],
    pub at_seq: u64,
}

impl ForkMark {
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        encode(vec![
            (1, Value::Bytes(self.run.to_vec())),
            (2, uint(self.at_seq)?),
        ])
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_VIEW_BYTES {
            return Err(StreamError::Invalid(
                "a fork mark is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a fork mark")?;
        let mark = Self {
            run: map.fixed(1)?,
            at_seq: map.uint(2)?,
        };
        map.finish()?;
        Ok(mark)
    }
}

/// One producer run as the consumer holds it, kept open between batches.
struct Held {
    dir: Dir,
    journal: Journal,
    /// The highest contiguous sequence the records hold.
    acked: u64,
    /// The digest of the record at `acked`, as the envelope spells it; genesis before any.
    last: String,
    oldest_retained: u64,
    /// Each RECORDS frame's first sequence and journal index, in order: where a read of a range
    /// starts, so a replay never reads the whole run (after the review).
    groups: Vec<(u64, u64)>,
}

impl Held {
    /// The records held from `from` through `to`, read from the frame `from` is in.
    fn records(&self, from: u64, to: u64) -> Result<Vec<(u64, Vec<u8>)>, StreamError> {
        let at = self.groups.partition_point(|(first, _)| *first <= from);
        let Some((_, index)) = at.checked_sub(1).and_then(|at| self.groups.get(at)) else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for frame in self.journal.frames_from(*index)? {
            if frame.kind != RECORDS {
                continue;
            }
            let (first, records) = decode_group(&frame.payload)?;
            if first > to {
                break;
            }
            for (offset, bytes) in records.into_iter().enumerate() {
                let seq = first + offset as u64;
                if (from..=to).contains(&seq) {
                    found.push((seq, bytes));
                }
            }
        }
        Ok(found)
    }
}

/// A run held open: `(resource component, producer, run)`.
type RunAt = (String, [u8; 16], [u8; 16]);

/// The typed consumer handle of one descriptor.
pub struct Consumer<C> {
    dir: Dir,
    claim: u64,
    descriptor: Descriptor,
    codec: C,
    /// The runs held open, by `(resource component, producer, run)`; the lock serializes
    /// admissions, one writer per consumer stream.
    held: Mutex<BTreeMap<RunAt, Held>>,
}

impl<C> std::fmt::Debug for Consumer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Consumer")
            .field("plane", &self.descriptor.plane)
            .field("stream_type", &self.descriptor.stream_type)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The name a cutover and an incident give a stream: its plane, type, resource digest and run.
fn stream_name(key: &StreamKey, run: &[u8; 16]) -> String {
    format!(
        "{}/{}/{}/{}",
        key.plane,
        key.stream_type,
        key.resource_component(),
        hex(run)
    )
}

/// The subdirectory `name` of `dir`, created when `create`, `None` when absent otherwise.
fn child(dir: &Dir, name: &str, create: bool) -> Result<Option<Dir>, StreamError> {
    if create || dir.subdirs()?.iter().any(|held| held == name) {
        return Ok(Some(dir.subdir(name, true)?));
    }
    Ok(None)
}

impl<C: RecordCodec> Consumer<C> {
    pub(crate) fn new(dir: Dir, claim: u64, descriptor: Descriptor, codec: C) -> Self {
        Self {
            dir,
            claim,
            descriptor,
            codec,
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// The ring the descriptor's batches are signed under.
    pub fn ring(&self) -> &'static str {
        self.descriptor.ring
    }

    /// The directory of `key`'s producer, beside its runs; `None` when absent and not `create`.
    fn producer_dir(&self, key: &StreamKey, create: bool) -> Result<Option<Dir>, StreamError> {
        let Some(resource) = child(&self.dir, &key.resource_component(), create)? else {
            return Ok(None);
        };
        child(&resource, &hex(&key.producer_host_id), create)
    }

    /// Opens `key`'s run `run_id`: the head re-derived from its records, the authority; `None`
    /// when the run is absent and not `create`, so a read leaves nothing behind.
    fn open(
        &self,
        key: &StreamKey,
        run_id: [u8; 16],
        create: bool,
    ) -> Result<Option<Held>, StreamError> {
        let Some(producer) = self.producer_dir(key, create)? else {
            return Ok(None);
        };
        let Some(dir) = child(&producer, &hex(&run_id), create)? else {
            return Ok(None);
        };
        let (journal, _) = Journal::open(
            dir.subdir(RECORDS_DIR, true)?,
            Options {
                claim: self.claim,
                ..Options::default()
            },
        )?;
        let mut acked = 0;
        let mut last = GENESIS_HEAD.to_owned();
        let mut groups = Vec::new();
        for frame in journal.frames()? {
            if frame.kind != RECORDS {
                continue;
            }
            let (first, records) = decode_group(&frame.payload)?;
            if first != acked + 1 {
                return Err(StreamError::Corruption(format!(
                    "the records of run {} skip from {acked} to {first}",
                    hex(&run_id)
                )));
            }
            groups.push((first, frame.index));
            acked += records.len() as u64;
            if let Some(record) = records.last() {
                last = digest_string(self.descriptor.record_domain, record);
            }
        }
        let oldest_retained = read_view(&dir, STATE, format::VIEW)?
            .map(|bytes| ConsumerState::decode(&bytes))
            .transpose()?
            .map_or(1, |state| state.oldest_retained);
        Ok(Some(Held {
            dir,
            journal,
            acked,
            last,
            oldest_retained,
            groups,
        }))
    }

    /// Runs `work` on `key`'s run `run_id`, held open; `None` when the run is absent and not
    /// `create`. A storage error drops the run from the cache, so the next call opens it again
    /// and its journal recovers: one failed flush never closes a run for the process's life
    /// (after the review).
    fn with_held<R>(
        &self,
        key: &StreamKey,
        run_id: [u8; 16],
        create: bool,
        work: impl FnOnce(&mut Held) -> Result<R, StreamError>,
    ) -> Result<Option<R>, StreamError> {
        let mut all = lock(&self.held);
        let at = (key.resource_component(), key.producer_host_id, run_id);
        if !all.contains_key(&at) {
            let Some(opened) = self.open(key, run_id, create)? else {
                return Ok(None);
            };
            all.insert(at.clone(), opened);
        }
        let held = all
            .get_mut(&at)
            .ok_or_else(|| StreamError::Corruption("a run held vanished".to_owned()))?;
        let done = work(held);
        if matches!(done, Err(StreamError::Storage(_))) {
            all.remove(&at);
        }
        done.map(Some)
    }

    /// Keeps `records`, verified upstream, from `first_seq` of `producer`'s run `run_id`: refused
    /// unless they continue what is kept and each reads with the codec.
    pub fn admit(
        &self,
        resource: &Resource,
        producer: [u8; 16],
        run_id: [u8; 16],
        first_seq: u64,
        records: &[Vec<u8>],
    ) -> Result<u64, StreamError> {
        let key = self.descriptor.key(resource, producer)?;
        for record in records {
            self.validate(record)?;
        }
        self.with_held(&key, run_id, true, |held| {
            if first_seq != held.acked + 1 || records.is_empty() {
                return Err(StreamError::Invalid(format!(
                    "records from sequence {first_seq} do not continue the {} kept",
                    held.acked
                )));
            }
            self.append(held, first_seq, records)?;
            Ok(held.acked)
        })?
        .ok_or_else(|| StreamError::Corruption("a run opened for writing is absent".to_owned()))
    }

    /// The typed validator: within the stream's bound, read by the codec, in its canonical
    /// encoding.
    fn validate(&self, record: &[u8]) -> Result<(), StreamError> {
        if record.len() > self.descriptor.max_record_bytes as usize {
            return Err(StreamError::Invalid(
                "a record over the stream's bound".to_owned(),
            ));
        }
        let decoded = self.codec.decode(record).map_err(StreamError::Invalid)?;
        if self.codec.encode(&decoded).map_err(StreamError::Invalid)? != record {
            return Err(StreamError::Invalid(
                "a record not in its canonical encoding".to_owned(),
            ));
        }
        Ok(())
    }

    /// Appends `records` from `first_seq`, the run's next, and keeps STATE after them.
    fn append(
        &self,
        held: &mut Held,
        first_seq: u64,
        records: &[Vec<u8>],
    ) -> Result<(), StreamError> {
        let group = super::producer::encode_group(first_seq, records.iter().map(Vec::as_slice))?;
        let index = held.journal.append(RECORDS, &group)?;
        held.groups.push((first_seq, index));
        held.acked = first_seq + records.len() as u64 - 1;
        if let Some(record) = records.last() {
            held.last = digest_string(self.descriptor.record_domain, record);
        }
        replace_view(
            &held.dir,
            STATE,
            format::VIEW,
            &ConsumerState {
                acked: held.acked,
                oldest_retained: held.oldest_retained,
            }
            .encode()?,
        )?;
        Ok(())
    }

    /// Ingests one shipped batch of the task `shipping` names (WP-5.3): answers the outcome, and
    /// the fork found when it is one. An error is a store that cannot answer now: `deferred`.
    pub fn ingest(
        &self,
        shipping: &Shipping<'_>,
        body: &[u8],
    ) -> Result<(Answer, Option<Forked>), StreamError> {
        let unverifiable = || Ok((Answer::of(Outcome::Unverifiable, 0), None));
        // Transport bounds, then what the message holds.
        let Ok(ship) = Ship::decode(body) else {
            return unverifiable();
        };
        // The task's resource and producer: the stream the batch must be of.
        let Ok(resource) = Resource::parse(shipping.resource) else {
            return unverifiable();
        };
        let Ok(key) = self.descriptor.key(&resource, shipping.member) else {
            return unverifiable();
        };
        // A forked producer is answered `fork` until an operator acts; the incident is reported
        // again, so a suspension that failed is retried (after the review).
        if let Some(mark) = self.mark(&key)? {
            return Ok((
                Answer::of(Outcome::Fork, 0),
                Some(Forked {
                    stream: stream_name(&key, &mark.run),
                    at_seq: mark.at_seq,
                }),
            ));
        }
        let (Ok(batch), Ok(statement)) = (
            SealedBatch::decode(&ship.batch),
            RingStatement::decode(&ship.statement),
        ) else {
            return unverifiable();
        };
        // The ring pin, then the key in the pinned set.
        let (Ok(kid), Ok(claimed)) = (batch.kid(), batch.envelope_unverified()) else {
            return unverifiable();
        };
        let Some(run) = unhex16(&claimed.run) else {
            return unverifiable();
        };
        let stream = stream_name(&key, &run);
        let pins: Vec<RingPin> = (shipping.pins)(&stream, claimed.first_seq);
        if !pins.iter().any(|pin| {
            pin.ring == self.descriptor.ring
                && permguard_host::membership::statement_matches(&statement, pin).is_ok()
        }) {
            return unverifiable();
        }
        let Some(jwk) = statement
            .keys
            .iter()
            .filter_map(|text| serde_json::from_str::<permguard_core::keys::Jwk>(text).ok())
            .find(|jwk| jwk.kid == kid)
        else {
            return unverifiable();
        };
        // The signature, the batch's commitments, then the task the batch names.
        let Ok((envelope, records)) = batch.verify(
            std::slice::from_ref(&jwk),
            self.descriptor.batch_typ,
            self.descriptor.record_domain,
        ) else {
            return unverifiable();
        };
        let membership = permguard_host::identity::record::uuid_text(&shipping.membership_id);
        if envelope.stream_key != KeyView::of(&key)
            || envelope.descriptor_version != self.descriptor.version
            || envelope.run != claimed.run
            || envelope.membership_id.as_deref() != Some(membership.as_str())
        {
            return unverifiable();
        }
        // The run's fence epoch is the one it was opened under: a re-pin moves the lease's on
        // while the run goes on, so an earlier epoch of the same membership is the run's own; a
        // later one no lease has issued (after the review). A restored volume is fenced by the
        // lease's epoch and boot id before its batches arrive (WP-4.3).
        if envelope.epoch.is_none_or(|epoch| epoch > shipping.epoch) {
            return unverifiable();
        }
        // The typed Plane validator.
        if records.iter().any(|record| self.validate(record).is_err()) {
            return unverifiable();
        }
        let ingested = self.with_held(&key, run, true, |held| {
            self.admit_batch(
                held,
                &key,
                run,
                &stream,
                &envelope,
                &records,
                &jwk,
                &ship.batch,
            )
        })?;
        ingested
            .ok_or_else(|| StreamError::Corruption("a run opened for writing is absent".to_owned()))
    }

    /// The range of a verified batch against what `held` holds, then the durable writes.
    #[allow(clippy::too_many_arguments)]
    fn admit_batch(
        &self,
        held: &mut Held,
        key: &StreamKey,
        run: [u8; 16],
        stream: &str,
        envelope: &super::batch::Envelope,
        records: &[Vec<u8>],
        jwk: &permguard_core::keys::Jwk,
        file: &[u8],
    ) -> Result<(Answer, Option<Forked>), StreamError> {
        let (first, last) = (envelope.first_seq, envelope.last_seq);
        if first < held.oldest_retained {
            return Ok((Answer::of(Outcome::Gone, held.acked), None));
        }
        if first > held.acked + 1 {
            return Ok((
                Answer {
                    outcome: Outcome::OutOfOrder,
                    acked: held.acked,
                    expected_seq: Some(held.acked + 1),
                },
                None,
            ));
        }
        let forked = |at_seq: u64| -> Result<(Answer, Option<Forked>), StreamError> {
            self.fork(key, run, at_seq, stream)?;
            Ok((
                Answer::of(Outcome::Fork, 0),
                Some(Forked {
                    stream: stream.to_owned(),
                    at_seq,
                }),
            ))
        };
        // The record before the batch: genesis, the head held, or the record held; below the
        // oldest retained no record remains to compare, and retention's anchor (WP-5.6) answers.
        let previous = if first == 1 {
            Some(GENESIS_HEAD.to_owned())
        } else if first - 1 == held.acked {
            Some(held.last.clone())
        } else if first - 1 < held.oldest_retained {
            None
        } else {
            held.records(first - 1, first - 1)?
                .first()
                .map(|(_, record)| digest_string(self.descriptor.record_domain, record))
        };
        if previous.is_some_and(|previous| envelope.previous_head != previous) {
            return forked(first);
        }
        // The overlap, against the records held.
        let overlap_end = last.min(held.acked);
        if overlap_end >= first {
            let held_overlap = held.records(first, overlap_end)?;
            if held_overlap.len() as u64 != overlap_end - first + 1 {
                return Err(StreamError::Corruption(
                    "the run does not hold the records its head says".to_owned(),
                ));
            }
            if let Some(at) = held_overlap
                .iter()
                .zip(records)
                .position(|((_, held), sent)| held != sent)
            {
                return forked(first + at as u64);
            }
        }
        // The span, decided before anything is written: another key over a range the spans
        // already cover is a conflicting transition (after the review).
        let mut spans = match read_view(&held.dir, SIGNERS, format::VIEW)? {
            Some(bytes) => Spans::decode(&bytes)?,
            None => Spans::default(),
        };
        let new_span = match spans.signing(&run, first) {
            Some(span) if span.kid == jwk.kid => false,
            covering => {
                let later = spans
                    .runs
                    .iter()
                    .find(|(held, _)| *held == run)
                    .and_then(|(_, spans)| spans.last())
                    .is_some_and(|span| span.from_seq >= first);
                if covering.is_some() && later {
                    return forked(first);
                }
                true
            }
        };
        // Durable before the answer: the batch file, the span, the records, STATE.
        let batches = held.dir.subdir(BATCHES, true)?;
        match publish_immutable(
            &batches,
            &format!("{first}-{last}.jws"),
            file,
            &|_| true,
            &|stored| stored == file,
        ) {
            Ok(Published::Written | Published::AlreadyThere) => {}
            // Another batch file of the same range: the producer signed it twice.
            Err(StorageError::Corruption(_)) => return forked(first),
            Err(error) => return Err(error.into()),
        }
        if new_span {
            spans.append(
                run,
                Span {
                    from_seq: first,
                    kid: jwk.kid.clone(),
                    jwk: canonical_jwk(jwk)?,
                },
            )?;
            replace_view(&held.dir, SIGNERS, format::VIEW, &spans.encode()?)?;
        }
        if last > held.acked {
            let suffix = &records[(held.acked + 1 - first) as usize..];
            let from = held.acked + 1;
            self.append(held, from, suffix)?;
        }
        Ok((Answer::of(Outcome::Ok, held.acked), None))
    }

    /// The fork mark of `key`'s producer, when its stream was found forked.
    fn mark(&self, key: &StreamKey) -> Result<Option<ForkMark>, StreamError> {
        let Some(dir) = self.producer_dir(key, false)? else {
            return Ok(None);
        };
        read_view(&dir, FORKED, format::VIEW)?
            .map(|bytes| ForkMark::decode(&bytes))
            .transpose()
    }

    /// Marks `key`'s producer forked at `at_seq` of `run`: every later batch is answered `fork`.
    fn fork(
        &self,
        key: &StreamKey,
        run: [u8; 16],
        at_seq: u64,
        stream: &str,
    ) -> Result<(), StreamError> {
        let dir = self
            .producer_dir(key, true)?
            .ok_or_else(|| StreamError::Corruption("a producer directory is absent".to_owned()))?;
        if read_view(&dir, FORKED, format::VIEW)?.is_none() {
            replace_view(
                &dir,
                FORKED,
                format::VIEW,
                &ForkMark { run, at_seq }.encode()?,
            )?;
        }
        tracing::error!(
            event.name = "host.stream.forked",
            component = "stream",
            stream = %stream,
            at_seq = at_seq,
            "a producer's stream differs from what the consumer holds: it is closed until an operator acts"
        );
        Ok(())
    }

    /// The fork mark of `producer` over `resource`, when its stream was found forked.
    pub fn forked(
        &self,
        resource: &Resource,
        producer: [u8; 16],
    ) -> Result<Option<ForkMark>, StreamError> {
        self.mark(&self.descriptor.key(resource, producer)?)
    }

    /// The highest contiguous sequence held of `producer`'s run `run_id` over `resource`: 0 for
    /// a run never ingested.
    pub fn acked(
        &self,
        resource: &Resource,
        producer: [u8; 16],
        run_id: [u8; 16],
    ) -> Result<u64, StreamError> {
        let key = self.descriptor.key(resource, producer)?;
        Ok(self
            .with_held(&key, run_id, false, |held| Ok(held.acked))?
            .unwrap_or(0))
    }

    /// The signer spans of `producer`'s run `run_id` over `resource`.
    pub fn spans(
        &self,
        resource: &Resource,
        producer: [u8; 16],
        run_id: [u8; 16],
    ) -> Result<Spans, StreamError> {
        let key = self.descriptor.key(resource, producer)?;
        Ok(self
            .with_held(&key, run_id, false, |held| {
                Ok(match read_view(&held.dir, SIGNERS, format::VIEW)? {
                    Some(bytes) => Spans::decode(&bytes)?,
                    None => Spans::default(),
                })
            })?
            .unwrap_or_default())
    }

    /// The records kept of `producer`'s run `run_id` over `resource` from `from_seq`, at most
    /// `limit`.
    pub fn read(
        &self,
        resource: &Resource,
        producer: [u8; 16],
        run_id: [u8; 16],
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, C::Record)>, StreamError> {
        let key = self.descriptor.key(resource, producer)?;
        let held = self.with_held(&key, run_id, false, |held| {
            let to = held
                .acked
                .min(from_seq.saturating_add(limit as u64).saturating_sub(1));
            held.records(from_seq.max(1), to)
        })?;
        held.unwrap_or_default()
            .into_iter()
            .map(|(seq, bytes)| {
                Ok((
                    seq,
                    self.codec.decode(&bytes).map_err(StreamError::Invalid)?,
                ))
            })
            .collect()
    }
}

fn unhex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..32)
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect();
    bytes?.try_into().ok()
}
