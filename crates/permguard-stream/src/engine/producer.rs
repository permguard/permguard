// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The producer side: one physical stream per resource, its runs inside one framed journal.
//!
//! | Frame     | Payload                                                         |
//! | --------- | --------------------------------------------------------------- |
//! | RUN_OPEN  | the run statement's COSE_Sign1 envelope                         |
//! | RECORDS   | {1 first_seq, 2 records}: the group one flush made durable      |
//! | TERMINAL  | the run's end {1 run_id, 2 last_seq, 3 last_record_digest}      |
//!
//! Group commit puts the records waiting into one frame, so the journal keeps its rule that a
//! frame is flushed before the next is written, and a crash leaves at most the last frame torn.
//!
//! A rollover writes the successor into STATE first, then TERMINAL, then RUN_OPEN, then STATE
//! again: whatever step a crash stops at, opening completes it with the same signed bytes.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use permguard_core::authz::Resource;
use permguard_host::keys::ring::Ring;
use permguard_host::storage::journal::{Journal, Options};
use permguard_host::storage::write::{allocate, read_view, release, replace_view};
use permguard_host::storage::{Dir, format};
use permguard_host::time::TimeGuard;
use permguard_objects::cbor::Value;

use super::codec::{Map, encode, uint};
use super::run::{Fence, RunEnd, RunStatement, statement_digest};
use super::state::{Base, State};
use super::{Descriptor, RecordCodec, StreamError, StreamKey, hex, record_digest};

mod inspect;
mod prune;
mod runs;
mod seal;
mod ship;

pub use seal::{
    Cutover, MAX_CUTOVER_BYTES, MAX_SIGNERS_BYTES, Sealing, Span, Spans, canonical_jwk,
};
pub use ship::{MAX_SUBSCRIPTION_BYTES, PressureBounds, Subscription, SubscriptionState};

/// The frame kinds of a producer's journal.
pub(crate) const RUN_OPEN: u16 = 1;
pub(crate) const RECORDS: u16 = 2;
pub(crate) const TERMINAL: u16 = 3;

const STATE_FILE: &str = "STATE";
const RESERVE_FILE: &str = "RESERVE";
const RECORDS_DIR: &str = "records";
/// The space kept for terminal and rollover metadata.
pub const RESERVE_BYTES: u64 = 64 * 1024;
/// The most record bytes one group frame carries, beyond its first record.
const GROUP_BYTES: usize = 4 * 1024 * 1024;
/// The most records one group frame carries.
pub const MAX_GROUP_RECORDS: usize = 4096;
/// The most bytes a group frame's payload takes: one group and its encoding.
pub const MAX_GROUP_FRAME_BYTES: usize = 2 * GROUP_BYTES;

/// What a producer handle runs with.
pub(crate) struct Context {
    pub(crate) dir: Dir,
    pub(crate) host_id: [u8; 16],
    pub(crate) boot_id: [u8; 16],
    pub(crate) claim: u64,
    pub(crate) operations: Arc<Ring>,
    pub(crate) time: Arc<TimeGuard>,
    /// The size past which the stream's journal segment rolls (WP-5.6b).
    pub(crate) segment_bytes: u64,
}

/// What an append answers once its record is durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub run_id: [u8; 16],
    pub seq: u64,
    pub record_digest: [u8; 32],
}

/// Where the next record of a stream lands: what a record that names its own position is built
/// from (WP-6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub run_id: [u8; 16],
    pub seq: u64,
    /// The digest of the record before it in the run; zeros at sequence 1.
    pub prev: [u8; 32],
}

/// What a `dr` restore did to a producer's streams (WP-7.7): the successor of each run it rolled
/// over, and each forked stream it left to its operator, by resource with where it forked.
#[derive(Debug, Default)]
pub struct Restored {
    pub rolled: Vec<RunStatement>,
    pub forked: Vec<(String, u64)>,
}

/// The typed producer handle of one descriptor.
pub struct Producer<C> {
    context: Context,
    descriptor: Descriptor,
    codec: C,
    streams: Mutex<BTreeMap<String, Arc<Physical>>>,
    /// The descriptor's ring, once the Host handed it: what batches are sealed under.
    signer: Option<Arc<Ring>>,
    /// Each subscription backing off: its attempts and the second it waits until (WP-5.4).
    backoff: Mutex<BTreeMap<String, (u32, u64)>>,
    /// The `history` floor the Plane registered (WP-5.6b), replaced when the Plane registers its
    /// own through the composition (WP-6.2a).
    floor: std::sync::RwLock<Option<Arc<dyn super::retention::RetentionFloor>>>,
    /// Keeps the garbage collection's passes from overlapping (WP-5.6b).
    pub(crate) lease: super::retention::Lease,
    /// The fence of each subscription seen shipping, with its task's selector: what a stream it
    /// covers opens its genesis run under (WP-6.1, after the review).
    fences: Mutex<Vec<(permguard_core::authz::Selector, Fence)>>,
    /// How long a batch is kept after every required subscription acknowledged it (WP-7.9b):
    /// `None` deletes it at once.
    acknowledged_retention: Option<std::time::Duration>,
}

impl<C> std::fmt::Debug for Producer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Producer")
            .field("plane", &self.descriptor.plane)
            .field("stream_type", &self.descriptor.stream_type)
            .field("version", &self.descriptor.version)
            .finish_non_exhaustive()
    }
}

impl<C: RecordCodec> Producer<C> {
    pub(crate) fn new(context: Context, descriptor: Descriptor, codec: C) -> Self {
        Self {
            context,
            descriptor,
            codec,
            streams: Mutex::new(BTreeMap::new()),
            signer: None,
            backoff: Mutex::new(BTreeMap::new()),
            floor: std::sync::RwLock::new(None),
            lease: super::retention::Lease::default(),
            fences: Mutex::new(Vec::new()),
            acknowledged_retention: None,
        }
    }

    /// This producer keeping each batch `retention` after every required subscription
    /// acknowledged it (WP-7.9b): a coordinator restored from a snapshot that old is resent what
    /// it lost. Zero deletes at once; a retention under a second counts as one.
    pub fn with_acknowledged_retention(mut self, retention: std::time::Duration) -> Self {
        self.acknowledged_retention = (!retention.is_zero()).then_some(retention);
        self
    }

    /// The acknowledged retention in force, seconds.
    pub(crate) fn acknowledged_retention_secs(&self) -> Option<u64> {
        self.acknowledged_retention
            .map(|retention| retention.as_secs().max(1))
    }

    /// This producer's `history` streams kept above `floor`, the oldest position a loaded
    /// temporal contract reads (WP-5.6b).
    pub fn with_retention_floor(
        mut self,
        floor: Arc<dyn super::retention::RetentionFloor>,
    ) -> Self {
        *self
            .floor
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(floor);
        self
    }

    /// The `history` floor in force.
    pub(crate) fn floor(&self) -> Option<Arc<dyn super::retention::RetentionFloor>> {
        self.floor
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// This producer sealing its batches under `signer`, the ring its descriptor names.
    pub fn with_signer(mut self, signer: Arc<Ring>) -> Result<Self, StreamError> {
        if signer.id() != self.descriptor.ring {
            return Err(StreamError::Sign(format!(
                "`{}/{}` seals under `{}`, not `{}`",
                self.descriptor.plane,
                self.descriptor.stream_type,
                self.descriptor.ring,
                signer.id()
            )));
        }
        self.signer = Some(signer);
        Ok(self)
    }

    /// Seals the next batch of the stream of `resource`, at most `max_records` and never more
    /// than the descriptor's batch bound: answers it once its file is durable.
    pub fn seal(&self, resource: &Resource, max_records: u64) -> Result<Sealing, StreamError> {
        self.seal_within(resource, max_records, usize::MAX)
    }

    /// [`Producer::seal`] with the batch's records within `max_record_bytes` as well: what a ship
    /// task's message bound allows (WP-5.4).
    pub fn seal_within(
        &self,
        resource: &Resource,
        max_records: u64,
        max_record_bytes: usize,
    ) -> Result<Sealing, StreamError> {
        let Some(signer) = &self.signer else {
            return Err(StreamError::Sign(
                "the producer was handed no ring to seal under".to_owned(),
            ));
        };
        let bound = max_records.min(u64::from(self.descriptor.max_batch_records));
        self.physical(resource)?.seal(
            &self.context,
            &self.descriptor,
            signer,
            bound,
            max_record_bytes,
        )
    }

    /// The signer spans of the stream of `resource`.
    pub fn spans(&self, resource: &Resource) -> Result<Spans, StreamError> {
        let physical = self.physical(resource)?;
        let writer = physical.writer();
        seal::spans_of(&writer.dir)
    }

    /// The cutovers this producer's streams wait for, as their CUTOVER views hold them.
    pub fn pending_cutovers(&self) -> Result<Vec<Cutover>, StreamError> {
        let mut found = Vec::new();
        for physical in self.every()? {
            if let Some(cutover) = seal::cutover_of(&physical.writer().dir)?
                && !cutover.confirmed
            {
                found.push(cutover);
            }
        }
        Ok(found)
    }

    /// `(stream, from_seq)` of every stream fenced by `membership_id` that needs a cutover before
    /// the descriptor ring's key `kid` seals it, each recorded pending (WP-4.5, WP-5.2).
    pub fn due_cutovers(
        &self,
        membership_id: &[u8; 16],
        kid: &str,
    ) -> Result<Vec<(String, u64)>, StreamError> {
        let Some(signer) = &self.signer else {
            return Err(StreamError::Sign(
                "the producer was handed no ring to seal under".to_owned(),
            ));
        };
        let mut due = Vec::new();
        for physical in self.every()? {
            if let Some(stream) = physical.due(&self.descriptor, signer, membership_id, kid)? {
                due.push(stream);
            }
        }
        Ok(due)
    }

    /// Records that the coordinator journaled the cutover of `stream` to `kid`: the key seals
    /// from the sequence the cutover names. Refuses a cutover the stream does not wait for.
    pub fn confirm_cutover(&self, stream: &str, kid: &str) -> Result<(), StreamError> {
        confirm(&self.every()?, stream, kid)
    }

    /// Every stream of this producer on disk, opened: the key of one not open yet read from the
    /// run its journal starts with, and refused unless it is this producer's at that place. A
    /// stream is opened under the map's lock, as `physical` opens one, so no journal is ever held
    /// twice; once open it stays in the map, and a later call only lists the directory.
    fn every(&self) -> Result<Vec<Arc<Physical>>, StreamError> {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        let host = hex(&self.context.host_id);
        let mut found = Vec::new();
        for component in self.context.dir.subdirs()? {
            if let Some(open) = streams
                .values()
                .find(|physical| physical.key.resource_component() == component)
            {
                found.push(Arc::clone(open));
                continue;
            }
            let dir = self.context.dir.subdir(&component, false)?;
            if !dir.subdirs()?.contains(&host) {
                continue;
            }
            let Some(key) = Physical::key_of(&self.context, &dir.subdir(&host, false)?)? else {
                continue;
            };
            let ours = key.plane == self.descriptor.plane
                && key.stream_type == self.descriptor.stream_type
                && key.version == self.descriptor.version
                && key.producer_host_id == self.context.host_id
                && key.resource_component() == component;
            if !ours {
                return Err(StreamError::Corruption(format!(
                    "the stream at `{component}` opens a run of another stream"
                )));
            }
            let physical = Arc::new(Physical::open(
                &self.context,
                &self.descriptor,
                key.clone(),
            )?);
            streams.insert(key.resource, Arc::clone(&physical));
            found.push(physical);
        }
        Ok(found)
    }

    /// The physical stream of `resource`, opened and recovered on first use.
    fn physical(&self, resource: &Resource) -> Result<Arc<Physical>, StreamError> {
        let key = self.descriptor.key(resource, self.context.host_id)?;
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = streams.get(&key.resource) {
            return Ok(Arc::clone(held));
        }
        let physical = Arc::new(Physical::open(
            &self.context,
            &self.descriptor,
            key.clone(),
        )?);
        streams.insert(key.resource, Arc::clone(&physical));
        Ok(physical)
    }

    /// Appends `record` to the stream of `resource`, opening a genesis run when none is; answers
    /// once the flush covering it completed.
    pub fn append(&self, resource: &Resource, record: &C::Record) -> Result<Receipt, StreamError> {
        let bytes = self.codec.encode(record).map_err(StreamError::Invalid)?;
        self.append_bytes(resource, bytes)
    }

    /// Appends a record's `bytes`, checked by the codec, to the stream of `resource`: what the
    /// composition's untyped `StreamProducer` reaches.
    pub fn append_bytes(
        &self,
        resource: &Resource,
        bytes: Vec<u8>,
    ) -> Result<Receipt, StreamError> {
        // The typed validator: what is appended reads back as a record, and is its canonical
        // encoding (after the review).
        self.check(&bytes)?;
        let physical = self.physical(resource)?;
        let mut bytes = Some(bytes);
        physical.append(
            &self.context,
            self.genesis_fence(resource),
            self.descriptor.record_domain,
            &mut |_| Ok(bytes.take().into_iter().collect()),
        )
    }

    /// Appends the records `build` makes from the stream's next position, under the lock that
    /// gives sequences, so a record can name its own place (WP-6.1): the records take consecutive
    /// sequences from `position.seq`, each checked by the codec as [`Self::append_bytes`] checks
    /// one. Answers the last record's receipt once the flush covering it completed.
    pub fn append_with(
        &self,
        resource: &Resource,
        build: impl FnOnce(Position) -> Result<Vec<Vec<u8>>, String>,
    ) -> Result<Receipt, StreamError> {
        let physical = self.physical(resource)?;
        let mut build = Some(build);
        physical.append(
            &self.context,
            self.genesis_fence(resource),
            self.descriptor.record_domain,
            &mut |position| {
                let build = build
                    .take()
                    .ok_or_else(|| StreamError::Invalid("a record built twice".to_owned()))?;
                let records = build(position).map_err(StreamError::Invalid)?;
                for bytes in &records {
                    self.check(bytes)?;
                }
                Ok(records)
            },
        )
    }

    /// The fence a stream of `resource` opens its genesis run under: the first subscription seen
    /// shipping whose task covers it, `None` on a standalone Host.
    fn genesis_fence(&self, resource: &Resource) -> Option<Fence> {
        self.fences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(selector, _)| selector.contains(resource))
            .map(|(_, fence)| fence.clone())
    }

    /// Remembers `fence`, with its task's `selector`, for the genesis runs it covers: in place of
    /// an earlier epoch of the same task.
    pub(crate) fn remember_fence(&self, selector: &permguard_core::authz::Selector, fence: Fence) {
        let mut fences = self.fences.lock().unwrap_or_else(PoisonError::into_inner);
        match fences.iter_mut().find(|(_, held)| {
            held.membership_id == fence.membership_id && held.task_id == fence.task_id
        }) {
            Some(held) if held.1.epoch <= fence.epoch => *held = (selector.clone(), fence),
            Some(_) => {}
            None => fences.push((selector.clone(), fence)),
        }
    }

    /// Refuses a record's `bytes` the codec does not read back, or not in its canonical
    /// encoding, or past the descriptor's bound.
    fn check(&self, bytes: &[u8]) -> Result<(), StreamError> {
        if bytes.len() > self.descriptor.max_record_bytes as usize {
            return Err(StreamError::Invalid(format!(
                "a record of {} bytes; this stream takes up to {}",
                bytes.len(),
                self.descriptor.max_record_bytes
            )));
        }
        let record = self.codec.decode(bytes).map_err(StreamError::Invalid)?;
        if self.codec.encode(&record).map_err(StreamError::Invalid)? != bytes {
            return Err(StreamError::Invalid(
                "a record is appended in its canonical encoding".to_owned(),
            ));
        }
        Ok(())
    }

    /// The run the stream of `resource` writes under, opening a genesis run carrying `fence`
    /// when none is.
    pub fn open_run(
        &self,
        resource: &Resource,
        fence: Option<Fence>,
    ) -> Result<RunStatement, StreamError> {
        self.physical(resource)?.ensure_run(&self.context, fence)
    }

    /// Ends the current run and opens its successor carrying `fence`: an ordinary rollover,
    /// refused while the stream is forked.
    pub fn rollover(
        &self,
        resource: &Resource,
        fence: Option<Fence>,
    ) -> Result<RunStatement, StreamError> {
        self.physical(resource)?
            .rollover(&self.context, fence, None)
    }

    /// Records that a consumer found the stream forked at `at_seq`: no record is appended and no
    /// run opens until an operator-approved successor.
    pub fn report_fork(&self, resource: &Resource, at_seq: u64) -> Result<(), StreamError> {
        self.physical(resource)?.report_fork(at_seq)
    }

    /// Opens the successor of a forked stream, authorized by `approval`, the digest of the plan
    /// an operator approved (WP-3.9).
    pub fn succeed_after_fork(
        &self,
        resource: &Resource,
        approval: [u8; 32],
        fence: Option<Fence>,
    ) -> Result<RunStatement, StreamError> {
        self.physical(resource)?
            .rollover(&self.context, fence, Some(approval))
    }

    /// Rolls every stream of this producer over after a `dr` restore (WP-7.7, owner decision of
    /// 2026-10-26): each run of the snapshot ends at its last durable record and its successor
    /// opens under this handle's boot id, the restore's, with the run's fence. A coordinator may
    /// hold a run further than its snapshot does, so the restored producer never appends to one;
    /// its successors are new runs to every consumer. A forked stream is left to its operator.
    pub fn succeed_restored(&self) -> Result<Restored, StreamError> {
        let mut restored = Restored::default();
        for physical in self.every()? {
            let (run, forked) = {
                let writer = physical.writer();
                (
                    writer.run.clone(),
                    writer.state.as_ref().and_then(|state| state.forked_at_seq),
                )
            };
            let Some(run) = run else {
                continue;
            };
            if let Some(at_seq) = forked {
                restored
                    .forked
                    .push((physical.key.resource.clone(), at_seq));
                continue;
            }
            restored.rolled.push(physical.rollover(
                &self.context,
                run.statement.fence.clone(),
                None,
            )?);
        }
        Ok(restored)
    }

    /// The stream's STATE, once it holds a run.
    pub fn state(&self, resource: &Resource) -> Result<Option<State>, StreamError> {
        let physical = self.physical(resource)?;
        let writer = physical.writer();
        Ok(writer.state.clone())
    }

    /// The records of the current run from `from_seq`, at most `limit`; a read starting at or
    /// below what the run deleted answers from the sequence after it, with the gap and the run's
    /// anchor (WP-5.6c), never as complete.
    pub fn read(
        &self,
        resource: &Resource,
        from_seq: u64,
        limit: usize,
    ) -> Result<super::anchor::Page<C::Record>, StreamError> {
        let physical = self.physical(resource)?;
        let page = Self::page_of(&physical, from_seq, limit)?;
        Ok(super::anchor::Page {
            records: page
                .records
                .into_iter()
                .map(|(seq, bytes)| {
                    Ok((
                        seq,
                        self.codec.decode(&bytes).map_err(StreamError::Invalid)?,
                    ))
                })
                .collect::<Result<_, StreamError>>()?,
            gap: page.gap,
        })
    }

    /// [`Self::read`] of `physical`, the records as their bytes.
    fn page_of(
        physical: &Physical,
        from_seq: u64,
        limit: usize,
    ) -> Result<super::anchor::Page<Vec<u8>>, StreamError> {
        let writer = physical.writer();
        let Some(run) = &writer.run else {
            return Ok(super::anchor::Page {
                records: Vec::new(),
                gap: None,
            });
        };
        // Read without creating: a stream that never sealed has no batches directory.
        let mut anchor = None;
        if writer.dir.subdirs()?.iter().any(|name| name == "batches") {
            let batches = writer.dir.subdir("batches", false)?;
            let run_dir = hex(&run.statement.run_id);
            if batches.subdirs()?.contains(&run_dir) {
                anchor = super::anchor::anchor_in(&batches.subdir(&run_dir, false)?)?;
            }
        }
        let low_watermark = anchor.as_ref().map_or(1, |anchor| anchor.low_watermark);
        let gap = match anchor {
            Some(anchor) if from_seq < anchor.low_watermark => Some(super::anchor::Gap {
                low_watermark: anchor.low_watermark,
                anchor,
            }),
            _ => None,
        };
        let from_seq = from_seq.max(low_watermark).max(1);
        let mut found = Vec::new();
        // Below the journal's first frame the run may have opened earlier (WP-5.6).
        let mut in_run = writer
            .base()
            .is_some_and(|base| statement_digest(&base.statement) == run.digest);
        for frame in writer.journal.frames()? {
            match frame.kind {
                RUN_OPEN => in_run = statement_digest(&frame.payload) == run.digest,
                RECORDS if in_run => {
                    let (first, records) = decode_group(&frame.payload)?;
                    for (offset, bytes) in records.into_iter().enumerate() {
                        let seq = first + offset as u64;
                        if seq >= from_seq && found.len() < limit {
                            found.push((seq, bytes));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(super::anchor::Page {
            records: found,
            gap,
        })
    }
}

/// One run as the segments hold it.
#[derive(Debug, Clone)]
struct Run {
    statement: RunStatement,
    digest: [u8; 32],
    last_seq: u64,
    last_digest: [u8; 32],
    ended: bool,
}

impl Run {
    fn end(&self) -> RunEnd {
        RunEnd {
            run_id: self.statement.run_id,
            last_seq: self.last_seq,
            last_record_digest: self.last_digest,
        }
    }
}

/// The journal side, behind the write gate.
struct Writer {
    journal: Journal,
    run: Option<Run>,
    state: Option<State>,
    dir: Dir,
    /// Whether RESERVE holds allocated blocks; `false` where the filesystem cannot, which leaves
    /// the stream to closed pressure.
    reserved: bool,
    /// Where the next seal starts, while its run is current (WP-5.2).
    next: Option<seal::Next>,
}

/// The sequences given and made durable, behind their own lock.
#[derive(Default)]
struct Queue {
    run_id: Option<[u8; 16]>,
    next_seq: u64,
    /// The digest of the last record given a sequence: the `prev` of the next (WP-6.1).
    last_digest: [u8; 32],
    durable: u64,
    pending: Vec<(u64, Vec<u8>)>,
    flushing: bool,
    paused: bool,
    /// The appends given a sequence that have not read their outcome yet: a rollover waits for
    /// none, so no run changes under a caller still to be answered (after the review).
    waiting: usize,
    failed: Option<String>,
    forked: Option<u64>,
}

/// One physical stream: a stream key and its runs.
struct Physical {
    key: StreamKey,
    writer: Mutex<Writer>,
    queue: Mutex<Queue>,
    moved: Condvar,
    /// Where each run's record groups sit in the journal, as far as a read has looked (WP-6.2a).
    groups: Mutex<runs::Groups>,
}

/// A RECORDS frame's payload: the records from `first`, one flush's group.
pub fn encode_group<'a>(
    first: u64,
    records: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, StreamError> {
    encode(vec![
        (1, uint(first)?),
        (
            2,
            Value::Array(
                records
                    .into_iter()
                    .map(|bytes| Value::Bytes(bytes.to_vec()))
                    .collect(),
            ),
        ),
    ])
}

/// A RECORDS frame's first sequence and records.
// conformance: boundary
pub fn decode_group(bytes: &[u8]) -> Result<(u64, Vec<Vec<u8>>), StreamError> {
    if bytes.len() > MAX_GROUP_FRAME_BYTES {
        return Err(StreamError::Invalid(
            "a group of records is out of its bound".to_owned(),
        ));
    }
    let mut map = Map::read(bytes, "a group of records")?;
    let first = map.uint(1)?;
    let records = map
        .array(2)?
        .into_iter()
        .map(|value| match value {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(StreamError::Invalid(
                "a record that is no byte string".to_owned(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    map.finish()?;
    if first == 0 || records.is_empty() || records.len() > MAX_GROUP_RECORDS {
        return Err(StreamError::Invalid(
            "a group of records starts at sequence 1 or later and holds one".to_owned(),
        ));
    }
    Ok((first, records))
}

/// Confirms the cutover of `stream` to `kid` among `streams`: refused unless it is the cutover
/// that stream waits for.
fn confirm(streams: &[Arc<Physical>], stream: &str, kid: &str) -> Result<(), StreamError> {
    let component = stream
        .split('/')
        .nth(2)
        .ok_or_else(|| StreamError::Invalid(format!("`{stream}` names no stream")))?;
    let physical = streams
        .iter()
        .find(|physical| physical.key.resource_component() == component)
        .ok_or_else(|| StreamError::Invalid(format!("`{stream}` is no stream of this Host")))?;
    let writer = physical.writer();
    match seal::cutover_of(&writer.dir)? {
        Some(mut cutover) if cutover.stream == stream && cutover.kid == kid => {
            if !cutover.confirmed {
                cutover.confirmed = true;
                seal::keep_cutover(&writer.dir, &cutover)?;
            }
            Ok(())
        }
        _ => Err(StreamError::Invalid(format!(
            "`{stream}` waits for no cutover to `{kid}`"
        ))),
    }
}

/// The base the journal starts at (WP-5.6): `None` while it holds every frame from 0. A STATE
/// base above the journal's first frame is a deletion a crash stopped after STATE and before
/// `BASE`, finished here; a journal starting after frame 0 where STATE names no base at that
/// frame lost what its open needs, and is corruption.
fn base_of(journal: &mut Journal, state: Option<&State>) -> Result<Option<Base>, StreamError> {
    let base = state.and_then(|state| state.base.clone());
    let first = journal.first_index();
    match &base {
        Some(held) if held.first_index > first => {
            let reached = journal.drop_prefix(held.first_index, None)?;
            if reached != held.first_index {
                return Err(StreamError::Corruption(format!(
                    "STATE's base is at frame {}, and no segment starts there",
                    held.first_index
                )));
            }
        }
        Some(held) if held.first_index == first => {}
        _ if first == 0 => return Ok(None),
        _ => {
            return Err(StreamError::Corruption(format!(
                "the journal starts at frame {first}, and STATE names no base there"
            )));
        }
    }
    Ok(base)
}

fn random_id() -> Result<[u8; 16], StreamError> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StreamError::Sign("the OS random source refused".to_owned()))?;
    Ok(bytes)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Physical {
    /// Opens the stream of `key`, recovering it: the head re-derived from the segments, a torn
    /// tail cut by the journal, a rollover a crash interrupted completed, and a STATE naming
    /// another stream or run refused.
    fn open(
        context: &Context,
        descriptor: &Descriptor,
        key: StreamKey,
    ) -> Result<Self, StreamError> {
        let dir = context
            .dir
            .subdir(&key.resource_component(), true)?
            .subdir(&hex(&key.producer_host_id), true)?;
        let reserved = allocate(&dir, RESERVE_FILE, RESERVE_BYTES)?;
        let (mut journal, _) = Journal::open(
            dir.subdir(RECORDS_DIR, true)?,
            Options {
                claim: context.claim,
                segment_bytes: context.segment_bytes,
                ..Options::default()
            },
        )?;
        let state = read_view(&dir, STATE_FILE, format::VIEW)?
            .map(|bytes| State::decode(&bytes))
            .transpose()?;
        let mut runs: Vec<Run> = Vec::new();
        let mut keys: Option<Vec<permguard_core::keys::Jwk>> = None;
        // Once a prefix went (WP-5.6), the run open at the journal's first frame comes from
        // STATE's base, written before `BASE`: a deletion a crash stopped between the two is
        // finished here, and a journal starting where STATE names no base is corruption.
        if let Some(base) = base_of(&mut journal, state.as_ref())? {
            keys = Some(super::run::own_keys(&context.operations)?);
            let statement =
                RunStatement::verify_among(&base.statement, keys.as_deref().unwrap_or(&[]))?;
            if statement.key != key {
                return Err(StreamError::Corruption(
                    "STATE's base opens a run of another stream".to_owned(),
                ));
            }
            runs.push(Run {
                digest: statement_digest(&base.statement),
                statement,
                last_seq: base.last_seq,
                last_digest: base.last_digest,
                ended: base.ended,
            });
        }
        for frame in journal.frames()? {
            match frame.kind {
                RUN_OPEN => {
                    // The ring's keys read once for every run the segments open (WP-5.2).
                    if keys.is_none() {
                        keys = Some(super::run::own_keys(&context.operations)?);
                    }
                    let statement =
                        RunStatement::verify_among(&frame.payload, keys.as_deref().unwrap_or(&[]))?;
                    if statement.key != key {
                        return Err(StreamError::Corruption(format!(
                            "frame {} opens a run of another stream",
                            frame.index
                        )));
                    }
                    if let Some(previous) = runs.last()
                        && (!previous.ended || statement.predecessor != Some(previous.end()))
                    {
                        return Err(StreamError::Corruption(format!(
                            "frame {} opens a run that does not succeed the one before",
                            frame.index
                        )));
                    }
                    runs.push(Run {
                        digest: statement_digest(&frame.payload),
                        statement,
                        last_seq: 0,
                        last_digest: [0; 32],
                        ended: false,
                    });
                }
                RECORDS => {
                    let run = runs.last_mut().filter(|run| !run.ended).ok_or_else(|| {
                        StreamError::Corruption(format!(
                            "frame {} holds records outside a run",
                            frame.index
                        ))
                    })?;
                    let (first, records) = decode_group(&frame.payload)?;
                    if first != run.last_seq + 1 {
                        return Err(StreamError::Corruption(format!(
                            "frame {} starts at sequence {first}, after {}",
                            frame.index, run.last_seq
                        )));
                    }
                    run.last_seq += records.len() as u64;
                    if let Some(last) = records.last() {
                        run.last_digest = record_digest(descriptor.record_domain, last);
                    }
                }
                TERMINAL => {
                    let end = RunEnd::decode(&frame.payload)?;
                    let run = runs
                        .last_mut()
                        .filter(|run| !run.ended && run.end() == end)
                        .ok_or_else(|| {
                            StreamError::Corruption(format!(
                                "frame {} ends no run it follows",
                                frame.index
                            ))
                        })?;
                    run.ended = true;
                }
                other => {
                    return Err(StreamError::Corruption(format!(
                        "frame {} is of the unknown kind {other}",
                        frame.index
                    )));
                }
            }
        }
        let mut writer = Writer {
            journal,
            run: runs.last().cloned(),
            state,
            dir,
            reserved,
            next: None,
        };
        writer.reconcile(context, &runs)?;
        let mut queue = Queue::default();
        if let Some(run) = &writer.run {
            queue.run_id = Some(run.statement.run_id);
            queue.next_seq = run.last_seq + 1;
            queue.last_digest = run.last_digest;
            queue.durable = run.last_seq;
        }
        queue.forked = writer.state.as_ref().and_then(|state| state.forked_at_seq);
        Ok(Self {
            key,
            writer: Mutex::new(writer),
            queue: Mutex::new(queue),
            moved: Condvar::new(),
            groups: Mutex::new(runs::Groups::default()),
        })
    }

    /// The key of the stream whose directory is `dir`, from the run its journal starts with,
    /// verified; `None` when it holds no run.
    fn key_of(context: &Context, dir: &Dir) -> Result<Option<StreamKey>, StreamError> {
        if !dir.subdirs()?.iter().any(|name| name == RECORDS_DIR) {
            return Ok(None);
        }
        let (journal, _) = Journal::open(
            dir.subdir(RECORDS_DIR, false)?,
            Options {
                claim: context.claim,
                segment_bytes: context.segment_bytes,
                ..Options::default()
            },
        )?;
        // Once a prefix went, the first run is the one STATE's base names (WP-5.6).
        if journal.first_index() > 0 {
            let state = read_view(dir, STATE_FILE, format::VIEW)?
                .map(|bytes| State::decode(&bytes))
                .transpose()?;
            let Some(base) = state.and_then(|state| state.base) else {
                return Err(StreamError::Corruption(format!(
                    "the journal starts at frame {}, and STATE names no base",
                    journal.first_index()
                )));
            };
            return Ok(Some(
                RunStatement::verify_own(&base.statement, &context.operations)?.key,
            ));
        }
        for frame in journal.frames()? {
            if frame.kind == RUN_OPEN {
                return Ok(Some(
                    RunStatement::verify_own(&frame.payload, &context.operations)?.key,
                ));
            }
        }
        Ok(None)
    }

    fn writer(&self) -> MutexGuard<'_, Writer> {
        lock(&self.writer)
    }

    /// The current run, opening a genesis run carrying `fence` when none is.
    fn ensure_run(
        &self,
        context: &Context,
        fence: Option<Fence>,
    ) -> Result<RunStatement, StreamError> {
        let mut writer = self.writer();
        if let Some(run) = &writer.run {
            return Ok(run.statement.clone());
        }
        let statement = RunStatement {
            key: self.key.clone(),
            run_id: random_id()?,
            producer_boot_id: context.boot_id,
            opened_at: context.time.now_secs(),
            predecessor: None,
            fence,
            approval: None,
        };
        let envelope = statement.sign(&context.operations)?;
        writer.journal.append(RUN_OPEN, &envelope)?;
        let run = Run {
            digest: statement_digest(&envelope),
            statement: statement.clone(),
            last_seq: 0,
            last_digest: [0; 32],
            ended: false,
        };
        writer.keep_state(&run, None, None)?;
        writer.run = Some(run);
        let mut queue = lock(&self.queue);
        queue.run_id = Some(statement.run_id);
        queue.next_seq = 1;
        queue.last_digest = [0; 32];
        queue.durable = 0;
        Ok(statement)
    }

    /// Gives the records `build` makes from the next position consecutive sequences, opening a
    /// genesis run carrying `fence` when the stream holds none, and
    /// answers once a flush made the last durable. `build` runs under the queue's lock, so the
    /// position it is handed is the one its records take.
    fn append(
        &self,
        context: &Context,
        fence: Option<Fence>,
        domain: &str,
        build: &mut dyn FnMut(Position) -> Result<Vec<Vec<u8>>, StreamError>,
    ) -> Result<Receipt, StreamError> {
        self.ensure_run(context, fence)?;
        let mut queue = lock(&self.queue);
        loop {
            if let Some(failed) = &queue.failed {
                return Err(StreamError::Invalid(format!(
                    "the stream stopped: {failed}"
                )));
            }
            if let Some(at_seq) = queue.forked {
                return Err(StreamError::Forked { at_seq });
            }
            if !queue.paused {
                break;
            }
            queue = self
                .moved
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
        let Some(run_id) = queue.run_id else {
            return Err(StreamError::Invalid("the stream holds no run".to_owned()));
        };
        let records = build(Position {
            run_id,
            seq: queue.next_seq,
            prev: queue.last_digest,
        })?;
        if records.is_empty() {
            return Err(StreamError::Invalid("an append of no record".to_owned()));
        }
        let mut seq = 0;
        let mut digest = queue.last_digest;
        for bytes in records {
            seq = queue.next_seq;
            queue.next_seq += 1;
            digest = record_digest(domain, &bytes);
            queue.pending.push((seq, bytes));
        }
        queue.last_digest = digest;
        queue.waiting += 1;
        let outcome = loop {
            if queue.durable >= seq && queue.run_id == Some(run_id) {
                break Ok(Receipt {
                    run_id,
                    seq,
                    record_digest: digest,
                });
            }
            if let Some(failed) = &queue.failed {
                break Err(StreamError::Invalid(format!(
                    "the stream stopped: {failed}"
                )));
            }
            if queue.flushing || queue.pending.is_empty() {
                queue = self
                    .moved
                    .wait(queue)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            // This caller leads: the records waiting, up to one frame, share one flush.
            queue.flushing = true;
            let mut taken = 0;
            let mut size = 0;
            for (_, record) in &queue.pending {
                if taken > 0 && (size + record.len() > GROUP_BYTES || taken == MAX_GROUP_RECORDS) {
                    break;
                }
                size += record.len();
                taken += 1;
            }
            let group: Vec<(u64, Vec<u8>)> = queue.pending.drain(..taken).collect();
            drop(queue);
            let written = self.write_group(&group, domain);
            queue = lock(&self.queue);
            queue.flushing = false;
            match written {
                Ok(last) => queue.durable = last,
                Err(error) => queue.failed = Some(error.to_string()),
            }
            self.moved.notify_all();
        };
        queue.waiting -= 1;
        self.moved.notify_all();
        outcome
    }

    /// Writes `group` as one frame and flushes it: answers its last sequence.
    fn write_group(&self, group: &[(u64, Vec<u8>)], domain: &str) -> Result<u64, StreamError> {
        let (Some((first, _)), Some((last, bytes))) = (group.first(), group.last()) else {
            return Err(StreamError::Invalid("an empty group".to_owned()));
        };
        let mut writer = self.writer();
        writer.journal.append(
            RECORDS,
            &encode_group(*first, group.iter().map(|(_, bytes)| bytes.as_slice()))?,
        )?;
        if let Some(run) = writer.run.as_mut() {
            run.last_seq = *last;
            run.last_digest = record_digest(domain, bytes);
        }
        Ok(*last)
    }

    /// Waits for every record given a sequence to be written, and stops new ones.
    fn pause(&self) -> Result<(), StreamError> {
        let mut queue = lock(&self.queue);
        while queue.flushing || !queue.pending.is_empty() || queue.paused || queue.waiting > 0 {
            if let Some(failed) = &queue.failed {
                return Err(StreamError::Invalid(format!(
                    "the stream stopped: {failed}"
                )));
            }
            queue = self
                .moved
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
        queue.paused = true;
        Ok(())
    }

    fn resume(&self) {
        let mut queue = lock(&self.queue);
        queue.paused = false;
        self.moved.notify_all();
    }

    /// Ends the current run and opens its successor: an ordinary rollover when `approval` is
    /// `None`, refused while forked; a successor after a fork when it names the approved plan.
    fn rollover(
        &self,
        context: &Context,
        fence: Option<Fence>,
        approval: Option<[u8; 32]>,
    ) -> Result<RunStatement, StreamError> {
        let has_run = self.writer().run.is_some();
        if !has_run {
            if approval.is_some() {
                return Err(StreamError::Invalid(
                    "an approval authorizes the successor of a run".to_owned(),
                ));
            }
            return self.ensure_run(context, fence);
        }
        self.pause()?;
        let rolled = self.roll(context, fence, approval);
        self.resume();
        rolled
    }

    fn roll(
        &self,
        context: &Context,
        fence: Option<Fence>,
        approval: Option<[u8; 32]>,
    ) -> Result<RunStatement, StreamError> {
        let mut writer = self.writer();
        let forked = writer.state.as_ref().and_then(|state| state.forked_at_seq);
        match (forked, approval) {
            (Some(at_seq), None) => return Err(StreamError::Forked { at_seq }),
            (None, Some(_)) => {
                return Err(StreamError::Invalid(
                    "an approval authorizes only the successor of a forked stream".to_owned(),
                ));
            }
            _ => {}
        }
        let Some(run) = writer.run.clone() else {
            return Err(StreamError::Invalid("the stream holds no run".to_owned()));
        };
        let statement = RunStatement {
            key: self.key.clone(),
            run_id: random_id()?,
            producer_boot_id: context.boot_id,
            opened_at: context.time.now_secs(),
            predecessor: Some(run.end()),
            fence,
            approval,
        };
        let envelope = statement.sign(&context.operations)?;
        let rolled = writer.complete_rollover(&run, envelope);
        // The queue follows the journal whatever step failed: the run the segments end with.
        let mut queue = lock(&self.queue);
        if let Some(current) = &writer.run {
            queue.run_id = Some(current.statement.run_id);
            queue.next_seq = current.last_seq + 1;
            queue.last_digest = current.last_digest;
            queue.durable = current.last_seq;
            if current.statement.run_id == statement.run_id {
                queue.forked = None;
            }
        }
        rolled?;
        Ok(statement)
    }

    fn report_fork(&self, at_seq: u64) -> Result<(), StreamError> {
        let mut writer = self.writer();
        let Some(run) = writer.run.clone() else {
            return Err(StreamError::Invalid("the stream holds no run".to_owned()));
        };
        writer.keep_state(&run, None, Some(at_seq))?;
        lock(&self.queue).forked = Some(at_seq);
        self.moved.notify_all();
        Ok(())
    }
}

impl Writer {
    /// STATE's base, once the journal no longer starts at frame 0 (WP-5.6).
    fn base(&self) -> Option<&Base> {
        let first = self.journal.first_index();
        self.state
            .as_ref()
            .and_then(|state| state.base.as_ref())
            .filter(|base| first > 0 && base.first_index == first)
    }

    /// Keeps `base` as STATE's, before the journal's prefix goes (WP-5.6b).
    fn keep_base(&mut self, base: Base) -> Result<(), StreamError> {
        let Some(mut state) = self.state.clone() else {
            return Err(StreamError::Corruption(
                "a stream whose prefix goes holds no STATE".to_owned(),
            ));
        };
        state.base = Some(base);
        replace_view(&self.dir, STATE_FILE, format::VIEW, &state.encode()?)?;
        self.state = Some(state);
        Ok(())
    }

    /// Puts STATE's base back to `base`, after a prefix deletion that did not reach the journal.
    fn restore_base(&mut self, base: Option<Base>) -> Result<(), StreamError> {
        let Some(mut state) = self.state.clone() else {
            return Ok(());
        };
        state.base = base;
        replace_view(&self.dir, STATE_FILE, format::VIEW, &state.encode()?)?;
        self.state = Some(state);
        Ok(())
    }

    /// Keeps `mark` as STATE's `unshipped`, or removes it (WP-5.8).
    fn keep_unshipped(&mut self, mark: Option<super::state::Unshipped>) -> Result<(), StreamError> {
        // A stream behind holds a run, and so a STATE: a mark with nowhere to go is never lost
        // quietly (after the review).
        let Some(mut state) = self.state.clone() else {
            return match mark {
                Some(_) => Err(StreamError::Corruption(
                    "a stream behind holds no STATE to mark".to_owned(),
                )),
                None => Ok(()),
            };
        };
        if state.unshipped == mark {
            return Ok(());
        }
        state.unshipped = mark;
        replace_view(&self.dir, STATE_FILE, format::VIEW, &state.encode()?)?;
        self.state = Some(state);
        Ok(())
    }

    /// Moves STATE's `acknowledged_seq` to `acknowledged`, the current run's `truncate_safe`,
    /// never past `signed_seq` (WP-5.4).
    fn keep_acknowledged(&mut self, acknowledged: u64) -> Result<(), StreamError> {
        let Some(mut state) = self.state.clone() else {
            return Ok(());
        };
        // Never backwards (after the review).
        let acknowledged = acknowledged.min(state.signed_seq);
        if acknowledged <= state.acknowledged_seq {
            return Ok(());
        }
        state.acknowledged_seq = acknowledged;
        replace_view(&self.dir, STATE_FILE, format::VIEW, &state.encode()?)?;
        self.state = Some(state);
        Ok(())
    }

    /// Moves STATE's `signed_seq` to `signed`, the watermark the batch files of `run` cover.
    fn keep_signed(&mut self, run: &Run, signed: u64) -> Result<(), StreamError> {
        let Some(mut state) = self
            .state
            .clone()
            .filter(|state| state.run_id == run.statement.run_id)
        else {
            return Err(StreamError::Corruption(
                "STATE names another run than the stream writes".to_owned(),
            ));
        };
        if state.signed_seq == signed {
            return Ok(());
        }
        // The head moves with it: a watermark never passes the durable one STATE names.
        state.next_seq = run.last_seq + 1;
        state.durable_seq = run.last_seq;
        state.signed_seq = signed;
        replace_view(&self.dir, STATE_FILE, format::VIEW, &state.encode()?)?;
        self.state = Some(state);
        Ok(())
    }

    /// Writes STATE for `run`: its watermarks at the head, with `pending` and `forked`.
    fn keep_state(
        &mut self,
        run: &Run,
        pending: Option<Vec<u8>>,
        forked: Option<u64>,
    ) -> Result<(), StreamError> {
        let held = self
            .state
            .as_ref()
            .filter(|state| state.run_id == run.statement.run_id);
        let state = State {
            run_id: run.statement.run_id,
            run_statement_digest: run.digest,
            next_seq: run.last_seq + 1,
            durable_seq: run.last_seq,
            signed_seq: held.map_or(0, |state| state.signed_seq.min(run.last_seq)),
            acknowledged_seq: held.map_or(0, |state| state.acknowledged_seq.min(run.last_seq)),
            oldest_retained_seq: held.map_or(1, |state| state.oldest_retained_seq),
            pending_successor: pending,
            forked_at_seq: forked,
            // A drain's mark outlives a rollover: it goes only when nothing is behind.
            unshipped: self.state.as_ref().and_then(|state| state.unshipped),
            // What the journal's deleted prefix gave its open belongs to the journal, not the run.
            base: self.state.as_ref().and_then(|state| state.base.clone()),
        };
        replace_view(&self.dir, STATE_FILE, format::VIEW, &state.encode()?)?;
        self.state = Some(state);
        Ok(())
    }

    /// The rollover from `run` to the successor `envelope` signs, from wherever a crash left it:
    /// STATE names the successor, the old run ends, the successor opens, STATE names it.
    fn complete_rollover(&mut self, run: &Run, envelope: Vec<u8>) -> Result<(), StreamError> {
        let forked = self.state.as_ref().and_then(|state| state.forked_at_seq);
        let pending = self
            .state
            .as_ref()
            .and_then(|state| state.pending_successor.clone());
        if pending.as_deref() != Some(envelope.as_slice()) {
            self.keep_state(run, Some(envelope.clone()), forked)?;
        }
        // The terminal and the successor take the reserve's blocks when nothing else is left.
        if self.reserved {
            release(&self.dir, RESERVE_FILE)?;
        }
        if !run.ended {
            self.journal.append(TERMINAL, &run.end().encode()?)?;
            if let Some(held) = self.run.as_mut() {
                held.ended = true;
            }
        }
        let statement = RunStatement::decode(
            permguard_objects::cose::Sign1::decode(&envelope)
                .map_err(|error| StreamError::Invalid(error.to_string()))?
                .payload_unverified(),
        )?;
        self.journal.append(RUN_OPEN, &envelope)?;
        let successor = Run {
            digest: statement_digest(&envelope),
            statement,
            last_seq: 0,
            last_digest: [0; 32],
            ended: false,
        };
        // The segments are the authority from here: the successor is the run, whatever fails
        // after it (after the review). A STATE left behind is reconciled at the next open; a
        // reserve that cannot be allocated again leaves the stream to closed pressure.
        self.run = Some(successor.clone());
        self.reserved = allocate(&self.dir, RESERVE_FILE, RESERVE_BYTES).unwrap_or(false);
        self.keep_state(&successor, None, None)
    }

    /// Makes STATE and the segments agree after a crash, or refuses a STATE of another stream.
    fn reconcile(&mut self, context: &Context, runs: &[Run]) -> Result<(), StreamError> {
        let Some(current) = runs.last().cloned() else {
            if self.state.is_some() {
                return Err(StreamError::Corruption(
                    "STATE names a run the segments do not hold".to_owned(),
                ));
            }
            return Ok(());
        };
        let Some(state) = self.state.clone() else {
            // A crash between RUN_OPEN and STATE.
            Self::not_ended(&current)?;
            return self.keep_state(&current, None, None);
        };
        if let Some(pending) = state.pending_successor.clone() {
            let successor = RunStatement::verify_own(&pending, &context.operations)?;
            if statement_digest(&pending) == current.digest {
                // The successor opened; STATE did not follow yet.
                return self.keep_state(&current, None, None);
            }
            if state.run_statement_digest == current.digest
                && successor.predecessor == Some(current.end())
            {
                // The rollover stopped before the successor opened: finish it.
                return self.complete_rollover(&current, pending);
            }
            return Err(StreamError::Corruption(
                "STATE names a successor of another run".to_owned(),
            ));
        }
        if state.run_statement_digest != current.digest {
            return Err(StreamError::Corruption(
                "STATE names another stream or run than its segments end with".to_owned(),
            ));
        }
        if state.durable_seq > current.last_seq {
            return Err(StreamError::Corruption(format!(
                "STATE says sequence {} was durable, the segments end at {}",
                state.durable_seq, current.last_seq
            )));
        }
        Self::not_ended(&current)
    }

    /// Refuses a stream whose last run ended and names no successor: nothing may be written
    /// after its TERMINAL (after the review).
    fn not_ended(run: &Run) -> Result<(), StreamError> {
        if run.ended {
            return Err(StreamError::Corruption(
                "the last run ended and no successor is named".to_owned(),
            ));
        }
        Ok(())
    }
}

impl<C: RecordCodec> permguard_host::composition::StreamAppender for Producer<C> {
    fn append(
        &self,
        resource: &Resource,
        record: &[u8],
    ) -> Result<permguard_host::composition::StreamReceipt, String> {
        self.append_bytes(resource, record.to_vec())
            .map(|receipt| permguard_host::composition::StreamReceipt {
                run_id: receipt.run_id,
                seq: receipt.seq,
            })
            .map_err(|error| error.to_string())
    }

    fn append_with(
        &self,
        resource: &Resource,
        build: permguard_host::composition::BuildRecords<'_>,
    ) -> Result<permguard_host::composition::StreamReceipt, String> {
        Producer::append_with(self, resource, |position| {
            build(permguard_host::composition::StreamPosition {
                run_id: position.run_id,
                seq: position.seq,
                prev: position.prev,
            })
        })
        .map(|receipt| permguard_host::composition::StreamReceipt {
            run_id: receipt.run_id,
            seq: receipt.seq,
        })
        .map_err(|error| error.to_string())
    }

    fn pressure(
        &self,
        resource: &Resource,
        max_bytes: u64,
        max_age_secs: u64,
    ) -> Result<Option<&'static str>, String> {
        // Without a ring nothing is ever sealed or acknowledged, so the pressure is unknown: an
        // error, which a Plane refuses its records on, never `None`.
        Producer::pressure(
            self,
            resource,
            PressureBounds {
                max_bytes,
                max_age_secs,
            },
        )
        .map_err(|error| error.to_string())
    }

    fn runs(
        &self,
        resource: &Resource,
    ) -> Result<Vec<permguard_host::composition::ProducedRun>, String> {
        self.produced_runs(resource)
            .map_err(|error| error.to_string())
    }

    fn records(
        &self,
        resource: &Resource,
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<permguard_host::composition::ConsumedPage, String> {
        let page = self
            .produced_records(resource, run, from, limit)
            .map_err(|error| error.to_string())?;
        Ok(permguard_host::composition::ConsumedPage {
            records: page.records,
            low_watermark: page.gap.map(|gap| gap.low_watermark),
        })
    }

    fn retain_above(
        &self,
        floor: Arc<dyn permguard_host::composition::StreamFloor>,
    ) -> Result<(), String> {
        *self
            .floor
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Arc::new(super::retention::PlaneFloor(floor)));
        Ok(())
    }
}

impl<C: RecordCodec> permguard_host::composition::StreamCutovers for Producer<C> {
    fn due(
        &self,
        membership_id: &[u8; 16],
        ring: &str,
        kid: &str,
    ) -> Result<Vec<(String, u64)>, String> {
        if ring != self.descriptor.ring {
            return Ok(Vec::new());
        }
        self.due_cutovers(membership_id, kid)
            .map_err(|error| error.to_string())
    }

    fn journaled(&self, ring: &str, kid: &str, streams: &[(String, u64)]) -> Result<(), String> {
        if ring != self.descriptor.ring {
            return Ok(());
        }
        let ours = format!("{}/{}/", self.descriptor.plane, self.descriptor.stream_type);
        let mine: Vec<&(String, u64)> = streams
            .iter()
            .filter(|(stream, _)| stream.starts_with(&ours))
            .collect();
        if mine.is_empty() {
            return Ok(());
        }
        // The streams on disk, listed once for them all (after the review).
        let every = self.every().map_err(|error| error.to_string())?;
        for (stream, _) in mine {
            confirm(&every, stream, kid).map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

impl<C: RecordCodec> super::retention::Prunable for Producer<C> {
    fn name(&self) -> String {
        format!(
            "producer {}/{} version {}",
            self.descriptor.plane, self.descriptor.stream_type, self.descriptor.version
        )
    }

    fn plan(&self, _now: u64) -> Result<Vec<super::retention::Pruned>, StreamError> {
        let mut planned = Vec::new();
        for physical in self.every()? {
            planned.extend(self.prune_stream(&physical, None)?);
        }
        Ok(planned)
    }

    fn run(
        &self,
        _now: u64,
        audit: super::retention::Audit<'_>,
    ) -> Result<Option<Vec<super::retention::Pruned>>, StreamError> {
        let Some(_held) = self.lease.take() else {
            return Ok(None);
        };
        // One stream that fails does not stop the others, nor their records (after the review).
        let mut pruned = Vec::new();
        for physical in self.every()? {
            match self.prune_stream(&physical, Some(audit)) {
                Ok(done) => pruned.extend(done),
                Err(error) => tracing::error!(
                    event.name = "host.stream.prune_failed",
                    component = "host",
                    stream = %Self::pruned_name(&physical),
                    error = %error,
                    "a stream's garbage collection pass failed; the others go on"
                ),
            }
        }
        Ok(Some(pruned))
    }
}
