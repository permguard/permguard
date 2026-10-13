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
use super::state::State;
use super::{Descriptor, RecordCodec, StreamError, StreamKey, hex, record_digest};

mod seal;

pub use seal::{
    Cutover, MAX_CUTOVER_BYTES, MAX_SIGNERS_BYTES, Sealing, Span, Spans, canonical_jwk,
};

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
}

/// What an append answers once its record is durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub run_id: [u8; 16],
    pub seq: u64,
    pub record_digest: [u8; 32],
}

/// The typed producer handle of one descriptor.
pub struct Producer<C> {
    context: Context,
    descriptor: Descriptor,
    codec: C,
    streams: Mutex<BTreeMap<String, Arc<Physical>>>,
    /// The descriptor's ring, once the Host handed it: what batches are sealed under.
    signer: Option<Arc<Ring>>,
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
        }
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
        let Some(signer) = &self.signer else {
            return Err(StreamError::Sign(
                "the producer was handed no ring to seal under".to_owned(),
            ));
        };
        let bound = max_records.min(u64::from(self.descriptor.max_batch_records));
        self.physical(resource)?
            .seal(&self.context, &self.descriptor, signer, bound)
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
        if bytes.len() > self.descriptor.max_record_bytes as usize {
            return Err(StreamError::Invalid(format!(
                "a record of {} bytes; this stream takes up to {}",
                bytes.len(),
                self.descriptor.max_record_bytes
            )));
        }
        // The typed validator: what is appended reads back as a record, and is its canonical
        // encoding (after the review).
        let record = self.codec.decode(&bytes).map_err(StreamError::Invalid)?;
        if self.codec.encode(&record).map_err(StreamError::Invalid)? != bytes {
            return Err(StreamError::Invalid(
                "a record is appended in its canonical encoding".to_owned(),
            ));
        }
        let physical = self.physical(resource)?;
        physical.append(&self.context, bytes, self.descriptor.record_domain)
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

    /// The stream's STATE, once it holds a run.
    pub fn state(&self, resource: &Resource) -> Result<Option<State>, StreamError> {
        let physical = self.physical(resource)?;
        let writer = physical.writer();
        Ok(writer.state.clone())
    }

    /// The records of the current run from `from_seq`, at most `limit`.
    pub fn read(
        &self,
        resource: &Resource,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, C::Record)>, StreamError> {
        let physical = self.physical(resource)?;
        let writer = physical.writer();
        let Some(run) = &writer.run else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        let mut in_run = false;
        for frame in writer.journal.frames()? {
            match frame.kind {
                RUN_OPEN => in_run = statement_digest(&frame.payload) == run.digest,
                RECORDS if in_run => {
                    let (first, records) = decode_group(&frame.payload)?;
                    for (offset, bytes) in records.into_iter().enumerate() {
                        let seq = first + offset as u64;
                        if seq >= from_seq && found.len() < limit {
                            found.push((
                                seq,
                                self.codec.decode(&bytes).map_err(StreamError::Invalid)?,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(found)
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
        let (journal, _) = Journal::open(
            dir.subdir(RECORDS_DIR, true)?,
            Options {
                claim: context.claim,
                ..Options::default()
            },
        )?;
        let mut runs: Vec<Run> = Vec::new();
        let mut keys: Option<Vec<permguard_core::keys::Jwk>> = None;
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
        let state = read_view(&dir, STATE_FILE, format::VIEW)?
            .map(|bytes| State::decode(&bytes))
            .transpose()?;
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
            queue.durable = run.last_seq;
        }
        queue.forked = writer.state.as_ref().and_then(|state| state.forked_at_seq);
        Ok(Self {
            key,
            writer: Mutex::new(writer),
            queue: Mutex::new(queue),
            moved: Condvar::new(),
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
                ..Options::default()
            },
        )?;
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
        queue.durable = 0;
        Ok(statement)
    }

    /// Gives `bytes` the next sequence and answers once a flush made it durable.
    fn append(
        &self,
        context: &Context,
        bytes: Vec<u8>,
        domain: &str,
    ) -> Result<Receipt, StreamError> {
        self.ensure_run(context, None)?;
        let digest = record_digest(domain, &bytes);
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
        let seq = queue.next_seq;
        queue.next_seq += 1;
        queue.pending.push((seq, bytes));
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
