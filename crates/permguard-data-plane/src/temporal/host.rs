// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One ledger's events on the Host's stream producer (WP-6.2a, owner decisions of 2026-10-18).
//!
//! ```text
//! submit ──► HostLedger ──► data/events, resource plane/data/zone/<id>/ledger/<id>
//!               │              the Host's producer: run, sequence, flush, seal, events.ship
//!               ▼
//!   planes/data/temporal/<zone>/<ledger>/
//!     LEGACY       the last sequence of the legacy journal, read before the Host runs
//!     RUNS         each Host run and the local ordinal its sequence 1 follows
//!     occurrences/ (source, event_id) → position, digest and the answer given: durable
//!     indexes/     the positions by type, history, action, kind and time: rebuildable
//! ```
//!
//! The plane keeps no record bytes: every read goes to the producer. What it keeps is where each
//! record is and what it is for, by one local ordinal: the legacy journal's sequences first, then
//! each Host run in the order the producer opened it, `base + seq`. The ordinal is what the
//! sequencer orders turns by and what a replay is bounded by, across runs.
//!
//! A record is durable once the producer's flush covers it; its occurrence entry and index
//! entries follow, and a crash between the two is caught up from the producer when the ledger is
//! opened again, so a durable record is never invisible and never recorded twice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use permguard_core::authz::Resource;
use permguard_events::index::{Index, Located, Query};
use permguard_events::journal::{JournalError, KnownOccurrence};
use permguard_events::record::{GENESIS, PRODUCER_CLASS_DATA_PLANE, Producer, Record, Stream};
use permguard_host::composition::StreamProducer;
use permguard_stream::engine::RecordCodec as _;
use serde_json::Value;

const LEGACY_FILE: &str = "LEGACY";
/// What marks a ledger the plane recorded on the Host: written when it is first opened.
pub const LEGACY_MARK: &str = LEGACY_FILE;
const RUNS_FILE: &str = "RUNS";
const OCCURRENCES_DIR: &str = "occurrences";
const OCCURRENCE_SUFFIX: &str = ".json";
const OCCURRENCES_COVERED_FILE: &str = "COVERED";
const INDEXES_DIR: &str = "indexes";

/// The most records one read of the producer takes.
const READ_PAGE: usize = 1024;

/// The widest gap between two wanted sequences a scan reads across rather than skipping.
const SCAN_GAP: u64 = 64;

/// Where a ledger's plane-side state lives below `root`, `planes/data/temporal`.
pub fn directory(root: &Path, zone: &str, ledger: &str) -> PathBuf {
    root.join(zone).join(ledger)
}

fn io(error: impl std::fmt::Display) -> JournalError {
    JournalError::Io(error.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (at, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The occurrence key: the source and the id, the source empty for a legacy entry.
fn occurrence_key(source: Option<&str>, event_id: &str) -> (String, String) {
    (source.unwrap_or_default().to_owned(), event_id.to_owned())
}

/// The occurrence entries, durable: one file per `(source, event_id)`, sharded by the first byte of
/// its digest, written through a temporary and a rename and flushed once per batch, as the legacy
/// journal kept them. A file is addressed by a digest of the key, so a read checks the key it holds.
struct Occurrences {
    directory: PathBuf,
    /// The entries written since the last flush: `(shard, name)`.
    pending: std::collections::BTreeSet<(String, String)>,
}

impl Occurrences {
    fn open(ledger: &Path) -> Result<Self, JournalError> {
        let directory = ledger.join(OCCURRENCES_DIR);
        std::fs::create_dir_all(&directory).map_err(io)?;
        // A temporary a crashed write left is never an entry: swept, in every shard.
        let root = permguard_host::storage::Dir::create_root(&directory).map_err(io)?;
        for shard in root.subdirs().map_err(io)? {
            root.subdir(&shard, false)
                .and_then(|dir| dir.sweep_temps())
                .map_err(io)?;
        }
        Ok(Self {
            directory,
            pending: std::collections::BTreeSet::new(),
        })
    }

    /// The shard and file name of a key.
    fn address(source: Option<&str>, event_id: &str) -> (String, String) {
        let (source, event_id) = occurrence_key(source, event_id);
        let mut key = source.into_bytes();
        key.push(0);
        key.extend_from_slice(event_id.as_bytes());
        let digest = permguard_events::record::digest_hex(&key);
        (
            digest.get(..2).unwrap_or("00").to_owned(),
            format!("{digest}{OCCURRENCE_SUFFIX}"),
        )
    }

    fn get(
        &self,
        source: Option<&str>,
        event_id: &str,
    ) -> Result<Option<KnownOccurrence>, JournalError> {
        let (shard, name) = Self::address(source, event_id);
        let path = self.directory.join(&shard).join(&name);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(error)),
        };
        let held: KnownOccurrence = serde_json::from_slice(&bytes)
            .map_err(|error| JournalError::Corrupt(format!("{}: {error}", path.display())))?;
        // A digest collision must never be read as a retry of another occurrence.
        if held.event_id != event_id || held.source.as_deref() != source {
            return Err(JournalError::Corrupt(format!(
                "{} holds another occurrence than the one it was addressed as",
                path.display()
            )));
        }
        Ok(Some(held))
    }

    /// Writes `known`, flushed by [`Self::sync`].
    fn stage(&mut self, known: &KnownOccurrence) -> Result<(), JournalError> {
        let (shard, name) = Self::address(known.source.as_deref(), &known.event_id);
        let bytes = serde_json::to_vec(known).map_err(|error| {
            JournalError::Malformed(format!("an occurrence entry does not render: {error}"))
        })?;
        let dir = permguard_host::storage::Dir::create_root(&self.directory)
            .and_then(|root| root.subdir(&shard, true))
            .map_err(io)?;
        let temporary = permguard_host::storage::dir::temp_name();
        {
            let mut file = dir.create_exclusive(&temporary).map_err(io)?;
            permguard_core::fault::write(&self.directory, bytes.len(), || {
                std::io::Write::write_all(&mut file, &bytes)
            })
            .map_err(io)?;
        }
        dir.rename(&temporary, &name).map_err(io)?;
        self.pending.insert((shard, name));
        Ok(())
    }

    /// Flushes every entry written since the last call, then every shard naming one, then the
    /// root.
    fn sync(&mut self) -> Result<(), JournalError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let root = permguard_host::storage::Dir::open(&self.directory).map_err(io)?;
        let mut shards = std::collections::BTreeSet::new();
        for (shard, name) in &self.pending {
            root.subdir(shard, false)
                .and_then(|dir| dir.sync_file(name))
                .map_err(io)?;
            shards.insert(shard.clone());
        }
        for shard in shards {
            root.subdir(&shard, false)
                .and_then(|dir| dir.sync())
                .map_err(io)?;
        }
        root.sync().map_err(io)?;
        self.pending.clear();
        Ok(())
    }

    /// The highest ordinal whose entry is durable, contiguously.
    fn covered(&self) -> Result<u64, JournalError> {
        match std::fs::read_to_string(self.directory.join(OCCURRENCES_COVERED_FILE)) {
            Ok(text) => text.trim().parse().map_err(|error| {
                JournalError::Corrupt(format!("{OCCURRENCES_COVERED_FILE}: {error}"))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(io(error)),
        }
    }

    fn cover(&self, through: u64) -> Result<(), JournalError> {
        let dir = permguard_host::storage::Dir::open(&self.directory).map_err(io)?;
        permguard_host::storage::write::replace_bytes(
            &dir,
            OCCURRENCES_COVERED_FILE,
            through.to_string().as_bytes(),
        )
        .map_err(io)
    }

    /// Forgets the entries naming an ordinal below `oldest`.
    fn forget_below(&mut self, oldest: u64) -> Result<usize, JournalError> {
        let root = permguard_host::storage::Dir::open(&self.directory).map_err(io)?;
        let mut gone = 0;
        for shard in root.subdirs().map_err(io)? {
            let dir = root.subdir(&shard, false).map_err(io)?;
            for name in dir.names().map_err(io)? {
                if !name.ends_with(OCCURRENCE_SUFFIX) {
                    continue;
                }
                let bytes = dir.read(&name).map_err(io)?.unwrap_or_default();
                // Unreadable, or naming what went: removed rather than kept for ever.
                let stale = serde_json::from_slice::<KnownOccurrence>(&bytes)
                    .map_or(true, |held| held.seq < oldest);
                if stale && dir.unlink(&name).map_err(io)? {
                    gone += 1;
                }
            }
            dir.sync().map_err(io)?;
        }
        Ok(gone)
    }
}

/// What one append wrote, record by record: the ordinal, the record's digest and the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    pub ordinal: u64,
    pub digest: String,
    pub run: String,
}

/// One ledger's events on the Host's producer, and what the plane keeps about them.
pub struct HostLedger {
    resource: Resource,
    producer: StreamProducer,
    /// The `host_id`, 32 lowercase hex digits: every record's producer id.
    host_id: String,
    directory: PathBuf,
    /// The legacy journal's last sequence: the Host runs' ordinals follow it.
    legacy_through: u64,
    /// Each Host run, in the order the producer opened it, with the ordinal its sequence 1
    /// follows.
    runs: Vec<([u8; 16], u64)>,
    /// The last ordinal held.
    last: u64,
    index: Index,
    occurrences: Occurrences,
    /// The ordinal below which entries were last forgotten: a pass that would forget nothing more
    /// reads nothing (after the review).
    forgotten_below: u64,
    /// Set when records became durable on the producer and their entries did not: the next write
    /// catches them up first, so a retry of what is durable is recognised rather than appended
    /// again (after the review).
    behind: bool,
}

impl HostLedger {
    /// Opens `zone`/`ledger` under `directory`, the Host runs following `legacy_through`, the
    /// legacy journal's last sequence when this plane first opens the ledger on the Host; what
    /// the producer holds beyond what the plane recorded is caught up.
    pub fn open(
        producer: StreamProducer,
        host_id: [u8; 16],
        zone: &str,
        ledger: &str,
        directory: PathBuf,
        legacy_through: u64,
    ) -> Result<Self, JournalError> {
        std::fs::create_dir_all(directory.join(INDEXES_DIR)).map_err(io)?;
        let dir = permguard_host::storage::Dir::create_root(&directory).map_err(io)?;
        let legacy_through = match std::fs::read_to_string(directory.join(LEGACY_FILE)) {
            Ok(text) => text
                .trim()
                .parse()
                .map_err(|error| JournalError::Corrupt(format!("{LEGACY_FILE}: {error}")))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Fixed once: the legacy journal is never written again, and an ordinal must
                // never move once given.
                permguard_host::storage::write::replace_bytes(
                    &dir,
                    LEGACY_FILE,
                    legacy_through.to_string().as_bytes(),
                )
                .map_err(io)?;
                legacy_through
            }
            Err(error) => return Err(io(error)),
        };
        let runs = read_runs(&directory)?;
        let (index, loaded) = Index::detached(directory.join(INDEXES_DIR))?;
        let mut held = Self {
            resource: Resource::ledger(crate::service::PLANE, zone, ledger),
            producer,
            host_id: hex(&host_id),
            directory,
            legacy_through,
            runs,
            last: legacy_through,
            index,
            occurrences: Occurrences::open(&dir_path(&dir))?,
            behind: false,
            forgotten_below: 0,
        };
        if !loaded {
            held.index.reset()?;
        }
        held.catch_up()?;
        Ok(held)
    }

    /// Catches up what the producer holds beyond the entries, when an append left them behind:
    /// called before anything is checked against them.
    pub fn repaired(&mut self) -> Result<(), JournalError> {
        if self.behind {
            self.catch_up()?;
            self.behind = false;
        }
        Ok(())
    }

    /// The resource this ledger's stream is of.
    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    /// The last ordinal this ledger holds.
    pub fn last(&self) -> u64 {
        self.last
    }

    /// The legacy journal's last sequence, which the Host runs follow.
    pub fn legacy_through(&self) -> u64 {
        self.legacy_through
    }

    /// The run this ledger's stream last wrote in, 32 lowercase hex digits.
    pub fn current_run(&self) -> Option<String> {
        self.runs.last().map(|(run, _)| hex(run))
    }

    /// Learns the runs the producer opened since, and indexes and records the occurrences of what
    /// it holds beyond what the plane recorded.
    fn catch_up(&mut self) -> Result<(), JournalError> {
        let produced = self.producer.runs(&self.resource).map_err(io)?;
        let mut previous: Option<(u64, u64)> = None;
        let mut learned = false;
        for run in &produced {
            let base = match self.base_of(&run.run) {
                Some(base) => base,
                None => {
                    let base = previous.map_or(self.legacy_through, |(base, last)| base + last);
                    self.runs.push((run.run, base));
                    learned = true;
                    base
                }
            };
            previous = Some((base, run.last_seq));
        }
        if learned {
            write_runs(&self.directory, &self.runs)?;
        }
        self.last = previous.map_or(self.legacy_through, |(base, last)| base + last);
        let indexed = self.index.covered_through().max(self.legacy_through);
        let recorded = self.occurrences.covered()?.max(self.legacy_through);
        let from = indexed.min(recorded);
        if from >= self.last {
            return Ok(());
        }
        let mut after = from;
        loop {
            let page = self.read_from(after, READ_PAGE)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            after = *last;
            for (ordinal, record) in &page {
                if *ordinal > indexed {
                    self.stage_index(*ordinal, record)?;
                }
                if *ordinal > recorded {
                    self.recover_occurrence(*ordinal, record)?;
                }
            }
            if after >= self.last {
                break;
            }
        }
        self.index.sync()?;
        self.occurrences.sync()?;
        self.occurrences.cover(self.last)?;
        Ok(())
    }

    fn recover_occurrence(&mut self, ordinal: u64, record: &Value) -> Result<(), JournalError> {
        let field = |name: &str| {
            record
                .get(name)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| JournalError::Corrupt(format!("an event record with no `{name}`")))
        };
        let event_id = field("event_id")?;
        let digest = field("occurrence_digest")?;
        let source = record
            .get("source")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        match self.occurrences.get(source.as_deref(), &event_id)? {
            Some(known) if known.seq == ordinal && known.occurrence_digest == digest => Ok(()),
            Some(known) => Err(JournalError::Corrupt(format!(
                "the occurrence `{event_id}` names position {} with digest `{}`, and the \
                 durable record is position {ordinal} with digest `{digest}`",
                known.seq, known.occurrence_digest
            ))),
            None => self.occurrences.stage(&KnownOccurrence {
                event_id,
                source,
                seq: ordinal,
                occurrence_digest: digest,
                decision_id: None,
                profile: None,
                kind: record
                    .get("event_type")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                response: Value::Null,
            }),
        }
    }

    fn stage_index(&mut self, ordinal: u64, record: &Value) -> Result<(), JournalError> {
        let Some((mut key, _)) = permguard_events::index::entry_of(record, 0, 0, 0) else {
            return Err(JournalError::Corrupt(
                "an event record the index cannot place".to_owned(),
            ));
        };
        // The record's own sequence is its run's; the ordinal orders across runs.
        key.seq = ordinal;
        self.index.stage(
            key,
            Located {
                seq: ordinal,
                segment: 0,
                offset: 0,
                length: 0,
            },
        )
    }

    fn base_of(&self, run: &[u8; 16]) -> Option<u64> {
        self.runs
            .iter()
            .find(|(held, _)| held == run)
            .map(|(_, base)| *base)
    }

    /// The run and sequence an ordinal of the Host runs names.
    fn locate(&self, ordinal: u64) -> Option<([u8; 16], u64)> {
        self.runs
            .iter()
            .rev()
            .find(|(_, base)| *base < ordinal)
            .map(|(run, base)| (*run, ordinal - base))
    }

    /// The Host runs' records after ordinal `after`, at most `limit`, by ordinal; what the
    /// producer deleted is skipped.
    pub fn read_from(&self, after: u64, limit: usize) -> Result<Vec<(u64, Value)>, JournalError> {
        let mut found = Vec::new();
        let from = after.max(self.legacy_through) + 1;
        let Some(start) = self
            .runs
            .iter()
            .rposition(|(_, base)| *base < from)
            .or_else(|| (!self.runs.is_empty()).then_some(0))
        else {
            return Ok(found);
        };
        for (at, (run, base)) in self.runs.iter().enumerate().skip(start) {
            let next_base = self.runs.get(at + 1).map(|(_, next)| *next);
            let mut seq = from.saturating_sub(*base).max(1);
            while found.len() < limit {
                if next_base.is_some_and(|next| base + seq > next) {
                    break;
                }
                let page = self
                    .producer
                    .records(
                        &self.resource,
                        run,
                        seq,
                        (limit - found.len()).min(READ_PAGE),
                    )
                    .map_err(io)?;
                let Some((last, _)) = page.records.last() else {
                    break;
                };
                let last = *last;
                for (held, bytes) in page.records {
                    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                        JournalError::Corrupt(format!("a Host event record: {error}"))
                    })?;
                    found.push((base + held, value));
                }
                seq = last + 1;
            }
            if found.len() >= limit {
                break;
            }
        }
        Ok(found)
    }

    /// The record at one ordinal of the Host runs.
    pub fn record_at(&self, ordinal: u64) -> Result<Option<Value>, JournalError> {
        let Some((run, seq)) = self.locate(ordinal) else {
            return Ok(None);
        };
        let page = self
            .producer
            .records(&self.resource, &run, seq, 1)
            .map_err(io)?;
        match page.records.into_iter().next() {
            Some((held, bytes)) if held == seq => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| JournalError::Corrupt(format!("a Host event record: {error}"))),
            _ => Ok(None),
        }
    }

    /// The records a temporal question needs, by ordinal, in the index's order.
    pub fn scan(&self, query: &Query) -> Result<Vec<(u64, Value)>, JournalError> {
        let wanted: Vec<u64> = self
            .index
            .scan(query)
            .into_iter()
            .map(|located| located.seq)
            .collect();
        let mut by_run: BTreeMap<[u8; 16], Vec<u64>> = BTreeMap::new();
        for ordinal in &wanted {
            if let Some((run, seq)) = self.locate(*ordinal) {
                by_run.entry(run).or_default().push(seq);
            }
        }
        let mut read: BTreeMap<u64, Value> = BTreeMap::new();
        for (run, mut seqs) in by_run {
            seqs.sort_unstable();
            let Some(base) = self.base_of(&run) else {
                continue;
            };
            let mut at = 0;
            while at < seqs.len() {
                // A window of wanted sequences close enough together to read in one page: what
                // lies between two far apart is not read (after the review).
                let first = seqs[at];
                let mut last = first;
                for next in &seqs[at + 1..] {
                    if next - last > SCAN_GAP || next - first >= READ_PAGE as u64 {
                        break;
                    }
                    last = *next;
                }
                let limit = usize::try_from(last - first + 1).unwrap_or(READ_PAGE);
                let page = self
                    .producer
                    .records(&self.resource, &run, first, limit)
                    .map_err(io)?;
                if page.records.is_empty() {
                    break;
                }
                let last = page.records.last().map_or(first, |(seq, _)| *seq);
                for (seq, bytes) in page.records {
                    if seqs.binary_search(&seq).is_ok() {
                        let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                            JournalError::Corrupt(format!("a Host event record: {error}"))
                        })?;
                        read.insert(base + seq, value);
                    }
                }
                while at < seqs.len() && seqs[at] <= last {
                    at += 1;
                }
            }
        }
        Ok(wanted
            .into_iter()
            .filter_map(|ordinal| read.remove(&ordinal).map(|value| (ordinal, value)))
            .collect())
    }

    /// The occurrence entry of `event_id` from `source`.
    pub fn occurrence(
        &self,
        source: Option<&str>,
        event_id: &str,
    ) -> Result<Option<KnownOccurrence>, JournalError> {
        self.occurrences.get(source, event_id)
    }

    /// Keeps `known`, durable once it returns.
    pub fn keep_occurrence(&mut self, known: &KnownOccurrence) -> Result<(), JournalError> {
        self.occurrences.stage(known)?;
        self.occurrences.sync()
    }

    /// Appends `records` in one append, each filled with its place on the Host's stream, and
    /// keeps their occurrence and index entries; answers once all of it is durable.
    pub fn append(
        &mut self,
        mut records: Vec<Record>,
        max_record_bytes: u32,
    ) -> Result<Vec<(Placed, Record)>, JournalError> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let count = records.len() as u64;
        let mut filled: Vec<(Record, Value)> = Vec::new();
        let host_id = self.host_id.clone();
        let receipt = self
            .producer
            .append_with(&self.resource, &mut |position| {
                filled.clear();
                let instance = hex(&position.run_id);
                let mut prev = if position.seq == 1 {
                    GENESIS.to_owned()
                } else {
                    format!("sha256:{}", hex(&position.prev))
                };
                let mut out = Vec::with_capacity(records.len());
                for (offset, record) in records.iter_mut().enumerate() {
                    record.stream = Stream {
                        producer: Producer {
                            class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
                            id: host_id.clone(),
                            instance: instance.clone(),
                        },
                        zone: record.stream.zone.clone(),
                        ledger: record.stream.ledger.clone(),
                    };
                    record.seq = position.seq + offset as u64;
                    record.prev = prev.clone();
                    let value = record.to_value().map_err(|error| error.to_string())?;
                    let bytes = encoded(&value, max_record_bytes)?;
                    prev =
                        permguard_events::digest_of(&value).map_err(|error| error.to_string())?;
                    filled.push((record.clone(), value));
                    out.push(bytes);
                }
                Ok(out)
            })
            .map_err(io)?;
        // Durable from here: whatever fails below leaves the entries behind the producer, which
        // the next write catches up before it checks anything.
        match self.place(receipt, count, filled) {
            Ok(placed) => Ok(placed),
            Err(error) => {
                self.behind = true;
                Err(error)
            }
        }
    }

    /// The entries of the `count` records `filled` that ended at `receipt`, kept durable.
    fn place(
        &mut self,
        receipt: permguard_host::composition::StreamReceipt,
        count: u64,
        filled: Vec<(Record, Value)>,
    ) -> Result<Vec<(Placed, Record)>, JournalError> {
        let first_seq = receipt.seq + 1 - count;
        let mut caught_up = false;
        let base = match self.base_of(&receipt.run_id) {
            Some(base) => base,
            None => {
                if first_seq != 1 {
                    caught_up = true;
                    // A run this plane never saw open with records already in it: learned from
                    // the producer rather than guessed.
                    self.catch_up()?;
                    self.base_of(&receipt.run_id).ok_or_else(|| {
                        JournalError::Corrupt("the run just appended to is not held".to_owned())
                    })?
                } else {
                    self.runs.push((receipt.run_id, self.last));
                    write_runs(&self.directory, &self.runs)?;
                    self.last
                }
            }
        };
        let run = hex(&receipt.run_id);
        let mut placed = Vec::with_capacity(filled.len());
        for (offset, (record, value)) in filled.into_iter().enumerate() {
            let ordinal = base + first_seq + offset as u64;
            // Caught up from the producer already, these included.
            if !caught_up {
                self.stage_occurrence(ordinal, &value, &record)?;
            }
            let digest = permguard_events::digest_of(&value).map_err(JournalError::Digest)?;
            placed.push((
                Placed {
                    ordinal,
                    digest,
                    run: run.clone(),
                },
                record,
            ));
        }
        self.last = self.last.max(base + receipt.seq);
        // Entries after the record, flushed before anybody is answered: a crash between the two
        // leaves a durable record the next open catches up, never an entry for nothing.
        self.index.sync()?;
        self.occurrences.sync()?;
        self.occurrences.cover(self.last)?;
        Ok(placed)
    }

    /// Stages the index and occurrence entries of the record `value` at `ordinal`.
    fn stage_occurrence(
        &mut self,
        ordinal: u64,
        value: &Value,
        record: &Record,
    ) -> Result<(), JournalError> {
        self.stage_index(ordinal, value)?;
        self.occurrences.stage(&KnownOccurrence {
            event_id: record.event_id.clone(),
            source: record.source.clone(),
            seq: ordinal,
            occurrence_digest: record.occurrence_digest.clone(),
            decision_id: None,
            profile: None,
            kind: None,
            response: Value::Null,
        })
    }

    /// For each Host run, the last sequence observed before `horizon` (epoch seconds), counted
    /// contiguously from what the run still holds: what a loaded window no longer reads.
    pub fn retention_safe(&self, horizon: i64) -> Result<Vec<([u8; 16], u64)>, JournalError> {
        let produced = self.producer.runs(&self.resource).map_err(io)?;
        let mut occurred: BTreeMap<u64, i64> = BTreeMap::new();
        for (key, located) in self.index.entries() {
            occurred.insert(located.seq, key.occurred_at);
        }
        let mut safe = Vec::new();
        for run in produced {
            let Some(base) = self.base_of(&run.run) else {
                continue;
            };
            let mut through = run.low_watermark.saturating_sub(1);
            for seq in run.low_watermark.max(1)..=run.last_seq {
                match occurred.get(&(base + seq)) {
                    Some(at) if *at < horizon => through = seq,
                    _ => break,
                }
            }
            safe.push((run.run, through));
        }
        Ok(safe)
    }

    /// Forgets the occurrence and index entries naming what the producer no longer holds.
    pub fn forget_deleted(&mut self) -> Result<usize, JournalError> {
        let produced = self.producer.runs(&self.resource).map_err(io)?;
        let oldest = produced
            .iter()
            .filter(|run| run.last_seq >= run.low_watermark)
            .filter_map(|run| self.base_of(&run.run).map(|base| base + run.low_watermark))
            .min()
            .unwrap_or(self.last + 1);
        if oldest <= self.forgotten_below {
            return Ok(0);
        }
        let gone = self.index.forget_below(oldest)? + self.occurrences.forget_below(oldest)?;
        self.forgotten_below = oldest;
        Ok(gone)
    }
}

fn dir_path(dir: &permguard_host::storage::Dir) -> PathBuf {
    dir.path().to_path_buf()
}

/// A record's canonical bytes, checked as the producer checks them: the same codec, the same
/// bound, so a record built under the engine's lock is never refused after its position was
/// taken.
fn encoded(value: &Value, max_record_bytes: u32) -> Result<Vec<u8>, String> {
    let codec = permguard_events::stream::Codec;
    let bytes = codec.encode(value)?;
    if bytes.len() as u64 > u64::from(max_record_bytes) {
        return Err(format!(
            "an event record of {} bytes; the stream takes up to {max_record_bytes}",
            bytes.len()
        ));
    }
    if codec.encode(&codec.decode(&bytes)?)? != bytes {
        return Err("an event record that is not its canonical encoding".to_owned());
    }
    Ok(bytes)
}

fn read_runs(directory: &Path) -> Result<Vec<([u8; 16], u64)>, JournalError> {
    let text = match std::fs::read_to_string(directory.join(RUNS_FILE)) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io(error)),
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (run, base) = line.split_once(' ').ok_or_else(|| {
                JournalError::Corrupt(format!("{RUNS_FILE}: `{line}` is not `<run> <base>`"))
            })?;
            Ok((
                unhex16(run).ok_or_else(|| {
                    JournalError::Corrupt(format!("{RUNS_FILE}: `{run}` is not a run"))
                })?,
                base.parse()
                    .map_err(|error| JournalError::Corrupt(format!("{RUNS_FILE}: {error}")))?,
            ))
        })
        .collect()
}

fn write_runs(directory: &Path, runs: &[([u8; 16], u64)]) -> Result<(), JournalError> {
    let text: String = runs
        .iter()
        .map(|(run, base)| format!("{} {base}\n", hex(run)))
        .collect();
    let dir = permguard_host::storage::Dir::open(directory).map_err(io)?;
    permguard_host::storage::write::replace_bytes(&dir, RUNS_FILE, text.as_bytes()).map_err(io)
}

#[cfg(test)]
mod tests;
