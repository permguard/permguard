// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One trail: `host/audit/trails/<class>/<resource digest>/`.
//!
//! | File                 | Content                                                               |
//! | -------------------- | --------------------------------------------------------------------- |
//! | `META.cbor`          | the class and the structured resource the digest path stands for      |
//! | `YYYY-MM-DD.cborseq` | the records of one UTC day, a CBOR sequence, each record one item     |
//! | `checkpoints/`       | the signed checkpoints ([`super::checkpoint`]), never deleted         |
//! | `ANCHOR.cbor`        | what retention deleted: the first sequence kept and the seal before it |
//!
//! A record is appended and flushed through the storage library before the append returns; an
//! append that fails cuts its own bytes back off. At open the newest day files are read: an
//! incomplete final item shorter than any record can be is a torn write and is cut with the
//! library's `write::truncate`; anything else that does not read is corruption and the trail
//! refuses to open (owner decision of 2026-10-07). The sequence and the chain continue across
//! days and restarts from the last record found, and a record never goes to a day file earlier
//! than the trail's last one, whatever the wall clock says.
//!
//! A day is sealed by a checkpoint once it ended (WP-3.7, owner decisions of 2026-10-11): the
//! engine seals every ended day when a record starts a new one, at its sweeps and on demand. A
//! sealed day is closed: no record goes to it again, whatever the wall clock says, the next one
//! going to the day after. Retention deletes whole sealed days older than the trail's retention
//! only, writing `ANCHOR.cbor` first, through the storage library's tombstones; a trail without
//! a retention keeps every day.

use permguard_core::encoding::hex;
use std::io::Write as _;
use std::time::Duration;

use permguard_objects::cbor::{self, CborError};
use permguard_objects::digest::Digest;

use crate::storage::write::{self, Published, publish_immutable};
use crate::storage::{Dir, Result as StorageResult, StorageError, tombstone};

use super::Class;
use super::checkpoint::{
    ANCHOR, Anchor, Checkpoint, CheckpointSigner, envelope_digest, file_name, no_checkpoint,
    order_of, ordered, parse_name, read_unverified,
};
use super::record::{AuditRecord, MAX_RECORD_BYTES, TrailMeta, digest_of, genesis};

/// The file holding the trail's class and resource.
pub const META: &str = "META.cbor";
/// The directory the checkpoints are published in.
pub const CHECKPOINTS: &str = "checkpoints";
/// The ending of a day file.
pub const DAY_SUFFIX: &str = ".cborseq";

/// The trail directory of `(class, resource)` below `trails`, created when asked.
pub fn directory(trails: &Dir, class: Class, resource: &str, create: bool) -> StorageResult<Dir> {
    trails
        .subdir(class.as_str(), create)?
        .subdir(&resource_digest(resource), create)
}

/// The directory name a resource is kept under: the SHA-256 of its text, in hex.
pub fn resource_digest(resource: &str) -> String {
    hex(Digest::compute(resource.as_bytes()).raw())
}

/// What one trail is kept in (iteration 03, decision E33): its day files, its checkpoints, its
/// anchor. Everything a trail is, where a record goes, what a seal covers and what retention
/// may delete, is [`Trail`]'s and the same on every backend; this is only where the bytes rest.
///
/// | Backend                  | Keeps a trail in                                             |
/// | ------------------------ | ------------------------------------------------------------ |
/// | [`Dir`], the file backend | `host/audit/trails/<class>/<resource digest>/`              |
pub trait TrailStore: Send {
    /// How a message names the trail, or what it keeps under `name`; the trail itself when
    /// `name` is empty.
    fn place(&self, name: &str) -> String;

    /// Makes the trail ready to continue: what an interrupted write left is completed or
    /// removed, and `meta`, the class and the resource the trail is of, is published once.
    fn prepare(&self, meta: &[u8]) -> StorageResult<()>;

    /// The day files held, oldest first.
    fn days(&self) -> StorageResult<Vec<String>>;

    /// The bytes of the day file `name`, whole; none when it holds nothing.
    fn day(&self, name: &str) -> StorageResult<Vec<u8>>;

    /// Adds `record`, the record `seq`, at the end of the day file `name`, durably. An append
    /// that fails leaves the day file as it found it.
    fn append(&self, name: &str, seq: u64, record: &[u8]) -> StorageResult<()>;

    /// Cuts the day file `name` to its first `to` bytes: what removes a torn final record.
    fn cut(&self, name: &str, to: u64) -> StorageResult<()>;

    /// Removes the day file `name`.
    fn remove_day(&self, name: &str) -> StorageResult<()>;

    /// The names of the checkpoints and of their co-signatures.
    fn checkpoint_names(&self) -> StorageResult<Vec<String>>;

    /// The checkpoint, or the co-signature, `name`.
    fn checkpoint(&self, name: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Publishes `envelope` as the checkpoint, or the co-signature, `name`, once: the same
    /// again is the first, another is refused.
    fn publish_checkpoint(&self, name: &str, envelope: &[u8]) -> StorageResult<()>;

    /// The anchor, when retention deleted a prefix.
    fn anchor(&self) -> StorageResult<Option<Vec<u8>>>;

    /// Replaces the anchor.
    fn replace_anchor(&self, anchor: &[u8]) -> StorageResult<()>;
}

/// Whether `error` says the thing asked for is not there.
fn absent(error: &StorageError) -> bool {
    matches!(error, StorageError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound)
}

impl TrailStore for Dir {
    fn place(&self, name: &str) -> String {
        if name.is_empty() {
            self.path().display().to_string()
        } else {
            self.child_path(name).display().to_string()
        }
    }

    fn prepare(&self, meta: &[u8]) -> StorageResult<()> {
        self.sweep_temps()?;
        tombstone::complete(self)?;
        let same = |held: &[u8]| held == meta;
        match publish_immutable(self, META, meta, &same, &same)? {
            Published::Written | Published::AlreadyThere => {}
        }
        self.subdir(CHECKPOINTS, true)?.sweep_temps()?;
        Ok(())
    }

    fn days(&self) -> StorageResult<Vec<String>> {
        let mut names: Vec<String> = self
            .names()?
            .into_iter()
            .filter(|name| name.ends_with(DAY_SUFFIX))
            .collect();
        names.sort();
        Ok(names)
    }

    fn day(&self, name: &str) -> StorageResult<Vec<u8>> {
        Ok(self.read(name)?.unwrap_or_default())
    }

    fn append(&self, name: &str, _seq: u64, record: &[u8]) -> StorageResult<()> {
        let mut file = match self.open_write(name) {
            Ok(file) => file,
            Err(error) if absent(&error) => {
                let file = self.create_exclusive(name)?;
                self.sync()?;
                file
            }
            Err(error) => return Err(error),
        };
        let end = file
            .metadata()
            .map_err(|source| StorageError::Io {
                what: format!("measuring {}", self.child_path(name).display()),
                source,
            })?
            .len();
        let written = (|| {
            std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(end)).map_err(|source| {
                StorageError::Io {
                    what: format!("seeking {}", self.child_path(name).display()),
                    source,
                }
            })?;
            permguard_core::fault::write(&self.child_path(name), record.len(), || {
                file.write_all(record)
            })
            .map_err(|source| StorageError::Io {
                what: format!("appending to {}", self.child_path(name).display()),
                source,
            })?;
            write::flush(self, name, &file)
        })();
        if let Err(error) = written {
            // Whatever part of the record reached the file is cut back off, so the next record
            // starts where this one would have. If the cut fails too, the caller reopens the
            // trail, and opening cuts a torn final item.
            let _ = write::truncate(self, name, &file, end);
            return Err(error);
        }
        Ok(())
    }

    fn cut(&self, name: &str, to: u64) -> StorageResult<()> {
        let file = self.open_write(name)?;
        write::truncate(self, name, &file, to)
    }

    fn remove_day(&self, name: &str) -> StorageResult<()> {
        tombstone::delete(self, name)
    }

    fn checkpoint_names(&self) -> StorageResult<Vec<String>> {
        match self.subdir(CHECKPOINTS, false) {
            Ok(held) => held.names(),
            Err(error) if absent(&error) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    fn checkpoint(&self, name: &str) -> StorageResult<Option<Vec<u8>>> {
        match self.subdir(CHECKPOINTS, false) {
            Ok(held) => held.read(name),
            Err(error) if absent(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn publish_checkpoint(&self, name: &str, envelope: &[u8]) -> StorageResult<()> {
        let held = self.subdir(CHECKPOINTS, true)?;
        let same = |kept: &[u8]| kept == envelope;
        match publish_immutable(&held, name, envelope, &same, &same)? {
            Published::Written | Published::AlreadyThere => Ok(()),
        }
    }

    fn anchor(&self) -> StorageResult<Option<Vec<u8>>> {
        self.read(ANCHOR)
    }

    fn replace_anchor(&self, anchor: &[u8]) -> StorageResult<()> {
        write::replace_bytes(self, ANCHOR, anchor)
    }
}

/// An open trail: where it continues.
pub struct Trail {
    store: Box<dyn TrailStore>,
    /// `<class>:<resource>`.
    name: String,
    next_seq: u64,
    previous: Digest,
    /// The newest day file, which no record goes before.
    last_day: Option<String>,
    retention: Option<Duration>,
    /// The newest checkpoint, which the next one chains to.
    last_checkpoint: Option<Sealed>,
    /// The newest day a seal closed, `YYYY-MM-DD`.
    sealed: Option<String>,
}

impl std::fmt::Debug for Trail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Trail")
            .field("name", &self.name)
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

/// A checkpoint as the trail continues from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub name: String,
    pub digest: Digest,
    pub last_seq: u64,
    pub head: Digest,
}

/// Where a trail continues: what [`Trail::over`] finds by reading the trail, and what a backend
/// that keeps it beside the trail hands [`Trail::resume`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// The sequence the next record gets.
    pub next_seq: u64,
    /// The digest the next record chains to.
    pub previous: Digest,
    /// The newest day file, which no record goes before.
    pub last_day: Option<String>,
    /// The newest checkpoint, which the next one chains to.
    pub last_checkpoint: Option<Sealed>,
    /// The newest day a seal closed, `YYYY-MM-DD`.
    pub sealed: Option<String>,
}

impl State {
    /// A trail that holds nothing yet.
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            previous: genesis(),
            last_day: None,
            last_checkpoint: None,
            sealed: None,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl Trail {
    /// Opens, or creates, the trail of `(class, resource)` below `trails`; `retention` bounds
    /// how long its day files are kept, `None` for ever.
    pub fn open(
        trails: &Dir,
        class: Class,
        resource: &str,
        retention: Option<Duration>,
    ) -> StorageResult<Self> {
        Self::over(
            Box::new(directory(trails, class, resource, true)?),
            class,
            resource,
            retention,
        )
    }

    /// The trail of `(class, resource)` kept in `store`, continued from what the store holds:
    /// its last record, its newest checkpoint, its anchor.
    pub fn over(
        store: Box<dyn TrailStore>,
        class: Class,
        resource: &str,
        retention: Option<Duration>,
    ) -> StorageResult<Self> {
        let meta = TrailMeta {
            class: class.as_str().to_owned(),
            resource: resource.to_owned(),
        }
        .encode()
        .map_err(|error| StorageError::Corruption(error.to_string()))?;
        store.prepare(&meta)?;
        let dir = store.as_ref();
        let names = ordered(store.checkpoint_names()?);
        let last_checkpoint = match names.last() {
            None => None,
            Some(name) => {
                let envelope = store.checkpoint(name)?.unwrap_or_default();
                let checkpoint = read_unverified(&envelope).map_err(|error| {
                    StorageError::Corruption(format!(
                        "the checkpoint {name} of {} does not read: {error}",
                        store.place("")
                    ))
                })?;
                Some(Sealed {
                    name: name.clone(),
                    digest: envelope_digest(&envelope),
                    last_seq: checkpoint.last_seq,
                    head: checkpoint.head_digest,
                })
            }
        };
        let sealed = names.iter().rev().find_map(|name| match parse_name(name) {
            Some((period, None)) => Some(period),
            _ => None,
        });

        let days = days(dir)?;
        let mut continued = None;
        // From the newest day back, past days a crash left empty or holding a torn item only.
        for (index, day) in days.iter().enumerate().rev() {
            let last = if index + 1 == days.len() {
                recover(dir, day)?
            } else {
                read_day(dir, day)?.pop()
            };
            if let Some(record) = last {
                continued = Some(record);
                break;
            }
        }
        let (mut next_seq, mut previous) = match continued {
            Some(record) => {
                let digest = record
                    .digest()
                    .map_err(|error| StorageError::Corruption(error.to_string()))?;
                (record.seq + 1, digest)
            }
            None => (0, genesis()),
        };
        if let Some(checkpoint) = &last_checkpoint
            && checkpoint.last_seq >= next_seq
        {
            // Records a checkpoint covers are gone from the day files: the trail continues after
            // the checkpoint, never reusing a sequence it sealed. Retention explains it when the
            // anchor keeps records from right after that checkpoint; anything else verification
            // reports as records missing.
            let retained =
                anchor(dir)?.is_some_and(|anchor| anchor.low_watermark == checkpoint.last_seq + 1);
            if !retained {
                tracing::error!(
                event.name = "audit.sealed_records_missing",
                component = "host",
                trail = %store.place(""),
                last_found = next_seq.checked_sub(1),
                last_sealed = checkpoint.last_seq,
                "records an audit checkpoint covers are missing from the trail"
                );
            }
            next_seq = checkpoint.last_seq + 1;
            previous = checkpoint.head.clone();
        }
        let last_day = days.last().cloned();
        Ok(Self::resume(
            store,
            class,
            resource,
            retention,
            State {
                next_seq,
                previous,
                last_day,
                last_checkpoint,
                sealed,
            },
        ))
    }

    /// The trail of `(class, resource)` kept in `store`, continued from `state`: for a backend
    /// that keeps where the trail continues beside it, and reads it with the trail held.
    pub fn resume(
        store: Box<dyn TrailStore>,
        class: Class,
        resource: &str,
        retention: Option<Duration>,
        state: State,
    ) -> Self {
        Self {
            store,
            name: format!("{}:{resource}", class.as_str()),
            next_seq: state.next_seq,
            previous: state.previous,
            last_day: state.last_day,
            retention,
            last_checkpoint: state.last_checkpoint,
            sealed: state.sealed,
        }
    }

    /// Where the trail continues now.
    pub fn state(&self) -> State {
        State {
            next_seq: self.next_seq,
            previous: self.previous.clone(),
            last_day: self.last_day.clone(),
            last_checkpoint: self.last_checkpoint.clone(),
            sealed: self.sealed.clone(),
        }
    }

    /// What the trail is kept in.
    pub fn store(&self) -> &dyn TrailStore {
        self.store.as_ref()
    }

    /// The name of the newest checkpoint.
    pub fn newest_checkpoint(&self) -> Option<&str> {
        self.last_checkpoint
            .as_ref()
            .map(|sealed| sealed.name.as_str())
    }

    /// The newest day file.
    pub fn last_day(&self) -> Option<&str> {
        self.last_day.as_deref()
    }

    /// The sequence the next record gets.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The digest of the last record appended, the one the next record chains to.
    pub fn head(&self) -> &Digest {
        &self.previous
    }

    /// Appends `record`, giving it its sequence and the previous record's digest, and flushes the
    /// day file before returning. An append that fails leaves the day file as it found it.
    /// Answers whether the record started a new day file.
    pub fn append(&mut self, mut record: AuditRecord) -> StorageResult<bool> {
        record.seq = self.next_seq;
        record.previous = self.previous.clone();
        let bytes = record
            .encode()
            .map_err(|error| StorageError::Corruption(error.to_string()))?;
        let by_clock = day_name(record.at);
        let mut name = match &self.last_day {
            Some(last) if *last > by_clock => last.clone(),
            _ => by_clock,
        };
        if let Some(sealed) = &self.sealed
            && name <= format!("{sealed}{DAY_SUFFIX}")
        {
            // A sealed day is closed: the record goes to the day after it.
            name = day_after(sealed).ok_or_else(|| {
                StorageError::Corruption(format!("the sealed day `{sealed}` has no day after"))
            })?;
        }
        let new_day = self.last_day.as_deref() != Some(name.as_str());
        self.store.append(&name, record.seq, &bytes)?;
        self.previous = digest_of(&bytes);
        self.next_seq += 1;
        self.last_day = Some(name);
        Ok(new_day)
    }

    /// Seals every day file before the day file `before` that no seal closed yet, oldest first,
    /// and answers the checkpoints written. A day without a record is left as it is.
    pub fn seal_before(
        &mut self,
        before: &str,
        signer: &dyn CheckpointSigner,
        host_id: [u8; 16],
        now: u64,
    ) -> Result<Vec<String>, String> {
        let mut written = Vec::new();
        for day in days(self.store.as_ref()).map_err(|error| error.to_string())? {
            if day.as_str() >= before {
                break;
            }
            let period = period_of(&day);
            if self
                .sealed
                .as_deref()
                .is_some_and(|sealed| period.as_str() <= sealed)
            {
                continue;
            }
            if let Some(name) = self.write_checkpoint(&day, true, signer, host_id, now)? {
                written.push(name);
            }
        }
        Ok(written)
    }

    /// Seals every ended day before the day file `today`, then checkpoints the trail's last day
    /// up to its last record when no checkpoint covers that record yet (`YYYY-MM-DD.<seq>.cose`).
    pub fn checkpoint_now(
        &mut self,
        today: &str,
        signer: &dyn CheckpointSigner,
        host_id: [u8; 16],
        now: u64,
    ) -> Result<Vec<String>, String> {
        let mut written = self.seal_before(today, signer, host_id, now)?;
        if let Some(last) = self.last_day.clone()
            && last.as_str() >= today
            && !self
                .sealed
                .as_deref()
                .is_some_and(|sealed| period_of(&last).as_str() <= sealed)
            && let Some(name) = self.write_checkpoint(&last, false, signer, host_id, now)?
        {
            written.push(name);
        }
        Ok(written)
    }

    /// Writes the checkpoint of the day file `day` up to its last record: its seal, or an
    /// on-demand checkpoint, which is skipped when the newest checkpoint already covers that
    /// record.
    fn write_checkpoint(
        &mut self,
        day: &str,
        seal: bool,
        signer: &dyn CheckpointSigner,
        host_id: [u8; 16],
        now: u64,
    ) -> Result<Option<String>, String> {
        let records = read_day(self.store.as_ref(), day).map_err(|error| error.to_string())?;
        let (Some(first), Some(last)) = (records.first(), records.last()) else {
            return Ok(None);
        };
        if !seal
            && self
                .last_checkpoint
                .as_ref()
                .is_some_and(|newest| newest.last_seq >= last.seq)
        {
            return Ok(None);
        }
        let period = period_of(day);
        let name = file_name(&period, (!seal).then_some(last.seq));
        let mut checkpoint = Checkpoint {
            trail: self.name.clone(),
            period: period.clone(),
            first_seq: first.seq,
            last_seq: last.seq,
            head_digest: last.digest().map_err(|error| error.to_string())?,
            previous_checkpoint: self
                .last_checkpoint
                .as_ref()
                .map_or_else(no_checkpoint, |newest| newest.digest.clone()),
            host_id,
            key_set_epoch: 0,
            created_at: now,
        };
        let envelope = signer.seal(&mut checkpoint)?;
        self.store
            .publish_checkpoint(&name, &envelope)
            .map_err(|error| error.to_string())?;
        self.last_checkpoint = Some(Sealed {
            name: name.clone(),
            digest: envelope_digest(&envelope),
            last_seq: checkpoint.last_seq,
            head: checkpoint.head_digest,
        });
        if seal {
            self.sealed = Some(period);
        }
        Ok(Some(name))
    }

    /// Deletes the sealed day files older than the retention, counted back from the day file
    /// `today`, writing `ANCHOR.cbor` before the first goes; answers the anchor written. The
    /// newest such day with a seal bounds the deletion, so the anchor always names a seal.
    ///
    /// `egress` is what an export of the trail allows (WP-5.9): `None` when no required task
    /// exports it; otherwise only the days whose seal is at or before the acknowledged checkpoint
    /// it names go, and none while nothing is acknowledged.
    pub fn prune(
        &self,
        today: &str,
        egress: Option<Option<&str>>,
    ) -> StorageResult<Option<Anchor>> {
        let (Some(retention), Some(sealed)) = (self.retention, &self.sealed) else {
            return Ok(None);
        };
        let Some(cutoff) = cutoff(today, retention) else {
            return Ok(None);
        };
        let acknowledged = match egress {
            None => None,
            Some(None) => return Ok(None),
            Some(Some(name)) => Some(order_of(name).ok_or_else(|| {
                StorageError::Corruption(format!("`{name}` names no checkpoint"))
            })?),
        };
        let sealed_day = format!("{sealed}{DAY_SUFFIX}");
        let doomed: Vec<String> = days(self.store.as_ref())?
            .into_iter()
            .filter(|day| *day < cutoff && day.as_str() != today && *day <= sealed_day)
            // A day goes only once the seal that closes it left the volume.
            .filter(|day| {
                acknowledged
                    .as_ref()
                    .is_none_or(|acknowledged| (period_of(day), u64::MAX) <= *acknowledged)
            })
            .collect();
        let Some((through, envelope)) = doomed
            .iter()
            .rev()
            .map(|day| {
                let period = period_of(day);
                self.store
                    .checkpoint(&file_name(&period, None))
                    .map(|held| held.map(|envelope| (day.clone(), envelope)))
            })
            .find_map(Result::transpose)
            .transpose()?
        else {
            return Ok(None);
        };
        let seal = read_unverified(&envelope).map_err(|error| {
            StorageError::Corruption(format!("the seal of {through} does not read: {error}"))
        })?;
        let anchor = Anchor {
            trail: self.name.clone(),
            low_watermark: seal.last_seq + 1,
            through: period_of(&through),
            checkpoint: envelope_digest(&envelope),
        };
        let bytes = anchor
            .encode()
            .map_err(|error| StorageError::Corruption(error.to_string()))?;
        self.store.replace_anchor(&bytes)?;
        for day in doomed.iter().filter(|day| **day <= through) {
            self.store.remove_day(day)?;
        }
        Ok(Some(anchor))
    }
}

/// Copies the trail `from` holds into the directory `into`, as the file backend lays a trail
/// out: its `META.cbor` from `meta`, its day files, its checkpoints and their co-signatures, its
/// anchor. What verifies a trail on files then verifies it, whatever backend kept it. Answers how
/// many day files it copied.
pub fn copy_into(from: &dyn TrailStore, meta: &[u8], into: &Dir) -> StorageResult<usize> {
    let same = |held: &[u8]| held == meta;
    match publish_immutable(into, META, meta, &same, &same)? {
        Published::Written | Published::AlreadyThere => {}
    }
    let days = from.days()?;
    for day in &days {
        write::replace_bytes(into, day, &from.day(day)?)?;
    }
    for name in from.checkpoint_names()? {
        if let Some(envelope) = from.checkpoint(&name)? {
            into.publish_checkpoint(&name, &envelope)?;
        }
    }
    if let Some(anchor) = from.anchor()? {
        into.replace_anchor(&anchor)?;
    }
    Ok(days.len())
}

/// The period of a day file: `YYYY-MM-DD`.
pub fn period_of(day: &str) -> String {
    day.strip_suffix(DAY_SUFFIX).unwrap_or(day).to_owned()
}

/// The day file of the day after the period `period`.
fn day_after(period: &str) -> Option<String> {
    let date = permguard_core::time::Date::from_iso(period)?;
    let next = permguard_core::time::days_of(date).checked_add(1)?;
    Some(format!(
        "{}{DAY_SUFFIX}",
        permguard_core::time::date_of(next).to_iso()
    ))
}

/// The anchor of the trail in `dir`, when retention deleted a prefix.
pub fn anchor(dir: &dyn TrailStore) -> StorageResult<Option<Anchor>> {
    dir.anchor()?
        .map(|bytes| {
            Anchor::decode(&bytes).map_err(|error| {
                StorageError::Corruption(format!("{} does not read: {error}", dir.place(ANCHOR)))
            })
        })
        .transpose()
}

/// The day file name before which files are older than `retention`, counted from `today`.
fn cutoff(today: &str, retention: Duration) -> Option<String> {
    let date = permguard_core::time::Date::from_iso(today.strip_suffix(DAY_SUFFIX)?)?;
    let days = permguard_core::time::days_of(date);
    let keep = i64::try_from(retention.as_secs() / 86_400).unwrap_or(i64::MAX);
    Some(format!(
        "{}{DAY_SUFFIX}",
        permguard_core::time::date_of(days.saturating_sub(keep)).to_iso()
    ))
}

/// The day file a record written at `at` (seconds) belongs to.
pub fn day_name(at: u64) -> String {
    let day = permguard_core::time::day_of(i64::try_from(at).unwrap_or(i64::MAX));
    format!(
        "{}{DAY_SUFFIX}",
        permguard_core::time::date_of(day).to_iso()
    )
}

/// The day files of a trail, oldest first.
pub fn days(dir: &dyn TrailStore) -> StorageResult<Vec<String>> {
    dir.days()
}

/// Every record of the day file `name`, in order; a torn final item is an error here, since only
/// [`Trail::open`] repairs.
pub fn read_day(dir: &dyn TrailStore, name: &str) -> StorageResult<Vec<AuditRecord>> {
    let bytes = dir.day(name)?;
    let (records, complete) = parse(dir, name, &bytes)?;
    if complete != bytes.len() {
        return Err(StorageError::Corruption(format!(
            "{} ends inside a record",
            dir.place(name)
        )));
    }
    Ok(records)
}

/// Every whole record of the day file `name`, in order, leaving out a final item still being
/// written: what a read of a live trail sees, the trail's append holding no lock against it.
pub fn read_written(dir: &dyn TrailStore, name: &str) -> StorageResult<Vec<AuditRecord>> {
    let bytes = dir.day(name)?;
    Ok(parse(dir, name, &bytes)?.0)
}

/// Reads the last day file, cuts a torn final item, and answers its last whole record.
fn recover(dir: &dyn TrailStore, name: &str) -> StorageResult<Option<AuditRecord>> {
    let bytes = dir.day(name)?;
    let (mut records, complete) = parse(dir, name, &bytes)?;
    if complete != bytes.len() {
        dir.cut(name, complete as u64)?;
        tracing::warn!(
            event.name = "audit.torn_record_cut",
            component = "host",
            bytes = bytes.len() - complete,
            "a torn audit record was cut from the end of a day file"
        );
    }
    Ok(records.pop())
}

/// The records of `bytes` and how many bytes the whole ones take: a final item that ends early
/// and is shorter than any record can be stops the reading as a torn write; anything else that
/// does not read is corruption, a damaged length that runs past the end included.
fn parse(
    dir: &dyn TrailStore,
    name: &str,
    bytes: &[u8],
) -> StorageResult<(Vec<AuditRecord>, usize)> {
    let mut records = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match cbor::decode_canonical_prefix(&bytes[at..]) {
            Ok((value, taken)) => {
                let record = AuditRecord::from_value(value).map_err(|error| {
                    StorageError::Corruption(format!(
                        "{} holds a record that does not read: {error}",
                        dir.place(name)
                    ))
                })?;
                records.push(record);
                at += taken;
            }
            Err(CborError::Truncated) if bytes.len() - at < MAX_RECORD_BYTES => break,
            Err(error) => {
                return Err(StorageError::Corruption(format!(
                    "{} holds bytes that are not a record at offset {at}: {error}",
                    dir.place(name)
                )));
            }
        }
    }
    Ok((records, at))
}

/// Checks a whole trail: every record reads, the sequence has no gap or repeat, and every
/// `previous` is the digest of the record before it. The first record kept starts the check: a
/// trail whose oldest days retention dropped begins mid-sequence. Answers how many records it
/// checked.
pub fn verify(dir: &dyn TrailStore) -> StorageResult<u64> {
    let mut expected: Option<(u64, Digest)> = None;
    let mut checked = 0;
    for day in days(dir)? {
        for record in read_day(dir, &day)? {
            let (seq, previous) = expected
                .clone()
                .unwrap_or_else(|| (record.seq, record.previous.clone()));
            if expected.is_none() && record.seq == 0 && record.previous != genesis() {
                return Err(StorageError::Corruption(format!(
                    "the first record of {} does not start the chain",
                    dir.place("")
                )));
            }
            if record.seq != seq {
                return Err(StorageError::Corruption(format!(
                    "record {} of {} follows record {}",
                    record.seq,
                    dir.place(""),
                    seq.saturating_sub(1)
                )));
            }
            if record.previous != previous {
                return Err(StorageError::Corruption(format!(
                    "record {} of {} does not chain to the record before it",
                    record.seq,
                    dir.place("")
                )));
            }
            let digest = record
                .digest()
                .map_err(|error| StorageError::Corruption(error.to_string()))?;
            expected = Some((record.seq + 1, digest));
            checked += 1;
        }
    }
    Ok(checked)
}
