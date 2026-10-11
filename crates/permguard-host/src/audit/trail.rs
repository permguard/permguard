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

use std::io::Write as _;
use std::time::Duration;

use permguard_objects::cbor::{self, CborError};
use permguard_objects::digest::Digest;

use crate::storage::write::{self, Published, publish_immutable};
use crate::storage::{Dir, Result as StorageResult, StorageError, tombstone};

use super::Class;
use super::checkpoint::{
    ANCHOR, Anchor, Checkpoint, CheckpointSigner, envelope_digest, file_name, no_checkpoint,
    ordered, parse_name, read_unverified,
};
use super::record::{AuditRecord, MAX_RECORD_BYTES, TrailMeta, digest_of, genesis, hex};

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

/// An open trail: where it continues.
#[derive(Debug)]
pub struct Trail {
    dir: Dir,
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

/// A checkpoint as the trail continues from it.
#[derive(Debug, Clone)]
struct Sealed {
    name: String,
    digest: Digest,
    last_seq: u64,
    head: Digest,
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
        let dir = directory(trails, class, resource, true)?;
        dir.sweep_temps()?;
        tombstone::complete(&dir)?;
        let meta = TrailMeta {
            class: class.as_str().to_owned(),
            resource: resource.to_owned(),
        }
        .encode()
        .map_err(|error| StorageError::Corruption(error.to_string()))?;
        let same = |held: &[u8]| held == meta.as_slice();
        match publish_immutable(&dir, META, &meta, &same, &same)? {
            Published::Written | Published::AlreadyThere => {}
        }
        let checkpoints = dir.subdir(CHECKPOINTS, true)?;
        checkpoints.sweep_temps()?;
        let names = ordered(checkpoints.names()?);
        let last_checkpoint = match names.last() {
            None => None,
            Some(name) => {
                let envelope = checkpoints.read(name)?.unwrap_or_default();
                let checkpoint = read_unverified(&envelope).map_err(|error| {
                    StorageError::Corruption(format!(
                        "{} does not read: {error}",
                        checkpoints.child_path(name).display()
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

        let days = days(&dir)?;
        let mut continued = None;
        // From the newest day back, past days a crash left empty or holding a torn item only.
        for (index, day) in days.iter().enumerate().rev() {
            let last = if index + 1 == days.len() {
                recover(&dir, day)?
            } else {
                read_day(&dir, day)?.pop()
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
                anchor(&dir)?.is_some_and(|anchor| anchor.low_watermark == checkpoint.last_seq + 1);
            if !retained {
                tracing::error!(
                event.name = "audit.sealed_records_missing",
                component = "host",
                trail = %dir.path().display(),
                last_found = next_seq.checked_sub(1),
                last_sealed = checkpoint.last_seq,
                "records an audit checkpoint covers are missing from the trail"
                );
            }
            next_seq = checkpoint.last_seq + 1;
            previous = checkpoint.head.clone();
        }
        Ok(Self {
            dir,
            name: format!("{}:{resource}", class.as_str()),
            next_seq,
            previous,
            last_day: days.last().cloned(),
            retention,
            last_checkpoint,
            sealed,
        })
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
        let mut file = match self.dir.open_write(&name) {
            Ok(file) => file,
            Err(StorageError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let file = self.dir.create_exclusive(&name)?;
                self.dir.sync()?;
                file
            }
            Err(error) => return Err(error),
        };
        let end = file
            .metadata()
            .map_err(|source| StorageError::Io {
                what: format!("measuring {}", self.dir.child_path(&name).display()),
                source,
            })?
            .len();
        let written = (|| {
            std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(end)).map_err(|source| {
                StorageError::Io {
                    what: format!("seeking {}", self.dir.child_path(&name).display()),
                    source,
                }
            })?;
            permguard_core::fault::write(&self.dir.child_path(&name), bytes.len(), || {
                file.write_all(&bytes)
            })
            .map_err(|source| StorageError::Io {
                what: format!("appending to {}", self.dir.child_path(&name).display()),
                source,
            })?;
            write::flush(&self.dir, &name, &file)
        })();
        if let Err(error) = written {
            // Whatever part of the record reached the file is cut back off, so the next record
            // starts where this one would have. If the cut fails too, the caller reopens the
            // trail, and opening cuts a torn final item.
            let _ = write::truncate(&self.dir, &name, &file, end);
            return Err(error);
        }
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
        for day in days(&self.dir).map_err(|error| error.to_string())? {
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
        let records = read_day(&self.dir, day).map_err(|error| error.to_string())?;
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
        let checkpoints = self
            .dir
            .subdir(CHECKPOINTS, true)
            .map_err(|error| error.to_string())?;
        let same = |held: &[u8]| held == envelope.as_slice();
        publish_immutable(&checkpoints, &name, &envelope, &same, &same)
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
    pub fn prune(&self, today: &str) -> StorageResult<Option<Anchor>> {
        let (Some(retention), Some(sealed)) = (self.retention, &self.sealed) else {
            return Ok(None);
        };
        let Some(cutoff) = cutoff(today, retention) else {
            return Ok(None);
        };
        let sealed_day = format!("{sealed}{DAY_SUFFIX}");
        let doomed: Vec<String> = days(&self.dir)?
            .into_iter()
            .filter(|day| *day < cutoff && day.as_str() != today && *day <= sealed_day)
            .collect();
        let checkpoints = self.dir.subdir(CHECKPOINTS, true)?;
        let Some((through, envelope)) = doomed
            .iter()
            .rev()
            .map(|day| {
                let period = period_of(day);
                checkpoints
                    .read(&file_name(&period, None))
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
        write::replace_bytes(&self.dir, ANCHOR, &bytes)?;
        for day in doomed.iter().filter(|day| **day <= through) {
            tombstone::delete(&self.dir, day)?;
        }
        Ok(Some(anchor))
    }
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
pub fn anchor(dir: &Dir) -> StorageResult<Option<Anchor>> {
    dir.read(ANCHOR)?
        .map(|bytes| {
            Anchor::decode(&bytes).map_err(|error| {
                StorageError::Corruption(format!(
                    "{} does not read: {error}",
                    dir.child_path(ANCHOR).display()
                ))
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
pub fn days(dir: &Dir) -> StorageResult<Vec<String>> {
    let mut names: Vec<String> = dir
        .names()?
        .into_iter()
        .filter(|name| name.ends_with(DAY_SUFFIX))
        .collect();
    names.sort();
    Ok(names)
}

/// Every record of the day file `name`, in order; a torn final item is an error here, since only
/// [`Trail::open`] repairs.
pub fn read_day(dir: &Dir, name: &str) -> StorageResult<Vec<AuditRecord>> {
    let bytes = dir.read(name)?.unwrap_or_default();
    let (records, complete) = parse(dir, name, &bytes)?;
    if complete != bytes.len() {
        return Err(StorageError::Corruption(format!(
            "{} ends inside a record",
            dir.child_path(name).display()
        )));
    }
    Ok(records)
}

/// Every whole record of the day file `name`, in order, leaving out a final item still being
/// written: what a read of a live trail sees, the trail's append holding no lock against it.
pub fn read_written(dir: &Dir, name: &str) -> StorageResult<Vec<AuditRecord>> {
    let bytes = dir.read(name)?.unwrap_or_default();
    Ok(parse(dir, name, &bytes)?.0)
}

/// Reads the last day file, cuts a torn final item, and answers its last whole record.
fn recover(dir: &Dir, name: &str) -> StorageResult<Option<AuditRecord>> {
    let bytes = dir.read(name)?.unwrap_or_default();
    let (mut records, complete) = parse(dir, name, &bytes)?;
    if complete != bytes.len() {
        let file = dir.open_write(name)?;
        write::truncate(dir, name, &file, complete as u64)?;
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
fn parse(dir: &Dir, name: &str, bytes: &[u8]) -> StorageResult<(Vec<AuditRecord>, usize)> {
    let mut records = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match cbor::decode_canonical_prefix(&bytes[at..]) {
            Ok((value, taken)) => {
                let record = AuditRecord::from_value(value).map_err(|error| {
                    StorageError::Corruption(format!(
                        "{} holds a record that does not read: {error}",
                        dir.child_path(name).display()
                    ))
                })?;
                records.push(record);
                at += taken;
            }
            Err(CborError::Truncated) if bytes.len() - at < MAX_RECORD_BYTES => break,
            Err(error) => {
                return Err(StorageError::Corruption(format!(
                    "{} holds bytes that are not a record at offset {at}: {error}",
                    dir.child_path(name).display()
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
pub fn verify(dir: &Dir) -> StorageResult<u64> {
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
                    dir.path().display()
                )));
            }
            if record.seq != seq {
                return Err(StorageError::Corruption(format!(
                    "record {} of {} follows record {}",
                    record.seq,
                    dir.path().display(),
                    seq.saturating_sub(1)
                )));
            }
            if record.previous != previous {
                return Err(StorageError::Corruption(format!(
                    "record {} of {} does not chain to the record before it",
                    record.seq,
                    dir.path().display()
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
