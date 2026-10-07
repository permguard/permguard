// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One trail: `host/audit/trails/<class>/<resource digest>/`.
//!
//! | File                 | Content                                                               |
//! | -------------------- | --------------------------------------------------------------------- |
//! | `META.cbor`          | the class and the structured resource the digest path stands for      |
//! | `YYYY-MM-DD.cborseq` | the records of one UTC day, a CBOR sequence, each record one item     |
//! | `checkpoints/`       | created here; the signed checkpoints and `ANCHOR.cbor` are WP-3.7's    |
//!
//! A record is appended and flushed through the storage library before the append returns; an
//! append that fails cuts its own bytes back off. At open the newest day files are read: an
//! incomplete final item shorter than any record can be is a torn write and is cut with the
//! library's `write::truncate`; anything else that does not read is corruption and the trail
//! refuses to open (owner decision of 2026-10-07). The sequence and the chain continue across
//! days and restarts from the last record found, and a record never goes to a day file earlier
//! than the trail's last one, whatever the wall clock says.
//!
//! An `access` or `operations` trail drops whole day files older than its retention through the
//! storage library's tombstones; a `security` trail keeps every day (owner decision of
//! 2026-10-07). After a drop, a trail is verified from the first day it kept.

use std::io::Write as _;
use std::time::Duration;

use permguard_objects::cbor::{self, CborError};
use permguard_objects::digest::Digest;

use crate::storage::write::{self, Published, publish_immutable};
use crate::storage::{Dir, Result as StorageResult, StorageError, tombstone};

use super::Class;
use super::record::{AuditRecord, MAX_RECORD_BYTES, TrailMeta, digest_of, genesis, hex};

/// The file holding the trail's class and resource.
pub const META: &str = "META.cbor";
/// The directory WP-3.7's checkpoints are published in.
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
    next_seq: u64,
    previous: Digest,
    /// The newest day file, which no record goes before.
    last_day: Option<String>,
    retention: Option<Duration>,
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
        dir.subdir(CHECKPOINTS, true)?;

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
        let (next_seq, previous) = match continued {
            Some(record) => {
                let digest = record
                    .digest()
                    .map_err(|error| StorageError::Corruption(error.to_string()))?;
                (record.seq + 1, digest)
            }
            None => (0, genesis()),
        };
        Ok(Self {
            dir,
            next_seq,
            previous,
            last_day: days.last().cloned(),
            retention,
        })
    }

    /// The sequence the next record gets.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Appends `record`, giving it its sequence and the previous record's digest, and flushes the
    /// day file before returning. An append that fails leaves the day file as it found it.
    pub fn append(&mut self, mut record: AuditRecord) -> StorageResult<()> {
        record.seq = self.next_seq;
        record.previous = self.previous.clone();
        let bytes = record
            .encode()
            .map_err(|error| StorageError::Corruption(error.to_string()))?;
        let by_clock = day_name(record.at);
        let name = match &self.last_day {
            Some(last) if *last > by_clock => last.clone(),
            _ => by_clock,
        };
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
        self.last_day = Some(name.clone());
        if new_day {
            self.prune(&name)?;
        }
        Ok(())
    }

    /// Drops the day files older than the retention, counted back from the day `today`.
    fn prune(&self, today: &str) -> StorageResult<()> {
        let Some(retention) = self.retention else {
            return Ok(());
        };
        let Some(cutoff) = cutoff(today, retention) else {
            return Ok(());
        };
        for day in days(&self.dir)? {
            if day < cutoff && day.as_str() != today {
                tombstone::delete(&self.dir, &day)?;
            }
        }
        Ok(())
    }
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
