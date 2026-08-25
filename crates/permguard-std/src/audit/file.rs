// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An audit trail that survives the process, and notices when somebody edits it.
//!
//! One JSON object per line, one file per UTC day, appended and flushed to the disk before the write
//! is reported as done.
//!
//! # The chain
//!
//! Every record carries the digest of the record before it. That makes the file a hash chain: change
//! a field, remove a line, reorder two entries, and every digest from that point on stops matching.
//!
//! This is tamper **evidence**, not tamper prevention, and the difference is worth being precise
//! about. Anyone who can write the file can also rewrite the whole chain from the point they changed
//! — the records are hashed, not signed, so nothing here stops an attacker with write access and
//! patience. What it stops is the much more common thing: a line quietly deleted, a value edited in
//! place, a file truncated. And because the chain is continuous across days, a whole day's file
//! going missing is detectable too.
//!
//! Making it survive an attacker with write access needs the head of the chain to leave the machine
//! — signed with a key they do not have, or written somewhere append-only. The chain is what makes
//! that possible later: a single digest is enough to attest to everything before it.
//!
//! # Why it flushes every record
//!
//! An audit trail that loses its last few records to a crash loses exactly the records that were
//! being written when whatever went wrong went wrong. Buffering would make this faster at the cost
//! of the entries most likely to matter.
//!
//! # Blocking
//!
//! The writes are synchronous, inside an async method. They are small, they are rare — a service
//! starting, a service stopping, an administrative call — and ordering them is the whole point, so
//! they are not worth moving off the runtime thread for. A deployment that audits per data-plane
//! request should implement the contract over something that batches.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use permguard_core::{AuditError, AuditEvent, AuditSink, BoxFuture, KeyManager, Pseudonymizer};

use permguard_core::time::{self as civil, Date};

/// What this sink answers with.
type Result<T> = std::result::Result<T, AuditError>;

/// What a file of records is called, either side of the date.
const PREFIX: &str = "audit-";
const SUFFIX: &str = ".jsonl";

/// What a seal is called, beside the day it closes.
const SEAL_SUFFIX: &str = ".seal";

/// The digest the first record of a trail names as its predecessor.
///
/// Sixty-four zeroes rather than an absent field, so every record has the same shape and the
/// verifier has one case instead of two.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Everything a record says, and the only thing the digest covers.
///
/// Nested inside the line rather than flattened beside the digest, because verification re-serialises
/// exactly this and compares — and a scheme where the hashed bytes have to be reconstructed by
/// removing a field from the middle of an object is a scheme that eventually disagrees with itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// Where this record sits in the trail, from 1 and never reused.
    pub seq: u64,
    /// When it happened, RFC 3339 in UTC.
    pub at: String,
    /// The digest of the record before this one, across day boundaries.
    pub prev: String,
    /// What happened.
    pub action: String,
    /// Who it was about, already rendered under the privacy policy in force.
    pub subject: String,
    /// What kind of thing the subject is, which survives even when the subject is masked.
    pub subject_kind: String,
    /// How sensitive that made it.
    pub subject_sensitivity: String,
    /// What it was done to, when the event named something.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    /// Stable continuity/lineage identifier, mirrored from PIC Token JWT `jti` when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub continuity_id: Option<String>,
    /// PCA position associated with the continuity event.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub continuity_position: Option<u64>,
    /// Which build recorded it.
    pub service: String,
    /// Which version of it.
    pub version: String,
}

/// One line of the trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The record itself.
    pub body: Body,
    /// The digest of `body`, which the next record names as its `prev`.
    pub digest: String,
}

impl Record {
    /// Returns the digest `body` should have.
    fn expected_digest(body: &Body) -> Result<String> {
        let canonical = serde_json::to_vec(body)
            .map_err(|error| AuditError::backend(format!("describing a record: {error}")))?;

        Ok(hex(Sha256::digest(&canonical).as_slice()))
    }
}

/// What a seal attests to: a day of the trail, and where the chain stood at the end of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealBody {
    /// The day this seal closes, as `YYYY-MM-DD`.
    pub day: String,
    /// When it was sealed, RFC 3339 in UTC.
    pub at: String,
    /// How many records the whole trail held at that point.
    pub records: u64,
    /// The digest of the last record — one value that stands for every record before it.
    pub head: String,
}

/// A statement about the trail that can leave the machine and still be checked.
///
/// # What this is for
///
/// The chain makes tampering *detectable by whoever holds the trail*. It does not help against
/// somebody who can rewrite the files, because they can recompute every digest from the point they
/// changed and the result verifies again.
///
/// What defeats that is the head **leaving**. A seal is the head in a form that can travel — to a log
/// collector, to a monitoring system, to another host — and, when a key ring is composed, signed, so
/// that whoever received it can check it against the published key set without trusting the sender.
/// Anyone holding yesterday's seal can then tell that today's trail no longer agrees with it.
///
/// The seal is written beside the trail *and* emitted to the log stream, and the second is the one
/// that matters: a seal that never leaves the volume it attests to is worth as little as the chain
/// it summarises.
///
/// It is still not proof against an attacker who owns the host — the signing key is on the same
/// volume. Making it so means keeping the key where they cannot reach it, which is what the
/// [`KeyManager`] contract exists to allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    /// What is attested, and the only thing the signature covers.
    pub body: SealBody,
    /// The key that signed it, when one was available.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
    /// The algorithm it was signed with.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub algorithm: Option<String>,
    /// The signature over `body`, lowercase hex.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<String>,
}

impl Seal {
    /// Returns the exact bytes a signature covers.
    ///
    /// Public because verifying happens elsewhere — in whatever holds the published key set — and a
    /// verifier that reconstructs these bytes by hand eventually reconstructs them differently.
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.body)
            .map_err(|error| AuditError::backend(format!("describing a seal: {error}")))
    }
}

/// The file currently being appended to.
struct Open {
    day: i64,
    file: File,
    seq: u64,
    previous: String,
}

/// An audit trail on the local filesystem.
pub struct FileAuditSink {
    directory: PathBuf,
    service_name: String,
    service_version: String,
    retention: Duration,
    keys: Option<Arc<dyn KeyManager>>,
    open: Mutex<Option<Open>>,
}

impl FileAuditSink {
    /// Builds a sink that writes to `directory`, keeping each day for `retention`.
    pub fn new(
        directory: impl Into<PathBuf>,
        service_name: impl Into<String>,
        service_version: impl Into<String>,
        retention: Duration,
    ) -> Self {
        Self {
            directory: directory.into(),
            service_name: service_name.into(),
            service_version: service_version.into(),
            retention,
            keys: None,
            open: Mutex::new(None),
        }
    }

    /// Signs every seal with `keys`.
    ///
    /// Without this the seals are still written and still record where the chain stood, which is
    /// worth something to whoever kept the previous one. The signature is what makes a seal
    /// checkable by somebody who does not trust the machine that produced it.
    pub fn sealed_by(mut self, keys: Arc<dyn KeyManager>) -> Self {
        self.keys = Some(keys);

        self
    }

    /// Returns the directory the trail lives in.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Prepares the directory and drops whatever is past its retention.
    ///
    /// Called once before the server starts, so a trail that cannot be written is a failure to start
    /// rather than a failure to record, discovered later by whoever needed the record.
    pub fn prepare(&self) -> Result<()> {
        fs::create_dir_all(&self.directory).map_err(|error| {
            AuditError::backend(format!("creating {}: {error}", self.directory.display()))
        })?;

        restrict(&self.directory, 0o700)?;
        self.expire(civil::day_of(now()))?;

        Ok(())
    }

    /// Removes every day of records older than the retention allows.
    fn expire(&self, today: i64) -> Result<usize> {
        let days = (self.retention.as_secs() / 86_400) as i64;
        let oldest_kept = today - days;
        let mut removed = 0;

        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(AuditError::unavailable(error)),
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(day) = day_of_file(&name.to_string_lossy()) else {
                continue;
            };

            if day >= oldest_kept {
                continue;
            }

            fs::remove_file(entry.path()).map_err(|error| {
                AuditError::backend(format!("removing {}: {error}", entry.path().display()))
            })?;
            // The seal goes with the day it attests to: a seal for records nobody kept is a claim
            // nobody can check.
            let _ = fs::remove_file(self.seal_path(day));
            removed += 1;

            tracing::info!(
                event.name = "audit.expired",
                component = "audit",
                path = %entry.path().display(),
                "removed a day of records that is past its retention"
            );
        }

        Ok(removed)
    }

    /// Attests to where the chain stood at the end of `day`, and lets the attestation leave.
    ///
    /// Written beside the trail and emitted to the log stream. A failure to seal is reported and does
    /// not stop the trail: losing the summary is bad, losing the records it summarises is worse.
    fn seal(&self, day: i64, records: u64, head: &str) -> Result<()> {
        let body = SealBody {
            day: civil::date_of(day).to_iso(),
            at: civil::to_rfc3339(now()),
            records,
            head: head.to_owned(),
        };

        let payload = serde_json::to_vec(&body)
            .map_err(|error| AuditError::backend(format!("describing a seal: {error}")))?;

        let signed = match &self.keys {
            Some(keys) => match keys.sign(&payload) {
                Ok(signature) => Some(signature),
                Err(error) => {
                    // A key ring that is not ready yet is the ordinary case at the very first
                    // rollover, and an unsigned seal is still worth writing.
                    tracing::warn!(
                        event.name = "audit.seal_unsigned",
                        component = "audit",
                        day = %body.day,
                        error = %error,
                        "the seal was written without a signature"
                    );

                    None
                }
            },
            None => None,
        };

        let seal = Seal {
            kid: signed.as_ref().map(|s| s.key_id().to_string()),
            algorithm: signed.as_ref().map(|s| s.algorithm().to_owned()),
            signature: signed.as_ref().map(|s| hex(s.bytes())),
            body,
        };

        let path = self.seal_path(day);
        let text = serde_json::to_string_pretty(&seal)
            .map_err(|error| AuditError::backend(format!("describing a seal: {error}")))?;

        fs::write(&path, text.as_bytes())
            .map_err(|error| AuditError::backend(format!("writing {}: {error}", path.display())))?;
        restrict(&path, 0o600)?;

        // The half that matters: the log stream leaves this machine, so the attestation does too.
        tracing::info!(
            event.name = "audit.sealed",
            component = "audit",
            audit.day = %seal.body.day,
            audit.records = seal.body.records,
            audit.head = %seal.body.head,
            audit.kid = seal.kid.as_deref(),
            audit.signature = seal.signature.as_deref(),
            "sealed a day of the audit trail"
        );

        Ok(())
    }

    /// Returns the file for `day`, opening or rolling over as needed.
    fn open_for(&self, open: &mut Option<Open>, day: i64) -> Result<()> {
        if open.as_ref().is_some_and(|current| current.day == day) {
            return Ok(());
        }

        // Where the chain continues from: the last record of whatever was being written, or — on a
        // cold start — the last record of the most recent day on disk.
        let tail = match open.as_ref() {
            Some(current) => Some((current.seq, current.previous.clone())),
            None => self.tail()?,
        };

        let path = self.path_for(day);
        fs::create_dir_all(&self.directory).map_err(|error| {
            AuditError::backend(format!("creating {}: {error}", self.directory.display()))
        })?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| AuditError::backend(format!("opening {}: {error}", path.display())))?;
        restrict(&path, 0o600)?;

        let (seq, previous) = tail.unwrap_or((0, GENESIS.to_owned()));

        *open = Some(Open {
            day,
            file,
            seq,
            previous,
        });

        Ok(())
    }

    /// Returns where the chain left off: the sequence and digest of the last record written.
    fn tail(&self) -> Result<Option<(u64, String)>> {
        let Some(latest) = self.days()?.pop() else {
            return Ok(None);
        };

        let file = File::open(self.path_for(latest)).map_err(AuditError::unavailable)?;

        // A whole day is read to find its last line. The file is small — an audit trail records
        // decisions, not traffic — and this happens once, when the process starts.
        let last = BufReader::new(file)
            .lines()
            .map_while(std::result::Result::ok)
            .filter(|line| !line.trim().is_empty())
            .last();

        let Some(last) = last else {
            return Ok(None);
        };

        let record: Record = serde_json::from_str(&last).map_err(|error| {
            AuditError::backend(format!("reading the last record of the trail: {error}"))
        })?;

        Ok(Some((record.body.seq, record.digest)))
    }

    /// Returns every day the directory holds records for, oldest first.
    fn days(&self) -> Result<Vec<i64>> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(AuditError::unavailable(error)),
        };

        let mut days: Vec<i64> = entries
            .flatten()
            .filter_map(|entry| day_of_file(&entry.file_name().to_string_lossy()))
            .collect();

        days.sort_unstable();

        Ok(days)
    }

    fn path_for(&self, day: i64) -> PathBuf {
        self.directory
            .join(format!("{PREFIX}{}{SUFFIX}", civil::date_of(day).to_iso()))
    }

    fn seal_path(&self, day: i64) -> PathBuf {
        self.directory.join(format!(
            "{PREFIX}{}{SEAL_SUFFIX}",
            civil::date_of(day).to_iso()
        ))
    }
}

impl AuditSink for FileAuditSink {
    fn name(&self) -> &'static str {
        "file"
    }

    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let seconds = now();
            let day = civil::day_of(seconds);

            let mut open = self
                .open
                .lock()
                .map_err(|_| AuditError::backend("the audit file lock is poisoned"))?;

            let rolled = !open.as_ref().is_some_and(|current| current.day == day);

            // The day that is closing gets its seal before the next one is opened, while its head is
            // still to hand. A failure here is reported and does not stop the record being written:
            // losing the summary is bad, losing what it summarises is worse.
            if rolled && let Some(closing) = open.as_ref() {
                let (closed, records, head) = (closing.day, closing.seq, closing.previous.clone());

                if let Err(error) = self.seal(closed, records, &head) {
                    tracing::warn!(
                        event.name = "audit.seal_failed",
                        component = "audit",
                        error = %error,
                        "a day of the trail was closed without a seal"
                    );
                }
            }

            self.open_for(&mut open, day)?;

            // A new day is the natural moment to drop the oldest one: it happens once, it happens
            // while something is already being written, and it needs no timer of its own.
            if rolled {
                self.expire(day)?;
            }

            let current = open
                .as_mut()
                .ok_or_else(|| AuditError::backend("the audit file was not opened"))?;

            let body = Body {
                seq: current.seq + 1,
                at: civil::to_rfc3339(seconds),
                prev: current.previous.clone(),
                action: event.action().to_owned(),
                subject: event.subject().render(policy),
                subject_kind: event.subject().kind().to_owned(),
                subject_sensitivity: event.subject().sensitivity().as_str().to_owned(),
                target: event.target().map(ToOwned::to_owned),
                continuity_id: event.continuity_id().map(ToOwned::to_owned),
                continuity_position: event.continuity_position(),
                service: self.service_name.clone(),
                version: self.service_version.clone(),
            };

            let digest = Record::expected_digest(&body)?;
            let line = serde_json::to_string(&Record {
                body,
                digest: digest.clone(),
            })
            .map_err(|error| AuditError::backend(format!("describing a record: {error}")))?;

            writeln!(current.file, "{line}")
                .map_err(|error| AuditError::backend(format!("appending a record: {error}")))?;
            current
                .file
                .sync_data()
                .map_err(|error| AuditError::backend(format!("flushing a record: {error}")))?;

            current.seq += 1;
            current.previous = digest;

            Ok(())
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut open = self
                .open
                .lock()
                .map_err(|_| AuditError::backend("the audit file lock is poisoned"))?;

            if let Some(current) = open.as_mut() {
                current
                    .file
                    .sync_all()
                    .map_err(|error| AuditError::backend(format!("closing the trail: {error}")))?;

                let (day, records, head) = (current.day, current.seq, current.previous.clone());

                // After the last record and after the flush: a seal that named a head the disk does
                // not hold would attest to something that never happened.
                if let Err(error) = self.seal(day, records, &head) {
                    tracing::warn!(
                        event.name = "audit.seal_failed",
                        component = "audit",
                        error = %error,
                        "the trail was closed without a seal"
                    );
                }
            }

            *open = None;

            Ok(())
        })
    }
}

/// What checking a trail found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// How many records were read.
    pub records: u64,
    /// How many days of records were read.
    pub days: usize,
    /// The digest of the last record, which is what attests to everything before it.
    pub head: String,
    /// Every seal found beside the trail, already checked against the records it attests to.
    ///
    /// Their *signatures* are not checked here, and deliberately: doing so needs the published key
    /// set, and a verifier that fetched it from the machine under suspicion would be checking a
    /// signature against a key the same attacker could have replaced. The caller supplies the keys it
    /// trusts — see [`permguard_std::keys::verify_signature`](crate::keys::verify_signature).
    pub seals: Vec<Seal>,
}

/// Reads a whole trail and checks that nothing in it has been altered.
///
/// Checks three things, and they catch different edits: every digest matches the record it covers
/// (a field was changed), every record names the previous digest (a record was replaced), and the
/// sequence increases by exactly one across the whole trail including day boundaries (a record, or a
/// whole day, was removed).
pub fn verify(directory: &Path) -> anyhow::Result<Verification> {
    use anyhow::{Context, bail};

    let mut days: Vec<i64> = fs::read_dir(directory)
        .with_context(|| format!("reading {}", directory.display()))?
        .flatten()
        .filter_map(|entry| day_of_file(&entry.file_name().to_string_lossy()))
        .collect();
    days.sort_unstable();

    // Every seal, indexed by the point in the trail it attests to. A seal is a *checkpoint over a
    // prefix*, not a statement about a finished day: a process that restarts and appends more records
    // to the same day has not tampered with anything, and its earlier seal still has to hold.
    let seals = read_seals(directory, &days)?;
    let mut checked: Vec<Seal> = Vec::new();

    let mut expected_previous = GENESIS.to_owned();
    let mut expected_seq = 1_u64;
    let mut records = 0_u64;

    for day in &days {
        let path = directory.join(format!("{PREFIX}{}{SUFFIX}", civil::date_of(*day).to_iso()));
        let file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;

        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line.with_context(|| format!("reading {}", path.display()))?;

            if line.trim().is_empty() {
                continue;
            }

            let where_ = format!("{}:{}", path.display(), index + 1);
            let record: Record =
                serde_json::from_str(&line).with_context(|| format!("parsing {where_}"))?;

            let digest = Record::expected_digest(&record.body)
                .map_err(|error| anyhow::anyhow!("{error}"))?;

            if digest != record.digest {
                bail!("{where_} has been altered: it does not match its own digest");
            }

            if record.body.prev != expected_previous {
                bail!(
                    "{where_} does not follow the record before it: the chain is broken, which \
                     means something between them was changed or removed"
                );
            }

            if record.body.seq != expected_seq {
                bail!(
                    "{where_} is numbered {} where {expected_seq} was expected: {} record(s) are \
                     missing",
                    record.body.seq,
                    record.body.seq.saturating_sub(expected_seq)
                );
            }

            expected_previous = record.digest;
            expected_seq += 1;
            records += 1;

            // The moment the trail reaches the point a seal attests to, the head has to be the one
            // the seal names. This is the check the chain alone cannot make: a trail rewritten from
            // the beginning verifies against itself, and stops agreeing with a seal.
            if let Some(seal) = seals.get(&records) {
                if seal.body.head != expected_previous {
                    bail!(
                        "the seal for {} attests that record {} was {}, and the trail now has {}: \
                         the records have been rewritten since they were sealed",
                        seal.body.day,
                        records,
                        seal.body.head,
                        expected_previous
                    );
                }

                checked.push(seal.clone());
            }
        }
    }

    // A seal for records the trail no longer holds is the case the chain by itself misses entirely:
    // cut the tail off and what remains is perfectly self-consistent. The seal is what makes a
    // truncation visible.
    if let Some(beyond) = seals.keys().find(|point| **point > records) {
        let seal = &seals[beyond];

        bail!(
            "the seal for {} attests to {} record(s) and the trail holds {}: {} record(s) have been \
             removed from the end",
            seal.body.day,
            seal.body.records,
            records,
            seal.body.records - records
        );
    }

    Ok(Verification {
        records,
        days: days.len(),
        head: expected_previous,
        seals: checked,
    })
}

/// Reads every seal beside the trail, indexed by the point in it each one attests to.
fn read_seals(directory: &Path, days: &[i64]) -> anyhow::Result<BTreeMap<u64, Seal>> {
    use anyhow::Context;

    let mut seals = BTreeMap::new();

    for day in days {
        let path = directory.join(format!(
            "{PREFIX}{}{SEAL_SUFFIX}",
            civil::date_of(*day).to_iso()
        ));

        if !path.is_file() {
            continue;
        }

        let seal: Seal = serde_json::from_str(
            &fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?;

        seals.insert(seal.body.records, seal);
    }

    Ok(seals)
}

/// Returns which day a file holds records for, or nothing when it is not one of ours.
fn day_of_file(name: &str) -> Option<i64> {
    let date = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;

    Date::from_iso(date).map(civil::days_of)
}

/// Returns the current time in seconds since the Unix epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");

        out
    })
}

/// Narrows permissions where the platform has them.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| AuditError::backend(format!("restricting {}: {error}", path.display())))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn body(seq: u64, prev: &str) -> Body {
        Body {
            seq,
            at: "2026-08-09T00:00:00Z".to_owned(),
            prev: prev.to_owned(),
            action: "server.start".to_owned(),
            subject: "default".to_owned(),
            subject_kind: "system".to_owned(),
            subject_sensitivity: "public".to_owned(),
            target: None,
            continuity_id: None,
            continuity_position: None,
            service: "permguard".to_owned(),
            version: "0.1.0".to_owned(),
        }
    }

    #[test]
    fn test_a_records_digest_covers_every_field_of_it() {
        let original = body(1, GENESIS);
        let digest = Record::expected_digest(&original).expect("it digests");

        let mut altered = original.clone();
        altered.action = "server.stop".to_owned();

        assert_ne!(
            Record::expected_digest(&altered).expect("it digests"),
            digest,
            "changing the action left the digest alone"
        );

        let mut retargeted = original;
        retargeted.target = Some("/permguard.admin.v1.Admin/GetVersion".to_owned());

        assert_ne!(
            Record::expected_digest(&retargeted).expect("it digests"),
            digest,
            "adding a target left the digest alone"
        );

        let mut correlated = body(1, GENESIS);
        correlated.continuity_id = Some("permguard-test-lineage".to_owned());

        assert_ne!(
            Record::expected_digest(&correlated).expect("it digests"),
            digest,
            "adding a continuity id left the digest alone"
        );
    }

    #[test]
    fn test_the_same_record_always_digests_to_the_same_value() {
        // The chain is only worth anything if two readers agree on what a record hashes to.
        assert_eq!(
            Record::expected_digest(&body(1, GENESIS)).expect("it digests"),
            Record::expected_digest(&body(1, GENESIS)).expect("it digests")
        );
    }

    #[test]
    fn test_only_our_own_files_are_treated_as_days_of_records() {
        assert_eq!(
            day_of_file("audit-1970-01-02.jsonl"),
            Some(1),
            "a file of ours"
        );

        for other in [
            "audit-1970-01-02.jsonl.gz",
            "audit-not-a-date.jsonl",
            "README.md",
            "audit-.jsonl",
            ".",
        ] {
            assert!(day_of_file(other).is_none(), "{other} was claimed");
        }
    }
}
