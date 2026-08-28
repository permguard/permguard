// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The spool: durable before the network, and the crash boundaries around it.
//!
//! # What it is for
//!
//! The decision path may never wait on the *network*, and a record may never be lost to a
//! restart. Those two together mean exactly one thing: the record is written to local durable
//! storage before the answer goes out, and the network happens later, from a different task,
//! against a receiver that may be down for hours.
//!
//! # The layout
//!
//! ```text
//! <volume>/data/decisions/spool/
//!   LOCK                    held exclusively — one writer per spool
//!   STATE                   instance, acked, digest(acked), a pending closure
//!   RESERVE                 preallocated: the terminal record always has room
//!   seg-<first_seq>.jsonl   one record per line, append-only
//! ```
//!
//! Under `data/` deliberately: until a record is acknowledged this is its
//! **only** copy, so a volume that treats the spool as scratch — an `emptyDir`,
//! a container's writable layer — loses decisions on the first restart. It sits
//! beside the store rather than inside it because the two are different duties
//! on the same subject: one plane writes here, another keeps what arrives.
//!
//! **The segments are the authority for what was written**, and `STATE` is the
//! authority for what was acknowledged. Splitting it that way is what makes
//! recovery unambiguous: a record that reached the disk is in a segment
//! whether or not anything else got updated, and a partial trailing line — a
//! torn write, the only thing a crash can leave behind — is truncated on open,
//! because a line that was never completed was never a record.
//!
//! # Why a reserve exists
//!
//! The producer cannot write its terminal record with the last byte:
//!
//! ```text
//! spool full  →  needs a discontinuity  →  cannot append it durably
//!             →  cannot legally discard  →  cannot continue at all
//! ```
//!
//! So `RESERVE` is allocated **when the spool is created**, outside the byte
//! bound, and the terminal record is written into it. A reservation made under
//! pressure is a reservation that fails under pressure; a spool that cannot
//! claim it refuses to open, exactly as one that cannot take the lock does.
//!
//! # Ending a stream, step by step
//!
//! The order is chosen so that every crash boundary is recoverable and no
//! boundary can mint two successors:
//!
//! ```text
//! 1. mint the successor and record it in STATE   ── crash here: retry, same successor
//! 2. write the terminal into RESERVE, flush      ── crash here: retry, same bytes
//! 3. discard the segments above `acked`          ── crash here: retry, idempotent
//! 4. adopt the successor as the live instance    ── ordinary operation resumes
//! ```
//!
//! The successor is named *inside* the terminal record, so a restart adopts
//! the one already decided rather than generating a second.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead as _, BufReader, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::instance;
use crate::record::{DigestError, GENESIS, digest_of};

/// The bytes held back so a terminal record always has somewhere to go.
///
/// Generous next to a record measured in hundreds of bytes: the cost of being
/// wrong in one direction is a few unused kilobytes, and in the other it is a
/// producer that cannot end its stream.
pub const RESERVE_BYTES: u64 = 64 * 1024;

const LOCK_FILE: &str = "LOCK";
const STATE_FILE: &str = "STATE";
const RESERVE_FILE: &str = "RESERVE";
const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".jsonl";

/// A stream that has ended and whose terminal record has not shipped yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Closing {
    /// The incarnation that ended.
    pub instance: String,
    /// Where its terminal record sits: `acked + 1`.
    pub terminal_seq: u64,
    /// The incarnation that continues it.
    pub successor: String,
    /// Why it ended.
    pub reason: String,
    /// The head the receiver holds for the closed stream — `digest(acked)`.
    ///
    /// Kept because the terminal record ships as a batch of its own, and that
    /// batch has to say which head it continues. The live spool has already
    /// reset to the successor's genesis by then, so this is the only place the
    /// closed stream's position survives.
    #[serde(default)]
    pub previous_head: String,
}

/// What the spool knows about itself across a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The live incarnation.
    pub instance: String,
    /// The highest sequence the control plane confirmed durable.
    pub acked: u64,
    /// The digest at that point — needed to chain a terminal record after the
    /// records above it are gone.
    pub acked_digest: String,
    /// A stream that ended and is still being shipped.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub closing: Option<Closing>,
    /// A successor decided but not yet written into a terminal record.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pending_successor: Option<String>,
}

/// How much a spool may hold before its stream must end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// The bound on decision records, excluding the reserve.
    pub bytes: u64,
    /// How old the oldest unshipped record may be.
    pub age: Duration,
    /// When a segment is closed and a new one started.
    pub segment_bytes: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            bytes: 512 * 1024 * 1024,
            age: Duration::from_secs(24 * 60 * 60),
            segment_bytes: 8 * 1024 * 1024,
        }
    }
}

/// The local, durable, append-only record of what this plane decided.
pub struct Spool {
    directory: PathBuf,
    bounds: Bounds,
    state: State,
    seq: u64,
    last_digest: String,
    open: Option<Segment>,
    /// Held for as long as this spool is: dropping it releases the claim.
    _lock: File,
}

struct Segment {
    first_seq: u64,
    file: File,
    bytes: u64,
}

impl Spool {
    /// Opens the spool at `directory`, creating it if it is not there.
    ///
    /// Refuses rather than sharing: a second writer would share a sequence,
    /// and two records claiming one `(stream, seq)` closes a stream
    /// permanently at the far end. Refusing to start is the cheaper failure.
    pub fn open(directory: impl AsRef<Path>, bounds: Bounds) -> Result<Self, SpoolError> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)
            .map_err(|error| SpoolError::io("creating the spool", error))?;

        let lock = claim_lock(&directory)?;
        reserve(&directory)?;

        let state = match read_state(&directory)? {
            Some(state) => state,
            None => {
                let state = State {
                    instance: instance::mint(),
                    acked: 0,
                    acked_digest: GENESIS.to_owned(),
                    closing: None,
                    pending_successor: None,
                };
                write_state(&directory, &state)?;
                state
            }
        };

        let (seq, last_digest) = recover(&directory, &state)?;

        Ok(Self {
            directory,
            bounds,
            state,
            seq,
            last_digest,
            open: None,
            _lock: lock,
        })
    }

    /// The live incarnation.
    pub fn instance(&self) -> &str {
        &self.state.instance
    }

    /// The highest sequence written.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The digest the next record must name as its `prev`.
    pub fn head(&self) -> &str {
        &self.last_digest
    }

    /// The highest sequence the control plane confirmed durable.
    pub fn acked(&self) -> u64 {
        self.state.acked
    }

    /// The digest at that point — the head the receiver holds for this stream.
    ///
    /// What a batch must declare as the head it continues. Durable, so a
    /// producer that restarts continues the receiver's chain rather than
    /// claiming to start a new one.
    pub fn acked_digest(&self) -> &str {
        &self.state.acked_digest
    }

    /// A stream that ended and whose terminal record still has to ship.
    pub fn closing(&self) -> Option<&Closing> {
        self.state.closing.as_ref()
    }

    /// The sequence and `prev` the next record must carry.
    pub fn next_position(&self) -> (u64, String) {
        (self.seq + 1, self.last_digest.clone())
    }

    /// Appends one record, and does not return until it is durable.
    ///
    /// The value is written verbatim: whatever the caller built is what is
    /// digested, shipped and stored, with nothing reserialised in between.
    pub fn append(&mut self, record: &Value) -> Result<Appended, SpoolError> {
        let appended = self.append_unsynced(record)?;
        self.sync_open()?;

        Ok(appended)
    }

    /// Appends one record without waiting for the disk.
    ///
    /// The half of [`Self::append`] group commit needs on its own: the write
    /// lands in the open segment and the sequence advances, and **durability
    /// is a separate, explicit step** — [`Self::sync_open`] — that one flush
    /// settles for every record appended before it. A caller that answers
    /// anybody on the strength of this append without that flush has broken
    /// the journal's contract, which is why the two-step form exists beside
    /// [`Self::append`] rather than instead of it.
    pub fn append_unsynced(&mut self, record: &Value) -> Result<Appended, SpoolError> {
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| SpoolError::Malformed("a record with no `seq`".to_owned()))?;
        if seq != self.seq + 1 {
            return Err(SpoolError::OutOfOrder {
                expected: self.seq + 1,
                found: seq,
            });
        }
        let prev = record
            .get("prev")
            .and_then(Value::as_str)
            .ok_or_else(|| SpoolError::Malformed("a record with no `prev`".to_owned()))?;
        if prev != self.last_digest {
            return Err(SpoolError::NotChained {
                expected: self.last_digest.clone(),
                found: prev.to_owned(),
            });
        }

        let digest = digest_of(record).map_err(SpoolError::Digest)?;
        let mut line =
            serde_json::to_vec(record).map_err(|error| SpoolError::Malformed(error.to_string()))?;
        line.push(b'\n');
        self.write_line(seq, &line)?;

        self.seq = seq;
        self.last_digest = digest.clone();

        Ok(Appended { seq, digest })
    }

    /// Every record after `after`, in order, up to `limit` of them.
    ///
    /// This is how the shipper reads: from the acknowledged point, never from
    /// a cursor of its own, so a restart cannot ship from the wrong place.
    pub fn read_from(&self, after: u64, limit: usize) -> Result<Vec<Value>, SpoolError> {
        let mut records = Vec::new();
        for (_, path) in self.segments()? {
            if records.len() >= limit {
                break;
            }
            let file =
                File::open(&path).map_err(|error| SpoolError::io("reading a segment", error))?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|error| SpoolError::io("reading a segment", error))?;
                if line.is_empty() {
                    continue;
                }
                // A torn tail is truncated on open; anything unreadable here
                // is a damaged segment, and stopping beats skipping.
                let value: Value = serde_json::from_str(&line)
                    .map_err(|error| SpoolError::Malformed(error.to_string()))?;
                if value.get("seq").and_then(Value::as_u64).unwrap_or_default() > after {
                    records.push(value);
                }
                if records.len() >= limit {
                    break;
                }
            }
        }

        Ok(records)
    }

    /// Records the highest contiguous durable sequence and frees what it covers.
    ///
    /// Acknowledgements never move backwards: a receiver reporting a number
    /// below one already recorded is answering about a stale view, and acting
    /// on it would re-ship records that are already durable there.
    pub fn acknowledge(&mut self, acked: u64, digest: impl Into<String>) -> Result<(), SpoolError> {
        if acked <= self.state.acked {
            return Ok(());
        }
        if acked > self.seq {
            return Err(SpoolError::AckAhead {
                acked,
                written: self.seq,
            });
        }
        self.state.acked = acked;
        self.state.acked_digest = digest.into();
        write_state(&self.directory, &self.state)?;
        self.discard_covered()?;

        Ok(())
    }

    /// Marks the terminal record shipped, so the closed stream is finished with.
    pub fn close_finished(&mut self) -> Result<(), SpoolError> {
        if self.state.closing.take().is_some() {
            write_state(&self.directory, &self.state)?;
            // The reserve goes back to being reserve.
            let _ = fs::write(
                self.directory.join(RESERVE_FILE),
                vec![0u8; RESERVE_BYTES as usize],
            );
        }

        Ok(())
    }

    /// The terminal record of a stream that ended, when one is waiting.
    pub fn terminal(&self) -> Result<Option<Value>, SpoolError> {
        if self.state.closing.is_none() {
            return Ok(None);
        }
        let bytes = fs::read(self.directory.join(RESERVE_FILE))
            .map_err(|error| SpoolError::io("reading the reserve", error))?;
        let text = String::from_utf8_lossy(&bytes);
        let line = text.lines().next().unwrap_or_default();
        if line.is_empty() {
            return Ok(None);
        }

        serde_json::from_str(line)
            .map(Some)
            .map_err(|error| SpoolError::Malformed(error.to_string()))
    }

    /// How many bytes of records the spool is holding.
    pub fn bytes(&self) -> Result<u64, SpoolError> {
        let mut total = 0;
        for (_, path) in self.segments()? {
            total += fs::metadata(&path)
                .map(|meta| meta.len())
                .map_err(|error| SpoolError::io("measuring a segment", error))?;
        }

        Ok(total)
    }

    /// Whether the spool has reached a bound and its stream must end.
    pub fn pressure(&self) -> Result<Option<&'static str>, SpoolError> {
        if self.bytes()? >= self.bounds.bytes {
            return Ok(Some("spool_full"));
        }
        if let Some(oldest) = self.oldest_modified()?
            && oldest.elapsed().unwrap_or_default() >= self.bounds.age
        {
            return Ok(Some("age_expiry"));
        }

        Ok(None)
    }

    /// Ends the live stream and starts its successor.
    ///
    /// `build` is handed the terminal record's position and returns the record
    /// to write, so this module never has to know what a record looks like
    /// beyond where it must sit.
    pub fn discontinue<F>(&mut self, reason: &str, build: F) -> Result<Discontinued, SpoolError>
    where
        F: FnOnce(Terminal) -> Result<Value, SpoolError>,
    {
        if self.state.closing.is_some() {
            return Err(SpoolError::AlreadyClosing);
        }

        // 1. The successor is decided first and written down, so a crash
        //    before the terminal exists cannot mint a second one.
        let successor = match self.state.pending_successor.clone() {
            Some(successor) => successor,
            None => {
                let successor = instance::mint();
                self.state.pending_successor = Some(successor.clone());
                write_state(&self.directory, &self.state)?;
                successor
            }
        };

        let terminal_seq = self.state.acked + 1;
        let terminal = build(Terminal {
            instance: self.state.instance.clone(),
            seq: terminal_seq,
            prev: self.state.acked_digest.clone(),
            successor: successor.clone(),
            lost_from: terminal_seq,
            lost_count: self.seq.saturating_sub(self.state.acked),
            reason: reason.to_owned(),
        })?;

        // 2. Into the reserve, which was claimed when the spool was created.
        let mut line = serde_json::to_vec(&terminal)
            .map_err(|error| SpoolError::Malformed(error.to_string()))?;
        line.push(b'\n');
        if line.len() as u64 > RESERVE_BYTES {
            return Err(SpoolError::TerminalTooLarge(line.len()));
        }
        let mut padded = line;
        padded.resize(RESERVE_BYTES as usize, b'\n');
        let mut file = OpenOptions::new()
            .write(true)
            .open(self.directory.join(RESERVE_FILE))
            .map_err(|error| SpoolError::io("opening the reserve", error))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| SpoolError::io("rewinding the reserve", error))?;
        file.write_all(&padded)
            .map_err(|error| SpoolError::io("writing the terminal record", error))?;
        file.sync_all()
            .map_err(|error| SpoolError::io("flushing the terminal record", error))?;

        // 3. The old stream is closed, and 4. the successor becomes live.
        let closed = self.state.instance.clone();
        self.state.closing = Some(Closing {
            instance: closed.clone(),
            terminal_seq,
            successor: successor.clone(),
            reason: reason.to_owned(),
            previous_head: self.state.acked_digest.clone(),
        });
        self.state.instance = successor.clone();
        self.state.pending_successor = None;
        self.state.acked = 0;
        self.state.acked_digest = GENESIS.to_owned();
        write_state(&self.directory, &self.state)?;

        self.open = None;
        for (_, path) in self.segments()? {
            fs::remove_file(&path)
                .map_err(|error| SpoolError::io("discarding a segment", error))?;
        }
        self.seq = 0;
        self.last_digest = GENESIS.to_owned();

        Ok(Discontinued {
            closed,
            successor,
            terminal_seq,
        })
    }

    fn write_line(&mut self, seq: u64, line: &[u8]) -> Result<(), SpoolError> {
        let rotate = match &self.open {
            None => true,
            Some(segment) => segment.bytes + line.len() as u64 > self.bounds.segment_bytes,
        };
        if rotate {
            // The segment being retired is flushed before the switch: after
            // it, nothing will hold its handle, and unsynced bytes in a closed
            // file are bytes a crash may take with it.
            self.sync_open()?;
            let path = self
                .directory
                .join(format!("{SEGMENT_PREFIX}{seq:020}{SEGMENT_SUFFIX}"));
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|error| SpoolError::io("opening a segment", error))?;
            self.open = Some(Segment {
                first_seq: seq,
                file,
                bytes: 0,
            });
        }
        let segment = self
            .open
            .as_mut()
            .ok_or_else(|| SpoolError::Malformed("no open segment".to_owned()))?;
        segment
            .file
            .write_all(line)
            .map_err(|error| SpoolError::io("appending a record", error))?;
        segment.bytes += line.len() as u64;

        Ok(())
    }

    /// Flushes the open segment, settling every record appended before it.
    ///
    /// The durability half of group commit: one call here makes durable
    /// everything [`Self::append_unsynced`] wrote since the last one, whoever
    /// wrote it. A spool with nothing open has nothing to settle.
    pub fn sync_open(&mut self) -> Result<(), SpoolError> {
        if let Some(segment) = &self.open {
            segment
                .file
                .sync_data()
                .map_err(|error| SpoolError::io("flushing a segment", error))?;
        }

        Ok(())
    }

    /// The open segment's handle, cloned, and the sequence a flush of it will
    /// cover.
    ///
    /// This is what lets the flush itself happen **outside** the spool lock: a
    /// flush that held the lock would stop every append for its whole
    /// duration, and the group it was flushing for would never grow past
    /// whatever slipped in between two flushes — group commit in name only.
    /// The clone is the same file description, so syncing it settles at least
    /// the bytes whose sequence the token reports. Later appends may become
    /// durable too, but a later group is the one that claims them. If a
    /// rotation happens after the token is issued, it flushes the old segment
    /// on its way out.
    pub fn flush_token(&self) -> Result<Option<(u64, File)>, SpoolError> {
        let Some(segment) = &self.open else {
            return Ok(None);
        };
        let handle = segment
            .file
            .try_clone()
            .map_err(|error| SpoolError::io("cloning a segment handle", error))?;

        Ok(Some((self.seq, handle)))
    }

    fn segments(&self) -> Result<Vec<(u64, PathBuf)>, SpoolError> {
        segments_of(&self.directory)
    }

    fn discard_covered(&mut self) -> Result<(), SpoolError> {
        let segments = self.segments()?;
        let open_first = self.open.as_ref().map(|segment| segment.first_seq);
        for (index, (first, path)) in segments.iter().enumerate() {
            // A segment may only go when the whole of it is acknowledged,
            // which is knowable from where the next segment starts.
            let covered = match segments.get(index + 1) {
                Some((next, _)) => *next <= self.state.acked + 1,
                None => false,
            };
            if covered && open_first != Some(*first) {
                fs::remove_file(path)
                    .map_err(|error| SpoolError::io("discarding a segment", error))?;
            }
        }

        Ok(())
    }

    fn oldest_modified(&self) -> Result<Option<SystemTime>, SpoolError> {
        let mut oldest: Option<SystemTime> = None;
        for (_, path) in self.segments()? {
            let modified = fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .map_err(|error| SpoolError::io("measuring a segment", error))?;
            oldest = Some(match oldest {
                Some(current) if current < modified => current,
                _ => modified,
            });
        }

        Ok(oldest)
    }
}

/// Where a terminal record has to sit, and what it has to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    /// The incarnation that is ending.
    pub instance: String,
    /// `acked + 1` — the only position a receiver can chain.
    pub seq: u64,
    /// `digest(acked)`.
    pub prev: String,
    /// The incarnation that continues.
    pub successor: String,
    /// The first sequence that will never be shipped.
    pub lost_from: u64,
    /// How many written records are being discarded.
    pub lost_count: u64,
    /// Why the stream ended.
    pub reason: String,
}

/// What a discontinuity did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discontinued {
    /// The incarnation that ended.
    pub closed: String,
    /// The one that took over.
    pub successor: String,
    /// Where the terminal record sits.
    pub terminal_seq: u64,
}

/// What appending established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// The sequence it took.
    pub seq: u64,
    /// Its digest, which the next record names.
    pub digest: String,
}

/// Why the spool refused.
#[derive(Debug)]
pub enum SpoolError {
    /// Another process holds this spool.
    Locked(PathBuf),
    /// The reserve could not be claimed, so a stream could not be ended cleanly.
    NoReserve(String),
    /// A record that is not one.
    Malformed(String),
    /// A record out of sequence — the caller's bug, refused rather than absorbed.
    OutOfOrder {
        /// What the spool was expecting.
        expected: u64,
        /// What it was handed.
        found: u64,
    },
    /// A record that does not continue the chain.
    NotChained {
        /// The spool's head.
        expected: String,
        /// What the record named.
        found: String,
    },
    /// An acknowledgement for something never written.
    AckAhead {
        /// What was acknowledged.
        acked: u64,
        /// What was written.
        written: u64,
    },
    /// A terminal record larger than the reserve.
    TerminalTooLarge(usize),
    /// A stream is already closing.
    AlreadyClosing,
    /// The digest could not be taken.
    Digest(DigestError),
    /// The filesystem said no.
    Io {
        /// What was being attempted.
        doing: &'static str,
        /// What the system said.
        detail: String,
    },
}

impl SpoolError {
    fn io(doing: &'static str, error: std::io::Error) -> Self {
        Self::Io {
            doing,
            detail: error.to_string(),
        }
    }
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked(path) => write!(
                formatter,
                "another process is writing the spool at {}: two writers would share a sequence",
                path.display()
            ),
            Self::NoReserve(detail) => write!(
                formatter,
                "the terminal record's reserve could not be claimed: {detail}. A producer that cannot end its stream cleanly must not begin one"
            ),
            Self::Malformed(detail) => write!(formatter, "not a record: {detail}"),
            Self::OutOfOrder { expected, found } => write!(
                formatter,
                "the spool is at sequence {expected} and was handed {found}"
            ),
            Self::NotChained { expected, found } => write!(
                formatter,
                "a record naming {found} as its predecessor does not continue a spool whose head is {expected}"
            ),
            Self::AckAhead { acked, written } => write!(
                formatter,
                "sequence {acked} was acknowledged but only {written} was ever written"
            ),
            Self::TerminalTooLarge(bytes) => write!(
                formatter,
                "a terminal record of {bytes} bytes does not fit the {RESERVE_BYTES}-byte reserve"
            ),
            Self::AlreadyClosing => write!(
                formatter,
                "this stream has already ended and its terminal record has not shipped"
            ),
            Self::Digest(error) => write!(formatter, "{error}"),
            Self::Io { doing, detail } => write!(formatter, "{doing}: {detail}"),
        }
    }
}

impl std::error::Error for SpoolError {}

fn segments_of(directory: &Path) -> Result<Vec<(u64, PathBuf)>, SpoolError> {
    let mut found = Vec::new();
    let entries =
        fs::read_dir(directory).map_err(|error| SpoolError::io("listing the spool", error))?;
    for entry in entries {
        let entry = entry.map_err(|error| SpoolError::io("listing the spool", error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(first) = segment_seq(&name) {
            found.push((first, entry.path()));
        }
    }
    found.sort_by_key(|(first, _)| *first);

    Ok(found)
}

/// Takes the spool's exclusive claim.
///
/// An **advisory lock on an open file**, not the existence of a lock file, and
/// the difference is the whole point: a lock held by existence outlives the
/// process that took it. A plane that was killed, or a host that lost power,
/// would leave a file behind and never be able to record again — and the usual
/// remedy, deleting a stale lock, is exactly the operation that lets two
/// writers share a sequence when it is done wrongly.
///
/// The kernel releases this one when the process ends, however it ends. So a
/// crash leaves the spool immediately reusable, and a second live writer is
/// still refused.
fn claim_lock(directory: &Path) -> Result<File, SpoolError> {
    let path = directory.join(LOCK_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|error| SpoolError::io("claiming the spool lock", error))?;

    match file.try_lock() {
        Ok(()) => {
            // For a human reading the volume; the claim itself is the lock.
            let _ = writeln!(file, "{}", std::process::id());
            let _ = file.flush();

            Ok(file)
        }
        Err(std::fs::TryLockError::WouldBlock) => Err(SpoolError::Locked(path)),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(SpoolError::io("claiming the spool lock", error))
        }
    }
}

fn reserve(directory: &Path) -> Result<(), SpoolError> {
    let path = directory.join(RESERVE_FILE);
    if fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0) >= RESERVE_BYTES {
        return Ok(());
    }
    // Written, not merely declared: a hole in a sparse file is not space.
    fs::write(&path, vec![b'\n'; RESERVE_BYTES as usize])
        .map_err(|error| SpoolError::NoReserve(error.to_string()))?;
    File::open(&path)
        .and_then(|file| file.sync_all())
        .map_err(|error| SpoolError::NoReserve(error.to_string()))?;

    Ok(())
}

fn read_state(directory: &Path) -> Result<Option<State>, SpoolError> {
    match fs::read(directory.join(STATE_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| SpoolError::Malformed(format!("the spool state: {error}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SpoolError::io("reading the spool state", error)),
    }
}

fn write_state(directory: &Path, state: &State) -> Result<(), SpoolError> {
    let temporary = directory.join(format!("{STATE_FILE}.next"));
    let bytes = serde_json::to_vec(state)
        .map_err(|error| SpoolError::Malformed(format!("the spool state: {error}")))?;
    {
        let mut file = File::create(&temporary)
            .map_err(|error| SpoolError::io("writing the spool state", error))?;
        file.write_all(&bytes)
            .map_err(|error| SpoolError::io("writing the spool state", error))?;
        file.sync_all()
            .map_err(|error| SpoolError::io("flushing the spool state", error))?;
    }
    // Rename is the atomic step: a reader sees the old state or the new one,
    // never half of either.
    fs::rename(&temporary, directory.join(STATE_FILE))
        .map_err(|error| SpoolError::io("replacing the spool state", error))?;
    if let Ok(handle) = File::open(directory) {
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Finds where the stream stands, truncating a torn trailing line.
fn recover(directory: &Path, state: &State) -> Result<(u64, String), SpoolError> {
    let segments = segments_of(directory)?;
    if segments.is_empty() {
        return Ok((state.acked, state.acked_digest.clone()));
    }

    let mut seq = 0;
    let mut digest = state.acked_digest.clone();
    for (_, path) in &segments {
        let bytes = fs::read(path).map_err(|error| SpoolError::io("reading a segment", error))?;
        // Everything up to the last newline is whole; anything after it was
        // interrupted, and was never a record.
        let complete = match bytes.iter().rposition(|byte| *byte == b'\n') {
            Some(position) => position + 1,
            None => 0,
        };
        if complete != bytes.len() {
            let file = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|error| SpoolError::io("truncating a torn record", error))?;
            file.set_len(complete as u64)
                .map_err(|error| SpoolError::io("truncating a torn record", error))?;
            let _ = file.sync_all();
        }
        for line in bytes[..complete].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_slice(line)
                .map_err(|error| SpoolError::Malformed(error.to_string()))?;
            seq = value.get("seq").and_then(Value::as_u64).unwrap_or(seq);
            digest = digest_of(&value).map_err(SpoolError::Digest)?;
        }
    }
    if seq == 0 {
        return Ok((state.acked, state.acked_digest.clone()));
    }

    Ok((seq, digest))
}

fn segment_seq(name: &str) -> Option<u64> {
    name.strip_prefix(SEGMENT_PREFIX)
        .and_then(|rest| rest.strip_suffix(SEGMENT_SUFFIX))
        .and_then(|digits| digits.parse().ok())
}
