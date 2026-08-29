// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The durable local event journal: one producer stream, on one volume.
//!
//! # Why this is not the decision spool
//!
//! The two share their crash mechanics, and this reuses them deliberately: an exclusive lock so
//! one writer owns a stream, bounded append-only segments, a reserve so the terminal record always
//! has somewhere to go, group commit, and a torn trailing record truncated on open because a
//! record that was never completed was never a record.
//!
//! What differs is what the journal is *for*, and it changes retention entirely.
//!
//! A decision record is evidence. Once the control plane acknowledges it, the producer is free to
//! forget it — acknowledgement empties an outbound queue. An event record is evidence **and an
//! input**: it is the history a temporal policy reads. Forgetting it the moment it shipped would
//! silently change what future decisions mean, which is the one failure this whole feature exists
//! to prevent. So deletion needs *both* boundaries:
//!
//! ```text
//! deletable through = min(acknowledged by the control plane,
//!                        older than every loaded policy could ask about)
//! ```
//!
//! The second boundary comes from the compiled schemas — the largest `max_window` any loaded
//! policy declares — widened by the configured allowed lateness and clock skew. A deployment whose
//! configured retention is shorter than that is refused at load rather than discovering at the
//! first eviction that its policies have started answering differently.
//!
//! # The layout
//!
//! ```text
//! data/events/streams/<zone>/<ledger>/<producer-class>/<producer-id>/<instance>/
//!   LOCK                       held exclusively — one writer per stream
//!   STATE                      identity, next sequence, chain head, watermarks
//!   RESERVE                    preallocated, outside the byte bound
//!   seg-<first-sequence>.events
//!   checkpoint-<first-sequence>.jws
//! ```
//!
//! The segments are the authority for what was written; `STATE` is the authority for what was
//! acknowledged, signed and retained. Splitting it that way is what makes recovery unambiguous.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::record::{DigestError, GENESIS, Stream, digest_of};

/// The bytes held back so a stream can always be ended durably.
pub const RESERVE_BYTES: u64 = 64 * 1024;

const LOCK_FILE: &str = "LOCK";
/// The file a journal keeps its watermarks in. Public because it is also what tells a directory
/// holding a stream apart from a directory that merely exists — how a restart finds every stream
/// it has to ship, including ones no request has touched since.
pub const STATE_FILE: &str = "STATE";
const RESERVE_FILE: &str = "RESERVE";
const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".events";
/// The signed checkpoint covering a batch, named by the batch's first sequence.
const CHECKPOINT_PREFIX: &str = "checkpoint-";
const CHECKPOINT_SUFFIX: &str = ".jws";
/// Where each occurrence's position and answer are kept, addressed by the id a client retries with.
const OCCURRENCES_DIRECTORY: &str = "occurrences";
const OCCURRENCE_SUFFIX: &str = ".json";

/// What the journal knows about itself across a restart.
///
/// Every watermark is separate on purpose. "Durable" and "signed" and "acknowledged" and "still
/// needed by a policy" are four different facts, and collapsing any two of them is how a record
/// gets deleted while something still depends on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Which stream this directory holds. Written so a directory moved or restored under the
    /// wrong path is refused rather than appended to.
    pub stream: Stream,
    /// The next sequence to assign. Never reset inside an instance.
    pub next_seq: u64,
    /// The digest of the record at `next_seq - 1`, or the genesis.
    pub head: String,
    /// The highest sequence written and `fsync`ed.
    pub durable_through: u64,
    /// The highest sequence covered by a persisted signed checkpoint.
    pub signed_through: u64,
    /// The highest sequence the control plane confirmed durable.
    pub acked_through: u64,
    /// The lowest sequence still on this volume. Rises only when a segment is deleted, and never
    /// renumbers what survives.
    pub oldest_retained: u64,
}

impl State {
    fn fresh(stream: Stream) -> Self {
        Self {
            stream,
            next_seq: 1,
            head: GENESIS.to_owned(),
            durable_through: 0,
            signed_through: 0,
            acked_through: 0,
            oldest_retained: 1,
        }
    }
}

/// What this ledger already knows about one occurrence id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownOccurrence {
    /// The id a client retries with.
    pub event_id: String,
    /// Where the occurrence sits in this stream.
    pub seq: u64,
    /// The canonical digest of what was recorded under that id.
    pub occurrence_digest: String,
    /// The answer this plane gave, as it gave it.
    pub response: Value,
}

/// How much a journal may hold, and how long it must.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// The bound on event records, excluding the reserve.
    pub max_bytes: u64,
    /// When a segment is closed and a new one started.
    pub segment_bytes: u64,
    /// The largest single record this journal accepts.
    pub max_record_bytes: u64,
    /// The shortest history this deployment promises to keep, before the policy-derived
    /// requirement is applied on top.
    pub retention_minimum: Duration,
    /// How late an event may arrive and still be accepted.
    pub allowed_lateness: Duration,
    /// How far a caller's clock may differ from this one.
    pub clock_skew: Duration,
}

impl Default for Bounds {
    /// The deployment defaults, taken from the configuration that publishes them.
    ///
    /// Read from `permguard_core::config` rather than written here, because these numbers are also
    /// what `permguard config show` prints and what the shipped configuration files document. Two
    /// copies would drift the first time one of them was tuned, and the symptom would be a
    /// deployment whose journal behaves differently from what its own configuration says.
    fn default() -> Self {
        Self {
            max_bytes: permguard_core::config::DEFAULT_EVENTS_MAX_BYTES,
            segment_bytes: permguard_core::config::DEFAULT_EVENTS_SEGMENT_BYTES,
            max_record_bytes: permguard_core::config::DEFAULT_EVENTS_MAX_RECORD_BYTES,
            retention_minimum: permguard_core::config::DEFAULT_EVENTS_RETENTION_MINIMUM,
            allowed_lateness: permguard_core::config::DEFAULT_EVENTS_ALLOWED_LATENESS,
            clock_skew: permguard_core::config::DEFAULT_EVENTS_CLOCK_SKEW,
        }
    }
}

impl Bounds {
    /// The history this configuration actually guarantees, given what the loaded policies ask for.
    ///
    /// A policy's `max_window` is how far back it may look. An event that arrives late, or from a
    /// clock that runs behind, must still land inside that window — so the journal has to keep
    /// `max_window + allowed_lateness + clock_skew`, and a configured minimum shorter than that is
    /// a configuration whose policies would quietly start answering differently once eviction
    /// caught up with them.
    pub fn required_retention(&self, max_window: Duration) -> Duration {
        max_window
            .saturating_add(self.allowed_lateness)
            .saturating_add(self.clock_skew)
    }

    /// Whether this configuration can serve policies that look back `max_window`.
    pub fn admits(&self, max_window: Duration) -> Result<(), JournalError> {
        let required = self.required_retention(max_window);
        if self.retention_minimum < required {
            return Err(JournalError::Retention {
                configured: self.retention_minimum,
                required,
            });
        }

        Ok(())
    }
}

/// The local, durable, append-only history one producer wrote for one tenant.
pub struct Journal {
    directory: PathBuf,
    bounds: Bounds,
    state: State,
    /// Held for the lifetime of the journal: one writer per stream, enforced by the filesystem.
    _lock: File,
    open_segment: Option<(u64, File)>,
    /// Where each record sits, by the coordinates a temporal question asks about.
    ///
    /// # Why the journal owns this
    ///
    /// Deciding against a history must not mean reading one. A partition whose schema pins the
    /// caller ranges over that caller's events; a leaf asking `within 1h` ranges over an hour. The
    /// index is what turns both into a range scan instead of a scan of the ledger, and it lives
    /// here because it is derived from exactly the bytes this type writes — kept in step by
    /// construction, rather than by a second component remembering to.
    ///
    /// Rebuildable from the segments, which stay authoritative: a damaged or missing index costs a
    /// pass over the segments at open, never a wrong answer.
    index: crate::index::Index,
}

impl Journal {
    /// Opens the journal for one stream, creating it if this is its first run.
    ///
    /// Recovery happens here and nowhere else: a torn trailing record is truncated, the chain head
    /// and next sequence are re-derived from the segments rather than trusted from `STATE`, and a
    /// `STATE` naming a different stream is refused instead of appended to.
    pub fn open(
        directory: impl AsRef<Path>,
        stream: Stream,
        bounds: Bounds,
    ) -> Result<Self, JournalError> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory).map_err(|error| JournalError::Io(error.to_string()))?;

        let lock = lock_exclusively(&directory.join(LOCK_FILE))?;
        reserve(&directory)?;

        let state_path = directory.join(STATE_FILE);
        let state = match fs::read(&state_path) {
            Ok(bytes) => {
                let held: State = serde_json::from_slice(&bytes)
                    .map_err(|error| JournalError::Corrupt(error.to_string()))?;
                // The chain's identity, not the incarnation's. This process minted a fresh
                // instance when it started; the journal's own is in the state it recovered, and
                // that is the one that continues — see [`Stream::same_chain_as`].
                if !held.stream.same_chain_as(&stream) {
                    return Err(JournalError::WrongStream {
                        expected: Box::new(stream),
                        found: Box::new(held.stream),
                    });
                }

                held
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State::fresh(stream),
            Err(error) => return Err(JournalError::Io(error.to_string())),
        };

        let index = crate::index::Index::open(&directory)?;
        let mut journal = Self {
            directory,
            bounds,
            state,
            _lock: lock,
            open_segment: None,
            index,
        };
        // The segments are the authority for what was written. Whatever `STATE` last managed to
        // record, the truth about the tail is on disk — including a record written just before a
        // crash that `STATE` never learned about.
        journal.recover()?;
        // And the index is derived from those same segments, so it can be behind them for exactly
        // the same reason: a crash between flushing a record and flushing its entry leaves the
        // record durable and unindexed. Unindexed means invisible to a scan, which for a temporal
        // engine is a history that answers differently before and after a restart — so the tail
        // beyond what the index covers is replayed into it here, once, at the only moment nothing
        // is depending on it yet.
        let durable_through = journal.state.next_seq.saturating_sub(1);
        if journal.index.covered_through() < durable_through {
            journal.index.rebuild()?;
        }
        journal.persist_state()?;

        Ok(journal)
    }

    /// The stream this journal holds.
    pub fn stream(&self) -> &Stream {
        &self.state.stream
    }

    /// What the journal knows about itself.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The sequence and `prev` the next record must carry.
    pub fn next_position(&self) -> (u64, String) {
        (self.state.next_seq, self.state.head.clone())
    }

    /// Appends one record and `fsync`s before returning.
    ///
    /// The durable-before-observed rule: a caller is not told its event was accepted, and no
    /// engine is allowed to see it, until this returns.
    pub fn append(&mut self, record: &Value) -> Result<Appended, JournalError> {
        let appended = self.append_unsynced(record)?;
        self.sync()?;

        Ok(appended)
    }

    /// Appends without `fsync`, for group commit.
    ///
    /// The caller must [`Journal::sync`] before treating the record as durable. Group commit
    /// amortizes the flush across a batch; it does not let a receipt out early.
    pub fn append_unsynced(&mut self, record: &Value) -> Result<Appended, JournalError> {
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| JournalError::Malformed("a record with no `seq`".to_owned()))?;
        if seq != self.state.next_seq {
            return Err(JournalError::OutOfOrder {
                expected: self.state.next_seq,
                found: seq,
            });
        }
        let prev = record
            .get("prev")
            .and_then(Value::as_str)
            .ok_or_else(|| JournalError::Malformed("a record with no `prev`".to_owned()))?;
        if prev != self.state.head {
            return Err(JournalError::NotChained {
                expected: self.state.head.clone(),
                found: prev.to_owned(),
            });
        }

        let mut line = serde_json::to_vec(record)
            .map_err(|error| JournalError::Malformed(error.to_string()))?;
        if line.len() as u64 > self.bounds.max_record_bytes {
            return Err(JournalError::TooLarge {
                bytes: line.len() as u64,
                limit: self.bounds.max_record_bytes,
            });
        }
        line.push(b'\n');

        if self.bytes()? + line.len() as u64 > self.bounds.max_bytes {
            return Err(JournalError::Full);
        }

        let digest = digest_of(record).map_err(JournalError::Digest)?;
        let (segment, offset) = self.write(seq, &line)?;

        // Staged, not flushed: [`Journal::sync`] makes the record and its entry durable together.
        // A record the index does not carry is a record no range scan finds, so this is not
        // bookkeeping beside the append — it is part of it.
        if let Some((key, located)) =
            crate::index::entry_of(record, segment, offset, line.len() as u64)
        {
            self.index.stage(key, located)?;
        }

        self.state.next_seq = seq.saturating_add(1);
        self.state.head = digest.clone();

        Ok(Appended { seq, digest })
    }

    /// Flushes and `fsync`s the open segment, then records the new durable watermark.
    pub fn sync(&mut self) -> Result<(), JournalError> {
        if let Some((_, file)) = &mut self.open_segment {
            file.flush()
                .map_err(|error| JournalError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| JournalError::Io(error.to_string()))?;
        }
        // After the segment, never before: an index entry durable ahead of the record it points at
        // would survive a crash the record did not, and a scan would then read a hole.
        self.index.sync()?;
        self.state.durable_through = self.state.next_seq.saturating_sub(1);
        self.persist_state()
    }

    /// Persists a signed checkpoint covering `first_seq..=last_seq`, then marks it signed.
    ///
    /// # Why the file exists rather than only the watermark
    ///
    /// `signed_through` claims that a signed checkpoint covering it is *persisted*. Until this
    /// existed, nothing wrote one: the watermark was set from the control plane's acknowledgement,
    /// which made it a second, less precise copy of `acked_through` — and the layout at the top of
    /// this module named a `checkpoint-*.jws` that no code produced. A reader who went looking for
    /// the evidence a watermark asserted would have found the directory did not have it.
    ///
    /// The evidence is the batch envelope this plane signed before shipping: the same bytes the
    /// control plane verifies, kept locally so the claim can be checked here too — after a restart,
    /// after the control plane is gone, or by an auditor with only this volume.
    ///
    /// Written before the batch leaves and before the acknowledgement comes back, because that is
    /// the order the watermarks are defined in: durable, then signed, then acknowledged.
    pub fn checkpoint(
        &mut self,
        first_seq: u64,
        last_seq: u64,
        jws: &str,
    ) -> Result<(), JournalError> {
        if last_seq > self.state.durable_through {
            return Err(JournalError::AheadOfDurable {
                claimed: last_seq,
                durable: self.state.durable_through,
            });
        }
        let name = format!("{CHECKPOINT_PREFIX}{first_seq:020}{CHECKPOINT_SUFFIX}");
        let path = self.directory.join(&name);
        let temporary = self.directory.join(format!("{name}.tmp"));
        {
            let mut file =
                File::create(&temporary).map_err(|error| JournalError::Io(error.to_string()))?;
            file.write_all(jws.as_bytes())
                .map_err(|error| JournalError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| JournalError::Io(error.to_string()))?;
        }
        // Atomically named, so a reader finds a whole checkpoint or none — never the prefix of one.
        fs::rename(&temporary, &path).map_err(|error| JournalError::Io(error.to_string()))?;
        // And the directory entry itself, or a crash could lose the name while keeping the bytes.
        if let Ok(directory) = File::open(&self.directory) {
            let _ = directory.sync_all();
        }

        self.mark_signed(last_seq)
    }

    /// The signed checkpoints this journal holds, oldest first, as `(first_sequence, path)`.
    pub fn checkpoints(&self) -> Result<Vec<(u64, PathBuf)>, JournalError> {
        let mut found = Vec::new();
        let entries =
            fs::read_dir(&self.directory).map_err(|error| JournalError::Io(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| JournalError::Io(error.to_string()))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(rest) = name.strip_prefix(CHECKPOINT_PREFIX) else {
                continue;
            };
            let Some(number) = rest.strip_suffix(CHECKPOINT_SUFFIX) else {
                continue;
            };
            let Ok(first) = number.parse::<u64>() else {
                continue;
            };
            found.push((first, entry.path()));
        }
        found.sort_by_key(|(first, _)| *first);

        Ok(found)
    }

    /// Keeps one occurrence's position, content digest and answer, addressed by its id.
    ///
    /// # Why this is durable and addressed by the id
    ///
    /// Two separate promises rest on it.
    ///
    /// The first is that a retry is answered rather than refused. A client that did not see the
    /// first reply sends the same occurrence again; the event must not be recorded twice, and must
    /// not be *observed* twice, because a temporal engine counts occurrences. Refusing the retry
    /// leaves the client with no way to learn its own occurrence's verdict, so the answer is kept
    /// and given again.
    ///
    /// The second is that the retry is *recognised* at all. Recognition used to be a window of the
    /// last few thousand ids held in memory and rebuilt from the journal's tail. Inside the window
    /// a repeat was idempotent; outside it, the same id was accepted as a new occurrence and
    /// counted a second time — a silent double-count, and the further behind a client's retry, the
    /// likelier it was. Addressed by id on the volume, recognition now lasts exactly as long as
    /// the record does: the horizon is retention, and eviction takes both together.
    pub fn record_occurrence(&self, known: &KnownOccurrence) -> Result<(), JournalError> {
        let path = self.occurrence_path(&known.event_id);
        let Some(directory) = path.parent() else {
            return Err(JournalError::Io(
                "an occurrence has no directory".to_owned(),
            ));
        };
        fs::create_dir_all(directory).map_err(|error| JournalError::Io(error.to_string()))?;
        let temporary = directory.join(format!("{}.tmp", known.seq));
        let bytes = serde_json::to_vec(known)
            .map_err(|error| JournalError::Malformed(error.to_string()))?;
        {
            let mut file =
                File::create(&temporary).map_err(|error| JournalError::Io(error.to_string()))?;
            file.write_all(&bytes)
                .map_err(|error| JournalError::Io(error.to_string()))?;
        }
        // Renamed, not flushed. Flushing here would put an `fsync` on every record inside a batch
        // that exists to pay one for all of them — group commit would amortise the journal's flush
        // and then lose it again to this. [`Journal::sync_occurrences`] pays it once, and the
        // caller runs it alongside the journal's own flush, before anybody in the batch is
        // answered.
        fs::rename(&temporary, &path).map_err(|error| JournalError::Io(error.to_string()))?;

        Ok(())
    }

    /// Flushes the occurrence entries written since the last call.
    ///
    /// One `fsync` per shard touched rather than per record: what has to be durable is the
    /// directory entry the rename created, and a directory is flushed as a whole.
    pub fn sync_occurrences(&self) -> Result<(), JournalError> {
        let root = self.directory.join(OCCURRENCES_DIRECTORY);
        let shards = match fs::read_dir(&root) {
            Ok(shards) => shards,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(JournalError::Io(error.to_string())),
        };
        for shard in shards {
            let shard = shard.map_err(|error| JournalError::Io(error.to_string()))?;
            let held =
                File::open(shard.path()).map_err(|error| JournalError::Io(error.to_string()))?;
            held.sync_all()
                .map_err(|error| JournalError::Io(error.to_string()))?;
        }

        Ok(())
    }

    /// What this ledger knows about an occurrence id, when it still holds the record.
    ///
    /// `None` means the id is new *here* — never seen, or seen and since evicted. A corrupt entry
    /// is an error rather than an absence: answering a retry from bytes that did not parse would
    /// be answering it from nothing, silently, and the answer is a verdict.
    pub fn occurrence(&self, event_id: &str) -> Result<Option<KnownOccurrence>, JournalError> {
        let path = self.occurrence_path(event_id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(JournalError::Io(error.to_string())),
        };
        let held: KnownOccurrence = serde_json::from_slice(&bytes)
            .map_err(|error| JournalError::Corrupt(format!("{}: {error}", path.display())))?;
        // The file is addressed by a digest of the id, and a digest collision must not be read as
        // a retry of a different occurrence.
        if held.event_id != event_id {
            return Err(JournalError::Corrupt(format!(
                "{} holds `{}` and was addressed as `{event_id}`",
                path.display(),
                held.event_id
            )));
        }

        Ok(Some(held))
    }

    /// Where one occurrence id's entry lives.
    ///
    /// Sharded by the first byte of the digest: an id is any string a client chose, so it cannot be
    /// a file name, and a ledger's occurrences would otherwise be one directory with as many
    /// entries as the retention holds.
    fn occurrence_path(&self, event_id: &str) -> PathBuf {
        let digest = crate::record::digest_hex(event_id.as_bytes());
        let shard = digest.get(..2).unwrap_or("00");

        self.directory
            .join(OCCURRENCES_DIRECTORY)
            .join(shard)
            .join(format!("{digest}{OCCURRENCE_SUFFIX}"))
    }

    /// Drops what this journal knows about occurrences whose records it no longer holds.
    fn forget_occurrences_below(&self, oldest: u64) -> Result<(), JournalError> {
        let root = self.directory.join(OCCURRENCES_DIRECTORY);
        let shards = match fs::read_dir(&root) {
            Ok(shards) => shards,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(JournalError::Io(error.to_string())),
        };
        for shard in shards {
            let shard = shard.map_err(|error| JournalError::Io(error.to_string()))?;
            let entries = match fs::read_dir(shard.path()) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(JournalError::Io(error.to_string())),
            };
            for entry in entries {
                let entry = entry.map_err(|error| JournalError::Io(error.to_string()))?;
                let Ok(bytes) = fs::read(entry.path()) else {
                    continue;
                };
                let Ok(held) = serde_json::from_slice::<KnownOccurrence>(&bytes) else {
                    // Unreadable, and its record is gone or going: removed rather than kept as a
                    // permanent unreadable entry.
                    let _ = fs::remove_file(entry.path());
                    continue;
                };
                if held.seq < oldest {
                    fs::remove_file(entry.path())
                        .map_err(|error| JournalError::Io(error.to_string()))?;
                }
            }
        }

        Ok(())
    }

    /// Records that a signed checkpoint covering `through` is persisted.
    ///
    /// Only ever moves forward: a checkpoint arriving out of order cannot un-sign what a later one
    /// already covered.
    pub fn mark_signed(&mut self, through: u64) -> Result<(), JournalError> {
        if through > self.state.durable_through {
            return Err(JournalError::AheadOfDurable {
                claimed: through,
                durable: self.state.durable_through,
            });
        }
        self.state.signed_through = self.state.signed_through.max(through);
        self.persist_state()
    }

    /// Records the control plane's acknowledgement.
    pub fn acknowledge(&mut self, through: u64) -> Result<(), JournalError> {
        if through > self.state.signed_through {
            return Err(JournalError::AheadOfSigned {
                claimed: through,
                signed: self.state.signed_through,
            });
        }
        self.state.acked_through = self.state.acked_through.max(through);
        self.persist_state()
    }

    /// The highest sequence this journal may delete through.
    ///
    /// Both boundaries, always: what the control plane has, and what no loaded policy could still
    /// ask about. `retention_safe_through` is supplied by the caller because only the loaded
    /// commit knows how far back its policies look.
    pub fn deletable_through(&self, retention_safe_through: u64) -> u64 {
        self.state.acked_through.min(retention_safe_through)
    }

    /// Drops whole segments that end at or below `deletable_through`.
    ///
    /// Whole segments only, and never the open one: deleting inside a segment would either
    /// rewrite it — which breaks every digest it contains — or leave a hole a reader would have to
    /// be told about. A consumer that falls behind the surviving beginning is told so explicitly.
    pub fn evict(&mut self, deletable_through: u64) -> Result<u64, JournalError> {
        let segments = self.segments()?;
        let mut dropped = 0;

        for (index, (first, path)) in segments.iter().enumerate() {
            // The last segment is the open one; the next segment's first sequence is this one's
            // exclusive end.
            let Some((next_first, _)) = segments.get(index + 1) else {
                break;
            };
            if next_first.saturating_sub(1) > deletable_through {
                break;
            }
            fs::remove_file(path).map_err(|error| JournalError::Io(error.to_string()))?;
            self.state.oldest_retained = *next_first;
            dropped += 1;
            let _ = first;
        }
        if dropped > 0 {
            self.persist_state()?;
            // The index addresses records by segment and offset, and those segments are gone. An
            // entry left behind is a scan result that cannot be read.
            self.index.forget_below(self.state.oldest_retained)?;
            // A checkpoint attests to records; one whose records have all been evicted attests to
            // nothing this volume can still produce. Its own name carries only where it starts, so
            // where it *ends* is read the way the segments' end is read — from the next one along.
            // Kept while any of its range survives, so a surviving record never loses the proof
            // that covers it, and the newest is always kept because nothing bounds it yet.
            // What is known about an occurrence outlives nothing: once its record is gone, a
            // retry of it could not be recognised as a retry anyway.
            self.forget_occurrences_below(self.state.oldest_retained)?;
            let checkpoints = self.checkpoints()?;
            for (index, (_, path)) in checkpoints.iter().enumerate() {
                let Some((next_first, _)) = checkpoints.get(index + 1) else {
                    break;
                };
                if next_first.saturating_sub(1) >= self.state.oldest_retained {
                    break;
                }
                fs::remove_file(path).map_err(|error| JournalError::Io(error.to_string()))?;
            }
        }

        Ok(dropped)
    }

    /// The records a temporal question actually needs, read by their coordinates.
    ///
    /// # Why this exists beside [`Journal::read_from`]
    ///
    /// `read_from` is the shipper's read: everything after a sequence, because a shipper ships
    /// everything. This is the evaluator's: one history partition, one event type, one time range —
    /// a range scan over the index, then exactly those records read by byte offset.
    ///
    /// The difference is the whole of what makes a busy ledger affordable. A partition pinned on
    /// the caller ranges over one caller's events, and a leaf asking `within 1h` ranges over an
    /// hour; reading the ledger to answer either would make one decision cost what the tenant's
    /// whole traffic costs.
    pub fn scan(&self, query: &crate::index::Query) -> Result<Vec<Value>, JournalError> {
        let mut found: Vec<&crate::index::Located> = self.index.scan(query);
        // In the order the records were written, which for one history partition is the order they
        // happened: a temporal engine is fed in order or not at all.
        found.sort_by_key(|located| located.seq);

        let mut records = Vec::with_capacity(found.len());
        for located in found {
            match self.record_at(located)? {
                Some(record) => records.push(record),
                // Evicted between the scan and the read. Not an error: retention removing a record
                // a scan had just seen is the ordinary race, and the answer is the history that is
                // still there.
                None => continue,
            }
        }

        Ok(records)
    }

    /// One record, by the coordinates the index holds for it.
    fn record_at(&self, located: &crate::index::Located) -> Result<Option<Value>, JournalError> {
        let path = self.directory.join(format!(
            "{SEGMENT_PREFIX}{:020}{SEGMENT_SUFFIX}",
            located.segment
        ));
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(JournalError::Io(error.to_string())),
        };
        file.seek(std::io::SeekFrom::Start(located.offset))
            .map_err(|error| JournalError::Io(error.to_string()))?;

        let mut line = vec![0u8; located.length as usize];
        if let Err(error) = file.read_exact(&mut line) {
            return match error.kind() {
                // The segment was truncated under us, by eviction or by a recovery that ran after
                // the scan. The same ordinary race as a missing segment.
                std::io::ErrorKind::UnexpectedEof => Ok(None),
                _ => Err(JournalError::Io(error.to_string())),
            };
        }
        let line = line.strip_suffix(b"\n").unwrap_or(&line);

        serde_json::from_slice(line)
            .map(Some)
            .map_err(|error| JournalError::Corrupt(error.to_string()))
    }

    /// How many records the index carries, which is what a scan ranges over.
    pub fn indexed(&self) -> usize {
        self.index.len()
    }

    /// Every record after `after`, in order, up to `limit` of them.
    pub fn read_from(&self, after: u64, limit: usize) -> Result<Vec<Value>, JournalError> {
        let mut records = Vec::new();
        for (_, path) in self.segments()? {
            if records.len() >= limit {
                break;
            }
            let file = File::open(&path).map_err(|error| JournalError::Io(error.to_string()))?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|error| JournalError::Io(error.to_string()))?;
                if line.trim().is_empty() {
                    continue;
                }
                let value: Value = serde_json::from_str(&line)
                    .map_err(|error| JournalError::Corrupt(error.to_string()))?;
                let seq = value.get("seq").and_then(Value::as_u64).unwrap_or_default();
                if seq > after {
                    records.push(value);
                }
                if records.len() >= limit {
                    break;
                }
            }
        }

        Ok(records)
    }

    /// How many bytes the segments hold, excluding the reserve.
    pub fn bytes(&self) -> Result<u64, JournalError> {
        let mut total = 0;
        for (_, path) in self.segments()? {
            total += fs::metadata(&path)
                .map_err(|error| JournalError::Io(error.to_string()))?
                .len();
        }

        Ok(total)
    }

    fn write(&mut self, seq: u64, line: &[u8]) -> Result<(u64, u64), JournalError> {
        let rotate = match &self.open_segment {
            None => true,
            Some((_, file)) => {
                let held = file
                    .metadata()
                    .map_err(|error| JournalError::Io(error.to_string()))?
                    .len();

                held + line.len() as u64 > self.bounds.segment_bytes
            }
        };
        if rotate {
            let path = self
                .directory
                .join(format!("{SEGMENT_PREFIX}{seq:020}{SEGMENT_SUFFIX}"));
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|error| JournalError::Io(error.to_string()))?;
            self.open_segment = Some((seq, file));
        }
        let Some((first, file)) = &mut self.open_segment else {
            return Err(JournalError::Io("no open segment".to_owned()));
        };
        let first = *first;
        // Where this record starts, taken before it is written: the index addresses records by
        // byte offset, and an offset read afterwards would be the offset of the record after it.
        let offset = file
            .metadata()
            .map_err(|error| JournalError::Io(error.to_string()))?
            .len();
        file.write_all(line)
            .map_err(|error| JournalError::Io(error.to_string()))?;

        Ok((first, offset))
    }

    /// The segments, oldest first.
    fn segments(&self) -> Result<Vec<(u64, PathBuf)>, JournalError> {
        let mut found = Vec::new();
        let entries =
            fs::read_dir(&self.directory).map_err(|error| JournalError::Io(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| JournalError::Io(error.to_string()))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(rest) = name.strip_prefix(SEGMENT_PREFIX) else {
                continue;
            };
            let Some(number) = rest.strip_suffix(SEGMENT_SUFFIX) else {
                continue;
            };
            let Ok(first) = number.parse::<u64>() else {
                continue;
            };
            found.push((first, entry.path()));
        }
        found.sort_by_key(|(first, _)| *first);

        Ok(found)
    }

    /// Re-derives the tail from the segments, truncating a torn final record.
    ///
    /// A crash can leave exactly one thing behind: a partial trailing line, because a line that
    /// was never completed was never a record. Everything before it is whole, so the chain head
    /// and next sequence come from the last *complete* record — not from `STATE`, which may not
    /// have been updated before the process died.
    fn recover(&mut self) -> Result<(), JournalError> {
        let segments = self.segments()?;
        let Some((first, path)) = segments.last().cloned() else {
            return Ok(());
        };

        // The oldest surviving sequence is whatever the earliest remaining segment starts at:
        // eviction removes whole segments, so the first one's first sequence *is* the beginning.
        let oldest = segments.first().map_or(1, |(earliest, _)| *earliest);

        // Newest first, until one holds a record. Normally that is the very first one looked at.
        // It can be empty, though: [`Journal::write`] creates a segment and writes into it in two
        // steps, so a crash between them leaves a rotated-to file with nothing in it. Reading only
        // the newest segment would then find no record and fall back to whatever `STATE` said —
        // which is the stale answer this function exists to replace.
        let mut last: Option<Value> = None;
        for (_, path) in segments.iter().rev() {
            let bytes = fs::read(path).map_err(|error| JournalError::Io(error.to_string()))?;
            let mut complete_len = 0usize;

            for line in bytes.split_inclusive(|byte| *byte == b'\n') {
                if !line.ends_with(b"\n") {
                    // A torn write: the process died mid-line.
                    break;
                }
                match serde_json::from_slice::<Value>(&line[..line.len() - 1]) {
                    Ok(value) => {
                        complete_len += line.len();
                        last = Some(value);
                    }
                    Err(error) => {
                        // A complete line that is not a record means corruption, not a torn write.
                        return Err(JournalError::Corrupt(format!(
                            "{}: {error}",
                            path.display()
                        )));
                    }
                }
            }

            if complete_len < bytes.len() {
                let file = OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(|error| JournalError::Io(error.to_string()))?;
                file.set_len(complete_len as u64)
                    .map_err(|error| JournalError::Io(error.to_string()))?;
                file.sync_all()
                    .map_err(|error| JournalError::Io(error.to_string()))?;
            }

            if last.is_some() {
                break;
            }
        }

        if let Some(value) = last {
            let seq = value
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or_else(|| JournalError::Corrupt("a record with no `seq`".to_owned()))?;
            self.state.next_seq = seq.saturating_add(1);
            self.state.head = digest_of(&value).map_err(JournalError::Digest)?;
            // The segments are the authority in *both* directions, and this is the half that is
            // easy to leave out. Clamping down is obvious: nothing beyond the last complete record
            // can be durable, whatever `STATE` claimed. Raising up is the one that matters after a
            // crash — a record whose line is whole on disk survived the crash, so it is durable
            // now, even though the `sync` that would have written `durable_through` never ran.
            //
            // Leaving it clamped would strand exactly that record: the shipper batches
            // `acked_through..durable_through`, so a watermark stuck behind the segment means the
            // ledger ships nothing until some *new* event happens to arrive and drag the watermark
            // forward. A plane that never sees another event would hold that backlog for ever
            // while reporting itself idle. The tail is also what the index rebuild in
            // [`Journal::open`] already treats as durable, so the two agree here rather than
            // disagreeing by one crash.
            self.state.durable_through = seq;
            self.state.signed_through = self.state.signed_through.min(seq);
            self.state.acked_through = self.state.acked_through.min(self.state.signed_through);
        }
        self.state.oldest_retained = oldest.max(1);

        // Reopen the tail for appending.
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|error| JournalError::Io(error.to_string()))?;
        self.open_segment = Some((first, file));

        Ok(())
    }

    fn persist_state(&self) -> Result<(), JournalError> {
        let path = self.directory.join(STATE_FILE);
        let temporary = self.directory.join(format!("{STATE_FILE}.tmp"));
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|error| JournalError::Malformed(error.to_string()))?;
        {
            let mut file =
                File::create(&temporary).map_err(|error| JournalError::Io(error.to_string()))?;
            file.write_all(&bytes)
                .map_err(|error| JournalError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| JournalError::Io(error.to_string()))?;
        }
        // Atomically replaced: a reader either sees the old state or the new one, never a
        // half-written file.
        fs::rename(&temporary, &path).map_err(|error| JournalError::Io(error.to_string()))?;

        Ok(())
    }
}

/// Takes the stream's exclusive lock, or refuses.
fn lock_exclusively(path: &Path) -> Result<File, JournalError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| JournalError::Io(error.to_string()))?;

    // One writer per stream. Two would interleave sequences into one chain and neither would be
    // verifiable afterwards.
    file.try_lock()
        .map_err(|_| JournalError::Locked(path.display().to_string()))?;

    Ok(file)
}

/// Claims the reserve at open, outside the byte bound.
///
/// A reservation made under pressure is a reservation that fails under pressure, so it is taken
/// when the journal is created and never touched by ordinary appends.
fn reserve(directory: &Path) -> Result<(), JournalError> {
    let path = directory.join(RESERVE_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|error| JournalError::Io(error.to_string()))?;
    let held = file
        .metadata()
        .map_err(|error| JournalError::Io(error.to_string()))?
        .len();
    if held < RESERVE_BYTES {
        file.set_len(RESERVE_BYTES)
            .map_err(|error| JournalError::Io(error.to_string()))?;
        file.sync_all()
            .map_err(|error| JournalError::Io(error.to_string()))?;
    }

    Ok(())
}

/// What one append produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    pub seq: u64,
    pub digest: String,
}

/// Why the journal refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    Io(String),
    /// Another process holds this stream.
    Locked(String),
    /// The directory holds a different stream than the one asked for.
    WrongStream {
        expected: Box<Stream>,
        found: Box<Stream>,
    },
    /// A complete record that is not one — corruption, not a torn write.
    Corrupt(String),
    Malformed(String),
    Digest(DigestError),
    OutOfOrder {
        expected: u64,
        found: u64,
    },
    NotChained {
        expected: String,
        found: String,
    },
    /// A record larger than this journal accepts.
    TooLarge {
        bytes: u64,
        limit: u64,
    },
    /// The byte bound is reached. Temporal history is never dropped to make room.
    Full,
    /// A checkpoint claiming to cover records that are not durable yet.
    AheadOfDurable {
        claimed: u64,
        durable: u64,
    },
    /// An acknowledgement of records that were never signed.
    AheadOfSigned {
        claimed: u64,
        signed: u64,
    },
    /// Configured retention is shorter than the loaded policies need.
    Retention {
        configured: Duration,
        required: Duration,
    },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(detail) => write!(formatter, "{detail}"),
            Self::Locked(path) => write!(
                formatter,
                "another process holds {path}: one writer owns a stream, because two would \
                 interleave sequences into one chain and neither would verify afterwards"
            ),
            Self::WrongStream { expected, found } => write!(
                formatter,
                "this directory holds {}/{} written by {}/{}, and was opened for {}/{} written by \
                 {}/{}: a journal moved or restored under the wrong identity is refused, never \
                 appended to",
                found.zone,
                found.ledger,
                found.producer.class,
                found.producer.id,
                expected.zone,
                expected.ledger,
                expected.producer.class,
                expected.producer.id
            ),
            Self::Corrupt(detail) => write!(formatter, "the journal is damaged: {detail}"),
            Self::Malformed(detail) => write!(formatter, "{detail}"),
            Self::Digest(detail) => write!(formatter, "{detail}"),
            Self::OutOfOrder { expected, found } => write!(
                formatter,
                "the next sequence is {expected} and this record is {found}"
            ),
            Self::NotChained { expected, found } => write!(
                formatter,
                "this record links to {found} and the head is {expected}"
            ),
            Self::TooLarge { bytes, limit } => write!(
                formatter,
                "the record is {bytes} bytes and this journal accepts {limit}"
            ),
            Self::Full => write!(
                formatter,
                "the journal is full: temporal history is never discarded to make room, because \
                 losing an event silently changes what future decisions mean"
            ),
            Self::AheadOfDurable { claimed, durable } => write!(
                formatter,
                "a checkpoint claims to cover {claimed} and only {durable} is durable"
            ),
            Self::AheadOfSigned { claimed, signed } => write!(
                formatter,
                "an acknowledgement claims {claimed} and only {signed} is signed"
            ),
            Self::Retention {
                configured,
                required,
            } => write!(
                formatter,
                "retention is {configured:?} and the loaded policies look back {required:?}: a \
                 journal that forgets what a policy can still ask about changes what future \
                 decisions mean"
            ),
        }
    }
}

impl std::error::Error for JournalError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::record::{Producer, RECORD_TYPE, Record, VERSION};
    use serde_json::json;

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-events-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);

        path
    }

    fn stream() -> Stream {
        Stream::new(Producer::data_plane("dp-a", "01931f2c"), "acme", "l")
    }

    fn record(seq: u64, prev: &str) -> Value {
        let built = Record {
            v: VERSION,
            record_type: RECORD_TYPE.to_owned(),
            stream: stream(),
            seq,
            prev: prev.to_owned(),
            event_type: "permguard.dogwood.event.v1".to_owned(),
            event_id: format!("e{seq}"),
            occurrence_digest: GENESIS.to_owned(),
            kind: "request".to_owned(),
            profile: "temporal".to_owned(),
            policy_partitions: vec!["session-access".to_owned()],
            commit: "sha256:abc".to_owned(),
            history_key: None,
            occurred_at: "2026-08-28T10:15:30Z".to_owned(),
            observed_at: "2026-08-28T10:15:31Z".to_owned(),
            event: json!({"n": seq}),
        };

        serde_json::to_value(built).expect("it serializes")
    }

    /// Appends `count` records, returning the journal.
    fn filled(directory: &Path, count: u64, bounds: Bounds) -> Journal {
        let mut journal = Journal::open(directory, stream(), bounds).expect("it opens");
        for _ in 0..count {
            let (seq, prev) = journal.next_position();
            journal.append(&record(seq, &prev)).expect("it appends");
        }

        journal
    }

    #[test]
    fn records_are_chained_and_readable_in_order() {
        let directory = scratch("chained");
        let journal = filled(&directory, 3, Bounds::default());

        let read = journal.read_from(0, 10).expect("it reads");
        assert_eq!(read.len(), 3);
        assert_eq!(journal.state().next_seq, 4);
        assert_eq!(journal.state().durable_through, 3);

        // The chain the journal built is the chain a verifier accepts.
        crate::chain::verify(&read, None).expect("the journal wrote a chain");
    }

    #[test]
    fn a_record_out_of_order_or_off_the_chain_is_refused() {
        let directory = scratch("order");
        let mut journal = filled(&directory, 1, Bounds::default());

        assert!(matches!(
            journal
                .append(&record(9, GENESIS))
                .expect_err("the sequence jumps"),
            JournalError::OutOfOrder {
                expected: 2,
                found: 9
            }
        ));

        let (seq, _) = journal.next_position();
        assert!(matches!(
            journal
                .append(&record(seq, "sha256:not-the-head"))
                .expect_err("it links to nothing"),
            JournalError::NotChained { .. }
        ));
    }

    /// The one thing a crash can leave behind is a partial trailing line.
    #[test]
    fn a_torn_final_record_is_truncated_and_the_tail_recovered() {
        let directory = scratch("torn");
        let head_before = {
            let journal = filled(&directory, 3, Bounds::default());
            journal.state().head.clone()
        };

        // Simulate the crash: append half a line to the open segment, as a process dying
        // mid-write would leave.
        let segment = fs::read_dir(&directory)
            .expect("it reads")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(SEGMENT_PREFIX))
            })
            .expect("a segment");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment)
            .expect("it opens");
        file.write_all(br#"{"seq":4,"prev":"sha256:ab"#)
            .expect("a torn write");
        drop(file);

        let reopened = Journal::open(&directory, stream(), Bounds::default()).expect("it recovers");

        assert_eq!(
            reopened.state().next_seq,
            4,
            "a line that was never completed was never a record"
        );
        assert_eq!(reopened.state().head, head_before);
        assert_eq!(reopened.read_from(0, 10).expect("it reads").len(), 3);
    }

    /// A complete line that is not a record is corruption, and is not silently dropped.
    #[test]
    fn a_complete_line_that_is_not_a_record_is_corruption_not_a_torn_write() {
        let directory = scratch("corrupt");
        {
            let _journal = filled(&directory, 2, Bounds::default());
        }
        let segment = fs::read_dir(&directory)
            .expect("it reads")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(SEGMENT_PREFIX))
            })
            .expect("a segment");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment)
            .expect("it opens");
        file.write_all(b"this is not json\n").expect("it writes");
        drop(file);

        assert!(matches!(
            Journal::open(&directory, stream(), Bounds::default())
                .err()
                .expect("it refuses"),
            JournalError::Corrupt(_)
        ));
    }

    #[test]
    fn one_writer_owns_a_stream() {
        let directory = scratch("locked");
        let _held = Journal::open(&directory, stream(), Bounds::default()).expect("it opens");

        assert!(matches!(
            Journal::open(&directory, stream(), Bounds::default())
                .err()
                .expect("a second writer is refused"),
            JournalError::Locked(_)
        ));
    }

    /// A journal restored under the wrong identity is refused, never appended to.
    #[test]
    fn a_directory_holding_another_stream_is_refused() {
        let directory = scratch("wrong-stream");
        {
            let _journal = filled(&directory, 1, Bounds::default());
        }

        let elsewhere = Stream::new(
            Producer::data_plane("dp-a", "01931f2c"),
            "acme",
            "a-different-ledger",
        );
        assert!(matches!(
            Journal::open(&directory, elsewhere, Bounds::default())
                .err()
                .expect("it refuses"),
            JournalError::WrongStream { .. }
        ));
    }

    /// One occurrence in a named history, at a stated second.
    fn record_in(seq: u64, prev: &str, history: &str, at: i64) -> Value {
        let mut built: Value = record(seq, prev);
        built["history_key"] = json!({
            "pins": ["callerPrincipal"],
            "values": [history],
            "digest": format!("sha256:{history}"),
        });
        let instant = crate::index::render_epoch_seconds(at).expect("an instant");
        built["occurred_at"] = json!(instant.clone());
        built["observed_at"] = json!(instant);
        built["event_id"] = json!(format!("{history}-{seq}"));

        built
    }

    /// Deciding against one history reads one history, and one window reads one window.
    ///
    /// # What this is actually about
    ///
    /// "Indexed" is a claim about what is *not* read, so a test that only checks the answer proves
    /// nothing: a scan of the whole ledger returns the same records, slowly. What is asserted here
    /// is the negative — a scan for one caller's history does not return another's, and a scan of
    /// an hour does not return what happened before it — because those are the properties that make
    /// one decision cost what its own history costs rather than what the tenant's traffic costs.
    #[test]
    fn a_scan_reads_one_history_and_one_window_and_nothing_else() {
        let directory = scratch("scan");
        let mut journal = Journal::open(&directory, stream(), Bounds::default()).expect("it opens");

        // Three callers, ten occurrences each, an hour apart.
        for round in 0..10i64 {
            for who in ["alice", "bob", "carol"] {
                let (seq, prev) = journal.next_position();
                journal
                    .append(&record_in(seq, &prev, who, 1_700_000_000 + round * 3_600))
                    .expect("it appends");
            }
        }
        assert_eq!(journal.indexed(), 30, "every record is placed");

        let query = |history: &str, from: i64, until: i64| crate::index::Query {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: format!("sha256:{history}"),
            action: None,
            kind: None,
            from,
            until,
        };

        // One history: ten records, and none of the other twenty.
        let alice = journal
            .scan(&query("alice", 0, i64::MAX))
            .expect("it scans");
        assert_eq!(alice.len(), 10, "one caller's history is one caller's");
        for record in &alice {
            assert_eq!(record["history_key"]["values"][0], json!("alice"));
        }
        // And in the order they happened, which is the only order an engine may be fed in.
        let times: Vec<&str> = alice
            .iter()
            .map(|record| record["occurred_at"].as_str().unwrap_or_default())
            .collect();
        let mut sorted = times.clone();
        sorted.sort_unstable();
        assert_eq!(times, sorted, "a replay is fed in order or not at all");

        // One window: the last three hours of that history, and not the seven before them.
        let recent = journal
            .scan(&query(
                "alice",
                1_700_000_000 + 7 * 3_600,
                1_700_000_000 + 9 * 3_600,
            ))
            .expect("it scans");
        assert_eq!(
            recent.len(),
            3,
            "`max_window` is a ceiling, not a reason to read everything under it"
        );

        // A history nobody wrote is empty rather than everything.
        assert!(
            journal
                .scan(&query("dave", 0, i64::MAX))
                .expect("it scans")
                .is_empty()
        );
    }

    /// A record durable but unindexed when the process died is indexed when it comes back.
    ///
    /// # What this is actually about
    ///
    /// The index is flushed after the records it points at — the safe order, because an entry
    /// durable ahead of its record would point at bytes a crash took away. The cost of that order
    /// is the other window: a crash between the two leaves a record on disk that no scan finds.
    ///
    /// Unindexed is invisible, and invisible to a temporal engine is a history that answers
    /// differently before and after a restart — the login is there, and the read is denied. So the
    /// tail beyond what the index covers is replayed into it when the journal opens, which is the
    /// one moment nothing is depending on it yet.
    #[test]
    fn a_record_written_before_a_crash_is_indexed_when_the_journal_reopens() {
        let directory = scratch("index-behind");
        {
            let mut journal =
                Journal::open(&directory, stream(), Bounds::default()).expect("it opens");
            for round in 0..3i64 {
                let (seq, prev) = journal.next_position();
                journal
                    .append(&record_in(seq, &prev, "alice", 1_700_000_000 + round * 60))
                    .expect("it appends");
            }
        }

        // The index as it would be if the process died after the segment's flush and before the
        // index's: the records are all on disk, and the last entry never reached it.
        let path = directory.join(crate::index::INDEX_FILE);
        let kept: Vec<String> = fs::read_to_string(&path)
            .expect("it reads")
            .lines()
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        assert_eq!(kept.len(), 3);
        fs::write(&path, format!("{}\n", kept[..2].join("\n"))).expect("it writes");

        let query = crate::index::Query {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: "sha256:alice".to_owned(),
            action: None,
            kind: None,
            from: 0,
            until: i64::MAX,
        };
        let found = Journal::open(&directory, stream(), Bounds::default())
            .expect("it opens")
            .scan(&query)
            .expect("it scans");

        assert_eq!(
            found.len(),
            3,
            "a durable record no scan could find is a history that changed across a restart"
        );
    }

    /// The index is derived, and a lost one costs a pass over the segments rather than an answer.
    ///
    /// The segments are the authority. An index that disagreed with them — or that vanished — must
    /// never change what a scan returns, only what it costs to return it.
    #[test]
    fn a_lost_index_is_rebuilt_from_the_segments_and_answers_the_same() {
        let directory = scratch("index-lost");
        {
            let mut journal =
                Journal::open(&directory, stream(), Bounds::default()).expect("it opens");
            for round in 0..4i64 {
                for who in ["alice", "bob"] {
                    let (seq, prev) = journal.next_position();
                    journal
                        .append(&record_in(seq, &prev, who, 1_700_000_000 + round * 60))
                        .expect("it appends");
                }
            }
        }
        let query = crate::index::Query {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: "sha256:alice".to_owned(),
            action: None,
            kind: None,
            from: 0,
            until: i64::MAX,
        };

        let before = Journal::open(&directory, stream(), Bounds::default())
            .expect("it opens")
            .scan(&query)
            .expect("it scans");
        assert_eq!(before.len(), 4);

        // The index is gone, as a crash between writing a segment and flushing its entries, or a
        // restore that copied only the segments, would leave it.
        fs::remove_file(directory.join(crate::index::INDEX_FILE)).expect("it is removed");

        let after = Journal::open(&directory, stream(), Bounds::default())
            .expect("it opens")
            .scan(&query)
            .expect("it scans");
        assert_eq!(after, before, "rebuilt from the authority, byte for byte");
    }

    /// A restarted process opens its own journal and continues the chain it left.
    ///
    /// # What this is actually about
    ///
    /// A process mints a fresh producer *instance* when it starts, and the journal it reopens holds
    /// the instance that actually wrote the records on disk. Those two differ on every restart, by
    /// design: the instance exists to say which incarnation wrote a run, so that a restart which
    /// cannot prove continuation starts a new one instead of reusing sequences.
    ///
    /// Which means the instance a restarting process proposes is always the wrong thing to compare
    /// against — comparing it refuses every restart as somebody else's stream, and a plane that
    /// cannot reopen its own journal cannot keep a history at all.
    ///
    /// So the comparison is over what identifies the *chain*: the producer's class and id, and the
    /// tenant's zone and ledger. All four outlive any process. The instance is adopted from the
    /// state that recovered, and the sequence goes on from where it was.
    #[test]
    fn a_restart_with_a_new_instance_continues_the_chain_it_left() {
        let directory = scratch("restart-instance");
        let head = {
            let journal = filled(&directory, 3, Bounds::default());
            assert_eq!(journal.next_position().0, 4);

            journal.state().head.clone()
        };

        // The same plane, restarted: same class, same id, a freshly minted instance.
        let restarted = Journal::open(
            &directory,
            Stream::new(
                Producer::data_plane("dp-a", "a-new-incarnation"),
                "acme",
                "l",
            ),
            Bounds::default(),
        )
        .expect("a plane reopens its own journal");

        let (seq, prev) = restarted.next_position();
        assert_eq!(seq, 4, "the sequence continues rather than restarting");
        assert_eq!(prev, head, "and it links to what was already there");
        assert_eq!(
            restarted.stream().producer.instance,
            "01931f2c",
            "the incarnation that wrote the records is the one that goes on writing them, not the \
             one this process happened to mint at startup"
        );
    }

    /// A different *producer* is still refused, instance or no instance.
    ///
    /// The loosening above is exactly one field wide. Two planes sharing a directory would
    /// interleave sequences into one chain and neither history would verify afterwards, so the
    /// three fields that say who and whose are compared as strictly as they ever were.
    #[test]
    fn a_directory_another_producer_wrote_is_still_refused() {
        let directory = scratch("other-producer");
        {
            let _journal = filled(&directory, 1, Bounds::default());
        }

        for (producer, zone, ledger) in [
            (Producer::data_plane("dp-b", "01931f2c"), "acme", "l"),
            (Producer::data_plane("dp-a", "01931f2c"), "other-zone", "l"),
            (
                Producer::data_plane("dp-a", "01931f2c"),
                "acme",
                "other-ledger",
            ),
        ] {
            let refused = Journal::open(
                &directory,
                Stream::new(producer.clone(), zone, ledger),
                Bounds::default(),
            )
            .err()
            .expect("it refuses");

            assert!(
                matches!(refused, JournalError::WrongStream { .. }),
                "{refused:?}"
            );
            // And it says which two identities it is comparing, producer included: a message
            // naming only the tenant would read as "these are the same" for the first case.
            let said = refused.to_string();
            assert!(said.contains("dp-a"), "{said}");
            assert!(said.contains(&producer.id), "{said}");
        }
    }

    /// A `STATE` that cannot be read refuses, rather than starting a second chain over the records.
    ///
    /// The segments are the authority for what was *written*, but not for the instance that wrote
    /// it, nor for how far a signature or an acknowledgement reached. A journal that treated an
    /// unreadable state as an empty one would begin again at sequence 1, on top of records that
    /// already hold those sequences — two different records under one coordinate, which is the one
    /// thing a hash chain cannot survive.
    #[test]
    fn an_unreadable_state_refuses_rather_than_starting_again_over_the_records() {
        let directory = scratch("corrupt-state");
        {
            let _journal = filled(&directory, 3, Bounds::default());
        }
        fs::write(directory.join(STATE_FILE), b"{ this is not the state ").expect("it writes");

        let refused = Journal::open(&directory, stream(), Bounds::default())
            .err()
            .expect("it refuses");
        assert!(matches!(refused, JournalError::Corrupt(_)), "{refused:?}");

        // And the records are untouched: whatever is done about this, it is done with the history
        // still there.
        let segments: Vec<_> = fs::read_dir(&directory)
            .expect("it reads")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("seg-"))
            .collect();
        assert!(!segments.is_empty(), "the segments survive the refusal");
    }

    /// The watermarks are ordered: nothing is acknowledged that was never signed, and nothing is
    /// signed that is not durable.
    #[test]
    fn a_watermark_cannot_run_ahead_of_the_one_it_depends_on() {
        let directory = scratch("watermarks");
        let mut journal = filled(&directory, 3, Bounds::default());

        assert!(matches!(
            journal.mark_signed(9).expect_err("only 3 are durable"),
            JournalError::AheadOfDurable { .. }
        ));
        assert!(matches!(
            journal.acknowledge(1).expect_err("nothing is signed yet"),
            JournalError::AheadOfSigned { .. }
        ));

        journal.mark_signed(2).expect("two are durable");
        journal.acknowledge(2).expect("two are signed");
        assert_eq!(journal.state().signed_through, 2);
        assert_eq!(journal.state().acked_through, 2);

        // And they never move backwards.
        journal.mark_signed(1).expect("an older checkpoint");
        assert_eq!(journal.state().signed_through, 2);
    }

    /// Deletion needs **both** boundaries: shipped, and no longer needed by a policy.
    #[test]
    fn nothing_is_deletable_until_both_boundaries_allow_it() {
        let directory = scratch("deletable");
        let mut journal = filled(&directory, 5, Bounds::default());
        journal.mark_signed(5).expect("all durable");
        journal.acknowledge(4).expect("four shipped");

        // The control plane has four; Dogwood still needs everything after two.
        assert_eq!(journal.deletable_through(2), 2, "the stricter bound wins");
        // Dogwood needs nothing; the control plane's acknowledgement is then the bound.
        assert_eq!(journal.deletable_through(99), 4);
        // Nothing shipped: nothing goes, however old it is.
        let mut fresh =
            Journal::open(scratch("deletable-2"), stream(), Bounds::default()).expect("it opens");
        assert_eq!(fresh.deletable_through(99), 0);
        assert_eq!(fresh.evict(0).expect("nothing to drop"), 0);
    }

    /// Eviction drops whole segments and never renumbers what survives.
    #[test]
    fn eviction_drops_whole_segments_and_leaves_surviving_sequences_alone() {
        let directory = scratch("evict");
        // A segment bound small enough that each record starts a new one.
        let bounds = Bounds {
            segment_bytes: 1,
            ..Bounds::default()
        };
        let mut journal = filled(&directory, 4, bounds);
        journal.mark_signed(4).expect("durable");
        journal.acknowledge(4).expect("shipped");

        let dropped = journal.evict(2).expect("it evicts");
        assert!(dropped > 0, "whole segments below the bound are dropped");
        assert_eq!(journal.state().oldest_retained, 3);

        // What survives keeps its sequence numbers, and still reads as a chain from its new
        // beginning.
        let survivors = journal.read_from(0, 10).expect("it reads");
        let first = survivors.first().expect("something survived");
        assert_eq!(first.get("seq").and_then(Value::as_u64), Some(3));
    }

    /// Retention is refused before it can silently change what a policy sees.
    #[test]
    fn a_retention_shorter_than_the_loaded_policies_need_is_refused() {
        let bounds = Bounds {
            retention_minimum: Duration::from_secs(60 * 60),
            allowed_lateness: Duration::from_secs(5 * 60),
            clock_skew: Duration::from_secs(30),
            ..Bounds::default()
        };

        // A one-hour window needs an hour plus lateness plus skew — more than the hour configured.
        assert!(matches!(
            bounds
                .admits(Duration::from_secs(60 * 60))
                .expect_err("an hour is not enough for an hour plus slack"),
            JournalError::Retention { .. }
        ));
        // Half an hour fits comfortably.
        assert!(bounds.admits(Duration::from_secs(30 * 60)).is_ok());
    }

    #[test]
    fn a_record_larger_than_the_bound_is_refused_rather_than_written() {
        let directory = scratch("too-large");
        let bounds = Bounds {
            max_record_bytes: 64,
            ..Bounds::default()
        };
        let mut journal = Journal::open(&directory, stream(), bounds).expect("it opens");
        let (seq, prev) = journal.next_position();

        assert!(matches!(
            journal
                .append(&record(seq, &prev))
                .expect_err("it is too large"),
            JournalError::TooLarge { .. }
        ));
        assert_eq!(journal.state().next_seq, 1, "nothing was written");
    }

    /// A full journal refuses rather than dropping history to make room.
    #[test]
    fn a_full_journal_refuses_and_never_discards_history() {
        let directory = scratch("full");
        // Sized from a measured record rather than guessed: a bound below one record would prove
        // only that nothing fits, which is not what this is about.
        let one = serde_json::to_vec(&record(1, GENESIS))
            .expect("it serializes")
            .len() as u64;
        let bounds = Bounds {
            max_bytes: one * 3,
            ..Bounds::default()
        };
        let mut journal = Journal::open(&directory, stream(), bounds).expect("it opens");

        let mut appended = 0;
        loop {
            let (seq, prev) = journal.next_position();
            match journal.append(&record(seq, &prev)) {
                Ok(_) => appended += 1,
                Err(JournalError::Full) => break,
                Err(other) => panic!("unexpected: {other}"),
            }
            assert!(appended < 100, "the bound should have been reached");
        }

        assert!(appended > 0, "something fit before the bound");
        assert_eq!(
            journal.read_from(0, 100).expect("it reads").len(),
            appended,
            "everything written before the bound is still there"
        );
    }

    /// Group commit does not let a receipt out early.
    #[test]
    fn an_unsynced_append_is_not_durable_until_it_is_synced() {
        let directory = scratch("group-commit");
        let mut journal = Journal::open(&directory, stream(), Bounds::default()).expect("it opens");

        for _ in 0..3 {
            let (seq, prev) = journal.next_position();
            journal
                .append_unsynced(&record(seq, &prev))
                .expect("it appends");
        }
        assert_eq!(
            journal.state().durable_through,
            0,
            "nothing is durable until the flush"
        );

        journal.sync().expect("it flushes");
        assert_eq!(journal.state().durable_through, 3);
    }

    /// Rewrites `STATE` as it would have been left by a crash between the segment's `fsync` and
    /// the state write that ordinarily follows it.
    fn rewind_state(directory: &Path, durable_through: u64) {
        let path = directory.join(STATE_FILE);
        let mut state: State =
            serde_json::from_slice(&fs::read(&path).expect("it reads")).expect("it parses");
        state.next_seq = durable_through.saturating_add(1);
        state.head = GENESIS.to_owned();
        state.durable_through = durable_through;
        state.signed_through = state.signed_through.min(durable_through);
        state.acked_through = state.acked_through.min(state.signed_through);
        fs::write(&path, serde_json::to_vec(&state).expect("it serializes")).expect("it writes");
    }

    /// The crash window between `fsync` and `STATE`: the record is on disk, so it is durable, and
    /// no *new* event is needed to say so.
    #[test]
    fn a_record_synced_before_the_state_write_is_durable_after_reopen() {
        let directory = scratch("state-behind-segment");
        let journal = filled(&directory, 3, Bounds::default());
        assert_eq!(journal.state().durable_through, 3);
        drop(journal);

        // The segment holds three records; `STATE` only ever learned about the first.
        rewind_state(&directory, 1);

        let journal = Journal::open(&directory, stream(), Bounds::default()).expect("it reopens");
        assert_eq!(
            journal.state().durable_through,
            3,
            "a complete record on disk survived the crash, so it is durable — a shipper that \
             waited for a new append would hold this backlog for ever"
        );
        assert_eq!(journal.state().next_seq, 4);
        assert_eq!(journal.read_from(0, 10).expect("it reads").len(), 3);
    }

    /// The other direction still holds: `STATE` claiming more than the segment carries is clamped.
    #[test]
    fn a_state_claiming_more_than_the_segment_holds_is_clamped_to_it() {
        let directory = scratch("state-ahead-of-segment");
        let journal = filled(&directory, 2, Bounds::default());
        drop(journal);

        let path = directory.join(STATE_FILE);
        let mut state: State =
            serde_json::from_slice(&fs::read(&path).expect("it reads")).expect("it parses");
        state.next_seq = 99;
        state.durable_through = 98;
        state.signed_through = 98;
        state.acked_through = 98;
        fs::write(&path, serde_json::to_vec(&state).expect("it serializes")).expect("it writes");

        let journal = Journal::open(&directory, stream(), Bounds::default()).expect("it reopens");
        assert_eq!(journal.state().durable_through, 2);
        assert_eq!(journal.state().signed_through, 2);
        assert_eq!(journal.state().acked_through, 2);
        assert_eq!(journal.state().next_seq, 3);
    }

    /// A segment created but never written into — the crash between `create` and `write_all` —
    /// must not hide the records the previous segment already holds.
    #[test]
    fn an_empty_final_segment_does_not_hide_the_previous_one() {
        let directory = scratch("empty-final-segment");
        let journal = filled(&directory, 3, Bounds::default());
        assert_eq!(journal.state().next_seq, 4);
        drop(journal);

        // What `Journal::write` leaves behind when it dies between the two steps.
        fs::write(
            directory.join(format!("{SEGMENT_PREFIX}{:020}{SEGMENT_SUFFIX}", 4)),
            b"",
        )
        .expect("it writes");
        rewind_state(&directory, 1);

        let journal = Journal::open(&directory, stream(), Bounds::default()).expect("it reopens");
        assert_eq!(journal.state().durable_through, 3);
        assert_eq!(journal.state().next_seq, 4);
        assert_eq!(journal.read_from(0, 10).expect("it reads").len(), 3);
    }

    /// The watermark that claims a persisted checkpoint has one behind it.
    ///
    /// `signed_through` says "covered by a persisted signed checkpoint", and the layout at the top
    /// of this module names the file. Both were assertions with nothing behind them: the watermark
    /// was set from the control plane's acknowledgement, and no code ever wrote a
    /// `checkpoint-*.jws`. An auditor holding only this volume could not check what it claimed.
    #[test]
    fn a_signed_checkpoint_is_on_the_volume_the_watermark_speaks_for() {
        let directory = scratch("signed-checkpoint");
        let mut journal = filled(&directory, 3, Bounds::default());
        assert!(
            journal.checkpoints().expect("it lists").is_empty(),
            "nothing is signed until a batch is"
        );

        journal
            .checkpoint(1, 3, "cHJvdGVjdGVk.cGF5bG9hZA.c2ln")
            .expect("the checkpoint is written");

        let held = journal.checkpoints().expect("it lists");
        assert_eq!(held.len(), 1, "one batch, one checkpoint");
        assert_eq!(held[0].0, 1, "named by the batch's first sequence");
        assert!(
            held[0]
                .1
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".jws")),
            "the file the layout documents: {:?}",
            held[0].1
        );
        assert_eq!(
            fs::read_to_string(&held[0].1).expect("it reads"),
            "cHJvdGVjdGVk.cGF5bG9hZA.c2ln",
            "the evidence is the envelope this plane signed, verbatim"
        );
        assert_eq!(journal.state().signed_through, 3);

        // And it survives the restart, because that is when the claim matters most.
        drop(journal);
        let journal = Journal::open(&directory, stream(), Bounds::default()).expect("it reopens");
        assert_eq!(journal.state().signed_through, 3);
        assert_eq!(journal.checkpoints().expect("it lists").len(), 1);
    }

    /// A retry is recognised by the volume, not by how recently it happened.
    ///
    /// Recognition used to be a window of the last few thousand ids held in memory. Inside it a
    /// repeat was idempotent; outside it the same id was accepted as a new occurrence and counted
    /// twice — silently, and the further behind a client's retry, the likelier it was. What this
    /// pins down is that the answer no longer depends on how much has happened since.
    #[test]
    fn an_occurrence_is_recognised_by_its_id_however_long_ago_it_was() {
        let directory = scratch("occurrence-horizon");
        let journal = filled(&directory, 1, Bounds::default());

        assert!(
            journal.occurrence("evt-1").expect("it reads").is_none(),
            "an id nothing recorded is new here"
        );
        journal
            .record_occurrence(&KnownOccurrence {
                event_id: "evt-1".to_owned(),
                seq: 1,
                occurrence_digest: "sha256:aaa".to_owned(),
                response: json!({"outcome": "accepted"}),
            })
            .expect("the entry is written");
        journal.sync_occurrences().expect("it flushes");

        // Whatever else happens afterwards, and however much of it.
        let held = journal
            .occurrence("evt-1")
            .expect("it reads")
            .expect("known");
        assert_eq!(held.seq, 1);
        assert_eq!(held.occurrence_digest, "sha256:aaa");
        assert_eq!(held.response["outcome"], "accepted");

        // And across the restart, which is when a client is most likely to be retrying.
        drop(journal);
        let journal = Journal::open(&directory, stream(), Bounds::default()).expect("it reopens");
        let held = journal
            .occurrence("evt-1")
            .expect("it reads")
            .expect("known");
        assert_eq!(held.seq, 1);
        assert_eq!(held.response["outcome"], "accepted");
    }

    /// An id is any string a client chose, and it never becomes a path.
    #[test]
    fn an_occurrence_id_is_addressed_by_digest_and_never_used_as_a_file_name() {
        let directory = scratch("occurrence-hostile-id");
        let journal = filled(&directory, 1, Bounds::default());
        let hostile = "../../../../etc/passwd";

        journal
            .record_occurrence(&KnownOccurrence {
                event_id: hostile.to_owned(),
                seq: 1,
                occurrence_digest: "sha256:bbb".to_owned(),
                response: Value::Null,
            })
            .expect("a hostile id is stored like any other");
        journal.sync_occurrences().expect("it flushes");

        let held = journal
            .occurrence(hostile)
            .expect("it reads")
            .expect("known");
        assert_eq!(held.seq, 1);
        assert!(
            directory.join(OCCURRENCES_DIRECTORY).is_dir(),
            "it landed inside the ledger's own directory"
        );
    }

    /// Eviction takes the record and what is known about it together.
    #[test]
    fn what_is_known_about_an_occurrence_goes_when_its_record_does() {
        let directory = scratch("occurrence-eviction");
        let bounds = Bounds {
            segment_bytes: 1,
            ..Bounds::default()
        };
        let mut journal = filled(&directory, 3, bounds);
        for seq in 1..=3u64 {
            journal
                .record_occurrence(&KnownOccurrence {
                    event_id: format!("evt-{seq}"),
                    seq,
                    occurrence_digest: format!("sha256:{seq}"),
                    response: Value::Null,
                })
                .expect("the entry is written");
        }
        journal.sync_occurrences().expect("it flushes");

        journal.mark_signed(3).expect("durable");
        journal.acknowledge(3).expect("signed");
        let dropped = journal
            .evict(journal.deletable_through(3))
            .expect("it evicts");
        assert!(dropped > 0, "whole segments were dropped");

        let oldest = journal.state().oldest_retained;
        for seq in 1..oldest {
            assert!(
                journal
                    .occurrence(&format!("evt-{seq}"))
                    .expect("it reads")
                    .is_none(),
                "sequence {seq} is gone, and so is what was known about it"
            );
        }
        assert!(
            journal
                .occurrence(&format!("evt-{oldest}"))
                .expect("it reads")
                .is_some(),
            "and a surviving record keeps its entry"
        );
    }

    /// A checkpoint cannot attest to what is not durable yet.
    #[test]
    fn a_checkpoint_ahead_of_the_durable_tail_is_refused() {
        let directory = scratch("checkpoint-ahead");
        let mut journal = filled(&directory, 2, Bounds::default());

        let refused = journal
            .checkpoint(1, 9, "a.b.c")
            .expect_err("nine is not durable");
        assert!(
            matches!(refused, JournalError::AheadOfDurable { .. }),
            "{refused}"
        );
        assert!(
            journal.checkpoints().expect("it lists").is_empty(),
            "a refused checkpoint leaves no file behind"
        );
    }
}
