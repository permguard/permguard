// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The append-only journal: checksummed frames in segments, and a torn tail truncated, never
//! guessed.
//!
//! # Layout
//!
//! ```text
//! <dir>/seg-<first frame index, 20 digits>.pgj
//!   header (16)  magic `PGJRNSEG` | version | flags | reserved
//!   SHA-256(header) (32)
//!   frame*       length u32 | type u16 | claim generation u64 | payload | SHA-256(the four before)
//! ```
//!
//! The segments are the authority: which segment is current, and the index of every frame,
//! follow from their names and their frames, so there is no state file to fall out of step with
//! them. The one other file a journal keeps is a failure record, [`FAILED`], present only between
//! a failed write or flush and the recovery that follows it.
//!
//! # Recovery, at open
//!
//! | What is found                                                         | What happens                                  |
//! | --------------------------------------------------------------------- | --------------------------------------------- |
//! | in the last segment, a damaged frame whose own extent reaches the end | truncated: a torn write                       |
//! | in the last segment, an incomplete frame header, or zeros to the end  | truncated: a torn write                       |
//! | with no record, a last segment of at most 48 bytes, header not whole  | removed: it held no frame                     |
//! | a failure record naming frame `n`                                     | frames from `n` cut, then the record removed  |
//! | with a record, an acknowledged frame not whole, or a segment missing  | [`StorageError::Corruption`], nothing changed |
//! | a damaged frame with bytes beyond its own extent                      | [`StorageError::Corruption`]                  |
//! | a damaged frame declaring more than the format's frame limit          | [`StorageError::Corruption`]                  |
//! | a damaged header on a segment holding frames                          | [`StorageError::Corruption`]                  |
//! | a torn frame in any segment but the last; a gap between segments      | [`StorageError::Corruption`]                  |
//! | a damaged failure record, or one naming a frame past the end          | [`StorageError::Corruption`]                  |
//! | a failed flush of an earlier repair, in this process                  | [`StorageError::NotRecoverable`]              |
//! | another magic, a newer version, an unknown flag                       | [`StorageError::Unsupported`]                 |
//!
//! Acknowledged frames are never modified: a truncation cuts exactly the torn bytes, or exactly
//! the frames a failure record names as never acknowledged. A repair whose flush fails is final:
//! the open fails, and this process does not open the journal again.
//!
//! A damaged frame is judged by its own extent, the bytes its length field claims. Appends are
//! serialized and each is flushed before the next is written, so a crash leaves at most one frame
//! in flight, and that frame's write is all that can follow the last whole frame: a prefix of it,
//! or zeros where a filesystem extended the file before the data landed. A damaged frame whose
//! extent reaches or passes the end of the segment is that write, and is cut, whatever its payload
//! holds; bytes beyond its extent are durable data after a damaged frame, and the journal does not
//! open. Zeros from a frame's start to the end of the segment are a write whose data never landed,
//! and are cut; zeros followed by data are corruption, never a cut. A length over [`FRAME_LIMIT`],
//! the format's own bound, was never written by any journal.
//!
//! Persistence out of order — a later page of the frame in flight landing while an earlier one did
//! not, which only a power loss can cause — can leave a header that is neither whole nor zero, and
//! then the journal does not open. Whether a storage stack keeps a file's pages in order is part of
//! its qualification (H-04, WP-1.3).
//!
//! The rule never searches the payload, so a payload that itself contains encoded frames cannot
//! make a crashed journal refuse to open, and recovery reads each byte once. What it cannot tell
//! from a torn write: damage to the last frame itself, and a length field enlarged by damage, within
//! the frame bound, so far that its extent passes the end, which cuts the frames it covers.
//!
//! # Exclusion
//!
//! Opening repairs the directory: it truncates, removes and sweeps. Only one process may hold a
//! journal open; the volume `LOCK` (WP-1.4) is what guarantees that, and a caller opens a journal
//! only under it.
//!
//! # Appends, and a failed flush
//!
//! An append writes one frame and flushes it with `fdatasync` before it returns.
//!
//! A failed write or flush is final (WP-1.2). The append fails, the handle refuses every later
//! append and read ([`StorageError::Poisoned`]) and its [`Readiness`] turns not ready. Before the
//! error returns, the journal writes and flushes a failure record, [`FAILED`], a view whose body is
//! the index of the first frame that was not acknowledged.
//!
//! Opening the journal again applies the record before anything else is judged, having refused any
//! segment of a newer format: it removes every segment whose first frame is at or after that
//! index, truncates the segment holding it where that frame starts, flushes each step, and removes
//! the record last. The frame that failed is cut, and so is a segment a failed roll started,
//! whatever the page cache still shows; the record stays until the cut is durable, so a crash at
//! any step applies it again. The cut is decided before anything changes: where an acknowledged
//! frame before the index is not whole, or a segment is missing, the journal does not open
//! (corruption) and nothing is removed or truncated; after the cut nothing more is cut either: a
//! torn or headerless segment then holds acknowledged frames, and is corruption.
//!
//! A record that cannot be made durable, or a repair whose flush fails while opening, leaves this
//! process refusing to open the journal again ([`StorageError::NotRecoverable`]). The process
//! remembers the journal by its directory's identity (device and inode on Unix), so a directory
//! recreated under a reused inode is refused too, which only fails closed; on Windows the identity
//! is the path. After a restart without a record, a frame whose flush failed cannot be told from a
//! write that crashed before its acknowledgement, and is kept as one.
//!
//! # Segment roll
//!
//! A segment past its size bound rolls at the start of the next append, before that append writes
//! anything: the segment is flushed, the next one is created exclusively with its header and the
//! header's checksum, flushed, and the directory flushed — a crash point at each step. A roll that
//! fails, at any step, gives the handle up like a failed append, writing nothing of the frame that
//! asked for it; every earlier frame was acknowledged after its own flush, so the record names the
//! next index and cuts only the segment the roll had started.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::dir::Dir;
use super::format::{self, CHECKSUM_LEN, HEADER_LEN};
use super::write::{read_view, replace_view};
use super::{Result, StorageError, crash::point, durability, io};

/// The largest payload any frame of this format carries: recovery judges damage against it, so it
/// is a property of the format, not of one journal's options.
pub const FRAME_LIMIT: u32 = 16 * 1024 * 1024;

/// The largest payload one frame carries unless a journal is told otherwise.
pub const DEFAULT_MAX_FRAME: u32 = FRAME_LIMIT;

/// The size past which a segment rolls, unless a journal is told otherwise.
pub const DEFAULT_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Bytes before a frame's payload: length, type, claim generation.
const FRAME_HEAD: usize = 4 + 2 + 8;

/// Bytes before a segment's first frame: the header and its checksum.
const SEGMENT_HEAD: usize = HEADER_LEN + CHECKSUM_LEN;

/// How a journal is bounded.
///
/// `max_frame` bounds appends and may be anything up to [`FRAME_LIMIT`]; a journal is opened with
/// any bound, lower or higher than the one it was written with, since recovery judges against the
/// format's limit. A segment rolls only once it holds a frame, so a `segment_bytes` below the
/// segment head means one frame per segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub max_frame: u32,
    pub segment_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_frame: DEFAULT_MAX_FRAME,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
        }
    }
}

/// The failure record's name in a journal's directory.
pub const FAILED: &str = "FAILED";

/// The journals whose failure record could not be made durable, by directory identity: this
/// process does not open them again.
static UNRECORDED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Whether a journal handle is ready: true from open, false for good once the handle is given up
/// (a failed write or flush, or any step of a roll that fails). The journal opened again to
/// recover is a new handle with its own readiness, which a watcher takes in place of the old.
/// Cloned freely, so the Host lifecycle can watch a journal it does not hold.
#[derive(Debug, Clone)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    /// Whether the journal accepts appends.
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn lose(&self) {
        self.0.store(false, Ordering::Release);
    }
}

/// One frame read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Its position in the journal, from zero.
    pub index: u64,
    pub kind: u16,
    /// The volume claim it was written under; zero until volume claims exist (WP-1.4).
    pub claim: u64,
    pub payload: Vec<u8>,
}

/// What opening the journal had to repair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Bytes cut from the end of the last segment: a torn final frame.
    pub truncated_bytes: u64,
    /// A last segment removed because its own header never became durable.
    pub removed_segment: Option<String>,
    /// Temporary files a crash left behind, swept.
    pub swept_temporaries: usize,
    /// The first frame a failure record named as never acknowledged; it and everything after it
    /// were cut.
    pub cut_from: Option<u64>,
}

/// An open journal.
#[derive(Debug)]
pub struct Journal {
    dir: Dir,
    options: Options,
    /// `(first index, name)` of every segment, in order.
    segments: Vec<(u64, String)>,
    current: File,
    current_len: u64,
    next_index: u64,
    poisoned: bool,
    readiness: Readiness,
    /// The directory's identity, taken at open: what the process remembers it by.
    identity: String,
}

fn segment_name(first: u64) -> String {
    format!("seg-{first:020}.pgj")
}

/// The first frame index a segment's name carries: `None` for a name that is not a segment's, and
/// corruption for one that is but names no frame a journal can hold.
fn segment_first(name: &str) -> Option<Result<u64>> {
    let digits = name.strip_prefix("seg-")?.strip_suffix(".pgj")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(digits.parse().map_err(|_| {
        StorageError::Corruption(format!(
            "segment `{name}` names a frame past the last index"
        ))
    }))
}

/// The bytes of one frame; a payload whose length does not fit the `u32` length field is refused.
pub fn encode_frame(kind: u16, claim: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(payload.len()).map_err(|_| {
        StorageError::TooLarge(format!(
            "a frame of {} bytes does not fit a frame's length field",
            payload.len()
        ))
    })?;
    let mut bytes = Vec::with_capacity(FRAME_HEAD + payload.len() + CHECKSUM_LEN);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&claim.to_be_bytes());
    bytes.extend_from_slice(payload);
    let sum = format::checksum(&bytes);
    bytes.extend_from_slice(&sum);
    Ok(bytes)
}

fn segment_head() -> Vec<u8> {
    let header = format::header(format::JOURNAL_SEGMENT, 0);
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&format::checksum(&header));
    bytes
}

/// How one segment's frames read.
enum Scan {
    /// Every frame verified; `frames` of them, ending at `end`.
    Whole { frames: Vec<Frame>, end: usize },
    /// The frames before `at` verified, and what follows is a torn final frame.
    Torn { frames: Vec<Frame>, at: usize },
}

/// The end of the frame that starts at `at`, when a whole frame that verifies starts there.
fn whole_frame_at(bytes: &[u8], at: usize) -> Option<usize> {
    let head = bytes.get(at..at.checked_add(FRAME_HEAD)?)?;
    let length = usize::try_from(u32::from_be_bytes([head[0], head[1], head[2], head[3]])).ok()?;
    let body_end = (at + FRAME_HEAD).checked_add(length)?;
    let end = body_end.checked_add(CHECKSUM_LEN)?;
    let sum = bytes.get(body_end..end)?;
    (format::checksum(&bytes[at..body_end]) == sum).then_some(end)
}

fn scan(bytes: &[u8], first: u64, name: &str) -> Result<Scan> {
    let mut frames = Vec::new();
    let mut at = SEGMENT_HEAD;
    while at < bytes.len() {
        let Some(end) = whole_frame_at(bytes, at) else {
            // Judged by its own extent: see "Recovery, at open".
            let index = first + frames.len() as u64;
            let Some(head) = bytes.get(at..at + FRAME_HEAD) else {
                return Ok(Scan::Torn { frames, at });
            };
            if bytes[at..].iter().all(|byte| *byte == 0) {
                return Ok(Scan::Torn { frames, at });
            }
            let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
            if length > FRAME_LIMIT {
                return Err(StorageError::Corruption(format!(
                    "frame {index} of `{name}` at byte {at} does not verify and declares {length} \
                     bytes, over the format's limit of {FRAME_LIMIT}"
                )));
            }
            if at + FRAME_HEAD + length as usize + CHECKSUM_LEN < bytes.len() {
                return Err(StorageError::Corruption(format!(
                    "frame {index} of `{name}` at byte {at} does not verify and bytes follow it"
                )));
            }
            return Ok(Scan::Torn { frames, at });
        };
        let head = &bytes[at..at + FRAME_HEAD];
        let body_end = end - CHECKSUM_LEN;
        frames.push(Frame {
            index: first + frames.len() as u64,
            kind: u16::from_be_bytes([head[4], head[5]]),
            claim: u64::from_be_bytes([
                head[6], head[7], head[8], head[9], head[10], head[11], head[12], head[13],
            ]),
            payload: bytes[at + FRAME_HEAD..body_end].to_vec(),
        });
        at = end;
    }
    Ok(Scan::Whole { frames, end: at })
}

/// Whether a segment's own header is durable and readable; `Unsupported` passes through.
fn head_is_whole(bytes: &[u8]) -> Result<bool> {
    let Some(head) = bytes.get(..SEGMENT_HEAD) else {
        return Ok(false);
    };
    if format::checksum(&head[..HEADER_LEN]) != head[HEADER_LEN..] {
        return Ok(false);
    }
    format::read_header(head, format::JOURNAL_SEGMENT)?;
    Ok(true)
}

impl Journal {
    /// Opens the journal in `dir`, creating it when empty, and repairs a torn tail and what a
    /// failure record names.
    ///
    /// A repair whose flush fails is final like an append's: the error is returned, and this
    /// process does not open the journal again, since what it would read back is the page cache,
    /// not what is durable.
    pub fn open(dir: Dir, options: Options) -> Result<(Self, Recovery)> {
        if options.max_frame > FRAME_LIMIT {
            return Err(StorageError::TooLarge(format!(
                "a frame bound of {} bytes; the format allows up to {FRAME_LIMIT}",
                options.max_frame
            )));
        }
        let identity = dir.identity()?;
        if UNRECORDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&identity)
        {
            return Err(StorageError::NotRecoverable(format!(
                "a flush the journal in {} depended on failed and could not be recorded; this \
                 process does not open it again",
                dir.path().display()
            )));
        }
        match Self::recover(dir, options, identity.clone()) {
            Err(error @ StorageError::Durability { .. }) => {
                remember_unrecorded(identity);
                Err(error)
            }
            other => other,
        }
    }

    fn recover(dir: Dir, options: Options, identity: String) -> Result<(Self, Recovery)> {
        let mut recovery = Recovery {
            swept_temporaries: dir.sweep_temps()?,
            ..Recovery::default()
        };
        let mut segments: Vec<(u64, String)> = dir
            .names()?
            .into_iter()
            .filter_map(|name| segment_first(&name).map(|first| first.map(|first| (first, name))))
            .collect::<Result<_>>()?;
        segments.sort();

        // What a failure record names is cut before anything is judged: those bytes were never
        // acknowledged, whatever shape a failed write left them in.
        let record = failure_record(&dir)?;
        if let Some(first_unacknowledged) = record {
            // A segment of a format this build does not read is refused before anything changes.
            for (_, name) in &segments {
                refuse_newer(&dir, name)?;
            }
            cut_from(&dir, &mut segments, first_unacknowledged)?;
            recovery.cut_from = Some(first_unacknowledged);
        }

        let mut expected = 0u64;
        let mut tail: Option<(u64, String, usize)> = None;
        let count = segments.len();
        for (position, (first, name)) in segments.clone().into_iter().enumerate() {
            let last = position + 1 == count;
            let bytes = dir.read(&name)?.unwrap_or_default();
            if first != expected {
                return Err(StorageError::Corruption(format!(
                    "segment `{name}` starts at frame {first}, and the journal holds {expected} \
                     frames before it"
                )));
            }
            if !head_is_whole(&bytes)? {
                // After a record's cut, nothing the failure left remains: a segment without a
                // whole header holds acknowledged frames, and is not removed.
                if last && bytes.len() <= SEGMENT_HEAD && record.is_none() {
                    // A roll that crashed before the new segment's header was durable: frames
                    // are written only after it is, so it holds none, and is removed.
                    dir.unlink(&name)?;
                    dir.sync()?;
                    segments.pop();
                    recovery.removed_segment = Some(name);
                    break;
                }
                return Err(StorageError::Corruption(format!(
                    "segment `{name}` has a damaged header and holds frames or segments follow it"
                )));
            }
            match scan(&bytes, first, &name)? {
                Scan::Whole { frames, end } => {
                    expected = first + frames.len() as u64;
                    tail = Some((first, name, end));
                }
                // After a record's cut, a torn frame is damage to an acknowledged one, and is
                // not cut.
                Scan::Torn { frames, at } if last && record.is_none() => {
                    let file = dir.open_write(&name)?;
                    let path = dir.child_path(&name);
                    file.set_len(at as u64)
                        .map_err(io(format!("truncating {}", path.display())))?;
                    permguard_core::fault::sync(&path, || file.sync_all())
                        .map_err(durability(format!("flushing {}", path.display())))?;
                    recovery.truncated_bytes = (bytes.len() - at) as u64;
                    expected = first + frames.len() as u64;
                    tail = Some((first, name, at));
                }
                Scan::Torn { .. } => {
                    return Err(StorageError::Corruption(format!(
                        "segment `{name}` ends in a torn frame, and segments follow it or a \
                         failure record says its frames were acknowledged"
                    )));
                }
            }
        }

        if let Some(first_unacknowledged) = record {
            if first_unacknowledged != expected {
                return Err(StorageError::Corruption(format!(
                    "the failure record in {} names frame {first_unacknowledged} as the first \
                     never acknowledged, and the journal holds {expected}: acknowledged frames \
                     are missing or damaged",
                    dir.path().display()
                )));
            }
            dir.unlink(FAILED)?;
            dir.sync()?;
            point("failure.record_removed");
        }

        let (segments, current, current_len) = match tail {
            Some((_, name, end)) => {
                let mut file = dir.open_write(&name)?;
                file.seek(SeekFrom::Start(end as u64))
                    .map_err(io(format!("opening {}", dir.child_path(&name).display())))?;
                (segments, file, end as u64)
            }
            None => {
                let name = segment_name(expected);
                let file = create_segment(&dir, &name)?;
                (vec![(expected, name)], file, SEGMENT_HEAD as u64)
            }
        };

        Ok((
            Self {
                dir,
                options,
                segments,
                current,
                current_len,
                next_index: expected,
                poisoned: false,
                readiness: Readiness::new(),
                identity,
            },
            recovery,
        ))
    }

    /// The index the next appended frame will have.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// The segments, oldest first.
    pub fn segments(&self) -> Vec<String> {
        self.segments.iter().map(|(_, name)| name.clone()).collect()
    }

    /// Appends one frame of `kind` and flushes it; answers its index.
    pub fn append(&mut self, kind: u16, payload: &[u8]) -> Result<u64> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        if payload.len() > self.options.max_frame as usize {
            return Err(StorageError::TooLarge(format!(
                "a frame of {} bytes; this journal takes up to {}",
                payload.len(),
                self.options.max_frame
            )));
        }
        let bytes = encode_frame(kind, 0, payload)?;
        if self.current_len >= self.options.segment_bytes && self.current_len > SEGMENT_HEAD as u64
        {
            self.roll()?;
        }
        let name = self.current_name();
        let path = self.dir.child_path(&name);
        let current = &mut self.current;
        if let Err(error) =
            permguard_core::fault::write(&path, bytes.len(), || current.write_all(&bytes))
        {
            // A failed write gives the handle up like a failed flush (decided for WP-1.2): what
            // it left is cut when the journal is opened again.
            let failed = io(format!("appending to {}", path.display()))(error);
            return Err(self.give_up(self.next_index, failed));
        }
        point("journal.frame_written");
        if let Err(error) = permguard_core::fault::sync(&path, || current.sync_data()) {
            let failed = durability(format!("flushing {}", path.display()))(error);
            return Err(self.give_up(self.next_index, failed));
        }
        point("journal.frame_flushed");
        let index = self.next_index;
        self.next_index += 1;
        self.current_len += bytes.len() as u64;
        Ok(index)
    }

    /// Every frame, oldest first. A handle given up answers nothing: what it would read is the
    /// page cache, which may hold a frame that was never acknowledged.
    pub fn frames(&self) -> Result<Vec<Frame>> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        let mut all = Vec::new();
        for (first, name) in &self.segments {
            let bytes = self.dir.read(name)?.unwrap_or_default();
            match scan(&bytes, *first, name)? {
                Scan::Whole { frames, .. } => all.extend(frames),
                Scan::Torn { .. } => {
                    return Err(StorageError::Corruption(format!(
                        "segment `{name}` changed under an open journal"
                    )));
                }
            }
        }
        Ok(all)
    }

    fn current_name(&self) -> String {
        self.segments
            .last()
            .map(|(_, name)| name.clone())
            .unwrap_or_default()
    }

    /// Flushes the current segment, creates and flushes the next, and flushes the directory. A
    /// failure at any step gives the handle up: every frame so far was acknowledged after its own
    /// flush, so the record names the next index, and opening the journal again removes whatever
    /// segment the roll had started.
    fn roll(&mut self) -> Result<()> {
        match self.roll_once() {
            Ok(()) => Ok(()),
            Err(failed) => Err(self.give_up(self.next_index, failed)),
        }
    }

    /// Gives up this handle after `failed`: refuses every later append, turns not ready, and
    /// records that frames from `first_unacknowledged` on were never acknowledged. A record that
    /// cannot be made durable is remembered by the process instead, and said in the error.
    fn give_up(&mut self, first_unacknowledged: u64, failed: StorageError) -> StorageError {
        self.poisoned = true;
        self.readiness.lose();
        let recorded = replace_view(
            &self.dir,
            FAILED,
            format::VIEW,
            &first_unacknowledged.to_be_bytes(),
        );
        match recorded {
            Ok(()) => {
                point("failure.recorded");
                failed
            }
            Err(record) => {
                remember_unrecorded(self.identity.clone());
                match failed {
                    StorageError::Io { what, source } => StorageError::Io {
                        what: format!("{what}; the failure could not be recorded either: {record}"),
                        source,
                    },
                    StorageError::Durability { what, source } => StorageError::Durability {
                        what: format!("{what}; the failure could not be recorded either: {record}"),
                        source,
                    },
                    other => other,
                }
            }
        }
    }

    /// This handle's readiness; see [`Readiness`].
    pub fn readiness(&self) -> Readiness {
        self.readiness.clone()
    }

    fn roll_once(&mut self) -> Result<()> {
        let old = self.dir.child_path(&self.current_name());
        let current = &mut self.current;
        permguard_core::fault::sync(&old, || current.sync_all())
            .map_err(durability(format!("flushing {}", old.display())))?;
        point("journal.roll_old_flushed");
        let name = segment_name(self.next_index);
        let file = create_segment(&self.dir, &name)?;
        self.segments.push((self.next_index, name));
        self.current = file;
        self.current_len = SEGMENT_HEAD as u64;
        Ok(())
    }
}

/// The index a failure record names, when there is one.
fn failure_record(dir: &Dir) -> Result<Option<u64>> {
    let Some(body) = read_view(dir, FAILED, format::VIEW)? else {
        return Ok(None);
    };
    let index = <[u8; 8]>::try_from(body.as_slice()).map_err(|_| {
        StorageError::Corruption(format!(
            "the failure record in {} holds {} bytes, not an index",
            dir.path().display(),
            body.len()
        ))
    })?;
    Ok(Some(u64::from_be_bytes(index)))
}

/// Refuses a segment whose whole header names a format this build does not read; reads only
/// the header.
fn refuse_newer(dir: &Dir, name: &str) -> Result<()> {
    use std::io::Read as _;
    let Some(file) = dir.open_read(name)? else {
        return Ok(());
    };
    let mut head = Vec::with_capacity(SEGMENT_HEAD);
    file.take(SEGMENT_HEAD as u64)
        .read_to_end(&mut head)
        .map_err(io(format!("reading {}", dir.child_path(name).display())))?;
    head_is_whole(&head).map(|_| ())
}

/// Remembers that this process must not open the journal `identity` again.
fn remember_unrecorded(identity: String) {
    UNRECORDED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(identity);
}

/// Cuts every frame from `index` on, deciding first and changing after.
///
/// Read-only first: every segment before `index` must follow the one before it, with a whole
/// header and only whole frames, and the segment holding `index` must hold every frame before
/// it whole; otherwise acknowledged frames are damaged or missing, and the answer is corruption
/// with nothing changed. Then the segments whose first frame is at or after `index`, which never
/// held an acknowledged frame, are removed and the directory flushed, and the segment holding
/// `index` is truncated where that frame starts, and flushed.
fn cut_from(dir: &Dir, segments: &mut Vec<(u64, String)>, index: u64) -> Result<()> {
    let damaged = |what: &str| {
        StorageError::Corruption(format!(
            "the failure record in {} names frame {index} as the first never acknowledged, and \
             {what}; nothing was changed",
            dir.path().display()
        ))
    };
    let kept: Vec<(u64, String)> = segments
        .iter()
        .filter(|(first, _)| *first < index)
        .cloned()
        .collect();
    if kept.is_empty() && index > 0 {
        return Err(damaged("no segment holds the frames before it"));
    }
    let mut expected = 0u64;
    let mut truncate: Option<(String, usize, usize)> = None;
    for (position, (first, name)) in kept.iter().enumerate() {
        let bytes = dir.read(name)?.unwrap_or_default();
        if *first != expected || !head_is_whole(&bytes)? {
            return Err(damaged(&format!("segment `{name}` does not follow whole")));
        }
        if position + 1 == kept.len() {
            let mut end = SEGMENT_HEAD;
            for _ in *first..index {
                end = whole_frame_at(&bytes, end).ok_or_else(|| {
                    damaged(&format!("a frame before it in `{name}` is not whole"))
                })?;
            }
            truncate = Some((name.clone(), end, bytes.len()));
        } else {
            match scan(&bytes, *first, name)? {
                Scan::Whole { frames, .. } => expected = first + frames.len() as u64,
                Scan::Torn { .. } => {
                    return Err(damaged(&format!(
                        "segment `{name}` holds a frame that is not whole"
                    )));
                }
            }
        }
    }

    let mut removed = false;
    while let Some((first, name)) = segments.last().cloned()
        && first >= index
    {
        dir.unlink(&name)?;
        segments.pop();
        removed = true;
    }
    if removed {
        dir.sync()?;
    }
    point("failure.cut_segments_removed");
    if let Some((name, end, length)) = truncate
        && end < length
    {
        let path = dir.child_path(&name);
        let file = dir.open_write(&name)?;
        file.set_len(end as u64)
            .map_err(io(format!("truncating {}", path.display())))?;
        permguard_core::fault::sync(&path, || file.sync_all())
            .map_err(durability(format!("flushing {}", path.display())))?;
    }
    point("failure.cut_flushed");
    Ok(())
}

/// Creates a segment exclusively with its header and the header's checksum, flushed, and the
/// directory flushed.
fn create_segment(dir: &Dir, name: &str) -> Result<File> {
    let path = dir.child_path(name);
    let mut file = dir.create_exclusive(name)?;
    point("journal.roll_segment_created");
    let head = segment_head();
    permguard_core::fault::write(&path, head.len(), || file.write_all(&head))
        .map_err(io(format!("writing {}", path.display())))?;
    permguard_core::fault::sync(&path, || file.sync_all())
        .map_err(durability(format!("flushing {}", path.display())))?;
    point("journal.roll_header_flushed");
    dir.sync()?;
    point("journal.roll_parent_flushed");
    // Opened again for reading and writing at its end: the handle `create_exclusive` gave is
    // write-only, and the journal reads its own segments back.
    drop(file);
    let mut file = dir.open_write(name)?;
    file.seek(SeekFrom::End(0))
        .map_err(io(format!("opening {}", path.display())))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-journal-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn open(path: &std::path::Path, options: Options) -> (Journal, Recovery) {
        Journal::open(Dir::open(path).expect("opened"), options).expect("the journal opens")
    }

    #[test]
    fn frames_round_trip_with_their_indexes_and_the_decided_layout() {
        let path = scratch("round-trip");
        let (mut journal, _) = open(&path, Options::default());
        assert_eq!(journal.append(7, b"first").expect("appended"), 0);
        assert_eq!(journal.append(8, b"second").expect("appended"), 1);
        drop(journal);

        let (journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery, Recovery::default());
        let frames = journal.frames().expect("read");
        assert_eq!(frames.len(), 2);
        assert_eq!(
            (frames[1].index, frames[1].kind, frames[1].claim),
            (1, 8, 0)
        );
        assert_eq!(frames[1].payload, b"second");

        let bytes = std::fs::read(path.join(segment_name(0))).expect("the segment");
        assert_eq!(&bytes[..8], b"PGJRNSEG");
        assert_eq!(
            &bytes[48..52],
            &5u32.to_be_bytes(),
            "the first frame's length"
        );
        assert_eq!(&bytes[52..54], &7u16.to_be_bytes(), "its type");
        assert_eq!(&bytes[54..62], &0u64.to_be_bytes(), "its claim generation");
    }

    #[test]
    fn a_torn_final_frame_is_truncated_and_nothing_before_it_moves() {
        let path = scratch("torn");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"kept").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let before = std::fs::read(&segment).expect("the segment");
        let mut torn = before.clone();
        torn.extend_from_slice(&encode_frame(1, 0, b"never finished").expect("a frame")[..10]);
        std::fs::write(&segment, &torn).expect("torn");

        let (journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery.truncated_bytes, 10);
        assert_eq!(
            std::fs::read(&segment).expect("the segment"),
            before,
            "earlier frames intact"
        );
        assert_eq!(journal.frames().expect("read").len(), 1);
    }

    #[test]
    fn a_final_frame_failing_its_checksum_is_torn_and_one_followed_by_frames_is_corruption() {
        let path = scratch("checksum");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        journal.append(1, b"two").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let good = std::fs::read(&segment).expect("the segment");

        // The last frame's payload flipped: a torn write, truncated.
        let mut last = good.clone();
        let at = last.len() - CHECKSUM_LEN - 1;
        last[at] ^= 1;
        std::fs::write(&segment, &last).expect("damaged");
        let (journal, recovery) = open(&path, Options::default());
        assert!(recovery.truncated_bytes > 0);
        assert_eq!(journal.frames().expect("read").len(), 1);
        drop(journal);

        // The first frame's payload flipped, with a frame after it: corruption, and nothing cut.
        let mut first = good.clone();
        first[SEGMENT_HEAD + FRAME_HEAD] ^= 1;
        std::fs::write(&segment, &first).expect("damaged");
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert_eq!(
            std::fs::read(&segment).expect("the segment"),
            first,
            "nothing was cut"
        );
    }

    #[test]
    fn segments_roll_and_indexes_continue_across_them() {
        let path = scratch("roll");
        let options = Options {
            max_frame: 1024,
            segment_bytes: 200,
        };
        let (mut journal, _) = open(&path, options);
        for index in 0..10u64 {
            assert_eq!(
                journal.append(1, &[index as u8; 40]).expect("appended"),
                index
            );
        }
        assert!(journal.segments().len() > 1, "{:?}", journal.segments());
        drop(journal);
        let (journal, _) = open(&path, options);
        let frames = journal.frames().expect("read");
        assert_eq!(frames.len(), 10);
        assert!(
            frames
                .iter()
                .enumerate()
                .all(|(at, frame)| frame.index == at as u64)
        );
        assert_eq!(journal.next_index(), 10);
    }

    /// A length field damaged past the format's frame limit was never written by any journal:
    /// corruption, and nothing is cut.
    #[test]
    fn a_damaged_length_with_frames_after_it_is_corruption_not_a_torn_tail() {
        let path = scratch("length");
        let (mut journal, _) = open(&path, Options::default());
        for payload in [b"one", b"two", b"six"] {
            journal.append(1, payload).expect("appended");
        }
        drop(journal);
        let segment = path.join(segment_name(0));
        let mut damaged = std::fs::read(&segment).expect("the segment");
        damaged[SEGMENT_HEAD] = 0x7f;
        std::fs::write(&segment, &damaged).expect("damaged");
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert_eq!(
            std::fs::read(&segment).expect("kept"),
            damaged,
            "nothing cut"
        );
    }

    /// A torn write of a frame whose payload itself holds an encoded frame is still a torn write:
    /// the rule never searches a payload.
    #[test]
    fn a_torn_frame_carrying_an_encoded_frame_is_still_torn() {
        let path = scratch("embedded");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"kept").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let before = std::fs::read(&segment).expect("the segment");
        let mut payload = vec![0x11; 100];
        payload.extend_from_slice(&encode_frame(1, 0, b"inner").expect("a frame"));
        payload.extend_from_slice(&[0x22; 400]);
        let frame = encode_frame(1, 0, &payload).expect("a frame");
        let mut torn = before.clone();
        torn.extend_from_slice(&frame[..FRAME_HEAD + 100 + 51 + 50]);
        std::fs::write(&segment, &torn).expect("torn");
        let (journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery.truncated_bytes as usize, torn.len() - before.len());
        assert_eq!(std::fs::read(&segment).expect("the segment"), before);
        assert_eq!(journal.frames().expect("read").len(), 1);
    }

    /// A damaged frame whose length is within bounds but whose extent ends before the file does is
    /// followed by durable bytes: corruption.
    #[test]
    fn bytes_beyond_a_damaged_frames_extent_are_corruption() {
        let path = scratch("beyond");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let mut damaged = std::fs::read(&segment).expect("the segment");
        damaged[SEGMENT_HEAD + FRAME_HEAD] ^= 1;
        damaged.extend_from_slice(&[0x33; 10]);
        std::fs::write(&segment, &damaged).expect("damaged");
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
    }

    /// Zeros followed by data are not a write whose data never landed: corruption, never a cut.
    #[test]
    fn zeros_followed_by_data_are_corruption() {
        let path = scratch("zeros-then-data");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"kept").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let mut damaged = std::fs::read(&segment).expect("the segment");
        damaged.extend_from_slice(&[0u8; 64]);
        damaged.extend_from_slice(&encode_frame(1, 0, b"after").expect("a frame"));
        std::fs::write(&segment, &damaged).expect("damaged");
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert_eq!(
            std::fs::read(&segment).expect("kept"),
            damaged,
            "nothing cut"
        );
    }

    /// Recovery judges against the format's limit, not the options a journal is opened with: a
    /// lower bound at reopening still cuts a torn frame larger than itself, and a bound over the
    /// limit is refused.
    #[test]
    fn the_frame_limit_is_the_formats_not_the_options() {
        let path = scratch("limit");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"kept").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let before = std::fs::read(&segment).expect("the segment");
        let mut torn = before.clone();
        torn.extend_from_slice(&encode_frame(1, 0, &[9u8; 1024]).expect("a frame")[..600]);
        std::fs::write(&segment, &torn).expect("torn");
        let lower = Options {
            max_frame: 16,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
        };
        let (journal, recovery) = open(&path, lower);
        assert_eq!(recovery.truncated_bytes, 600);
        assert_eq!(journal.frames().expect("read").len(), 1);
        drop(journal);
        let over = Options {
            max_frame: FRAME_LIMIT + 1,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
        };
        assert!(matches!(
            Journal::open(Dir::open(&path).expect("opened"), over).expect_err("refused"),
            StorageError::TooLarge(_)
        ));
    }

    /// The known limit, pinned so that a change to it is deliberate: a length field enlarged within
    /// the frame bound, so far that its extent passes the end, reads as a torn write and the frames
    /// its extent covers are cut.
    #[test]
    fn a_length_enlarged_past_the_end_cuts_the_frames_it_covers() {
        let path = scratch("enlarged");
        let (mut journal, _) = open(&path, Options::default());
        for payload in [b"one", b"two", b"six"] {
            journal.append(1, payload).expect("appended");
        }
        drop(journal);
        let segment = path.join(segment_name(0));
        let mut damaged = std::fs::read(&segment).expect("the segment");
        let second = SEGMENT_HEAD + FRAME_HEAD + 3 + CHECKSUM_LEN;
        damaged[second..second + 4].copy_from_slice(&200u32.to_be_bytes());
        std::fs::write(&segment, &damaged).expect("damaged");
        let (journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery.truncated_bytes as usize, damaged.len() - second);
        assert_eq!(journal.frames().expect("read").len(), 1);
    }

    /// A segment rolls only once it holds a frame, so a bound below the segment head cannot make a
    /// roll recreate the segment it is in.
    #[test]
    fn a_bound_below_the_segment_head_rolls_after_every_frame() {
        let path = scratch("tiny-segments");
        let options = Options {
            max_frame: 64,
            segment_bytes: 0,
        };
        let (mut journal, _) = open(&path, options);
        for index in 0..3u64 {
            assert_eq!(journal.append(1, &[index as u8]).expect("appended"), index);
        }
        assert_eq!(journal.segments().len(), 3);
        let frames = journal.frames().expect("read");
        assert_eq!(frames.len(), 3);
        drop(journal);
        let (journal, _) = open(&path, options);
        assert_eq!(journal.frames().expect("read"), frames);
    }

    /// A failed flush during a roll is final like any other.
    #[test]
    fn a_failed_flush_during_a_roll_poisons_the_journal() {
        let path = scratch("roll-fsync");
        let options = Options {
            max_frame: 1024,
            segment_bytes: 100,
        };
        let (mut journal, _) = open(&path, options);
        journal.append(1, &[1u8; 40]).expect("appended");
        {
            let _guard = permguard_core::fault::inject(&path, permguard_core::fault::Fault::Fsync);
            assert!(matches!(
                journal
                    .append(1, &[2u8; 40])
                    .expect_err("the roll's flush failed"),
                StorageError::Durability { .. }
            ));
        }
        assert!(matches!(
            journal.append(1, &[3u8; 40]).expect_err("refused"),
            StorageError::Poisoned
        ));
    }

    /// A segment name whose index overflows is not ignored.
    #[test]
    fn a_segment_name_past_the_last_index_is_corruption() {
        let path = scratch("overflow");
        drop(open(&path, Options::default()));
        std::fs::write(path.join("seg-99999999999999999999.pgj"), b"").expect("a stray segment");
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
    }

    /// A filesystem may extend the file before the data lands: zeros after the last whole frame
    /// are a torn write, however many of them there are.
    #[test]
    fn a_zero_filled_tail_is_a_torn_write() {
        let path = scratch("zeros");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"kept").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let before = std::fs::read(&segment).expect("the segment");
        let mut torn = before.clone();
        torn.extend_from_slice(&[0u8; 300]);
        std::fs::write(&segment, &torn).expect("extended");
        let (journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery.truncated_bytes, 300);
        assert_eq!(std::fs::read(&segment).expect("the segment"), before);
        assert_eq!(journal.frames().expect("read").len(), 1);
    }

    /// A damaged header on a segment that holds frames is corruption, never a segment to remove.
    #[test]
    fn a_damaged_header_on_a_segment_with_frames_is_corruption() {
        let path = scratch("damaged-header");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"durable").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let mut damaged = std::fs::read(&segment).expect("the segment");
        damaged[HEADER_LEN] ^= 1;
        std::fs::write(&segment, &damaged).expect("damaged");
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert_eq!(std::fs::read(&segment).expect("kept"), damaged);
    }

    /// A roll that fails for want of space gives the handle up (decided for WP-1.2); opening the
    /// journal again removes the segment the roll had started, and appends go on from there.
    #[test]
    fn a_failed_roll_gives_the_handle_up_and_reopening_removes_what_it_started() {
        let path = scratch("failed-roll");
        let options = Options {
            max_frame: 1024,
            segment_bytes: 100,
        };
        let (mut journal, _) = open(&path, options);
        assert_eq!(journal.append(1, &[1u8; 40]).expect("appended"), 0);
        {
            let _full = permguard_core::fault::inject(
                path.join(segment_name(1)),
                permguard_core::fault::Fault::DiskFull { remaining_bytes: 0 },
            );
            assert!(matches!(
                journal
                    .append(1, &[2u8; 40])
                    .expect_err("no space for the roll"),
                StorageError::Io { .. }
            ));
        }
        assert!(!journal.readiness().is_ready());
        assert!(matches!(
            journal.append(1, b"x"),
            Err(StorageError::Poisoned)
        ));
        drop(journal);
        let (mut journal, _) = open(&path, options);
        assert!(
            !path.join(segment_name(1)).exists(),
            "the started segment is gone"
        );
        assert_eq!(payloads(&journal), [vec![1u8; 40]]);
        assert_eq!(journal.append(1, &[3u8; 40]).expect("rolled now"), 1);
    }

    /// A write that fails gives the handle up, and what it left is cut when the journal opens
    /// again. The debris is put there by hand: the fault shim's disk-full writes nothing.
    #[test]
    fn a_failed_write_gives_the_handle_up_and_its_debris_is_cut() {
        let path = scratch("partial-write");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        journal
            .current
            .write_all(&[0xab; 500])
            .expect("debris of a write that failed part-way");
        {
            let _full = permguard_core::fault::inject(
                path.join(segment_name(0)),
                permguard_core::fault::Fault::DiskFull { remaining_bytes: 0 },
            );
            assert!(journal.append(1, b"two").is_err());
        }
        assert!(matches!(
            journal.append(1, b"three"),
            Err(StorageError::Poisoned)
        ));
        drop(journal);
        let (mut journal, _) = open(&path, Options::default());
        assert_eq!(payloads(&journal), [b"one".to_vec()]);
        assert_eq!(journal.append(1, b"three").expect("appended"), 1);
    }

    #[test]
    fn a_last_segment_without_a_durable_header_is_removed() {
        let path = scratch("headerless");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"kept").expect("appended");
        drop(journal);
        std::fs::write(path.join(segment_name(1)), b"PGJRN").expect("a torn creation");
        let (journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery.removed_segment, Some(segment_name(1)));
        assert_eq!(journal.next_index(), 1);
    }

    #[test]
    fn a_newer_segment_version_is_refused_not_rewritten() {
        let path = scratch("newer");
        let mut head = format::header(format::JOURNAL_SEGMENT, 0);
        head[9] = 9;
        let mut bytes = head.to_vec();
        bytes.extend_from_slice(&format::checksum(&head));
        std::fs::write(path.join(segment_name(0)), &bytes).expect("a newer segment");
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("unsupported");
        assert!(matches!(refused, StorageError::Unsupported(_)), "{refused}");
        assert_eq!(
            std::fs::read(path.join(segment_name(0))).expect("kept"),
            bytes
        );
    }

    /// A failed flush is final: the append fails and every later append is refused.
    #[test]
    fn a_failed_flush_poisons_the_journal() {
        let path = scratch("fsync");
        let (mut journal, _) = open(&path, Options::default());
        {
            let _guard = permguard_core::fault::inject(&path, permguard_core::fault::Fault::Fsync);
            assert!(matches!(
                journal.append(1, b"x").expect_err("the flush failed"),
                StorageError::Durability { .. }
            ));
        }
        assert!(matches!(
            journal.append(1, b"y").expect_err("refused"),
            StorageError::Poisoned
        ));
    }

    fn exact_fsync(path: &std::path::Path) -> permguard_core::fault::Injected {
        permguard_core::fault::inject_exact(path, permguard_core::fault::Fault::Fsync)
    }

    fn payloads(journal: &Journal) -> Vec<Vec<u8>> {
        journal
            .frames()
            .expect("read")
            .into_iter()
            .map(|frame| frame.payload)
            .collect()
    }

    /// WP-1.2: a frame whose flush failed is never acknowledged, never handed out, and cut when the
    /// journal opens again, whatever the page cache still shows.
    #[test]
    fn a_frame_whose_flush_failed_is_cut_when_the_journal_opens_again() {
        let path = scratch("finality");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        let readiness = journal.readiness();
        {
            let _guard = exact_fsync(&path.join(segment_name(0)));
            assert!(matches!(
                journal.append(1, b"two").expect_err("the flush failed"),
                StorageError::Durability { .. }
            ));
        }
        assert!(!readiness.is_ready(), "not ready after a failed flush");
        assert!(matches!(
            journal.append(1, b"three").expect_err("refused"),
            StorageError::Poisoned
        ));
        assert!(
            matches!(journal.frames(), Err(StorageError::Poisoned)),
            "a handle given up hands nothing out"
        );
        assert!(path.join(FAILED).exists(), "the failure is recorded");
        drop(journal);

        let (mut journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery.cut_from, Some(1));
        assert_eq!(payloads(&journal), [b"one".to_vec()]);
        assert!(
            !path.join(FAILED).exists(),
            "the record goes once the cut is durable"
        );
        assert!(journal.readiness().is_ready(), "the new handle is ready");
        assert!(
            !readiness.is_ready(),
            "the old handle's readiness stays lost"
        );
        assert_eq!(journal.append(1, b"after").expect("appended"), 1);
    }

    /// A record found at open, as after a restart, cuts from its index across segments: every
    /// segment starting at or after it is removed, the one holding it truncated.
    #[test]
    fn a_failure_record_found_at_open_cuts_across_segments() {
        let path = scratch("record-restart");
        let options = Options {
            max_frame: 64,
            segment_bytes: 120,
        };
        let (mut journal, _) = open(&path, options);
        for index in 0..6u8 {
            journal.append(1, &[index; 20]).expect("appended");
        }
        assert_eq!(journal.segments().len(), 3, "two frames per segment");
        drop(journal);
        let dir = Dir::open(&path).expect("opened");
        replace_view(&dir, FAILED, format::VIEW, &3u64.to_be_bytes()).expect("a record");

        let (journal, recovery) = open(&path, options);
        assert_eq!(recovery.cut_from, Some(3));
        assert_eq!(
            payloads(&journal),
            [vec![0u8; 20], vec![1u8; 20], vec![2u8; 20]]
        );
        assert_eq!(journal.next_index(), 3);
        assert_eq!(journal.segments(), [segment_name(0), segment_name(2)]);
        assert!(!path.join(segment_name(4)).exists());
        drop(journal);
        let (journal, recovery) = open(&path, options);
        assert_eq!(recovery, Recovery::default(), "nothing left to repair");
        assert_eq!(journal.next_index(), 3);
    }

    /// A record naming a frame past the end says acknowledged frames are missing.
    #[test]
    fn a_failure_record_past_the_end_is_corruption() {
        let path = scratch("record-past");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        drop(journal);
        let dir = Dir::open(&path).expect("opened");
        replace_view(&dir, FAILED, format::VIEW, &2u64.to_be_bytes()).expect("a record");
        let refused = Journal::open(dir, Options::default()).expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
    }

    /// A failed flush whose record cannot be made durable either leaves the journal closed for
    /// this process.
    #[test]
    fn a_failure_that_cannot_be_recorded_keeps_the_journal_closed_in_this_process() {
        let path = scratch("unrecorded");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        {
            let _guard = permguard_core::fault::inject(&path, permguard_core::fault::Fault::Fsync);
            assert!(journal.append(1, b"two").is_err());
        }
        assert!(!journal.readiness().is_ready());
        drop(journal);
        let refused = Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect_err("refused");
        assert!(
            matches!(refused, StorageError::NotRecoverable(_)),
            "{refused}"
        );
    }

    /// With a record, nothing is changed before what is wrong is judged: a damaged acknowledged
    /// frame is corruption, not a torn tail to cut, and a segment of a newer format is refused
    /// before any cut. The bytes stay as they were.
    #[test]
    fn with_a_record_damage_and_newer_formats_are_refused_before_anything_changes() {
        // An acknowledged frame damaged, the frame the record names never written.
        let path = scratch("record-damaged-frame");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        journal.append(1, b"two").expect("appended");
        drop(journal);
        let segment = path.join(segment_name(0));
        let mut damaged = std::fs::read(&segment).expect("the segment");
        let last = damaged.len() - CHECKSUM_LEN - 1;
        damaged[last] ^= 1;
        std::fs::write(&segment, &damaged).expect("damaged");
        let dir = Dir::open(&path).expect("opened");
        replace_view(&dir, FAILED, format::VIEW, &2u64.to_be_bytes()).expect("a record");
        let refused = Journal::open(dir, Options::default()).expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert_eq!(
            std::fs::read(&segment).expect("kept"),
            damaged,
            "nothing cut"
        );

        // A segment of a newer version, and a record that would cut it.
        let path = scratch("record-newer");
        let mut head = format::header(format::JOURNAL_SEGMENT, 0);
        head[9] = 9;
        let mut bytes = head.to_vec();
        bytes.extend_from_slice(&format::checksum(&head));
        bytes.extend_from_slice(&encode_frame(1, 0, b"newer").expect("a frame"));
        std::fs::write(path.join(segment_name(0)), &bytes).expect("a newer segment");
        let dir = Dir::open(&path).expect("opened");
        replace_view(&dir, FAILED, format::VIEW, &0u64.to_be_bytes()).expect("a record");
        let refused = Journal::open(dir, Options::default()).expect_err("unsupported");
        assert!(matches!(refused, StorageError::Unsupported(_)), "{refused}");
        assert_eq!(
            std::fs::read(path.join(segment_name(0))).expect("kept"),
            bytes
        );
    }

    /// With a record, a damaged acknowledged frame in an earlier segment is found before the cut
    /// removes anything: the segment a failed roll started is still there afterwards.
    #[test]
    fn with_a_record_damage_is_found_before_any_segment_is_removed() {
        let path = scratch("record-damage-first");
        let options = Options {
            max_frame: 64,
            segment_bytes: 120,
        };
        let (mut journal, _) = open(&path, options);
        for index in 0..4u8 {
            journal.append(1, &[index; 20]).expect("appended");
        }
        drop(journal);
        let first = path.join(segment_name(0));
        let mut damaged = std::fs::read(&first).expect("the segment");
        damaged[SEGMENT_HEAD + FRAME_HEAD] ^= 1;
        std::fs::write(&first, &damaged).expect("damaged");
        let dir = Dir::open(&path).expect("opened");
        replace_view(&dir, FAILED, format::VIEW, &2u64.to_be_bytes()).expect("a record");
        let refused = Journal::open(dir, options).expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert!(path.join(segment_name(2)).exists(), "nothing was removed");
        assert_eq!(std::fs::read(&first).expect("kept"), damaged);
    }

    #[test]
    fn a_damaged_failure_record_is_corruption() {
        let path = scratch("record-damaged");
        drop(open(&path, Options::default()));
        let dir = Dir::open(&path).expect("opened");
        replace_view(&dir, FAILED, format::VIEW, b"abc").expect("a record");
        let refused = Journal::open(dir, Options::default()).expect_err("corruption");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
    }

    /// WP-1.2 step 4: a failed write or flush at every boundary of an append and a roll stops the
    /// handle; the journal reopens with exactly the acknowledged frames — or, where even the
    /// record's flush failed, stays closed for this process.
    #[test]
    fn a_failure_at_every_append_boundary_stops_the_handle_and_recovers_by_the_rule() {
        use permguard_core::fault::{self, Fault};

        let options = Options {
            max_frame: 64,
            segment_bytes: 100,
        };
        /// A boundary, whether it is reached through a roll, the fault there, and whether the
        /// record can still be written.
        type Boundary = (
            &'static str,
            bool,
            fn(&std::path::Path) -> fault::Injected,
            bool,
        );
        let boundaries: [Boundary; 7] = [
            (
                "frame write",
                false,
                |path| fault::inject(path.join(segment_name(0)), Fault::WriteFails),
                true,
            ),
            (
                "frame flush",
                false,
                |path| fault::inject_exact(path.join(segment_name(0)), Fault::Fsync),
                true,
            ),
            (
                "roll: old segment flush",
                true,
                |path| fault::inject_exact(path.join(segment_name(0)), Fault::Fsync),
                true,
            ),
            (
                "roll: header write",
                true,
                |path| fault::inject(path.join(segment_name(1)), Fault::WriteFails),
                true,
            ),
            (
                "roll: header flush",
                true,
                |path| fault::inject_exact(path.join(segment_name(1)), Fault::Fsync),
                true,
            ),
            (
                "roll: directory flush",
                true,
                |path| fault::inject_exact(path, Fault::Fsync),
                false,
            ),
            (
                // The directory's flush fails once: the record's own flush after it succeeds,
                // and recovery follows the rule.
                "roll: directory flush, once",
                true,
                |path| fault::inject_exact(path, Fault::FsyncTimes { remaining: 1 }),
                true,
            ),
        ];
        for (at, (boundary, rolls, arm, recorded)) in boundaries.into_iter().enumerate() {
            let path = scratch(&format!("boundary-{at}"));
            let (mut journal, _) = open(&path, options);
            if rolls {
                journal.append(1, &[0u8; 40]).expect("fills the segment");
            }
            let acknowledged = journal.next_index();
            {
                let _guard = arm(&path);
                assert!(journal.append(1, &[1u8; 40]).is_err(), "{boundary}");
            }
            assert!(!journal.readiness().is_ready(), "{boundary}");
            assert!(
                matches!(journal.append(1, b"x"), Err(StorageError::Poisoned)),
                "{boundary}: the handle cannot continue"
            );
            drop(journal);
            let reopened = Journal::open(Dir::open(&path).expect("opened"), options);
            if recorded {
                let (journal, _) = reopened.expect(boundary);
                assert_eq!(journal.next_index(), acknowledged, "{boundary}");
                let expected: Vec<Vec<u8>> = (0..acknowledged).map(|_| vec![0u8; 40]).collect();
                assert_eq!(
                    payloads(&journal),
                    expected,
                    "{boundary}: nothing else survives"
                );
                assert_eq!(journal.segments(), [segment_name(0)], "{boundary}");
                assert!(!path.join(FAILED).exists(), "{boundary}");
            } else {
                assert!(
                    matches!(reopened, Err(StorageError::NotRecoverable(_))),
                    "{boundary}"
                );
            }
        }
    }

    /// A repair at open whose flush fails is final too: the open fails and this process does not
    /// open the journal again, since what it would read back is the page cache.
    #[test]
    fn a_failed_flush_while_recovering_keeps_the_journal_closed_in_this_process() {
        use permguard_core::fault::{Fault, inject_exact};

        // (repair, how the directory is prepared, the fault armed while opening)
        type Repair = (
            &'static str,
            fn(&std::path::Path),
            fn(&std::path::Path) -> permguard_core::fault::Injected,
        );
        let repairs: [Repair; 4] = [
            (
                "the cut",
                |path| {
                    let (mut journal, _) = open(path, Options::default());
                    journal.append(1, b"one").expect("appended");
                    journal.append(1, b"two").expect("appended");
                    drop(journal);
                    let dir = Dir::open(path).expect("opened");
                    replace_view(&dir, FAILED, format::VIEW, &1u64.to_be_bytes())
                        .expect("a record");
                },
                |path| inject_exact(path.join(segment_name(0)), Fault::Fsync),
            ),
            (
                "the cut's removal of a segment",
                |path| {
                    let options = Options {
                        max_frame: 64,
                        segment_bytes: 0,
                    };
                    let (mut journal, _) = open(path, options);
                    journal.append(1, b"one").expect("appended");
                    journal.append(1, b"two").expect("appended");
                    drop(journal);
                    let dir = Dir::open(path).expect("opened");
                    replace_view(&dir, FAILED, format::VIEW, &1u64.to_be_bytes())
                        .expect("a record");
                },
                |path| inject_exact(path, Fault::FsyncTimes { remaining: 1 }),
            ),
            (
                "the record's removal",
                |path| {
                    let (mut journal, _) = open(path, Options::default());
                    journal.append(1, b"one").expect("appended");
                    drop(journal);
                    let dir = Dir::open(path).expect("opened");
                    replace_view(&dir, FAILED, format::VIEW, &1u64.to_be_bytes())
                        .expect("a record");
                },
                |path| inject_exact(path, Fault::Fsync),
            ),
            (
                "a torn tail's truncation",
                |path| {
                    let (mut journal, _) = open(path, Options::default());
                    journal.append(1, b"one").expect("appended");
                    drop(journal);
                    let segment = path.join(segment_name(0));
                    let mut torn = std::fs::read(&segment).expect("the segment");
                    torn.extend_from_slice(&[0x11; 7]);
                    std::fs::write(&segment, &torn).expect("torn");
                },
                |path| inject_exact(path.join(segment_name(0)), Fault::Fsync),
            ),
        ];
        for (at, (repair, prepare, arm)) in repairs.into_iter().enumerate() {
            let path = scratch(&format!("repair-{at}"));
            prepare(&path);
            {
                let _guard = arm(&path);
                assert!(
                    matches!(
                        Journal::open(Dir::open(&path).expect("opened"), Options::default()),
                        Err(StorageError::Durability { .. })
                    ),
                    "{repair}"
                );
            }
            if repair.starts_with("the cut") {
                // The open stopped at the cut, before it went on to remove the record.
                assert!(path.join(FAILED).exists(), "{repair}: the record stays");
            }
            assert!(
                matches!(
                    Journal::open(Dir::open(&path).expect("opened"), Options::default()),
                    Err(StorageError::NotRecoverable(_))
                ),
                "{repair}: not opened again in this process"
            );
        }
    }

    /// The contract suite other crates run against their journals holds for this one.
    #[test]
    fn the_journal_keeps_the_torn_tail_contract() {
        crate::storage::testing::torn_tail_contract(&scratch("contract"));
    }

    #[test]
    fn a_frame_over_the_bound_is_refused() {
        let path = scratch("bound");
        let (mut journal, _) = open(
            &path,
            Options {
                max_frame: 4,
                segment_bytes: DEFAULT_SEGMENT_BYTES,
            },
        );
        assert!(matches!(
            journal.append(1, b"12345"),
            Err(StorageError::TooLarge(_))
        ));
    }
}
