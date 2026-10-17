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
//! them. A journal keeps two other files: a failure record, [`FAILED`], present only between a
//! failed write or flush and the recovery that follows it, and [`BASE`], present once a prefix was
//! deleted, naming the first frame still held.
//!
//! # Prefix deletion (WP-5.6a)
//!
//! [`Journal::drop_prefix`] removes the whole segments every frame of which is below an index,
//! never the segment being written. `BASE`, a view holding the deterministic CBOR map
//! `{1 first_index, 2 claim}`, names the first frame of the first segment kept and the claim
//! generation of the writer that deleted the prefix; it is written and flushed before the first
//! removal, and each removal is a tombstone deletion. A crash after `BASE` leaves segments below
//! it, which opening removes; a crash before it leaves the journal as it was. Frame indexes are
//! never reused: the frames kept keep theirs.
//!
//! Opening decides before it changes anything. No segment starting exactly at `BASE` (0 without
//! one) means acknowledged frames are missing, since a deletion never removes the segment being
//! written. Where segments below `BASE` remain, its claim generation is judged like a failure
//! record's, so a superseded writer's unfinished deletion is refused rather than completed. Only
//! then are the tombstones and the segments below `BASE` removed. A deletion a superseded writer
//! finished with its own handle is the volume's `LOCK`'s to prevent, as its appends are.
//!
//! # Recovery, at open
//!
//! | What is found                                                         | What happens                                       |
//! | --------------------------------------------------------------------- | -------------------------------------------------- |
//! | in the last segment, a damaged frame whose own extent reaches the end | truncated: a torn write                            |
//! | in the last segment, an incomplete frame header, or zeros to the end  | truncated: a torn write                            |
//! | with no record, a last segment of at most 48 bytes, header not whole  | removed: it held no frame                          |
//! | a failure record naming frame `n`                                     | frames from `n` cut, then the record removed       |
//! | with a record, an acknowledged frame not whole, or a segment missing  | [`StorageError::Corruption`], nothing changed      |
//! | a damaged frame with bytes beyond its own extent                      | [`StorageError::Corruption`]                       |
//! | a damaged frame declaring more than the format's frame limit          | [`StorageError::Corruption`]                       |
//! | a damaged header on a segment holding frames                          | [`StorageError::Corruption`]                       |
//! | an earlier segment without a whole header and first frame             | [`StorageError::Corruption`]                       |
//! | a damaged failure record, or one naming a frame past the end          | [`StorageError::Corruption`]                       |
//! | a failed flush of an earlier repair, in this process                  | [`StorageError::NotRecoverable`]                   |
//! | another magic, a newer version, an unknown flag                       | [`StorageError::Unsupported`]                      |
//! | a frame's claim generation below one before it                        | [`StorageError::StaleWriter`], nothing changed     |
//! | a frame's claim generation above the volume's claim                   | [`StorageError::ClaimBehindData`], nothing changed |
//! | no segment starting at the frame `BASE` names (0 without one)         | [`StorageError::Corruption`], nothing changed      |
//! | a `BASE` that does not decode                                         | [`StorageError::Corruption`], nothing changed      |
//! | segments below `BASE`, its generation below a frame kept              | [`StorageError::StaleWriter`], nothing changed     |
//! | segments below `BASE`, its generation above the volume's claim        | [`StorageError::ClaimBehindData`], nothing changed |
//! | segments below `BASE`, or tombstones, a deletion left                 | removed: the deletion finished                     |
//!
//! Opening is bounded: it reads the last segment whole, and of every earlier segment only the
//! name, the header and the first frame. A gap between earlier segments, a torn or damaged frame
//! inside one, or a claim generation that decreases inside one is found by deep verification
//! ([`crate::storage::verify`]), which reads every frame and repairs nothing.
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
//! journal open; the volume's `LOCK`, which [`crate::storage::volume::Volume::claim`] takes and
//! holds, is what guarantees that on one mount, and a caller opens a journal only under it.
//!
//! # Claim generations
//!
//! Every frame carries the claim generation of [`Options::claim`], the one the writer's
//! [`Volume`](crate::storage::volume::Volume) holds. Opening judges every frame, in index order and
//! before any repair, against the volume's current claim: generations equal to it, or below it and
//! never decreasing, are history; a decrease is a writer whose claim was superseded, and a
//! generation above the claim is a claim behind the data. Either refuses the open with its own
//! error and code, and nothing is rewritten to make the sequence fit. A failure record carries its
//! writer's generation and is judged the same way before its cut, against every frame there, so a
//! superseded writer's record cannot cut the new owner's acknowledged frames.
//!
//! # Appends, and a failed flush
//!
//! An append writes one frame and flushes it with `fdatasync` before it returns.
//!
//! A failed write or flush is final (WP-1.2). The append fails, the handle refuses every later
//! append and read ([`StorageError::Poisoned`]) and its [`Readiness`] turns not ready. Before the
//! error returns, the journal writes and flushes a failure record, [`FAILED`], a view whose body is
//! the index of the first frame that was not acknowledged and the writer's claim generation.
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

use permguard_objects::cbor::{self, Value};

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
///
/// `claim` is the volume claim generation the writer holds ([`crate::storage::volume`]): every
/// appended frame carries it, and opening judges the frames already there against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub max_frame: u32,
    pub segment_bytes: u64,
    pub claim: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_frame: DEFAULT_MAX_FRAME,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
            claim: crate::storage::volume::UNCLAIMED,
        }
    }
}

/// The failure record's name in a journal's directory.
pub const FAILED: &str = "FAILED";

/// The name of the view naming the first frame a journal still holds, once a prefix was deleted.
pub const BASE: &str = "BASE";

/// The body of `BASE`: the deterministic CBOR map `{1 first_index, 2 claim}`, the claim being the
/// generation of the writer that deleted the prefix.
pub fn encode_base(first_index: u64, claim: u64) -> Result<Vec<u8>> {
    let signed = |value: u64| {
        i64::try_from(value)
            .map_err(|_| StorageError::TooLarge(format!("{value} is past the signed 64-bit range")))
    };
    cbor::encode(&Value::Map(vec![
        (Value::Int(1), Value::Int(signed(first_index)?)),
        (Value::Int(2), Value::Int(signed(claim)?)),
    ]))
    .map_err(|error| StorageError::TooLarge(error.to_string()))
}

/// The `(first frame index, claim generation)` a body of `BASE` names; anything but
/// `{1 first_index, 2 claim}` is refused.
pub fn decode_base(body: &[u8]) -> Result<(u64, u64)> {
    let refused = |what: &str| StorageError::Corruption(format!("`{BASE}` {what}"));
    let value = cbor::decode_canonical(body).map_err(|error| refused(&error.to_string()))?;
    let Value::Map(pairs) = value else {
        return Err(refused("is not a map"));
    };
    match pairs.as_slice() {
        [
            (Value::Int(1), Value::Int(first)),
            (Value::Int(2), Value::Int(claim)),
        ] => Ok((
            u64::try_from(*first).map_err(|_| refused("names a negative frame index"))?,
            u64::try_from(*claim).map_err(|_| refused("names a negative claim generation"))?,
        )),
        _ => Err(refused(
            "holds other labels than 1, the first frame index, and 2, the claim generation",
        )),
    }
}

/// What `dir`'s `BASE` names, `(first index, claim generation)`; `None` without one.
pub(crate) fn base_of(dir: &Dir) -> Result<Option<(u64, u64)>> {
    read_view(dir, BASE, format::VIEW)?
        .map(|body| {
            decode_base(&body).map_err(|error| {
                StorageError::Corruption(format!("in {}: {error}", dir.path().display()))
            })
        })
        .transpose()
}

/// Judges the claim generation of a `BASE` whose deletion is unfinished, as a failure record's is
/// judged, before anything below it is removed: above the volume's claim is a claim behind the
/// data, and below a frame the journal keeps is a superseded writer's, whose deletion the new
/// owner must not complete. Every kept segment is read whole, as for a record: this runs only
/// after a crash interrupted a deletion. A segment that does not read is left to the open.
fn judge_base(
    dir: &Dir,
    kept: &[(u64, String)],
    base: u64,
    generation: u64,
    claim: u64,
) -> Result<()> {
    if generation > claim {
        return Err(StorageError::ClaimBehindData {
            journal: dir.path().display().to_string(),
            index: base,
            generation,
            claim,
        });
    }
    for (first, name) in kept {
        let bytes = dir.read(name)?.unwrap_or_default();
        let Ok(Scan::Whole { frames, .. } | Scan::Torn { frames, .. }) = scan(&bytes, *first, name)
        else {
            continue;
        };
        if let Some(frame) = frames.iter().find(|frame| frame.claim > generation) {
            return Err(StorageError::StaleWriter {
                journal: dir.path().display().to_string(),
                index: base,
                generation,
                after: frame.claim,
            });
        }
    }
    Ok(())
}

/// The journals whose failure record could not be made durable, by directory identity: this
/// process does not open them again.
static UNRECORDED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Whether a journal handle is ready: true from open, false for good once the handle is given up
/// (a failed write or flush, or any step of a roll that fails). The journal opened again to
/// recover is a new handle with its own readiness, which a watcher takes in place of the old.
/// Cloned freely, so the Host lifecycle can watch a journal it does not hold. A
/// [`Quota`](crate::storage::quota::Quota) answers one too, which, unlike a journal's, turns true
/// again once space returns.
#[derive(Debug, Clone)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    /// Whether the journal accepts appends.
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn lose(&self) {
        self.0.store(false, Ordering::Release);
    }

    pub(crate) fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }
}

/// One frame read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Its position in the journal, from zero.
    pub index: u64,
    pub kind: u16,
    /// The volume claim generation its writer held; zero for a frame written without a claim.
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
    /// Segments below `BASE` a crash left during a prefix deletion, removed (WP-5.6a).
    pub dropped_segments: Vec<String>,
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
    /// The quota every append reserves from before it writes, once one is attached.
    scope: Option<crate::storage::quota::Scope>,
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

/// Judges the claim generations of `frames`, in index order, against the volume's `claim`.
///
/// | Generation                                        | Meaning                                   |
/// | ------------------------------------------------- | ----------------------------------------- |
/// | equal to the claim                                | the current writer's                      |
/// | below the claim, never below a frame before it    | history from an earlier owner             |
/// | below a frame before it                           | [`StorageError::StaleWriter`]             |
/// | above the claim                                   | [`StorageError::ClaimBehindData`]         |
fn judge_claims(dir: &Dir, frames: &[Frame], claim: u64, highest: &mut u64) -> Result<()> {
    for frame in frames {
        if frame.claim > claim {
            return Err(StorageError::ClaimBehindData {
                journal: dir.path().display().to_string(),
                index: frame.index,
                generation: frame.claim,
                claim,
            });
        }
        if frame.claim < *highest {
            return Err(StorageError::StaleWriter {
                journal: dir.path().display().to_string(),
                index: frame.index,
                generation: frame.claim,
                after: *highest,
            });
        }
        *highest = frame.claim;
    }

    Ok(())
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
        // A prefix deletion a crash interrupted (WP-5.6a), decided before anything changes: a
        // segment starts exactly at `BASE`, since a deletion never removes the segment being
        // written, and the writer of `BASE` holds the claim, judged like a failure record's.
        let (base, base_claim) = base_of(&dir)?.unwrap_or((0, crate::storage::volume::UNCLAIMED));
        let mut segments = segment_names(&dir)?;
        if (base > 0 || !segments.is_empty()) && !segments.iter().any(|(first, _)| *first == base) {
            return Err(StorageError::Corruption(format!(
                "no segment of {} starts at frame {base}, the first the journal holds: \
                 acknowledged frames are missing",
                dir.path().display()
            )));
        }
        let below: Vec<String> = segments
            .iter()
            .take_while(|(first, _)| *first < base)
            .map(|(_, name)| name.clone())
            .collect();
        if !below.is_empty() {
            judge_base(
                &dir,
                &segments[below.len()..],
                base,
                base_claim,
                options.claim,
            )?;
        }
        // Then finished as it would have been: the tombstones it wrote, and the segments below
        // `BASE` it had not reached, with one flush; `BASE` is durable, so no tombstone is needed.
        super::tombstone::complete(&dir)?;
        for name in &below {
            dir.unlink(name)?;
        }
        if !below.is_empty() {
            dir.sync()?;
            point("prefix.recovered");
        }
        segments.drain(..below.len());
        recovery.dropped_segments = below;

        // What a failure record names is cut before anything is judged: those bytes were never
        // acknowledged, whatever shape a failed write left them in.
        let record = failure_record(&dir)?;
        if let Some((first_unacknowledged, generation)) = record {
            // A segment of a format this build does not read is refused before anything changes.
            for (_, name) in &segments {
                refuse_newer(&dir, name)?;
            }
            // The record is judged before its cut, like a frame against every frame there: a
            // superseded writer's record would otherwise cut the new owner's acknowledged frames.
            judge_record(
                &dir,
                &segments,
                first_unacknowledged,
                generation,
                options.claim,
            )?;
            cut_from(&dir, &mut segments, first_unacknowledged, base)?;
            recovery.cut_from = Some(first_unacknowledged);
        }

        // Bounded at startup (WP-1.6): of every segment but the last, only the name, the header
        // and the first frame are read, and the claim generations judged on that frame. A gap, a
        // torn frame or a decreasing generation inside an older segment is deep verification's
        // to find (`storage::verify`).
        // The highest claim generation a frame so far carried: generations never decrease.
        let mut highest = crate::storage::volume::UNCLAIMED;
        let count = segments.len();
        for (first, name) in segments.iter().take(count.saturating_sub(1)) {
            let frame = first_frame(&dir, name, *first)?;
            judge_claims(
                &dir,
                std::slice::from_ref(&frame),
                options.claim,
                &mut highest,
            )?;
        }

        // The last segment, the open tail, is read whole. A roll that crashed before its new
        // segment's header was durable leaves a last segment holding no frame; it is removed, once,
        // and the segment before it becomes the tail, read whole in turn.
        let mut expected = base;
        let mut tail: Option<(u64, String, usize)> = None;
        let mut removable = record.is_none();
        while let Some((first, name)) = segments.last().cloned() {
            let bytes = dir.read(&name)?.unwrap_or_default();
            if !head_is_whole(&bytes)? {
                // After a record's cut, nothing the failure left remains: a segment without a
                // whole header holds acknowledged frames, and is not removed.
                if removable && bytes.len() <= SEGMENT_HEAD {
                    // Frames are written only after a header is durable: it holds none.
                    dir.unlink(&name)?;
                    dir.sync()?;
                    segments.pop();
                    recovery.removed_segment = Some(name);
                    removable = false;
                    expected = first;
                    continue;
                }
                return Err(StorageError::Corruption(format!(
                    "segment `{name}` has a damaged header and holds frames or segments follow it"
                )));
            }
            let scanned = scan(&bytes, first, &name)?;
            // Before the tail is cut, or anything else changes: a frame no claim allows refuses
            // the open, and nothing is rewritten to make the sequence fit (H-05).
            let (Scan::Whole { frames, .. } | Scan::Torn { frames, .. }) = &scanned;
            judge_claims(&dir, frames, options.claim, &mut highest)?;
            match scanned {
                Scan::Whole { frames, end } => {
                    expected = first + frames.len() as u64;
                    tail = Some((first, name, end));
                }
                // After a record's cut, or once a later segment was removed, a torn frame is
                // damage to an acknowledged one, and is not cut.
                Scan::Torn { frames, at } if removable => {
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
            break;
        }

        if let Some((first_unacknowledged, _)) = record {
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
                scope: None,
            },
            recovery,
        ))
    }

    /// The index the next appended frame will have.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// The index of the first frame the journal holds: 0 unless a prefix was deleted.
    pub fn first_index(&self) -> u64 {
        self.segments
            .first()
            .map_or(self.next_index, |(first, _)| *first)
    }

    /// Deletes the whole segments every frame of which is below `below`, never the segment being
    /// written (WP-5.6a), and answers the first frame index the journal then holds.
    ///
    /// `BASE` is written and flushed first, then each segment goes through a tombstone, charged to
    /// `maintenance` when given, the reserve garbage collection runs on (`BASE` itself replaces a
    /// view and is not charged). A crash after `BASE` leaves segments below it, which the next open
    /// removes; a crash before it leaves the journal as it was.
    ///
    /// A failed write or flush here does not give the handle up, unlike an append's: it touches no
    /// acknowledged frame, and either outcome is one the next open accepts — `BASE` not durable and
    /// nothing removed, or `BASE` durable and some segments below it left. The handle reads from
    /// `BASE` once it is written, whether every removal followed or not.
    pub fn drop_prefix(
        &mut self,
        below: u64,
        maintenance: Option<&crate::storage::quota::Scope>,
    ) -> Result<u64> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        // A segment is wholly below `below` when the one after it starts at or below it: the
        // segment being written has none after it, and is never removed.
        let count = self
            .segments
            .windows(2)
            .take_while(|pair| pair[1].0 <= below)
            .count();
        if count == 0 {
            return Ok(self.first_index());
        }
        let base = self.segments[count].0;
        replace_view(
            &self.dir,
            BASE,
            format::VIEW,
            &encode_base(base, self.options.claim)?,
        )?;
        point("prefix.base_written");
        let dropped: Vec<String> = self.segments.drain(..count).map(|(_, name)| name).collect();
        for name in &dropped {
            match maintenance {
                Some(scope) => super::tombstone::delete_in(scope, &self.dir, name)?,
                None => super::tombstone::delete(&self.dir, name)?,
            }
        }
        point("prefix.segments_removed");
        Ok(base)
    }

    /// The segments, oldest first.
    pub fn segments(&self) -> Vec<String> {
        self.segments.iter().map(|(_, name)| name.clone()).collect()
    }

    /// Charges every later append to `scope`: each reserves its frame, and a segment's head and file
    /// when it rolls, before it writes, and the quota's readiness keeps the largest of them above
    /// the floor. A refused reservation writes nothing and leaves the handle as it was.
    pub fn charge(&mut self, scope: crate::storage::quota::Scope) -> Result<()> {
        let largest =
            u64::from(self.options.max_frame) + (FRAME_HEAD + CHECKSUM_LEN + SEGMENT_HEAD) as u64;
        scope.quota().note_largest_write(largest)?;
        self.scope = Some(scope);

        Ok(())
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
        let bytes = encode_frame(kind, self.options.claim, payload)?;
        let rolls = self.current_len >= self.options.segment_bytes
            && self.current_len > SEGMENT_HEAD as u64;
        // Reserved before anything is written: a refusal leaves the journal exactly as it was.
        let reservation = match &self.scope {
            Some(scope) => Some(scope.reserve(
                bytes.len() as u64 + if rolls { SEGMENT_HEAD as u64 } else { 0 },
                u64::from(rolls),
            )?),
            None => None,
        };
        if rolls {
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
        if let Some(reservation) = reservation {
            reservation.land(
                bytes.len() as u64 + if rolls { SEGMENT_HEAD as u64 } else { 0 },
                u64::from(rolls),
            );
        }
        let index = self.next_index;
        self.next_index += 1;
        self.current_len += bytes.len() as u64;
        Ok(index)
    }

    /// Every frame the journal holds, oldest first: from `BASE` once a prefix was deleted. A handle
    /// given up answers nothing: what it would read is the page cache, which may hold a frame that
    /// was never acknowledged.
    pub fn frames(&self) -> Result<Vec<Frame>> {
        self.frames_from(0)
    }

    /// The frames from `index` on, oldest first: a segment wholly before it is not read (WP-5.2).
    /// Below the first frame the journal holds (see [`Journal::first_index`]) there is nothing to
    /// read: the answer starts there.
    pub fn frames_from(&self, index: u64) -> Result<Vec<Frame>> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        let mut all = Vec::new();
        for (at, (first, name)) in self.segments.iter().enumerate() {
            if self
                .segments
                .get(at + 1)
                .is_some_and(|(next, _)| *next <= index)
            {
                continue;
            }
            let bytes = self.dir.read(name)?.unwrap_or_default();
            match scan(&bytes, *first, name)? {
                Scan::Whole { frames, .. } => {
                    all.extend(frames.into_iter().filter(|frame| frame.index >= index));
                }
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
        let mut body = first_unacknowledged.to_be_bytes().to_vec();
        body.extend_from_slice(&self.options.claim.to_be_bytes());
        let recorded = replace_view(&self.dir, FAILED, format::VIEW, &body);
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

/// The index a failure record names and the claim generation of the writer that failed, when
/// there is one; a record of the first format, the index alone, is generation 0.
fn failure_record(dir: &Dir) -> Result<Option<(u64, u64)>> {
    let Some(body) = read_view(dir, FAILED, format::VIEW)? else {
        return Ok(None);
    };
    let word = |at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&body[at..at + 8]);
        u64::from_be_bytes(bytes)
    };
    match body.len() {
        8 => Ok(Some((word(0), crate::storage::volume::UNCLAIMED))),
        16 => Ok(Some((word(0), word(8)))),
        held => Err(StorageError::Corruption(format!(
            "the failure record in {} holds {held} bytes, not an index and a generation",
            dir.path().display()
        ))),
    }
}

/// Every segment in `dir`, `(first frame index, name)`, in order.
pub(crate) fn segment_names(dir: &Dir) -> Result<Vec<(u64, String)>> {
    let mut segments: Vec<(u64, String)> = dir
        .names()?
        .into_iter()
        .filter_map(|name| segment_first(&name).map(|first| first.map(|first| (first, name))))
        .collect::<Result<_>>()?;
    segments.sort();
    Ok(segments)
}

/// Deep verification of one segment's bytes: how many frames it holds and each frame's
/// `(index, claim generation)`, or what is wrong with it. A torn tail is accepted only in the last
/// segment, where an append may be under way.
pub(crate) fn verify_segment(
    bytes: &[u8],
    first: u64,
    name: &str,
    last: bool,
) -> std::result::Result<(u64, Vec<(u64, u64)>), String> {
    match head_is_whole(bytes) {
        Ok(true) => {}
        Ok(false) if last && bytes.len() <= SEGMENT_HEAD => return Ok((0, Vec::new())),
        Ok(false) => return Err("the segment's header is damaged".to_owned()),
        Err(error) => return Err(error.to_string()),
    }
    let frames = match scan(bytes, first, name) {
        Ok(Scan::Whole { frames, .. }) => frames,
        Ok(Scan::Torn { frames, .. }) if last => frames,
        Ok(Scan::Torn { frames, at }) => {
            return Err(format!(
                "frame {} at byte {at} is torn or damaged, and segments follow it",
                first + frames.len() as u64
            ));
        }
        Err(error) => return Err(error.to_string()),
    };
    let claims = frames
        .iter()
        .map(|frame| (frame.index, frame.claim))
        .collect();
    Ok((frames.len() as u64, claims))
}

/// The first frame of the segment `name`, read without reading the rest of it: corruption when the
/// header is not whole or no whole frame follows it, since a segment rolls only once it holds one.
fn first_frame(dir: &Dir, name: &str, first: u64) -> Result<Frame> {
    use std::io::Read as _;
    let path = dir.child_path(name);
    let corrupt = || {
        StorageError::Corruption(format!(
            "segment `{name}` has no whole header and first frame, and segments follow it"
        ))
    };
    let Some(file) = dir.open_read(name)? else {
        return Err(corrupt());
    };
    let mut prefix = Vec::new();
    file.take((SEGMENT_HEAD + FRAME_HEAD) as u64)
        .read_to_end(&mut prefix)
        .map_err(io(format!("reading {}", path.display())))?;
    if !head_is_whole(&prefix)? || prefix.len() < SEGMENT_HEAD + FRAME_HEAD {
        return Err(corrupt());
    }
    let head = &prefix[SEGMENT_HEAD..];
    let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if length > FRAME_LIMIT {
        return Err(corrupt());
    }
    let extent = (SEGMENT_HEAD + FRAME_HEAD + length as usize + CHECKSUM_LEN) as u64;
    let Some(file) = dir.open_read(name)? else {
        return Err(corrupt());
    };
    let mut bytes = Vec::new();
    file.take(extent)
        .read_to_end(&mut bytes)
        .map_err(io(format!("reading {}", path.display())))?;
    match scan(&bytes, first, name)? {
        Scan::Whole { mut frames, .. } if !frames.is_empty() => Ok(frames.swap_remove(0)),
        _ => Err(corrupt()),
    }
}

/// Judges a failure record's generation against the claim and against every frame the journal
/// holds: a record below the highest frame is a superseded writer's, and one above the claim is a
/// claim behind the data. A segment that does not read is left to the cut to judge.
///
/// Every segment is read whole here, unlike the bounded open: a record exists only after a failed
/// write, its cut reads the segments it keeps anyway, and a superseded writer's generation hidden
/// inside an older segment must not let its record cut the new owner's acknowledged frames.
fn judge_record(
    dir: &Dir,
    segments: &[(u64, String)],
    index: u64,
    generation: u64,
    claim: u64,
) -> Result<()> {
    let journal = || dir.path().display().to_string();
    if generation > claim {
        return Err(StorageError::ClaimBehindData {
            journal: journal(),
            index,
            generation,
            claim,
        });
    }
    let mut highest = crate::storage::volume::UNCLAIMED;
    for (first, name) in segments {
        let bytes = dir.read(name)?.unwrap_or_default();
        if !head_is_whole(&bytes).unwrap_or(false) {
            continue;
        }
        if let Ok(Scan::Whole { frames, .. } | Scan::Torn { frames, .. }) =
            scan(&bytes, *first, name)
        {
            highest = frames
                .iter()
                .map(|frame| frame.claim)
                .fold(highest, u64::max);
        }
    }
    if generation < highest {
        return Err(StorageError::StaleWriter {
            journal: journal(),
            index,
            generation,
            after: highest,
        });
    }

    Ok(())
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
fn cut_from(dir: &Dir, segments: &mut Vec<(u64, String)>, index: u64, base: u64) -> Result<()> {
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
    if kept.is_empty() && index > base {
        return Err(damaged("no segment holds the frames before it"));
    }
    let mut expected = base;
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

    fn claimed(claim: u64) -> Options {
        Options {
            claim,
            ..Options::default()
        }
    }

    /// The whole journal directory, name by name, to prove a refused open changed nothing.
    fn contents(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut all: Vec<(String, Vec<u8>)> = std::fs::read_dir(path)
            .expect("listed")
            .map(|entry| {
                let entry = entry.expect("entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).expect("read"),
                )
            })
            .collect();
        all.sort();
        all
    }

    /// Appends `frame` to the last segment behind the journal's back: what a second writer does.
    fn append_behind(path: &std::path::Path, frame: &[u8]) {
        use std::io::Write as _;
        let mut segments: Vec<_> = std::fs::read_dir(path)
            .expect("listed")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "pgj"))
            .collect();
        segments.sort();
        let last = segments.last().expect("a segment");
        std::fs::OpenOptions::new()
            .append(true)
            .open(last)
            .expect("opened")
            .write_all(frame)
            .expect("appended");
    }

    #[test]
    fn frames_carry_the_claim_and_monotonic_history_recovers() {
        let path = scratch("claims");
        for claim in [0, 1, 1, 4] {
            let (mut journal, _) = open(&path, claimed(claim));
            journal.append(1, b"x").expect("appended");
        }
        let (journal, recovery) = open(&path, claimed(4));
        assert_eq!(recovery, Recovery::default());
        let generations: Vec<u64> = journal
            .frames()
            .expect("read")
            .iter()
            .map(|frame| frame.claim)
            .collect();
        assert_eq!(generations, vec![0, 1, 1, 4], "earlier owners' history");

        // A later owner reads the same history as legitimate.
        open(&path, claimed(9));
    }

    #[test]
    fn a_generation_that_decreases_is_a_stale_writer_and_nothing_is_cut() {
        let path = scratch("stale");
        for claim in [2, 3] {
            let (mut journal, _) = open(&path, claimed(claim));
            journal.append(1, b"owner").expect("appended");
        }
        // The superseded writer of generation 2 appends after the takeover, and dies mid-frame.
        append_behind(&path, &encode_frame(1, 2, b"stale").expect("encoded"));
        append_behind(&path, &encode_frame(1, 2, b"torn").expect("encoded")[..9]);
        let before = contents(&path);

        let refused = Journal::open(Dir::open(&path).expect("opened"), claimed(3))
            .expect_err("a stale writer");
        match &refused {
            StorageError::StaleWriter {
                index,
                generation,
                after,
                ..
            } => assert_eq!((*index, *generation, *after), (2, 2, 3)),
            other => panic!("{other}"),
        }
        assert_eq!(
            refused.code(),
            Some(permguard_core::codes::storage::STALE_WRITER)
        );
        assert_eq!(contents(&path), before, "the torn tail is not cut either");
    }

    #[test]
    fn a_generation_above_the_claim_is_a_claim_behind_the_data() {
        let path = scratch("behind");
        let (mut journal, _) = open(&path, claimed(5));
        journal.append(1, b"x").expect("appended");
        drop(journal);
        let before = contents(&path);

        // The claim was rolled back to 4 after a writer of generation 5 wrote.
        let refused = Journal::open(Dir::open(&path).expect("opened"), claimed(4))
            .expect_err("behind the data");
        match &refused {
            StorageError::ClaimBehindData {
                index,
                generation,
                claim,
                ..
            } => assert_eq!((*index, *generation, *claim), (0, 5, 4)),
            other => panic!("{other}"),
        }
        assert_eq!(
            refused.code(),
            Some(permguard_core::codes::storage::CLAIM_BEHIND_DATA)
        );
        assert_ne!(
            refused.code(),
            Some(permguard_core::codes::storage::STALE_WRITER)
        );
        assert_eq!(contents(&path), before, "nothing is rewritten to fit");
    }

    fn record(path: &std::path::Path, index: u64, generation: u64) {
        let mut body = index.to_be_bytes().to_vec();
        body.extend_from_slice(&generation.to_be_bytes());
        replace_view(
            &Dir::open(path).expect("opened"),
            FAILED,
            format::VIEW,
            &body,
        )
        .expect("a record");
    }

    #[test]
    fn a_superseded_writers_failure_record_cuts_nothing() {
        let path = scratch("stale-record");
        for claim in [2, 2, 3, 3] {
            let (mut journal, _) = open(&path, claimed(claim));
            journal.append(1, b"x").expect("appended");
        }
        // The writer of generation 2, unfenced, fails at the index it believed next.
        record(&path, 2, 2);
        let before = contents(&path);

        let refused = Journal::open(Dir::open(&path).expect("opened"), claimed(3))
            .expect_err("a stale writer's record");
        match &refused {
            StorageError::StaleWriter {
                index,
                generation,
                after,
                ..
            } => assert_eq!((*index, *generation, *after), (2, 2, 3)),
            other => panic!("{other}"),
        }
        assert_eq!(contents(&path), before, "the new owner's frames stay");

        // A record above the claim is a claim behind the data, and cuts nothing either.
        record(&path, 3, 4);
        let refused = Journal::open(Dir::open(&path).expect("opened"), claimed(3))
            .expect_err("behind the data");
        assert!(
            matches!(
                refused,
                StorageError::ClaimBehindData {
                    generation: 4,
                    claim: 3,
                    ..
                }
            ),
            "{refused}"
        );
    }

    #[test]
    fn the_current_writers_failure_record_cuts_as_before() {
        let path = scratch("own-record");
        let (mut journal, _) = open(&path, claimed(3));
        for _ in 0..3 {
            journal.append(1, b"x").expect("appended");
        }
        drop(journal);
        record(&path, 2, 3);

        let (journal, recovery) = open(&path, claimed(3));
        assert_eq!(recovery.cut_from, Some(2));
        assert_eq!(journal.next_index(), 2);
        assert!(!path.join(FAILED).exists());
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

    /// WP-5.2: the frames from an index are those `frames` answers from it, across segments, and a
    /// segment wholly before it is not read.
    #[test]
    fn frames_from_an_index_skip_the_segments_before_it() {
        let path = scratch("from");
        let options = Options {
            segment_bytes: 100,
            ..Options::default()
        };
        let (mut journal, _) = open(&path, options);
        for n in 0..12u8 {
            journal.append(1, &[n; 40]).expect("appended");
        }
        assert!(journal.segments().len() > 3, "the segments rolled");
        let all = journal.frames().expect("read");
        for from in [0, 1, 5, 11, 12, 40] {
            assert_eq!(
                journal.frames_from(from).expect("read"),
                all.iter()
                    .filter(|frame| frame.index >= from)
                    .cloned()
                    .collect::<Vec<_>>(),
                "from {from}"
            );
        }
        // A segment wholly before the index is not read: removing it changes nothing from there.
        std::fs::remove_file(path.join(segment_name(0))).expect("removed");
        let later = journal.segments()[2].clone();
        let first_later = all
            .iter()
            .map(|frame| frame.index)
            .find(|index| segment_name(*index) == later)
            .expect("the third segment's first frame");
        assert_eq!(
            journal.frames_from(first_later).expect("read").len() as u64,
            12 - first_later
        );
        assert!(
            journal.frames().expect("read").len() < all.len(),
            "the whole journal reads the removed one"
        );
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
            ..Options::default()
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
            ..Options::default()
        };
        let (journal, recovery) = open(&path, lower);
        assert_eq!(recovery.truncated_bytes, 600);
        assert_eq!(journal.frames().expect("read").len(), 1);
        drop(journal);
        let over = Options {
            max_frame: FRAME_LIMIT + 1,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
            ..Options::default()
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
            ..Options::default()
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
            ..Options::default()
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
            ..Options::default()
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
            ..Options::default()
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
            ..Options::default()
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
            ..Options::default()
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
                        ..Options::default()
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
                ..Options::default()
            },
        );
        assert!(matches!(
            journal.append(1, b"12345"),
            Err(StorageError::TooLarge(_))
        ));
    }
    /// Two 40-byte frames per segment: 48 bytes of head and 86 per frame pass 200 at the second,
    /// so the third rolls.
    fn rolling() -> Options {
        Options {
            max_frame: 1024,
            segment_bytes: 200,
            ..Options::default()
        }
    }

    /// `frames` frames, each its index repeated: segments start at 0, 2, 4 and so on.
    fn filled(path: &std::path::Path, frames: u8) -> Journal {
        let (mut journal, _) = open(path, rolling());
        for index in 0..frames {
            journal.append(1, &[index; 40]).expect("appended");
        }
        journal
    }

    fn firsts(journal: &Journal) -> Vec<u64> {
        journal.segments.iter().map(|(first, _)| *first).collect()
    }

    /// WP-5.6a: a prefix deletion removes the segments every frame of which is below the index:
    /// an index inside a segment keeps that segment, an index at a segment's start keeps it and
    /// removes the one before. The frames kept keep their indexes and appends continue.
    #[test]
    fn a_dropped_prefix_keeps_every_later_frame_at_its_index() {
        let path = scratch("drop");
        let mut journal = filled(&path, 7);
        assert_eq!(firsts(&journal), vec![0, 2, 4, 6]);
        assert_eq!(
            journal.drop_prefix(3, None).expect("dropped"),
            2,
            "inside [2, 3]"
        );
        assert_eq!(firsts(&journal), vec![2, 4, 6]);
        assert_eq!(
            journal.drop_prefix(4, None).expect("dropped"),
            4,
            "at the start of [4, 5]"
        );
        assert_eq!(firsts(&journal), vec![4, 6]);
        assert_eq!(journal.first_index(), 4);
        let frames = journal.frames().expect("read");
        assert_eq!(
            frames.iter().map(|frame| frame.index).collect::<Vec<_>>(),
            vec![4, 5, 6]
        );
        assert!(
            frames
                .iter()
                .all(|frame| frame.payload == [frame.index as u8; 40])
        );
        assert_eq!(
            journal.frames_from(1).expect("read"),
            frames,
            "nothing below BASE"
        );
        assert_eq!(journal.append(1, &[7; 40]).expect("appended"), 7);
        let names: Vec<String> = contents(&path).into_iter().map(|(name, _)| name).collect();
        assert!(
            !names.iter().any(|name| name.ends_with(".tomb")),
            "{names:?}"
        );
        drop(journal);

        let (journal, recovery) = open(&path, rolling());
        assert_eq!(recovery, Recovery::default());
        assert_eq!(journal.first_index(), 4);
        assert_eq!(journal.frames().expect("read").len(), 4);
        assert_eq!(
            decode_base(
                &read_view(&journal.dir, BASE, format::VIEW)
                    .expect("read")
                    .expect("BASE")
            )
            .expect("decoded"),
            (4, crate::storage::volume::UNCLAIMED)
        );
    }

    /// WP-5.6a: the segment being written is never removed, however far the index reaches, and an
    /// index inside the first segment removes nothing and writes no `BASE`.
    #[test]
    fn a_prefix_deletion_never_removes_the_segment_being_written() {
        let path = scratch("tail");
        let mut journal = filled(&path, 5);
        assert_eq!(journal.drop_prefix(1, None).expect("nothing"), 0);
        assert!(
            !journal.dir.exists(BASE).expect("asked"),
            "nothing dropped, no BASE"
        );
        assert_eq!(journal.drop_prefix(u64::MAX, None).expect("dropped"), 4);
        assert_eq!(firsts(&journal), vec![4]);
        assert_eq!(journal.append(1, &[9; 40]).expect("appended"), 5);
    }

    /// WP-5.6a: what a crash left below `BASE` is removed at open, and listed.
    #[test]
    fn open_finishes_a_prefix_deletion() {
        let path = scratch("crashed");
        let journal = filled(&path, 7);
        let names = journal.segments();
        drop(journal);
        // `BASE` written, nothing removed yet: the crash after its flush.
        replace_view(
            &Dir::open(&path).expect("opened"),
            BASE,
            format::VIEW,
            &encode_base(4, 0).expect("encoded"),
        )
        .expect("written");
        let (journal, recovery) = open(&path, rolling());
        assert_eq!(recovery.dropped_segments, names[..2].to_vec());
        assert_eq!(journal.first_index(), 4);
        assert_eq!(journal.frames().expect("read").len(), 3);
        assert!(!path.join(&names[0]).exists() && !path.join(&names[1]).exists());
    }

    /// WP-5.6a (after the review): no segment starting exactly at `BASE` is acknowledged frames
    /// missing — whether `BASE` falls inside a segment, past every segment, or the segment at it
    /// was removed — and the open refuses it having changed nothing.
    #[test]
    fn open_refuses_a_base_no_segment_starts_at_and_changes_nothing() {
        for (case, base, remove) in [
            ("inside a segment", 3, None),
            ("past every segment", 100, None),
            ("its segment removed", 4, Some(2)),
        ] {
            let path = scratch(&format!("missing-{base}"));
            let journal = filled(&path, 7);
            let names = journal.segments();
            drop(journal);
            replace_view(
                &Dir::open(&path).expect("opened"),
                BASE,
                format::VIEW,
                &encode_base(base, 0).expect("encoded"),
            )
            .expect("written");
            if let Some(at) = remove {
                std::fs::remove_file(path.join(&names[at])).expect("removed");
            }
            let before = contents(&path);
            let refused =
                Journal::open(Dir::open(&path).expect("opened"), rolling()).expect_err(case);
            assert!(
                matches!(refused, StorageError::Corruption(_)),
                "{case}: {refused}"
            );
            assert_eq!(
                contents(&path),
                before,
                "{case}: a refused open changes nothing"
            );
        }
    }

    /// WP-5.6a (owner decision after the review): an unfinished deletion whose `BASE` a superseded
    /// writer wrote is refused, not completed; one above the volume's claim is a claim behind the
    /// data. Neither changes anything. A deletion by an earlier owner, older than every frame kept,
    /// is completed.
    #[test]
    fn an_unfinished_deletion_is_judged_by_the_claim_of_its_writer() {
        for (case, base_claim, open_claim) in [
            ("a superseded writer", 1, 2),
            ("above the claim", 3, 2),
            ("an earlier owner", 2, 3),
        ] {
            let path = scratch(&format!("claim-{base_claim}-{open_claim}"));
            let (mut journal, _) = open(
                &path,
                Options {
                    claim: 2,
                    ..rolling()
                },
            );
            for index in 0..7u8 {
                journal.append(1, &[index; 40]).expect("appended");
            }
            drop(journal);
            replace_view(
                &Dir::open(&path).expect("opened"),
                BASE,
                format::VIEW,
                &encode_base(4, base_claim).expect("encoded"),
            )
            .expect("written");
            let before = contents(&path);
            let opened = Journal::open(
                Dir::open(&path).expect("opened"),
                Options {
                    claim: open_claim,
                    ..rolling()
                },
            );
            match case {
                "a superseded writer" => {
                    assert!(
                        matches!(opened, Err(StorageError::StaleWriter { .. })),
                        "{case}: {opened:?}"
                    );
                    assert_eq!(contents(&path), before, "{case}");
                }
                "above the claim" => {
                    assert!(
                        matches!(opened, Err(StorageError::ClaimBehindData { .. })),
                        "{case}: {opened:?}"
                    );
                    assert_eq!(contents(&path), before, "{case}");
                }
                _ => {
                    let (journal, recovery) = opened.expect("completed");
                    assert_eq!(recovery.dropped_segments.len(), 2, "{case}");
                    assert_eq!(journal.first_index(), 4, "{case}");
                }
            }
        }
    }

    /// WP-5.6a: a segment missing at the start of a journal that never dropped a prefix is refused
    /// at open, and `BASE` holds exactly `{1 first_index, 2 claim}`.
    #[test]
    fn base_is_two_labels_and_a_journal_without_it_starts_at_zero() {
        let path = scratch("zero");
        let journal = filled(&path, 3);
        let first = journal.segments()[0].clone();
        drop(journal);
        std::fs::remove_file(path.join(&first)).expect("removed");
        assert!(matches!(
            Journal::open(Dir::open(&path).expect("opened"), rolling()),
            Err(StorageError::Corruption(_))
        ));

        assert_eq!(
            decode_base(&encode_base(42, 7).expect("encoded")).expect("read"),
            (42, 7)
        );
        let map = |pairs: Vec<(i64, i64)>| {
            cbor::encode(&Value::Map(
                pairs
                    .into_iter()
                    .map(|(label, value)| (Value::Int(label), Value::Int(value)))
                    .collect(),
            ))
            .expect("encoded")
        };
        for refused in [
            map(vec![(1, 1)]),
            map(vec![(1, 1), (2, 1), (3, 1)]),
            map(vec![(1, -1), (2, 1)]),
            map(vec![(1, 1), (2, -1)]),
            cbor::encode(&Value::Int(1)).expect("encoded"),
            vec![0xff],
        ] {
            assert!(decode_base(&refused).is_err(), "{refused:?}");
        }
    }

    /// WP-5.6a: a failure record's cut counts from `BASE`: after a prefix deletion, a failed
    /// append is cut at its index and appends continue there.
    #[test]
    fn a_failure_after_a_dropped_prefix_is_cut_from_base() {
        let path = scratch("failure-base");
        let mut journal = filled(&path, 6);
        assert_eq!(journal.drop_prefix(4, None).expect("dropped"), 4);
        drop(journal);
        replace_view(
            &Dir::open(&path).expect("opened"),
            FAILED,
            format::VIEW,
            &[5u64.to_be_bytes(), 0u64.to_be_bytes()].concat(),
        )
        .expect("a record");
        let (mut journal, recovery) = open(&path, rolling());
        assert_eq!(recovery.cut_from, Some(5));
        assert_eq!(journal.first_index(), 4);
        assert_eq!(journal.append(1, &[9; 40]).expect("appended"), 5);
    }

    /// WP-5.6a: a failure record naming `BASE` itself cuts every frame the journal holds, and the
    /// journal continues at `BASE`, never at 0; `BASE` keeps the claim of the writer that wrote it.
    #[test]
    fn a_failure_at_base_continues_at_base() {
        let path = scratch("failure-at-base");
        let (mut journal, _) = open(
            &path,
            Options {
                claim: 2,
                ..rolling()
            },
        );
        for index in 0..6u8 {
            journal.append(1, &[index; 40]).expect("appended");
        }
        assert_eq!(journal.drop_prefix(4, None).expect("dropped"), 4);
        assert_eq!(
            decode_base(
                &read_view(&journal.dir, BASE, format::VIEW)
                    .expect("read")
                    .expect("BASE")
            )
            .expect("decoded"),
            (4, 2),
            "the writer's claim"
        );
        drop(journal);
        replace_view(
            &Dir::open(&path).expect("opened"),
            FAILED,
            format::VIEW,
            &[4u64.to_be_bytes(), 2u64.to_be_bytes()].concat(),
        )
        .expect("a record");
        let (mut journal, recovery) = open(
            &path,
            Options {
                claim: 2,
                ..rolling()
            },
        );
        assert_eq!(recovery.cut_from, Some(4));
        assert_eq!(journal.first_index(), 4);
        assert_eq!(journal.segments(), vec![segment_name(4)]);
        assert_eq!(journal.append(1, &[9; 40]).expect("appended"), 4);
    }
}
