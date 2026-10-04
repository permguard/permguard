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
//! The segments are the whole authority: which segment is current, and the index of every frame,
//! follow from their names and their frames, so there is no separate state file to fall out of
//! step with them.
//!
//! # Recovery, at open
//!
//! | What is found                                                          | What happens                  |
//! | ---------------------------------------------------------------------- | ----------------------------- |
//! | in the last segment, a damaged frame whose own extent reaches the end  | truncated: a torn write       |
//! | in the last segment, an incomplete frame header, or zeros to the end   | truncated: a torn write       |
//! | a last segment of at most 48 bytes (header and its checksum) not whole | removed: it held no frame     |
//! | a damaged frame with bytes beyond its own extent                       | [`StorageError::Corruption`]  |
//! | a damaged frame declaring more than the format's frame limit           | [`StorageError::Corruption`]  |
//! | a damaged header on a segment holding frames                           | [`StorageError::Corruption`]  |
//! | a torn frame in any segment but the last; a gap between segments       | [`StorageError::Corruption`]  |
//! | another magic, a newer version, an unknown flag                        | [`StorageError::Unsupported`] |
//!
//! Earlier frames are never modified: a truncation cuts exactly the torn bytes.
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
//! An append writes one frame and flushes it with `fdatasync` before it returns. A write that fails
//! is rolled back: the segment is cut back to its last whole frame before the error is returned, and
//! a journal that cannot cut it back refuses every later append. A failed flush is final: the append
//! fails with [`StorageError::Durability`] and the journal refuses every later append
//! ([`StorageError::Poisoned`]). Whether recovery keeps or drops the frame that preceded the failure
//! is the open question WP-1.2 resolves; nothing here retries it.
//!
//! # Segment roll
//!
//! A segment past its size bound rolls at the start of the next append, before that append writes
//! anything: the segment is flushed, the next one is created exclusively with its header and the
//! header's checksum, flushed, and the directory flushed — a crash point at each step. A roll that
//! fails is not a failed append of the frame before it, which is already durable: the append that
//! attempted the roll fails having written nothing, and the next append rolls again, first
//! removing whatever the failed attempt created (it never held a frame). A failed flush during a
//! roll is final like any other.

use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};

use super::dir::Dir;
use super::format::{self, CHECKSUM_LEN, HEADER_LEN};
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
    /// Opens the journal in `dir`, creating it when empty, and repairs a torn tail.
    pub fn open(dir: Dir, options: Options) -> Result<(Self, Recovery)> {
        if options.max_frame > FRAME_LIMIT {
            return Err(StorageError::TooLarge(format!(
                "a frame bound of {} bytes; the format allows up to {FRAME_LIMIT}",
                options.max_frame
            )));
        }
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
                if last && bytes.len() <= SEGMENT_HEAD {
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
                Scan::Torn { frames, at } if last => {
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
                        "segment `{name}` ends in a torn frame and segments follow it"
                    )));
                }
            }
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
            // A failed write may have left part of the frame: cut back to the last whole frame,
            // or a later frame written after the debris would read as corruption.
            let end = self.current_len;
            let rewound = current
                .set_len(end)
                .and_then(|()| current.seek(SeekFrom::Start(end)).map(|_| ()));
            if rewound.is_err() {
                self.poisoned = true;
            }
            return Err(io(format!("appending to {}", path.display()))(error));
        }
        point("journal.frame_written");
        if let Err(error) = permguard_core::fault::sync(&path, || current.sync_data()) {
            self.poisoned = true;
            return Err(durability(format!("flushing {}", path.display()))(error));
        }
        point("journal.frame_flushed");
        let index = self.next_index;
        self.next_index += 1;
        self.current_len += bytes.len() as u64;
        Ok(index)
    }

    /// Every frame, oldest first.
    pub fn frames(&self) -> Result<Vec<Frame>> {
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

    /// Flushes the current segment, creates and flushes the next, and flushes the directory; a
    /// failed flush poisons the journal, any other failure leaves the roll to the next append.
    fn roll(&mut self) -> Result<()> {
        let rolled = self.roll_once();
        if matches!(rolled, Err(StorageError::Durability { .. })) {
            self.poisoned = true;
        }
        rolled
    }

    fn roll_once(&mut self) -> Result<()> {
        let old = self.dir.child_path(&self.current_name());
        let current = &mut self.current;
        permguard_core::fault::sync(&old, || current.sync_all())
            .map_err(durability(format!("flushing {}", old.display())))?;
        point("journal.roll_old_flushed");
        let name = segment_name(self.next_index);
        // Only an earlier roll of this journal that failed can have left the next segment: no
        // frame was ever written to it, and it is created again from nothing.
        if self.dir.unlink(&name)? {
            self.dir.sync()?;
        }
        let file = create_segment(&self.dir, &name)?;
        self.segments.push((self.next_index, name));
        self.current = file;
        self.current_len = SEGMENT_HEAD as u64;
        Ok(())
    }
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

    /// A roll that fails for want of space fails the append that attempted it, writes nothing,
    /// and is attempted again by the next append; the journal reopens whole.
    #[test]
    fn a_failed_roll_is_retried_and_the_journal_stays_whole() {
        let path = scratch("failed-roll");
        let options = Options {
            max_frame: 1024,
            segment_bytes: 100,
        };
        let (mut journal, _) = open(&path, options);
        assert_eq!(journal.append(1, &[1u8; 40]).expect("appended"), 0);
        {
            let _full = permguard_core::fault::inject(
                &path,
                permguard_core::fault::Fault::DiskFull { remaining_bytes: 0 },
            );
            assert!(matches!(
                journal
                    .append(1, &[2u8; 40])
                    .expect_err("no space for the roll"),
                StorageError::Io { .. }
            ));
        }
        assert_eq!(journal.append(1, &[3u8; 40]).expect("rolled now"), 1);
        assert_eq!(journal.append(1, &[4u8; 40]).expect("appended"), 2);
        drop(journal);
        let (journal, recovery) = open(&path, options);
        assert_eq!(recovery, Recovery::default());
        let payloads: Vec<u8> = journal
            .frames()
            .expect("read")
            .iter()
            .map(|frame| frame.payload[0])
            .collect();
        assert_eq!(payloads, [1, 3, 4]);
    }

    /// A write that fails part-way is cut back before the error returns, so the next frame does not
    /// land after debris. The partial bytes are put there by hand: the fault shim's disk-full writes
    /// nothing.
    #[test]
    fn a_failed_write_is_cut_back_to_the_last_whole_frame() {
        let path = scratch("partial-write");
        let (mut journal, _) = open(&path, Options::default());
        journal.append(1, b"one").expect("appended");
        journal
            .current
            .write_all(&[0xab; 500])
            .expect("debris of a write that failed part-way");
        {
            let _full = permguard_core::fault::inject(
                &path,
                permguard_core::fault::Fault::DiskFull { remaining_bytes: 0 },
            );
            assert!(journal.append(1, b"two").is_err());
        }
        journal.append(1, b"three").expect("appended");
        drop(journal);
        let (journal, recovery) = open(&path, Options::default());
        assert_eq!(recovery, Recovery::default(), "nothing to repair");
        assert_eq!(journal.frames().expect("read").len(), 2);
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
