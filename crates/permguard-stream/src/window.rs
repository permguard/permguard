// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The read itself: what a consumer asks for, and the block it gets back.
//!
//! # Both bounds, always
//!
//! A record limit alone does not bound a response: a hundred records of a hundred bytes and a
//! hundred records of a megabyte are the same number and two very different answers. So a read
//! carries both, the server clamps both, and a block never exceeds either.
//!
//! # `more` means what the request asked it to mean
//!
//! With a fixed `until`, `more` is measured against that bound — which is what lets an export
//! finish on a stream that is still being written. Without one, it is measured against the
//! watermark this read observed, which is what lets a tail know it has caught up. One field, two
//! behaviours, and no second code path.
//!
//! # An empty block is not the end
//!
//! Filtering happens under the read, so a page may legitimately match nothing while still
//! advancing over the positions it examined. A consumer that stopped on "empty" would stop in the
//! middle of a ledger whose next segment is full of what it asked for. Consumers stop from `next`,
//! `more` and `until` — never from emptiness — and the scan work is bounded separately from the
//! records returned so a sparse filter cannot turn one page into a full scan.

use serde::{Deserialize, Serialize};

use crate::cursor::Cursor;
use crate::frontier::Frontier;

/// The most records one block may carry, whatever a caller asks for.
pub const MAX_RECORDS: usize = 1_000;
/// The most bytes one block may carry, whatever a caller asks for.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// The records one block carries when a caller asks for no particular number.
pub const DEFAULT_RECORDS: usize = 100;
/// The bytes one block carries when a caller asks for no particular size.
pub const DEFAULT_BYTES: u64 = 1024 * 1024;
/// The most positions one block may examine while looking for matches.
///
/// The bound that keeps a sparse filter from turning one page into a full scan. Separate from the
/// record limit because they answer different questions — how much is returned, and how much is
/// looked at — and a store that bounded only the first would let a caller ask for one matching
/// record and pay for a million.
pub const MAX_EXAMINED: usize = 50_000;

/// What a consumer is asking for.
#[derive(Debug, Clone)]
pub struct Window {
    /// Where to start. `None` is the oldest position still held.
    pub from: Option<String>,
    /// The fixed end of a finite snapshot, echoed from the first page's watermark.
    ///
    /// Present, this read is part of an export and finishes. Absent, it is a tail.
    pub until: Option<Frontier>,
    /// How many records at most. Clamped to [`MAX_RECORDS`].
    pub limit_records: usize,
    /// How many bytes at most. Clamped to [`MAX_BYTES`].
    pub limit_bytes: u64,
    /// Whether to return the signed envelopes and inclusion paths.
    pub proof: bool,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            from: None,
            until: None,
            limit_records: DEFAULT_RECORDS,
            limit_bytes: DEFAULT_BYTES,
            proof: false,
        }
    }
}

impl Window {
    /// The record limit this server will actually honour.
    ///
    /// Clamped rather than refused: a caller asking for more than a server will send has made no
    /// mistake, and answering with less plus an honest `more` is what the contract already means.
    /// Zero is the one value that *is* a mistake — a page of no records makes no progress — so it
    /// becomes the default rather than an empty answer forever.
    pub fn records(&self) -> usize {
        match self.limit_records {
            0 => DEFAULT_RECORDS,
            held => held.min(MAX_RECORDS),
        }
    }

    /// The byte limit this server will actually honour.
    pub fn bytes(&self) -> u64 {
        match self.limit_bytes {
            0 => DEFAULT_BYTES,
            held => held.min(MAX_BYTES),
        }
    }

    /// Whether this read is a finite snapshot.
    pub fn is_export(&self) -> bool {
        self.until.is_some()
    }
}

/// What a block proves about what it covers.
///
/// A filtered view cannot claim chain completeness — the records in between were filtered out, and
/// the chain does not verify across a subsequence. Saying so explicitly is the difference between
/// a proof and a claim.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Whether the returned records are a contiguous run of one producer's stream.
    ///
    /// `true` means the chain links across them and a reader can verify it. `false` means this is
    /// a subsequence — filtered, or merged across producers — and the inclusion paths are what
    /// there is to verify with.
    pub contiguous: bool,
    /// How many positions this read examined to produce this block.
    ///
    /// Not decoration: it is what tells a consumer that its filter is sparse, and what makes the
    /// scan bound visible rather than a silent truncation.
    pub examined: usize,
    /// Whether the scan bound stopped this block before its record or byte bound did.
    ///
    /// When true the block may be short — or empty — and `next` has still advanced. A consumer
    /// reads on rather than concluding it has reached the end.
    pub scan_bounded: bool,
}

/// One block of an evidence stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block<T> {
    /// The records, in the scope's deterministic order.
    pub records: Vec<T>,
    /// The offset to present for the following block, opaque and authenticated.
    ///
    /// Returned even for an empty block, because an empty block still advanced over the positions
    /// it examined and a consumer that re-presented its previous offset would examine them again.
    pub next: String,
    /// The oldest offset this scope still holds, so a new consumer can choose the retained
    /// beginning deliberately rather than by guessing.
    pub oldest_available: String,
    /// The exclusive end this read observed, as the opaque token a client echoes.
    ///
    /// A token rather than a number, because for a view merged across producers there is no
    /// truthful number: a single sequence would have to pretend one producer's position orders
    /// against another's. A client captures this on its first page and sends it back as `until`.
    pub high_watermark: String,
    /// Whether there is more, relative to this request's `until` when it has one and to
    /// `high_watermark` otherwise.
    pub more: bool,
    /// The signed envelopes covering these records, when the reader asked.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof: Vec<serde_json::Value>,
    /// One inclusion path per record, when the reader asked.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub inclusion: Vec<serde_json::Value>,
    /// What this block proves about what it covers.
    pub coverage: Coverage,
}

/// The answer to a consumer that fell behind retention.
///
/// Expected behaviour rather than corruption, and it says so: the records between where the
/// consumer stood and where the stream now begins left on the retention schedule. The server never
/// silently restarts such a consumer at the beginning — that would turn a gap it could have
/// reported into a duplicate run it cannot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Expired {
    /// The oldest offset still held, to resume from deliberately.
    pub oldest_available: String,
    /// The first sequence still held, so the size of the gap is visible.
    pub oldest_sequence: u64,
    /// The sequence the consumer stood at.
    pub requested_sequence: u64,
}

impl Expired {
    /// How many positions the consumer lost.
    pub fn gap(&self) -> u64 {
        self.oldest_sequence.saturating_sub(self.requested_sequence)
    }
}

/// Whether a read that reached `frontier` has finished, for this window.
///
/// The whole of the `more` rule, in one place so the two stores cannot answer it differently.
pub fn more(window: &Window, reached: &Frontier, stream_end: &Frontier) -> bool {
    match &window.until {
        // A finite snapshot: finished when every producer the snapshot bounded has been read to
        // the position it recorded. A record that arrives after belongs to a later export.
        Some(bound) => !reached.reached(bound),
        // A tail: more when the stream has moved past what this read observed.
        None => !reached.reached(stream_end),
    }
}

/// Seals a cursor into the token a block carries.
pub fn seal(
    cursor: &Cursor,
    key: &crate::cursor::CursorKey,
) -> Result<String, crate::cursor::CursorError> {
    cursor.seal(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_bounds_are_clamped_and_neither_can_be_zero() {
        let asked = Window {
            limit_records: usize::MAX,
            limit_bytes: u64::MAX,
            ..Window::default()
        };
        assert_eq!(asked.records(), MAX_RECORDS);
        assert_eq!(asked.bytes(), MAX_BYTES);

        let nothing = Window {
            limit_records: 0,
            limit_bytes: 0,
            ..Window::default()
        };
        assert_eq!(
            nothing.records(),
            DEFAULT_RECORDS,
            "a page of nothing makes no progress"
        );
        assert_eq!(nothing.bytes(), DEFAULT_BYTES);
    }

    /// An export finishes on a stream that is still being written.
    #[test]
    fn an_export_finishes_against_its_own_bound_rather_than_a_moving_end() {
        let bound = Frontier::of("p1", 100);
        let window = Window {
            until: Some(bound.clone()),
            ..Window::default()
        };
        // The stream has moved well past the snapshot, and the export still ends.
        let moved_on = Frontier::of("p1", 5_000);

        assert!(more(&window, &Frontier::of("p1", 50), &moved_on));
        assert!(!more(&window, &Frontier::of("p1", 100), &moved_on));
        assert!(
            !more(&window, &Frontier::of("p1", 120), &moved_on),
            "reading past the bound does not reopen the snapshot"
        );
    }

    /// A tail is finished only when it has caught up with the stream.
    #[test]
    fn a_tail_is_measured_against_the_stream_rather_than_a_bound() {
        let window = Window::default();

        assert!(more(
            &window,
            &Frontier::of("p1", 50),
            &Frontier::of("p1", 100)
        ));
        assert!(!more(
            &window,
            &Frontier::of("p1", 100),
            &Frontier::of("p1", 100)
        ));
    }

    #[test]
    fn a_gap_says_how_much_was_lost() {
        let expired = Expired {
            oldest_available: "token".to_owned(),
            oldest_sequence: 900,
            requested_sequence: 400,
        };

        assert_eq!(expired.gap(), 500);
    }
}
