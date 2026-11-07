// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Accepting a batch: verify, append, flush, and answer with a number the
//! producer can safely delete by.
//!
//! # The acknowledgement is the whole contract
//!
//! It is the highest **contiguous durable** sequence for that stream — not the
//! highest accepted. The shipper truncates its spool by it, and truncating by
//! a number that had a hole behind it is exactly how a gap becomes permanent.
//!
//! # What each answer means
//!
//! ```text
//! ≤ acked entirely   ok, acked unchanged      a replay: deduplicated
//! acked + 1          ok, acked moves          the ordinary case
//! > acked + 1        out_of_order             nothing stored; resend from expected_seq
//! same seq, other digest   integrity          the stream is closed permanently
//! beyond the ceiling       not_accepted       nothing stored; the stream stays where it was
//! ```
//!
//! The last one is not a retry and never becomes one. Two different records
//! claiming one `(stream, seq)` means a bug or an attack, and in both cases the
//! stream's history can no longer be reasoned about as a single sequence.
//! Nothing is repaired, nothing is overwritten: what is stored stays as
//! evidence, and the producer opens a new incarnation to keep logging.

/// What accepting a batch concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// Stored (or already held), and durable through `acked`.
    Ok {
        /// The highest contiguous durable sequence.
        acked: u64,
        /// How many records this batch added. Zero for a replay.
        stored: u64,
    },
    /// The shipper ran ahead: nothing was stored.
    OutOfOrder {
        /// What the store needs next.
        expected_seq: u64,
    },
}

/// Why a batch was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The signature does not verify, or names a key nobody published.
    Unattributable(String),
    /// The records are not a chain, or do not match what the envelope attests.
    Unverifiable(String),
    /// A record conflicts with one already stored. The stream is now closed.
    Conflict {
        /// Where the two disagree.
        seq: u64,
    },
    /// The stream was closed permanently and accepts nothing more.
    Closed(String),
    /// The store could not accept right now. A shipper retries this.
    Unavailable(String),
    /// A record carries in clear what this store does not accept (`controlPlane.decisions.accept`).
    /// Nothing was stored; the producer stops until its inclusion or this ceiling changes.
    NotAccepted(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unattributable(detail) => write!(formatter, "{detail}"),
            Self::Unverifiable(detail) => write!(formatter, "{detail}"),
            Self::Conflict { seq } => write!(
                formatter,
                "a different record is already stored at sequence {seq}: this stream is closed permanently and what it holds is kept as evidence"
            ),
            Self::Closed(reason) => write!(
                formatter,
                "this stream was closed permanently ({reason}) and accepts nothing further: open a new incarnation"
            ),
            Self::Unavailable(detail) => write!(formatter, "{detail}"),
            Self::NotAccepted(member) => {
                write!(
                    formatter,
                    "{}",
                    permguard_decisions::ceiling::refusal(member)
                )
            }
        }
    }
}
