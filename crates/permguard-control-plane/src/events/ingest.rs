// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Accepting a batch of events: verify, append, flush, and answer with a number the producer can
//! safely delete by.
//!
//! # The acknowledgement is the whole contract, and it means more here than for decisions
//!
//! It is the highest **contiguous durable** sequence for that stream. A decision producer deletes
//! its spool by it; an event producer does the same, and its journal is *also* the history its own
//! policies read. So a number with a hole behind it does not merely lose evidence — it changes
//! what future authorizations mean on the plane that trusted it.
//!
//! # What each answer means
//!
//! ```text
//! ≤ acked entirely       ok, acked unchanged     a replay: deduplicated
//! acked + 1              ok, acked moves         the ordinary case
//! > acked + 1            out_of_order            nothing stored; resend from expected_seq
//! same seq, other bytes  fork                    the stream is closed permanently
//! ```
//!
//! The last is not a retry and never becomes one. Two different records claiming one
//! `(stream, seq)` is a bug or an attack, and in both cases the stream's history can no longer be
//! reasoned about as one sequence. Nothing is repaired and nothing is overwritten: what is stored
//! stays as evidence, and the producer opens a new incarnation to keep recording.
//!
//! # What is checked before anything is durable
//!
//! The producer class is registered and permitted; the signature verifies against a key that
//! producer published; the envelope's type and algorithm are the event log's own; every record's
//! digest matches, chains, and belongs to the stream the envelope names; the Merkle root is the
//! root of exactly those digests; every record's event type is one this build registers. In that
//! order, and all of it before a byte is written.

use permguard_events::record::PRODUCER_CLASS_DATA_PLANE;

/// The producer classes this release accepts.
///
/// One entry, and the list is a list on purpose: the record, batch and storage protocols are
/// generic so a later authenticated producer — a PIP, say — can be admitted without changing
/// offsets, envelopes or layout. What is *not* done is enabling one before its payload, its owner
/// and its validation contract exist, because an unenforced registry entry is an open door with a
/// label on it.
pub const ACCEPTED_PRODUCER_CLASSES: [&str; 1] = [PRODUCER_CLASS_DATA_PLANE];

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
    /// A producer class or event type this build does not accept.
    Unregistered(String),
    /// A record conflicts with one already stored. The stream is now closed.
    Fork {
        /// Where the two disagree.
        seq: u64,
    },
    /// The stream was closed permanently and accepts nothing more.
    Closed(String),
    /// The store could not accept right now. A shipper retries this.
    Unavailable(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unattributable(detail)
            | Self::Unverifiable(detail)
            | Self::Unregistered(detail)
            | Self::Unavailable(detail) => write!(formatter, "{detail}"),
            Self::Fork { seq } => write!(
                formatter,
                "a different record is already stored at sequence {seq}: this stream has forked, \
                 so it is closed permanently and what it holds is kept as evidence"
            ),
            Self::Closed(reason) => write!(
                formatter,
                "this stream was closed permanently ({reason}) and accepts nothing further: open a \
                 new incarnation"
            ),
        }
    }
}

/// The code a caller switches on.
impl Refused {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unattributable(_) => permguard_core::codes::stream::BATCH_UNATTRIBUTABLE,
            Self::Unverifiable(_) => permguard_core::codes::stream::BATCH_UNVERIFIABLE,
            Self::Unregistered(_) => permguard_core::codes::stream::BATCH_UNREGISTERED,
            Self::Fork { .. } => permguard_core::codes::stream::STREAM_FORKED,
            Self::Closed(_) => permguard_core::codes::stream::STREAM_CLOSED,
            Self::Unavailable(_) => permguard_core::codes::stream::STORE_UNAVAILABLE,
        }
    }
}

/// One batch, as the wire carries it.
///
/// The producer's own definition, not a copy: both sides must agree about it byte for byte, and
/// two definitions would be two chances to render the same batch two ways.
pub use permguard_events::Batch;
