// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The foundation every evidence stream shares: how it is read, how it is named, where it
//! lives, and who signed which stretch of it.
//!
//! # Why this is one crate and not two of everything
//!
//! Permguard keeps two streams of evidence — the decision log and the event log — and they are
//! different in every way that matters cryptographically: different digest domains, different
//! envelope types, different retention rules, different things they prove. What they are *not*
//! different in is how a consumer reads them: an append-only, producer-partitioned stream, read in
//! bounded blocks, from an offset the consumer owns.
//!
//! That model was written once, for decisions, and then the event log needed it too. Written
//! twice, the second one would be the one whose cursor is not authenticated, or whose `more` is
//! computed against a moving end so an export never finishes. So it is written here, once, and
//! both stores are read through it. The same argument then repeated for everything else two
//! streams share and a third would rewrite: the canonical bytes a digest is taken over ([`jcs`]),
//! the per-batch inclusion tree ([`merkle`]), the declaration of what streams a process serves
//! ([`descriptor`]), where a stream keeps its data ([`layout`]), and which key signed which
//! stretch of it ([`signers`]). What stays *out* is everything that carries a domain — record
//! digests, envelope types, retention rules — because two streams that shared a domain would be
//! confusable by a verifier, and that is the one sharing this crate exists to prevent.
//!
//! It is Kafka-like in exactly that limited sense. There are no brokers, no consumer groups, no
//! globally ordered partitions and no protocol compatibility, and none of those words appear in
//! what this serves.
//!
//! # What the offset is, and why it is authenticated
//!
//! An offset is a logical position, not an array index and not a filename. A consumer keeps it and
//! presents it back; the server keeps nothing. That is what lets any number of independent readers
//! coexist — a SIEM in near-real-time, a nightly export, an application answering "why was I
//! denied" — with none of them able to affect the others, and nothing to clean up when one leaves.
//!
//! It carries a MAC, and that is not decoration. Without one an offset is a base64 JSON object a
//! consumer can edit: it can move itself to a position it was never given, or present a position
//! issued for one tenant under another. The binding covers the API family, the scope, the
//! normalized filter set and the export bound, so every one of those is a stable refusal rather
//! than a reinterpretation — a read of one tenant's stream cannot become a read of another's by
//! changing a string.
//!
//! # Fixed snapshots, and why `until` exists
//!
//! An export that stops when the stream is empty never stops on a busy ledger: records keep
//! arriving, and `more` keeps being true. So an export captures the high watermark of its first
//! page and presents it as `until` on every page after that. Records that arrive later belong to a
//! later export. A tail does the opposite — no `until`, read from `next`, idle when caught up —
//! and the difference between the two is one field rather than two code paths.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

pub mod cursor;
pub mod descriptor;
pub mod frontier;
pub mod jcs;
pub mod layout;
pub mod merkle;
pub mod name;
pub mod signers;
pub mod window;

pub use cursor::{Cursor, CursorError, CursorKey, Position};
pub use descriptor::{
    Registered, RegistryError, Role, StreamDescriptor, StreamIdentity, StreamRegistry,
};
pub use frontier::Frontier;
pub use name::{PositionError, StreamPosition, is_portable_name};
pub use signers::{MAX_SIGNER_SPANS, SIGNERS_FILE, SignerError, SignerSpan, Signers};
pub use window::{Block, Coverage, Expired, Window, more};
