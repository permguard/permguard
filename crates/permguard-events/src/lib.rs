// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What an **event record** is, and what a signed batch of them attests to.
//!
//! This crate holds the normative half of the event log: everything two independent
//! implementations must compute identically or the history one produces cannot be verified by the
//! other. It says nothing about *what is done* with a record — the data plane appends and ships
//! them, the control plane keeps and serves them, the CLI verifies them — which is what lets every
//! side agree on digests without agreeing on anything else.
//!
//! | Module | What it fixes |
//! | --- | --- |
//! | [`record`] | the record, its identity, and `digest(record)` |
//! | [`chain`] | `prev(N) = digest(N − 1)`, across one producer's stream |
//! | [`envelope`] | the signed head a batch of records travels under |
//!
//! # Why this is not the decision log
//!
//! The two are the same *shape* — an append-only, producer-partitioned, hash-chained stream shipped
//! in signed batches — and it would be tempting to reuse the decision log wholesale. Two things
//! forbid it.
//!
//! The first is cryptographic. A verifier must never be able to accept a decision record where an
//! event record belongs, or the reverse; that is what domain separation is for, and sharing a
//! domain would delete it. So the record digest lives under `permguard.event.record.v1` and the
//! batch signature declares `typ: permguard.event.batch.v1`, and neither string appears in the
//! decision log.
//!
//! The second is operational. A decision record is *evidence*: once shipped and acknowledged, the
//! producer is free to forget it. An event record is evidence **and** an input — it is the history
//! a temporal policy reads — so it may only be deleted when both the control plane has it and no
//! loaded policy could still ask about it. A store that forgot an event the moment it was shipped
//! would change what future decisions mean.
//!
//! What *is* shared is what carries no domain: JCS canonicalization and the per-batch Merkle tree,
//! taken from [`permguard_decisions`] rather than written twice.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

pub mod chain;
pub mod envelope;
pub mod index;
pub mod journal;
pub mod record;

pub use chain::{ChainError, Verified};

pub use envelope::{BATCH_TYPE, Batch, Envelope, EnvelopeError, Signed};
/// Recomputes a Merkle root from a leaf and its inclusion path.
///
/// Re-exported from the decision log's tree, which is the same tree: the Merkle construction
/// carries no domain, so sharing it is safe in exactly the way sharing a digest domain would not
/// be. A verifier needs it to check that a path reaches the root its envelope attests.
pub use permguard_decisions::merkle::recompute as merkle_of;
pub use record::{
    DIGEST_DOMAIN, GENESIS, HISTORY_DOMAIN, HistoryKey, PRODUCER_CLASS_DATA_PLANE, Producer,
    RECORD_TYPE, Record, RecordError, Stream, digest_of, history_digest_of, occurrence_digest_of,
    validate,
};
