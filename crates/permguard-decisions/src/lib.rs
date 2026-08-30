// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a decision record **is**, as specified in `docs/decision-logs.md`.
//!
//! This crate holds everything the specification calls normative — everything
//! two independent implementations must compute identically or the chain they
//! produce cannot be verified by the same code:
//!
//! | Module | What it fixes |
//! | --- | --- |
//! | [`record`] | the record, its kinds, and `digest(record)` |
//! | [`chain`] | `prev(N) = digest(N − 1)`, across a whole stream |
//! | [`envelope`] | the signed head a batch travels under |
//! | [`commitment`] | keyed commitments over caller-supplied inputs |
//! | [`spool`] | the durable local record, and the crash boundaries around it |
//! | [`instance`] | incarnation identifiers, minted where a stream begins |
//!
//! The two primitives that carry no decision domain at all — [`jcs`], the canonical bytes every
//! digest is taken over, and [`merkle`], the per-batch inclusion tree — live in
//! `permguard-stream` and are re-exported here unchanged: every evidence stream needs them, and a
//! future stream type must be able to depend on them without depending on decisions.
//!
//! It says nothing about *what is done* with a record: the data plane writes
//! and ships them, the control plane keeps and serves them, the CLI verifies
//! them. None of that is visible from here — which is what lets every side
//! compute the same digests without agreeing on anything else.

pub mod chain;
pub mod commitment;
pub mod envelope;
pub mod instance;
pub mod record;
pub mod spool;

pub use permguard_stream::jcs;
pub use permguard_stream::merkle;

pub use chain::{ChainError, Verified};
pub use commitment::Commitment;
pub use envelope::{Batch, Envelope, EnvelopeError, Signed};
pub use record::{Body, GENESIS, Record, Stream, digest_of};
pub use spool::{Spool, SpoolError, State};
