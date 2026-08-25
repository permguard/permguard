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
//! | [`jcs`] | the canonical bytes every digest is taken over |
//! | [`record`] | the record, its kinds, and `digest(record)` |
//! | [`chain`] | `prev(N) = digest(N − 1)`, across a whole stream |
//! | [`merkle`] | the per-batch tree that lets one tenant verify without seeing others |
//! | [`envelope`] | the signed head a batch travels under |
//! | [`commitment`] | keyed commitments over caller-supplied inputs |
//! | [`spool`] | the durable local record, and the crash boundaries around it |
//! | [`instance`] | incarnation identifiers, minted where a stream begins |
//!
//! It says nothing about *what is done* with a record: the data plane writes
//! and ships them, the control plane keeps and serves them, the CLI verifies
//! them. None of that is visible from here — which is what lets every side
//! compute the same digests without agreeing on anything else.

pub mod chain;
pub mod commitment;
pub mod envelope;
pub mod instance;
pub mod jcs;
pub mod merkle;
pub mod record;
pub mod spool;

pub use chain::{ChainError, Verified};
pub use commitment::Commitment;
pub use envelope::{Batch, Envelope, EnvelopeError, Signed};
pub use record::{Body, GENESIS, Record, Stream, digest_of};
pub use spool::{Spool, SpoolError, State};
