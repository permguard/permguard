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
//! | [`ceiling`] | what a store accepts in clear |
//! | [`instance`] | incarnation identifiers, minted where a stream begins |
//!
//! Two halves are a runtime over that model, and a feature each, so that a verifier links the
//! model alone (the crate boundaries refactoring, RD-14):
//!
//! | Feature | What it adds |
//! | --- | --- |
//! | `storage` | `spool`, the durable local record and the crash boundaries around it, and `archive` |
//! | `stream` | `stream`, the decision log as the Host's stream engine registers it |
//!
//! The model links no Host: an envelope is framed and its key selected by `permguard-objects`,
//! and only those two features reach a Host. A third feature joins the model to a decision point:
//!
//! | Feature | What it adds |
//! | --- | --- |
//! | `evaluator` | `answer`, the record's answer from an evaluator's |
//!
//! The two primitives that carry no decision domain at all — [`jcs`], the canonical bytes every
//! digest is taken over, and [`merkle`], the per-batch inclusion tree — live in
//! `permguard-canonical` and are re-exported here unchanged: every evidence stream needs them, and a
//! future stream type must be able to depend on them without depending on decisions.
//!
//! It says nothing about *what is done* with a record: the data plane writes
//! and ships them, the control plane keeps and serves them, the CLI verifies
//! them. None of that is visible from here — which is what lets every side
//! compute the same digests without agreeing on anything else.

#[cfg(feature = "evaluator")]
pub mod answer;
#[cfg(feature = "storage")]
pub mod archive;
pub mod ceiling;
pub mod chain;
pub mod commitment;
pub mod envelope;
pub mod instance;
pub mod record;
#[cfg(feature = "storage")]
pub mod spool;
#[cfg(feature = "stream")]
pub mod stream;

pub use permguard_canonical::jcs;
pub use permguard_canonical::merkle;

pub use chain::{ChainError, Verified};
pub use commitment::Commitment;
pub use envelope::{Batch, Envelope, EnvelopeError, Signed};
pub use record::{Body, GENESIS, Record, Stream, digest_of};
#[cfg(feature = "storage")]
pub use spool::{Spool, SpoolError, State};
