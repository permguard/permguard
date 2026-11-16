// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The policy decision point's kernel, over the contracts of `permguard-language-core`: how one
//! question reaches the partitions of a profile ([`route::Route`]), and how their evaluations run,
//! together, in order, bounded by the deadline, the panic boundary and the stack headroom
//! ([`evaluate_all`], [`fanout`]).
//!
//! What a compiled partition is, the evaluating and the remembering contracts, the engine value
//! and the budget of the histories kept warm, is `permguard-language-core`'s, since a language
//! package implements it: it is named here, where everything that evaluates already looks for it.
//!
//! A language's validating half needs none of this package: a build that only validates, as the
//! Control Plane's ingest does, links every language without it (the crate boundaries
//! refactoring, RD-6).

pub mod evaluate;
pub mod fanout;
pub mod route;

/// The engine value, both halves of one language: `permguard-language-core`'s.
pub use permguard_language_core::engine;
/// The remembering role of a temporal partition: `permguard-language-core`'s.
pub use permguard_language_core::remembering as temporal;
/// The budget of the histories kept warm: `permguard-language-core`'s.
pub use permguard_language_core::warm;

pub use engine::Engine;
pub use evaluate::{Answered, Evaluating, Evaluator, evaluate_all};
pub use route::{PartitionTarget, Route};
