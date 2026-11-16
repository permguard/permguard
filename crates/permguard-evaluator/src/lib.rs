// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision alone, for an application that embeds no Data Plane ([`Evaluator`], [`kernel`]),
//! and the policy decision point's kernel a Data Plane is built on: how one
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

/// The engines this build selected, each by its feature: an application that names this package
/// alone registers them from here, and one that named no language finds none.
pub mod engines {
    /// Cedar, both halves.
    #[cfg(feature = "cedar")]
    pub fn cedar() -> crate::Engine {
        permguard_language_cedar::engine()
    }

    /// Dogwood, both halves. It decides against a history, which the stateless
    /// [`Evaluator`](crate::Evaluator) keeps none of and refuses by name.
    #[cfg(feature = "dogwood")]
    pub fn dogwood() -> crate::Engine {
        permguard_language_dogwood::engine()
    }

    /// Rego, both halves.
    #[cfg(feature = "rego")]
    pub fn rego() -> crate::Engine {
        permguard_language_rego::engine()
    }
}
pub mod evaluate;
pub mod fanout;
pub mod kernel;
pub mod route;

/// The engine value, both halves of one language: `permguard-language-core`'s.
pub use permguard_language_core::engine;
/// The remembering role of a temporal partition: `permguard-language-core`'s.
pub use permguard_language_core::remembering as temporal;
/// The budget of the histories kept warm: `permguard-language-core`'s.
pub use permguard_language_core::warm;

pub use engine::Engine;
pub use evaluate::{Answered, Evaluating, evaluate_all};
pub use kernel::{Builder, Decision, Evaluator, Policies, Provenance, Refused, Request};
/// What a request and an answer are made of, named here so an application that embeds the
/// evaluator alone imports them from it: `permguard-language-core`'s.
pub use permguard_language_core::artifact::Artifacts;
pub use permguard_language_core::evaluate::{Action, Entity, EvaluationError, Outcome, Resolution};
pub use permguard_language_core::input::PartitionData;
pub use route::{PartitionTarget, Route};
