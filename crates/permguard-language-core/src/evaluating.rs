// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The evaluating half of a policy language, as a contract: [`Evaluating`] compiles a partition
//! and [`Evaluator`] answers one query.
//!
//! A language package implements it, so it lives beneath the languages, beside the validating
//! role. What runs it, every partition of a profile together, bounded by the deadline, the panic
//! boundary and the stack headroom, is `permguard-evaluator`'s, which a language package needs for
//! nothing: the kernel selects a language, never the reverse.

use crate::evaluate::{Query, StoredPolicy, Verdict};

/// A compiled, immutable set of policies, ready to answer requests.
///
/// Shared across threads and across requests: everything expensive already
/// happened in [`Evaluating::compile`].
pub trait Evaluator: Send + Sync {
    /// Answers one request. Never errors: a request that cannot be evaluated
    /// is a [`Verdict::Error`], which the profile resolves to indeterminate.
    fn evaluate(&self, query: &Query) -> Verdict;

    /// Checks a materialised input against this partition's compiled schema.
    ///
    /// Run **before any policy is consulted**, which is the difference between a bad request and a
    /// denied one: a caller that sent an entity its schema does not declare has made a mistake
    /// nobody's policy can express an opinion about, and hearing `deny` for it would send them
    /// looking through the rules. The schema is already compiled — this is a check, not a parse.
    ///
    /// The default accepts: a partition whose type has nothing beyond its shape to check has
    /// nothing to do here, and the shape was checked when the input was normalised.
    fn check_input(&self, input: &crate::input::PartitionData) -> Result<(), String> {
        let _ = input;

        Ok(())
    }

    /// The same check, by `deadline`, telling an input refused from a check that could not run.
    ///
    /// `Ok(Ok(()))` admits the input and `Ok(Err(why))` refuses it — the caller's mistake, a
    /// `400`. `Err(why)` is a check that could not run at all — the partition failing, which a
    /// plane answers as `evaluation_indeterminate`. The default runs [`Evaluator::check_input`] in
    /// process, where it always runs; a partition evaluated in a supervised worker overrides it.
    fn check_input_by(
        &self,
        input: &crate::input::PartitionData,
        deadline: Option<std::time::Instant>,
    ) -> Result<Result<(), String>, String> {
        let _ = deadline;

        Ok(self.check_input(input))
    }

    /// How much memory this compiled program holds, for the cache that decides what to keep: a
    /// conservative estimate of what the engine keeps, never below it (LANG-07,
    /// `tests/footprint.rs`). Not the size of the sources, which undercounts by an order of
    /// magnitude.
    fn footprint(&self) -> usize;

    /// The policies it was compiled from, by identity, for a report that has
    /// to say what is loaded.
    fn policies(&self) -> Vec<String>;

    /// The remembering half of this compiled partition, when its runtime has one.
    ///
    /// Asked for, never assumed — exactly like [`Language::authoring`](crate::role::Language) and
    /// [`Language::evaluating`](crate::role::Language). A stateless runtime answers `None`, and a
    /// caller that wanted to submit an event learns so at load rather than by having one accepted
    /// as something else.
    fn temporal(&self) -> Option<&dyn crate::remembering::Temporal> {
        None
    }
}

/// The compiling half: sources in, an [`Evaluator`] out.
pub trait Evaluating: Send + Sync {
    /// Compiles a partition's policies against the artifacts it carries.
    ///
    /// A schema is not decoration: when the partition carries one, every policy is **validated
    /// against it** here, and a policy that does not type-check refuses the load. A ledger that
    /// would evaluate differently than it reads is not one to serve.
    ///
    /// `artifacts` is everything the partition holds that is not a policy, by registered type. A
    /// runtime asks for the types it owns by name; a runtime with one schema asks for one, and a
    /// runtime with an action schema, an event schema, a macro library and provider programs asks
    /// for those — without the signature, or the walk that filled it, knowing either of them.
    fn compile(
        &self,
        policies: &[StoredPolicy],
        artifacts: &crate::artifact::Artifacts,
    ) -> Result<Box<dyn Evaluator>, String>;
}
