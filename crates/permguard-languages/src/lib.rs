// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The built-in policy languages: Cedar, Rego and Dogwood.
//!
//! Split by role, because the two sides of the product ask a language
//! different things:
//!
//! | Role | Who asks | What it answers |
//! | --- | --- | --- |
//! | [`Language`] | both sides | is this legal, and what alias does the source declare — the base every consumer needs |
//! | [`Authoring`] | the CLI | split a source file into the policies it holds — the server never reads files |
//! | [`Evaluating`] | the data plane | compile a partition once, then decide — the PDP's half, which no ingest path can reach |
//! | [`temporal::Temporal`] | the data plane | remember: check an occurrence against the loaded schemas, then observe and decide it |
//!
//! Nothing here is visible to the object model: what an object *is* — bytes,
//! digests, trees, identity, signatures — knows no language, so a language
//! pack from anywhere can plug in without the model changing. The dispatch
//! that turns "this media type" into "ask that language" lives in
//! [`registry`], on this side of the boundary.
//!
//! Languages are **compiled in, never loaded**: a language is a build, not a
//! deployment action, so what interprets policy is exactly what was
//! reviewed, signed and shipped.

// The languages themselves are internals: they are reached through the roles
// and the lookups, never by name. Keeping them private is what makes the role
// split a rule the compiler enforces — an ingest path cannot get hold of
// `Cedar` and call the splitter on it.
mod cedar;
mod dogwood;
mod rego;

pub mod artifact;
pub mod evaluate;
pub mod fanout;
pub mod headroom;
pub mod input;
pub mod lookup;
pub mod manifest_file;
pub mod partition;
pub mod registry;
pub mod request;
pub mod role;
pub mod temporal;

pub use dogwood::artifacts as dogwood_artifacts;
pub use dogwood::occurrence::{
    self as event, EntityRef, EntityUidBody, Occurrence, OccurrenceBody,
};
pub use dogwood::{NAME as DOGWOOD, POLICY_MEDIA_TYPE as MEDIA_TYPE_POLICY_DOGWOOD};
pub use evaluate::{
    Action, Entity, Evaluating, Evaluator, Outcome, Query, StoredPolicy, Verdict, resolve,
};
pub use input::{PartitionData, PartitionInputBody, input_type, input_types};
pub use lookup::{language, language_for_media_type, languages};
pub use registry::evaluating;
pub use request::{
    Asked, CheckRequest, CheckResponse, Decision, DecisionContext, Malformed, Semantic,
};
pub use role::{Authoring, ExtractedPolicy, Language};

/// The furthest back a Dogwood partition may look when its schema says nothing.
///
/// Exposed so a deployment's journal bounds can be checked against it at startup rather than at
/// the first submission: a plane whose retention is shorter than the runtimes it carries would
/// refuse every ledger, and finding that out at boot is the difference between a configuration
/// error and an outage.
pub fn dogwood_default_max_window_seconds() -> i64 {
    dogwood::compiled::DEFAULT_MAX_WINDOW_SECONDS
}
