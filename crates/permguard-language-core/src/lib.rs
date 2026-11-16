// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a policy language is to Permguard, without any language in it: the roles a language
//! answers ([`Language`], [`Authoring`]), the artifacts a partition carries, the descriptor that
//! pins an engine build, the request model — the queries, verdicts and their combination, the
//! attestation, the temporal interface's wire model — and the occurrence that interface takes.
//! The evaluating half, and the path every evaluation takes, are `permguard-evaluator`'s.
//!
//! An engine (`permguard-language-cedar`, `-rego`, `-dogwood`) implements these roles and nothing
//! else; `permguard-languages` holds the catalogue of the engines a build carries and every rule
//! over them (the crate boundaries refactoring, RD-6). The occurrence's values are Dogwood's value
//! domain, held here variant for variant ([`value::Value`]) so this package links no engine: the
//! Dogwood package converts them where its authorizer reads them.

pub mod artifact;
pub mod attestation;
pub mod descriptor;
pub mod evaluate;
pub mod guard;
pub mod headroom;
pub mod input;
pub mod names;
pub mod occurrence;
pub mod partition;
pub mod registry;
pub mod request;
pub mod role;
pub mod temporal;
pub mod value;

pub use evaluate::{
    Action, Entity, EvaluationError, Outcome, Query, Resolution, StoredPolicy, Verdict, resolve,
};
pub use input::{PartitionData, PartitionInputBody, input_type, input_types};
pub use occurrence::{
    self as event, EntityRef, EntityUidBody, Occurrence, OccurrenceBody, OccurrenceBodyV2,
};
pub use request::{
    Asked, CheckRequest, CheckResponse, Decision, DecisionContext, Malformed, Semantic,
};
pub use role::{Authoring, ExtractedPolicy, Language};
