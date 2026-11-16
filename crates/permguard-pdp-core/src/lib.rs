// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The policy decision point's evaluating half, over the contracts of `permguard-language-core`:
//! what a compiled partition is ([`Evaluating`], [`Evaluator`], [`temporal::Temporal`]), how one
//! question reaches the partitions of a profile ([`route::Route`]), and how their evaluations run —
//! together, in order, bounded by the deadline, the panic boundary and the stack headroom
//! ([`evaluate_all`], [`fanout`]) — and how the histories they keep warm are charged ([`warm`]).
//!
//! A language's validating half needs none of it: a build that only validates, as the Control
//! Plane's ingest does, links every language without this package (the crate boundaries
//! refactoring, RD-6).

pub mod evaluate;
pub mod fanout;
pub mod guard;
pub mod route;
pub mod temporal;
pub mod warm;

pub use evaluate::{Answered, Evaluating, Evaluator, evaluate_all};
pub use route::{PartitionTarget, Route};
