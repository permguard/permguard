#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane's domain: the mirrors that keep the verified policies current, the evaluation
//! pipeline and its authorization, the decision log and the temporal history. It serves nothing
//! and listens nowhere; its routes over HTTP and gRPC, its module for the composition and its
//! binary are `permguard-data-plane-server`'s (the crate boundaries refactoring, RD-2).

pub mod authz;
pub mod blocking;
pub mod decisions;
pub mod evaluation;
pub mod handles;
pub mod mirrors;
pub mod plane;
pub mod temporal;

/// The Plane's id, as configuration spells it.
pub const PLANE: &str = "data";
/// The component name its logs and metrics carry.
pub const COMPONENT: &str = "data-plane";

/// Reports a panic by where it happened, never by what it said: the first call of every binary that
/// hosts this plane, after [`serve_if_worker`].
pub use permguard_languages::guard::report_panics_without_their_words;
/// Serves as a supervised evaluation worker, and exits, when this process was started as one: the
/// first call of every binary that hosts this plane.
pub use permguard_languages::worker::serve_if_worker;
