#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane's domain: the mirrors that keep the verified policies current, the evaluation
//! pipeline and its authorization, the decision log and the temporal history. It serves nothing
//! and listens nowhere; its routes over HTTP and gRPC, its module for the composition and its
//! binary are `permguard-data-plane-server`'s (the crate boundaries refactoring, RD-2).
//!
//! # The supported surface
//!
//! What an embedding application builds against is [`embedded`], with the request, response,
//! refusal and health types it re-exports, the two calls a hosting binary makes first,
//! [`serve_if_worker`] and [`report_panics_without_their_words`], and the Plane's names.
//!
//! Every other module is the domain's own, public only because the server adapter is another
//! package: hidden from the documentation, and no part of what a version promises. A test holds
//! the list to that.

#[doc(hidden)]
pub mod authz;
#[doc(hidden)]
pub mod blocking;
#[doc(hidden)]
pub mod decisions;
pub mod embedded;
#[doc(hidden)]
pub mod evaluation;
#[doc(hidden)]
pub mod handles;
#[doc(hidden)]
pub mod mirrors;
#[doc(hidden)]
pub mod plane;
#[doc(hidden)]
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
