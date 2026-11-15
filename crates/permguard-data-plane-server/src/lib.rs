#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane served: its routes over HTTP and gRPC, the documents that describe it, its
//! module for the composition and the `permguard-data-plane` binary that registers it. What it
//! serves, the mirrors, the evaluation and its authorization, the decision log and the temporal
//! history, is `permguard-data-plane`'s (the crate boundaries refactoring, RD-2).

mod api;
mod body;
mod service;
/// The generated `permguard.data.v1` server stubs, compiled from the one `contracts/proto/` root.
///
/// Public because they *are* the contract this plane serves: a test that drives the PDP over a
/// real socket needs the same service definition the server mounts, and a hand-written stand-in
/// would prove only that the stand-in works.
pub mod v1;

/// The domain's authorization, with the routes that serve it and the answer each transport gives
/// a refusal.
pub mod authz {
    pub use permguard_data_plane::authz::*;

    pub mod gate;
    pub mod grpc;
    pub mod http;
    pub mod translate;
}

/// The domain's temporal history, with the routes that take its submissions.
pub mod temporal {
    pub use permguard_data_plane::temporal::*;

    pub mod grpc;
    pub mod http;
}

/// The domain the routes serve, under the names the routes were written against.
use permguard_data_plane::{COMPONENT, PLANE, evaluation, handles};

pub use permguard_data_plane::{report_panics_without_their_words, serve_if_worker};
pub use service::{DataPlaneModule, module};
