#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Control Plane served: its routes over HTTP and gRPC, the documents that describe it, its
//! module for the composition and the `permguard-control-plane` binary, which registers the
//! Authority Plane beside it. What it serves, the catalog, the ledger store and NOTP, and the
//! evidence stores, is `permguard-control-plane`'s (the crate boundaries refactoring, RD-3).

mod api;
mod members;
mod served;
mod service;
#[cfg(test)]
mod testing;
mod v1;
mod wire;

/// The catalog, with the routes that serve it.
mod catalog {
    pub use permguard_control_plane::catalog::*;

    pub mod grpc;
    pub mod http;
    mod parity;
    pub mod serving;
}

/// The decision store, with the routes that read it.
mod decisions {
    pub use permguard_control_plane::decisions::*;

    pub mod grpc;
    pub mod http;
}

/// The event store, with the routes that read it.
mod events {
    pub use permguard_control_plane::events::*;

    pub mod grpc;
    pub mod http;
    #[cfg(test)]
    mod members_parity;
}

/// The ledger store's protocol, with the routes that carry it.
mod notp {
    pub use permguard_control_plane::notp::*;

    pub mod grpc;
    pub mod http;
}

#[cfg(test)]
use permguard_control_plane::engine;
/// The domain the routes serve, under the names the routes were written against.
use permguard_control_plane::{COMPONENT, PLANE, evidence, handles, query};

pub use service::{ControlPlaneModule, module};
