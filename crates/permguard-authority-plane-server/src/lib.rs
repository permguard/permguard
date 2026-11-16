#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane served (`2-security/8` Where it runs): its routes over HTTP and gRPC, the
//! documents that describe it, its module for the composition, and the `permguard-authority-plane`
//! binary that registers it alone. What it serves, the accounts, the access keys, the tokens and
//! the lists, is `permguard-authority-plane`'s (the crate boundaries refactoring, RD-1).

mod grpc;
mod http;
mod module;
mod wire;

#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod v1 {
    pub use permguard_contracts::authority::v1::*;
}

/// The domain the routes serve, under the names the routes were written against.
use permguard_authority_plane::{COMPONENT, PLANE, authority};

pub use module::{AuthorityPlaneModule, module};
