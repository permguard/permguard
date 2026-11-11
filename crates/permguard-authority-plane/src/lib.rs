#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane (`2-security/8`): who may call Permguard is decided here. It keeps the
//! service accounts, their scopes and access keys, issues the access tokens, publishes the keys
//! that verify them and the lists that revoke them. Every other Plane, and every Host API,
//! verifies a token by itself, with no call to this plane on the request path.
//!
//! The community edition serves service accounts and their tokens, nothing else; an enterprise
//! Authority Plane adds ways to obtain a token, never another kind of token.

pub mod access_keys;
pub mod accounts;
pub mod admin;
pub mod authority;
pub mod cbor;
mod grpc;
mod http;
mod plane;
pub mod tokens;
mod wire;

#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod v1 {
    tonic::include_proto!("permguard.authority.v1");
}

pub use plane::{AuthorityPlaneModule, issuer_of, module};

/// The plane's id, as `runtime.planes` names it.
pub const PLANE: &str = "authority";
/// The component every record of the plane carries.
pub const COMPONENT: &str = "authority-plane";
