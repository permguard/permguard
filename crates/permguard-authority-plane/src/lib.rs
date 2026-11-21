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
//!
//! This package is the Plane's domain: it serves nothing and listens nowhere. Its routes over HTTP
//! and gRPC, its module for the composition and its binary are `permguard-authority-plane-server`'s
//! (the crate boundaries refactoring, RD-1).

pub mod access_keys;
pub mod accounts;
pub mod admin;
pub mod authority;
pub mod cbor;
mod handles;
pub mod marks;
pub mod plane;
pub mod tokens;

pub use plane::{Composition, issuer_of};

/// The Plane's id, as configuration spells it.
pub const PLANE: &str = "authority";
/// The component name its logs and metrics carry.
pub const COMPONENT: &str = "authority-plane";
