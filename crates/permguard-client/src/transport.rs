// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which transport a URL names, and the refusal of one this build does not carry.
//!
//! One URL, and the scheme decides the transport: `http` and `https` ride the REST surface, `grpc`
//! and `grpcs` the gRPC one. Each transport is a feature of this package, so a build may carry one
//! alone; a URL naming the other is refused here, by name, never answered over the one compiled in.

// A helper every surface shares is idle in a build that selects the few that do not call it.
#![cfg_attr(not(feature = "full"), allow(dead_code, unused_imports))]

/// Whether the URL's scheme names the gRPC transport.
pub fn is_grpc(url: &str) -> bool {
    url.starts_with("grpc://") || url.starts_with("grpcs://")
}

/// The refusal of a gRPC URL by a build with no gRPC transport.
#[cfg(not(feature = "grpc"))]
pub(crate) fn no_grpc(url: &str) -> String {
    format!(
        "`{url}` names the gRPC transport, and this build of the client carries the REST one \
         alone: use an `https://` address, or a build with the `grpc` feature"
    )
}

/// The refusal of a REST URL by a build with no REST transport.
#[cfg(not(feature = "http"))]
pub(crate) fn no_http(url: &str) -> String {
    format!(
        "`{url}` names the REST transport, and this build of the client carries the gRPC one \
         alone: use a `grpcs://` address, or a build with the `http` feature"
    )
}
