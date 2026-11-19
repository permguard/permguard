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
    let scheme = url
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_default();
    scheme == "grpc" || scheme == "grpcs"
}

/// Whether a discovery document is the control plane's: a remote is the plane that clones and
/// applies ledgers, and another Permguard plane is refused by name, on both transports (BUG-0022,
/// DEC-0005).
pub(crate) fn control_plane_document(body: &[u8]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| format!("the discovery document does not parse: {error}"))?;
    match value.get("plane").and_then(|plane| plane.as_str()) {
        None => Err("this endpoint answers, but not with a Permguard plane".to_owned()),
        Some("control-plane") => Ok(()),
        Some(other) => Err(format!(
            "this endpoint is the Permguard `{other}`, and a remote is the control plane, which \
             clones and applies ledgers: name the control plane's endpoint"
        )),
    }
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
