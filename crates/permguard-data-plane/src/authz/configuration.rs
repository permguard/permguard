// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a data plane publishes about the interface it serves, at
//! [`permguard_languages::request::CONFIGURATION_PATH`].
//!
//! # Three documents, three questions
//!
//! Discovery is layered, and each layer answers a different question, so a caller is handed one
//! URL and finds the rest:
//!
//! | Document | Question |
//! | --- | --- |
//! | `/.well-known/server-configuration` on the process | which planes does this process host, and where are they |
//! | `/.well-known/server-configuration` on a plane | who is this plane, what keys does it sign with, and which interfaces does it expose |
//! | `/.well-known/permguard-pdp-v1-configuration` | what does `permguard.api.pdp.native.v1` offer here |
//!
//! The plane's own document links to this one, so a caller that does not already know the
//! interface can find it. A caller that *does* — Permguard's own client, which is versioned
//! against the native interface — links against the same constants the routes are mounted from and
//! posts straight to them.
//!
//! # It is ours, and it says so
//!
//! `interface` names the contract and its version in one field. This document is not a profile of
//! anybody else's specification and does not borrow field names from one: what is served here is
//! the native interface, defined in [`permguard_languages::request`], and a caller reading this
//! learns exactly what that offers rather than what some other document might have led them to
//! assume.
//!
//! # The endpoints are the routes
//!
//! Both come from the same constants the router mounts, so the document cannot advertise a path
//! this plane does not answer. That is worth more than a test asserting they match, because it is
//! not a thing anybody can forget to keep in step.

use serde::Serialize;

pub use permguard_languages::request::{
    CAPABILITIES, CONFIGURATION_PATH, EVALUATION_PATH, EVALUATIONS_PATH, INTERFACE,
};

/// Where one question is asked, and where many are.
#[derive(Debug, Clone, Serialize)]
pub struct Endpoints {
    pub evaluation: String,
    pub evaluations: String,
}

/// Which fields name the policy store, and whether a caller must state them.
///
/// Stated rather than implied: a caller reading a discovery document should not have to read prose
/// to learn that `zone` and `ledger` are required in the body.
#[derive(Debug, Clone, Serialize)]
pub struct StoreScope {
    /// Where the store is named. `payload`, here — never the URL.
    pub r#in: &'static str,
    pub zone: &'static str,
    pub ledger: &'static str,
    pub profile: &'static str,
}

/// What this plane publishes about the interface it serves.
#[derive(Debug, Clone, Serialize)]
pub struct Configuration {
    /// The contract and its version: `permguard.api.pdp.native.v1`.
    pub interface: &'static str,
    /// This PDP's identifier — the base URL the document was fetched from.
    pub pdp: String,
    pub endpoints: Endpoints,
    /// What this interface offers. Every entry is implemented and tested here.
    pub capabilities: Vec<String>,
    pub store_scope: StoreScope,
}

/// The configuration for a plane reached at `base_url`.
pub fn configuration(base_url: &str) -> Configuration {
    let base = base_url.trim_end_matches('/');

    Configuration {
        interface: INTERFACE,
        pdp: base.to_owned(),
        endpoints: Endpoints {
            evaluation: format!("{base}{EVALUATION_PATH}"),
            evaluations: format!("{base}{EVALUATIONS_PATH}"),
        },
        capabilities: CAPABILITIES.iter().map(|urn| (*urn).to_owned()).collect(),
        store_scope: StoreScope {
            r#in: "payload",
            zone: "required",
            ledger: "required",
            // Absent means `default`, which is a profile every ledger declares or is refused for.
            profile: "optional",
        },
    }
}

/// The document as JSON, for a caller that wants the text rather than the value — a test
/// comparing two transports, say.
///
/// The HTTP route does **not** go through here: it answers with the value and lets the response
/// type serialize it. This used to fall back to `"{}"` when serialization failed, which would have
/// answered `200` with a configuration describing an interface that offers nothing — a caller
/// would have configured itself from it and found no endpoints, with no error anywhere to explain
/// why.
pub fn document(base_url: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&configuration(base_url))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn parsed(base: &str) -> serde_json::Value {
        serde_json::from_str(&document(base).expect("it serializes")).expect("the document is JSON")
    }

    #[test]
    fn the_document_says_exactly_which_interface_it_describes() {
        assert_eq!(
            parsed("http://host")["interface"],
            permguard_languages::request::INTERFACE
        );
    }

    #[test]
    fn the_endpoints_are_the_ones_the_router_mounts() {
        let document = parsed("http://127.0.0.1:7656/");

        assert_eq!(
            document["endpoints"]["evaluation"],
            format!("http://127.0.0.1:7656{EVALUATION_PATH}")
        );
        assert_eq!(
            document["endpoints"]["evaluations"],
            format!("http://127.0.0.1:7656{EVALUATIONS_PATH}")
        );
        assert_eq!(
            document["pdp"], "http://127.0.0.1:7656",
            "the trailing slash is not part of an identifier"
        );
    }

    #[test]
    fn the_store_scope_is_stated_rather_than_left_to_prose() {
        let scope = &parsed("http://host")["store_scope"];

        assert_eq!(scope["in"], "payload");
        assert_eq!(scope["zone"], "required");
        assert_eq!(scope["ledger"], "required");
        assert_eq!(scope["profile"], "optional");
    }

    /// Every capability is Permguard's own, named for the interface it belongs to.
    #[test]
    fn the_capabilities_are_this_interfaces_own() {
        let document = parsed("http://host");
        let capabilities = document["capabilities"]
            .as_array()
            .expect("capabilities is an array");

        assert_eq!(capabilities.len(), CAPABILITIES.len());
        for capability in capabilities {
            let urn = capability.as_str().expect("a URN is a string");
            assert!(
                urn.starts_with("urn:permguard:pdp:v1:"),
                "a capability of this interface is named for it: {urn}"
            );
        }
    }
}
