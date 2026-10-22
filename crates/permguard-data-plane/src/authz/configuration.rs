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
    /// The common header (WP-7.4a): `version`, `component`, `state`, `stage` and `sunset`.
    #[serde(flatten)]
    pub header: permguard_core::stages::Header,
    /// This PDP's identifier — the base URL the document was fetched from.
    pub pdp: String,
    pub endpoints: Endpoints,
    /// What this interface offers. Every entry is implemented and tested here.
    pub capabilities: Vec<String>,
    pub store_scope: StoreScope,
    /// What one request is held to (WP-7.4a).
    pub limits: Limits,
    /// Whether a request may ask for a signed response (WP-6.6b).
    pub response_signing: ResponseSigningState,
}

/// The closed `response_signing` object: `optional` with the lifetime the server emits and the
/// skew a verifier allows, or `disabled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ResponseSigningState {
    Optional {
        validity_seconds: u32,
        clock_skew_seconds: u32,
    },
    Disabled,
}

impl ResponseSigningState {
    /// The state of `signing`, as this plane offers it.
    pub fn of(signing: Option<&super::signing::ResponseSigning>) -> Self {
        match signing {
            Some(signing) => Self::Optional {
                validity_seconds: u32::try_from(signing.validity.as_secs()).unwrap_or(u32::MAX),
                clock_skew_seconds: u32::try_from(signing.clock_skew.as_secs()).unwrap_or(u32::MAX),
            },
            None => Self::Disabled,
        }
    }
}

/// The ceilings of one request.
#[derive(Debug, Clone, Serialize)]
pub struct Limits {
    /// The most evaluations one boxcar request carries; more is `too_many_evaluations`.
    pub max_evaluations: u64,
}

/// The configuration for a plane reached at `base_url`, its requests held to `max_evaluations`.
pub fn configuration(
    base_url: &str,
    header: permguard_core::stages::Header,
    max_evaluations: usize,
    signing: Option<&super::signing::ResponseSigning>,
) -> Configuration {
    let base = base_url.trim_end_matches('/');
    let mut capabilities: Vec<String> = CAPABILITIES.iter().map(|urn| (*urn).to_owned()).collect();
    // Listed exactly when a request may ask for it: a capability listed and refused is a defect.
    if signing.is_some() {
        capabilities.push(permguard_core::domains::capability::PDP_V1_SIGNED_RESPONSE.to_owned());
    }

    Configuration {
        interface: INTERFACE,
        header,
        pdp: base.to_owned(),
        endpoints: Endpoints {
            evaluation: format!("{base}{EVALUATION_PATH}"),
            evaluations: format!("{base}{EVALUATIONS_PATH}"),
        },
        capabilities,
        store_scope: StoreScope {
            r#in: "payload",
            zone: "required",
            ledger: "required",
            // Absent means `default`, which is a profile every ledger declares or is refused for.
            profile: "optional",
        },
        limits: Limits {
            max_evaluations: max_evaluations as u64,
        },
        response_signing: ResponseSigningState::of(signing),
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
pub fn document(
    base_url: &str,
    header: permguard_core::stages::Header,
    max_evaluations: usize,
    signing: Option<&super::signing::ResponseSigning>,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&configuration(base_url, header, max_evaluations, signing))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn parsed(base: &str) -> serde_json::Value {
        serde_json::from_str(
            &document(
                base,
                permguard_core::stages::Describer::detached("data-plane")
                    .header(permguard_core::domains::interface::PDP_NATIVE_V1)
                    .expect("served"),
                100,
                None,
            )
            .expect("it serializes"),
        )
        .expect("the document is JSON")
    }

    /// WP-7.4a, after the review: the interface this plane serves here is one the stage registry
    /// serves, or its link would vanish from the plane document and its own document refuse.
    #[test]
    fn the_served_interface_is_in_the_stage_registry() {
        assert!(permguard_core::stages::served(permguard_languages::request::INTERFACE).is_ok());
    }

    /// WP-7.4a, owner decision of 2026-10-21: the document carries the common header and the
    /// boxcar bound it enforces.
    #[test]
    fn every_interface_document_carries_the_common_header() {
        let document = parsed("http://host");
        assert_eq!(document["component"], "data-plane");
        assert_eq!(document["state"], "bootstrap");
        assert_eq!(document["stage"], "v1");
        assert_eq!(document["version"], "");
        assert!(
            document.get("sunset").is_none(),
            "only a deprecated interface has one"
        );
        assert_eq!(document["limits"]["max_evaluations"], 100);
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
        let document = parsed("http://127.0.0.1:7443/");

        assert_eq!(
            document["endpoints"]["evaluation"],
            format!("http://127.0.0.1:7443{EVALUATION_PATH}")
        );
        assert_eq!(
            document["endpoints"]["evaluations"],
            format!("http://127.0.0.1:7443{EVALUATIONS_PATH}")
        );
        assert_eq!(
            document["pdp"], "http://127.0.0.1:7443",
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
