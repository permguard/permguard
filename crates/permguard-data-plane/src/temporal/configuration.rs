// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane publishes about the temporal interface.
//!
//! The third layer of the discovery chain, beside the stateless interface's own document: the
//! process says which planes it runs, a plane says which interfaces it serves, and an interface
//! document says what that interface offers *here*. A caller that found this document has already
//! been told, twice, that it exists.
//!
//! Everything in it is linked against the constants the routes are mounted from and the event
//! types the registry carries, so the document cannot advertise a path this plane does not answer
//! or an event type it would refuse.

use serde::{Deserialize, Serialize};

use permguard_languages::temporal;

/// Where a data plane publishes what this interface offers.
pub const CONFIGURATION_PATH: &str = "/.well-known/permguard-pdp-temporal-v1alpha1-configuration";

/// What this plane publishes about `permguard.api.pdp.temporal.v1alpha1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// The contract and its version.
    pub interface: String,
    /// This PDP's identifier.
    pub pdp: String,
    pub endpoints: Endpoints,
    /// The registered occurrence contracts this plane accepts.
    ///
    /// A list, not a single value, because the interface admits more than one and this build
    /// implements one. A caller reads what is here rather than assuming what is here.
    pub event_types: Vec<String>,
    /// Every entry is implemented and tested here. A capability is a promise.
    pub capabilities: Vec<String>,
    pub store_scope: StoreScope,
}

/// Where an occurrence is submitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoints {
    pub submission: String,
}

/// Which fields name the policy store, and whether a caller must state them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreScope {
    /// Where the store is named: `payload` — never the URL.
    pub r#in: String,
    pub zone: String,
    pub ledger: String,
    pub profile: String,
}

/// The document for a plane reached at `base`.
pub fn document(base: &str, pdp: &str) -> Document {
    let base = base.trim_end_matches('/');

    Document {
        interface: temporal::INTERFACE.to_owned(),
        pdp: pdp.to_owned(),
        endpoints: Endpoints {
            // Built from the constant the router mounts, so the two cannot drift.
            submission: format!("{base}{}", temporal::SUBMISSION_PATH),
        },
        // Read off the registry rather than written here: a build that gains an occurrence
        // contract advertises it, and one that does not cannot claim it.
        event_types: vec![permguard_languages::event::EVENT_TYPE.to_owned()],
        capabilities: temporal::CAPABILITIES
            .iter()
            .map(|held| (*held).to_owned())
            .collect(),
        store_scope: StoreScope {
            r#in: "payload".to_owned(),
            zone: "required".to_owned(),
            ledger: "required".to_owned(),
            profile: "optional".to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn parsed(base: &str) -> serde_json::Value {
        serde_json::to_value(document(base, "test-plane")).expect("the document serializes")
    }

    #[test]
    fn the_endpoint_is_the_path_the_router_mounts() {
        let document = parsed("http://host/");

        assert_eq!(
            document["endpoints"]["submission"],
            format!("http://host{}", temporal::SUBMISSION_PATH)
        );
        assert_eq!(document["interface"], temporal::INTERFACE);
    }

    #[test]
    fn it_advertises_the_event_types_this_build_actually_accepts() {
        let document = parsed("http://host");

        assert_eq!(
            document["event_types"],
            serde_json::json!([permguard_languages::event::EVENT_TYPE])
        );
    }

    /// The store is named in the payload, like the stateless interface's — never in the URL.
    #[test]
    fn the_store_is_named_in_the_payload() {
        assert_eq!(parsed("http://host")["store_scope"]["in"], "payload");
    }
}
