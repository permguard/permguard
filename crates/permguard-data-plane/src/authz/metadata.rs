// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PDP metadata document, at `/.well-known/authzen-configuration`.
//!
//! # What a document says by leaving something out
//!
//! The standard makes absence meaningful: a PEP learns what a PDP *cannot* do
//! from the endpoints its metadata does not name. So this document names the
//! two evaluation endpoints and **no search endpoints** — that is the whole
//! declaration that the Search APIs are not served here, and it is why we do
//! not have to say it anywhere else.
//!
//! `capabilities` names what this profile adds on top of the standard, in our
//! own namespace: a PEP that knows Permguard reads them, and one that does not
//! ignores them, which is exactly the extension mechanism the standard
//! provides.

use serde::Serialize;

/// What this plane publishes about itself as a PDP.
#[derive(Debug, Clone, Serialize)]
pub struct Metadata {
    /// This PDP's identifier — the base URL the document was fetched from.
    pub policy_decision_point: String,
    pub access_evaluation_endpoint: String,
    pub access_evaluations_endpoint: String,
    /// What this profile adds. Ours, versioned by us.
    pub capabilities: Vec<String>,
    /// The profile these endpoints implement, so a Permguard-aware PEP can
    /// tell which contract it is talking to without probing.
    pub permguard_profile: String,
    /// Where the policy store is named, since it is not the URL here. Stated
    /// rather than implied: a PEP that reads metadata should not have to read
    /// prose to learn that `zone` and `ledger` are required.
    pub permguard_store_scope: String,
}

/// The capability URNs this profile declares.
pub const CAPABILITIES: [&str; 4] = [
    "urn:permguard:authzen:store-in-payload",
    "urn:permguard:authzen:entities",
    "urn:permguard:authzen:principal",
    "urn:permguard:authzen:structured-reasons",
];

/// The profile these endpoints serve.
pub const PROFILE: &str = "permguard.pdp.v1";

/// Builds the document for a plane reached at `base_url`.
pub fn metadata(base_url: &str) -> Metadata {
    let base = base_url.trim_end_matches('/');

    Metadata {
        policy_decision_point: base.to_owned(),
        access_evaluation_endpoint: format!("{base}/access/v1/evaluation"),
        access_evaluations_endpoint: format!("{base}/access/v1/evaluations"),
        capabilities: CAPABILITIES.iter().map(|urn| (*urn).to_owned()).collect(),
        permguard_profile: PROFILE.to_owned(),
        permguard_store_scope: "payload: `zone` and `ledger` are required".to_owned(),
    }
}

/// The document as JSON — what the endpoint answers.
pub fn document(base_url: &str) -> String {
    serde_json::to_string_pretty(&metadata(base_url)).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn the_document_names_the_two_endpoints_and_no_search_ones() {
        let document = document("http://127.0.0.1:7656/");
        let parsed: serde_json::Value =
            serde_json::from_str(&document).expect("the document is JSON");

        assert_eq!(
            parsed["access_evaluation_endpoint"],
            "http://127.0.0.1:7656/access/v1/evaluation"
        );
        assert_eq!(
            parsed["access_evaluations_endpoint"],
            "http://127.0.0.1:7656/access/v1/evaluations"
        );
        assert_eq!(
            parsed["policy_decision_point"], "http://127.0.0.1:7656",
            "the trailing slash is not part of an identifier"
        );
        for absent in [
            "search_subject_endpoint",
            "search_resource_endpoint",
            "search_action_endpoint",
        ] {
            assert!(
                parsed.get(absent).is_none(),
                "absence is the declaration: {absent}"
            );
        }
    }

    #[test]
    fn the_extensions_are_declared_where_a_pep_looks_for_them() {
        let parsed: serde_json::Value =
            serde_json::from_str(&document("http://host")).expect("the document is JSON");

        assert_eq!(parsed["permguard_profile"], PROFILE);
        let capabilities = parsed["capabilities"]
            .as_array()
            .expect("capabilities is an array");
        assert_eq!(capabilities.len(), CAPABILITIES.len());
        assert!(
            capabilities
                .iter()
                .any(|urn| urn == "urn:permguard:authzen:store-in-payload"),
            "the one difference a PEP must know about is declared"
        );
    }
}
