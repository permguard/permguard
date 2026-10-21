// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use super::*;

/// WP-7.4a, after the review: the interface this plane serves here is one the stage registry
/// serves, or its link would vanish from the plane document and its own document refuse.
#[test]
fn the_served_interface_is_in_the_stage_registry() {
    assert!(permguard_core::stages::served(super::super::read::API).is_ok());
}

fn parsed(base: &str) -> serde_json::Value {
    serde_json::to_value(document(
        base,
        "test-store",
        permguard_core::stages::Describer::detached("control-plane")
            .header(permguard_core::domains::interface::DECISIONS_NATIVE_V1)
            .expect("served"),
    ))
    .expect("the document serializes")
}

/// WP-6.3b: every endpoint is the path the router mounts, on the base the plane is reached at.
#[test]
fn every_decision_endpoint_is_a_path_the_router_mounts() {
    let document = parsed("http://host/");
    for (member, path) in [
        ("batches", super::super::http::BATCHES_PATH),
        ("records", super::super::http::RECORDS_PATH),
        ("tenant_records", super::super::http::TENANT_RECORDS_PATH),
        ("signers", super::super::http::SIGNERS_PATH),
    ] {
        assert_eq!(
            document["endpoints"][member],
            format!("http://host{path}"),
            "{member}"
        );
    }
    assert!(
        document["endpoints"]["tenant_records"]
            .as_str()
            .is_some_and(|template| template.contains("{zone}") && template.contains("{ledger}"))
    );
}

/// WP-6.3b, owner decision of 2026-10-20: the document names its interface, the capabilities
/// that hold, an opaque offset of its own family, the read parameters and the page ceilings, and
/// matches its OpenAPI schema.
#[test]
fn the_decision_document_names_its_interface_and_capabilities() {
    let document = parsed("http://host");
    assert_eq!(
        document["interface"],
        permguard_core::domains::interface::DECISIONS_NATIVE_V1
    );
    assert_eq!(document["store"], "test-store");
    assert_eq!(
        document["capabilities"],
        serde_json::json!([
            "atomic-batches",
            "idempotent-ingest",
            "attributed-records",
            "authenticated-offsets",
            "read-coverage",
            "tenant-scoped-reads"
        ])
    );
    assert_eq!(document["offsets"]["api"], document["interface"]);
    assert_eq!(document["offsets"]["format"], "opaque");
    assert_eq!(document["offsets"]["editable"], false);
    assert_eq!(
        document["read_parameters"]
            .as_array()
            .map(|held| held.len()),
        Some(9)
    );
    assert_eq!(
        document["limits"]["max_records"],
        permguard_stream::window::MAX_RECORDS as u64
    );
    permguard_conformance::schema::Document::load("evidence-decisions.json")
        .check_json("ConfigurationDocument", &document);
}
