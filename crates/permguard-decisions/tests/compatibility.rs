// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_decisions::commitment::Commitment;
use permguard_decisions::record::{Record, VERSION};
use permguard_decisions::{chain, record};
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    let text = match name {
        "marker" => include_str!("fixtures/compat/v1/marker-record.json"),
        "decision" => include_str!("fixtures/compat/v1/decision-record-with-extra.json"),
        other => panic!("unknown fixture {other}"),
    };

    serde_json::from_str(text).expect("fixture is json")
}

fn fixture_value(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .expect("fixture has a value")
}

#[test]
fn v1_decision_log_fixtures_replay_with_the_current_verifier() {
    let marker = fixture("marker");
    let decision = fixture("decision");

    let marker_digest = record::digest_of(&marker).expect("marker digests");
    let decision_digest = record::digest_of(&decision).expect("decision digests");

    assert_eq!(
        marker_digest,
        include_str!("fixtures/compat/v1/marker-record.sha256").trim()
    );
    assert_eq!(
        decision_digest,
        include_str!("fixtures/compat/v1/decision-record-with-extra.sha256").trim()
    );

    let records = vec![marker.clone(), decision.clone()];
    let verified = chain::verify(&records, None).expect("fixtures form a chain");

    assert_eq!(verified.first_seq, 1);
    assert_eq!(verified.last_seq, 2);
    assert_eq!(
        verified.head,
        include_str!("fixtures/compat/v1/head.sha256").trim()
    );

    let parsed: Record = serde_json::from_value(decision.clone()).expect("old record parses");
    assert_eq!(parsed.v, VERSION);

    let mut without_extra = decision;
    without_extra
        .as_object_mut()
        .expect("record is an object")
        .remove("retained_by_newer_producer");
    assert_ne!(
        record::digest_of(&without_extra).expect("edited record digests"),
        verified.head,
        "unknown fields are still part of the verbatim digest"
    );
}

#[test]
fn v1_commitment_fixture_stays_stable() {
    let scheme = Commitment::new(b"compatibility-key-v1", "v1");
    let committed = scheme
        .commit(&json!({
            "department": "finance",
            "risk": 3,
            "zone": "acme"
        }))
        .expect("commitment is canonical");

    assert_eq!(
        committed,
        fixture_value(include_str!("fixtures/compat/v1/context-commitment.txt"))
    );
}
