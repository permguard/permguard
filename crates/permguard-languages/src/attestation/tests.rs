// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-6.6a: the nonce, the evidence object and the two digests. The golden digests were computed
//! apart from this code, over the normalized values written out below, by a JCS that sorts members
//! and writes no white space (these values hold strings, booleans and objects only).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::json;

use super::*;
use crate::request::{DecisionContext, Reason};

const NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";

#[test]
fn a_nonce_is_canonical_base64url_of_16_to_64_bytes() {
    let encode =
        |length: usize| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![7_u8; length]);
    assert_eq!(
        nonce_bytes(NONCE).expect("16 bytes"),
        (0..16).collect::<Vec<u8>>()
    );
    assert_eq!(nonce_bytes(&encode(64)).expect("64 bytes").len(), 64);
    for (nonce, why) in [
        (encode(15), "too short"),
        (encode(65), "too long"),
        (format!("{NONCE}=="), "padded"),
        (NONCE.replace('A', "+"), "standard alphabet"),
        // 16 bytes end on two bits of the last character: `x` sets one of the four that must be
        // zero, so the same bytes would have two encodings.
        (format!("{}x", &NONCE[..21]), "non-canonical trailing bits"),
        (String::new(), "empty"),
    ] {
        assert!(nonce_bytes(&nonce).is_err(), "{why}: {nonce}");
    }
}

fn position() -> Position {
    Position {
        host_id: "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
        run: "0102030405060708090a0b0c0d0e0f10".to_owned(),
        sequence: "7".to_owned(),
    }
}

#[test]
fn the_evidence_object_agrees_with_its_mode_and_names_a_record_only_when_durable() {
    let durable = Evidence::durable(EvidenceMode::Required, "dec-1".to_owned(), position());
    durable.check(false).expect("required and durable");
    Evidence::disabled()
        .check(true)
        .expect("disabled and disabled");
    Evidence::unrecorded(EvidenceMode::BestEffort, EvidenceStatus::SampledOut)
        .check(true)
        .expect("a sampled permit");
    Evidence::unrecorded(EvidenceMode::BestEffort, EvidenceStatus::Dropped)
        .check(false)
        .expect("a counted loss");
    assert_eq!(
        serde_json::to_value(&durable).expect("JSON"),
        json!({
            "mode": "required",
            "status": "durable",
            "record_id": "dec-1",
            "position": {
                "host_id": "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
                "run": "0102030405060708090a0b0c0d0e0f10",
                "sequence": "7",
            },
        })
    );
    assert_eq!(
        serde_json::to_value(Evidence::disabled()).expect("JSON"),
        json!({"mode": "disabled", "status": "disabled", "record_id": null, "position": null}),
        "every member present"
    );

    let refused = [
        (
            Evidence::unrecorded(EvidenceMode::Required, EvidenceStatus::SampledOut),
            true,
            "required answers only durable",
        ),
        (
            Evidence::unrecorded(EvidenceMode::Disabled, EvidenceStatus::Dropped),
            false,
            "disabled answers only disabled",
        ),
        (
            Evidence::durable(EvidenceMode::Disabled, "dec-1".to_owned(), position()),
            false,
            "no log records nothing",
        ),
        (
            Evidence::unrecorded(EvidenceMode::BestEffort, EvidenceStatus::SampledOut),
            false,
            "only a permit is sampled out",
        ),
        (
            Evidence {
                position: None,
                ..durable.clone()
            },
            false,
            "durable without a position",
        ),
        (
            Evidence {
                record_id: Some("dec-1".to_owned()),
                ..Evidence::disabled()
            },
            false,
            "a record named by a status that has none",
        ),
        (
            Evidence {
                position: Some(Position {
                    host_id: "0193A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B".to_owned(),
                    ..position()
                }),
                ..durable.clone()
            },
            false,
            "an uppercase UUID",
        ),
        (
            Evidence {
                position: Some(Position {
                    sequence: "07".to_owned(),
                    ..position()
                }),
                ..durable.clone()
            },
            false,
            "a leading zero",
        ),
        (
            Evidence {
                position: Some(Position {
                    run: "0102".to_owned(),
                    ..position()
                }),
                ..durable
            },
            false,
            "a short run",
        ),
    ];
    for (evidence, permitted, why) in refused {
        assert!(evidence.check(permitted).is_err(), "{why}: {evidence:?}");
    }
}

#[test]
fn a_single_request_normalizes_with_its_defaults_and_digests_as_computed_apart() {
    let request: CheckRequest = serde_json::from_value(json!({
        "zone": "acme",
        "ledger": "main",
        "subject": {"type": "User", "id": "alice"},
        "resource": {"type": "Doc", "id": "d1", "properties": {"owner": "alice"}},
        "action": {"name": "read"},
        "request_nonce": NONCE,
    }))
    .expect("a request");
    assert_eq!(
        normalized(&request),
        json!({
            "interface": INTERFACE,
            "store": {"zone": "acme", "ledger": "main", "profile": "default"},
            "semantic": "execute_all",
            "request_id": null,
            "request_nonce": NONCE,
            "asserted_principal": null,
            "evaluations": [{
                "subject": {"type": "User", "id": "alice"},
                "resource": {"type": "Doc", "id": "d1", "properties": {"owner": "alice"}},
                "action": {"name": "read"},
                "partition_inputs": {},
                "request_id": null,
            }],
        })
    );
    assert_eq!(
        request_digest(&request).expect("a digest"),
        "sha256:8a151b7ee69f585831e71b4ece9799e984ff97b4397120241e68d15972ff566b"
    );
}

#[test]
fn a_boxcar_normalizes_what_each_evaluation_inherits_and_digests_as_computed_apart() {
    let request: CheckRequest = serde_json::from_value(json!({
        "zone": "acme",
        "ledger": "main",
        "profile": "gateway",
        "principal": {"type": "Agent", "id": "bot-7"},
        "subject": {"type": "User", "id": "alice"},
        "action": {"name": "read", "properties": {"mode": "fast"}},
        "context": {"ip": "10.0.0.1"},
        "partition_inputs": {"risk": {"type": crate::input::REGO_DATA_V1, "data": {"score": 3}}},
        "request_id": "batch-1",
        "evaluations": [
            {"resource": {"type": "Doc", "id": "d1"}, "request_id": "a"},
            // Stated, even empty, a field replaces what it would inherit.
            {"resource": {"type": "Doc", "id": "d2"}, "context": {}, "partition_inputs": {},
             "request_id": "b"},
        ],
    }))
    .expect("a request");
    let mut request = request;
    request.options = Some(crate::request::OptionsBody {
        evaluations_semantic: Some(Semantic::DenyOnFirstDeny),
    });
    let value = normalized(&request);
    assert_eq!(
        value["evaluations"][0]["context"],
        json!({"ip": "10.0.0.1"})
    );
    assert_eq!(value["evaluations"][1]["context"], json!({}));
    assert_eq!(value["evaluations"][1]["partition_inputs"], json!({}));
    assert_eq!(
        value["asserted_principal"],
        json!({"type": "Agent", "id": "bot-7"})
    );
    // A subject an evaluation states replaces the one it would inherit.
    let mut own_subject = request.clone();
    own_subject.evaluations[1].subject =
        serde_json::from_value(json!({"type": "User", "id": "bob"})).expect("an entity");
    let replaced = normalized(&own_subject);
    assert_eq!(replaced["evaluations"][0]["subject"]["id"], "alice");
    assert_eq!(replaced["evaluations"][1]["subject"]["id"], "bob");
    assert_eq!(
        request_digest(&request).expect("a digest"),
        "sha256:a188cc8baf23d2be0200ac29c3b4bdaa5e0c7bb223c3a8273e80e2e6b663af0e"
    );

    // Absent and empty are different questions, and so different digests.
    let mut without_context = request.clone();
    without_context.evaluations[1].context = None;
    assert_ne!(
        request_digest(&without_context).expect("a digest"),
        request_digest(&request).expect("a digest")
    );
}

#[test]
fn the_response_digest_covers_the_answer_without_its_attestation() {
    let response = CheckResponse {
        decision: true,
        request_id: Some("r-1".to_owned()),
        context: Some(DecisionContext {
            id: Some("dec-1".to_owned()),
            reason_admin: Some(Reason {
                code: "permit".to_owned(),
                message: "allowed".to_owned(),
            }),
            reason_user: Some(Reason {
                code: "permit".to_owned(),
                message: "allowed".to_owned(),
            }),
            policies: vec!["p-1".to_owned()],
            absent_inputs: Vec::new(),
            evidence: Some(Evidence::durable(
                EvidenceMode::Required,
                "dec-1".to_owned(),
                position(),
            )),
        }),
        evaluations: None,
        attestation: None,
    };
    let digest = response_digest(&response).expect("a digest");
    assert_eq!(
        digest,
        "sha256:687e3ca0c2a79205aa2b272ef19e494eed621743214aeb8a478379733d9bf7c2"
    );
    // What a verifier reads back from the bytes, an attestation beside it removed, digests alike.
    let mut received = serde_json::to_value(&response).expect("JSON");
    received["attestation"] = json!({"protected": "x", "payload": "y", "signature": "z"});
    received
        .as_object_mut()
        .expect("an object")
        .remove("attestation");
    assert_eq!(response_value_digest(&received).expect("a digest"), digest);
}

#[test]
fn the_canonical_forms_are_exact() {
    assert!(is_uuid("0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"));
    assert!(!is_uuid("0193a1b2c3d47e5f8a9b0c1d2e3f4a5b"));
    assert!(is_decimal_u64("0") && is_decimal_u64("18446744073709551615"));
    assert!(!is_decimal_u64("18446744073709551616") && !is_decimal_u64("-1"));
    assert!(!is_decimal_u64("") && !is_decimal_u64("01") && !is_decimal_u64("1.0"));
    assert!(is_sha256(&format!("sha256:{}", "a".repeat(64))));
    assert!(!is_sha256(&format!("sha256:{}", "A".repeat(64))));
    assert!(!is_sha256(&format!("sha512:{}", "a".repeat(64))));
}

#[test]
fn a_padded_or_empty_name_is_the_question_its_trimmed_form_asks() {
    let base = json!({
        "zone": "acme",
        "ledger": "main",
        "subject": {"type": "User", "id": "alice"},
        "resource": {"type": "Doc", "id": "d1"},
        "action": {"name": "read"},
        "request_id": "abc",
    });
    let digest_of = |value: Value| {
        request_digest(&serde_json::from_value::<CheckRequest>(value).expect("a request"))
            .expect("a digest")
    };
    let plain = digest_of(base.clone());
    let mut padded = base.clone();
    padded["zone"] = json!(" acme ");
    padded["request_id"] = json!(" abc ");
    padded["subject"]["id"] = json!("alice ");
    padded["action"]["name"] = json!(" read");
    assert_eq!(digest_of(padded), plain, "trimmed as the plane reads it");

    let mut defaulted = base.clone();
    defaulted["profile"] = json!("default");
    let mut blank = base.clone();
    blank["profile"] = json!("  ");
    assert_eq!(
        digest_of(blank),
        digest_of(defaulted),
        "a blank profile is the default"
    );

    let mut absent = base.clone();
    absent
        .as_object_mut()
        .expect("an object")
        .remove("request_id");
    let mut empty = base;
    empty["request_id"] = json!("");
    assert_eq!(digest_of(empty), digest_of(absent), "an empty id is no id");
}

/// One change to a payload, named.
type Alteration = Box<dyn Fn(&mut Payload)>;

fn payload() -> Payload {
    Payload {
        v: PAYLOAD_VERSION,
        interface: INTERFACE.to_owned(),
        request_digest: format!("sha256:{}", "a".repeat(64)),
        request_nonce: NONCE.to_owned(),
        request_ids: vec![None, Some("two".to_owned())],
        audience: "spiffe://acme/pep".to_owned(),
        policy: Policy {
            authority_host_id: "01937000-0000-7000-8000-00000000a0a0".to_owned(),
            zone_id: "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
            ledger_id: "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c".to_owned(),
            reference: "main".to_owned(),
            commit: format!("sha256:{}", "b".repeat(64)),
            counter: "18446744073709551615".to_owned(),
            profile: "default".to_owned(),
        },
        decision: true,
        response_digest: format!("sha256:{}", "c".repeat(64)),
        evidence: Evidence::durable(EvidenceMode::Required, "dec-1".to_owned(), position()),
        issued_at: "2026-10-22T10:00:00Z".to_owned(),
        expires_at: "2026-10-22T10:05:00Z".to_owned(),
    }
}

#[test]
fn the_payload_is_closed_canonical_and_every_form_is_checked() {
    let held = payload();
    held.check().expect("every form canonical");
    let bytes = held.canonical().expect("JCS");
    let text = String::from_utf8(bytes.clone()).expect("UTF-8");
    assert!(
        text.starts_with(r#"{"audience":"spiffe://acme/pep","decision":true,"evidence":{"#),
        "{text}"
    );
    assert!(text.contains(r#""policy":{"authority_host_id":"#), "{text}");
    assert!(text.contains(r#""ref":"main""#), "{text}");
    assert!(text.contains(r#""request_ids":[null,"two"]"#), "{text}");
    assert!(
        text.contains(r#""counter":"18446744073709551615""#),
        "{text}"
    );
    assert_eq!(
        serde_json::from_slice::<Payload>(&bytes).expect("reads back"),
        held
    );

    let refused: Vec<(&str, Alteration)> = vec![
        ("version", Box::new(|p| p.v = 2)),
        (
            "interface",
            Box::new(|p| {
                p.interface = permguard_core::domains::interface::PDP_TEMPORAL_V1ALPHA1.to_owned()
            }),
        ),
        (
            "request digest",
            Box::new(|p| p.request_digest = "sha256:AA".to_owned()),
        ),
        (
            "response digest",
            Box::new(|p| p.response_digest = format!("sha512:{}", "c".repeat(64))),
        ),
        ("nonce", Box::new(|p| p.request_nonce = "short".to_owned())),
        ("no evaluation", Box::new(|p| p.request_ids.clear())),
        ("no audience", Box::new(|p| p.audience.clear())),
        (
            "authority",
            Box::new(|p| p.policy.authority_host_id = "nope".to_owned()),
        ),
        (
            "zone",
            Box::new(|p| p.policy.zone_id = p.policy.zone_id.to_uppercase()),
        ),
        ("counter", Box::new(|p| p.policy.counter = "01".to_owned())),
        ("commit", Box::new(|p| p.policy.commit = "abc".to_owned())),
        ("ref", Box::new(|p| p.policy.reference.clear())),
        ("evidence", Box::new(|p| p.evidence.position = None)),
        (
            "issued",
            Box::new(|p| p.issued_at = "2026-10-22T10:00:00.5Z".to_owned()),
        ),
        (
            "offset",
            Box::new(|p| p.expires_at = "2026-10-22T12:05:00+02:00".to_owned()),
        ),
        ("order", Box::new(|p| p.expires_at = p.issued_at.clone())),
        (
            "hour 24",
            Box::new(|p| p.expires_at = "2026-10-22T24:00:00Z".to_owned()),
        ),
        (
            "day 32",
            Box::new(|p| p.expires_at = "2026-10-32T10:05:00Z".to_owned()),
        ),
        (
            "second 60",
            Box::new(|p| p.expires_at = "2026-10-22T23:59:60Z".to_owned()),
        ),
    ];
    for (why, alter) in refused {
        let mut altered = payload();
        alter(&mut altered);
        assert!(altered.check().is_err(), "{why}: {altered:?}");
    }
    // Closed: a member the contract does not name is refused at reading.
    let mut extra = serde_json::to_value(payload()).expect("JSON");
    extra["extension"] = json!(true);
    assert!(serde_json::from_value::<Payload>(extra).is_err());
}

#[test]
fn the_response_digest_leaves_the_attestation_out() {
    let mut response = CheckResponse {
        decision: false,
        request_id: None,
        context: None,
        evaluations: None,
        attestation: None,
    };
    let unsigned = response_digest(&response).expect("a digest");
    response.attestation = Some(Attestation {
        protected: "p".to_owned(),
        payload: "q".to_owned(),
        signature: "s".to_owned(),
    });
    assert_eq!(
        response_digest(&response).expect("a digest"),
        unsigned,
        "signing never changes what it signs"
    );
}
