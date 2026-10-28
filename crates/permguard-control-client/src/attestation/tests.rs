// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-6.6c: the signed responses of `contracts/vectors/signed-response.json`, which
//! `signed_response.py` computes apart, reproduced and accepted; and every binding altered on its
//! own.
//!
//! The key is RFC 8032's first Ed25519 test vector, a published throwaway key. Each negative
//! case alters one binding and signs again under that key, so the refusal names the binding and
//! not the signature; the signature itself is altered on its own too.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::json;

use super::*;
use permguard_languages::attestation::{request_digest, response_value_digest};
use permguard_objects::crypto::suite::SigningKey;

/// RFC 8032 section 7.1, test 1: the secret seed.
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// Its public key.
const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const KID: &str = "data-attest-vector-1";
const AUDIENCE: &str = "spiffe://acme/pep";
const NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";
const ISSUED: i64 = 1_790_000_000;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn key() -> SigningKey {
    SigningKey::ed25519_from_seed(&hex(SEED), &hex(PUBLIC)).expect("RFC 8032's key")
}

fn pinned() -> Vec<Jwk> {
    vec![serde_json::from_value(vectors()["key"].clone()).expect("the vector's key")]
}

/// The frozen vectors, as `signed_response.py` printed them.
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/vectors/signed-response.json"
    ))
    .expect("the vector file")
}

fn request() -> Value {
    vectors()["single"]["request"].clone()
}

/// The single answer, as received, without its attestation.
fn answer() -> Value {
    let mut answer = vectors()["single"]["response"].clone();
    answer.as_object_mut().unwrap().remove("attestation");
    answer
}

fn policy() -> Policy {
    serde_json::from_value(vectors()["policy"].clone()).expect("the policy")
}

fn payload_for(_request: &Value, _answer: &Value) -> Value {
    vectors()["single"]["payload"].clone()
}

fn header() -> Value {
    json!({"alg": "EdDSA", "kid": KID, "typ": permguard_core::domains::protected::DECISION_RESPONSE})
}

/// `answer` with an attestation over `payload` and `header`, both written as JCS, signed.
fn signed(answer: &Value, header: &Value, payload: &Value) -> Value {
    let jcs = |value: &Value| permguard_languages::attestation::jcs(value).expect("JCS");
    let protected = b64(&jcs(header));
    let payload = b64(&jcs(payload));
    let signature = key()
        .sign(format!("{protected}.{payload}").as_bytes())
        .expect("signed");
    let mut answer = answer.clone();
    answer["attestation"] =
        json!({"protected": protected, "payload": payload, "signature": b64(&signature)});
    answer
}

fn golden() -> (Vec<u8>, Vec<u8>) {
    let single = &vectors()["single"];
    (
        serde_json::to_vec(&single["request"]).expect("bytes"),
        serde_json::to_vec(&single["response"]).expect("bytes"),
    )
}

fn expectation(policy: &Policy) -> Expectation<'_> {
    let vectors = vectors();
    assert_eq!(vectors["audience"], AUDIENCE);
    Expectation {
        audience: AUDIENCE,
        now: vectors["now"].as_i64().expect("now"),
        validity_seconds: vectors["validity_seconds"].as_u64().expect("validity") as u32,
        clock_skew_seconds: vectors["clock_skew_seconds"].as_u64().expect("skew") as u32,
        policy: Some(policy),
    }
}

fn outstanding() -> Outstanding {
    let mut nonces = Outstanding::default();
    nonces.issue(NONCE);
    nonces
}

fn check(request: &[u8], response: &[u8]) -> Result<Payload, Refused> {
    let policy = policy();
    verify(
        request,
        response,
        &pinned(),
        &expectation(&policy),
        &mut outstanding(),
    )
}

/// Each vector reproduced here, by a second implementation of every rule, and accepted by the
/// verifier a PEP uses: the request and response digests, the header and payload bytes, the
/// signature (Ed25519 is deterministic), and the payload the verifier returns.
#[test]
fn the_frozen_vectors_are_reproduced_and_verify() {
    let vectors = vectors();
    assert_eq!(vectors["key"]["x"], json!(b64(&hex(PUBLIC))));
    assert_eq!(vectors["key"]["kid"], json!(KID));
    let policy = policy();
    for case in ["single", "batch"] {
        let held = &vectors[case];
        let attestation: Value = held["response"]["attestation"].clone();
        let mut answer = held["response"].clone();
        answer.as_object_mut().unwrap().remove("attestation");
        let sent: permguard_languages::CheckRequest =
            serde_json::from_value(held["request"].clone()).expect("a request");
        let payload: Payload = serde_json::from_value(held["payload"].clone()).expect("closed");
        assert_eq!(
            payload.request_digest,
            request_digest(&sent).expect("a digest"),
            "{case}"
        );
        assert_eq!(
            payload.response_digest,
            response_value_digest(&answer).expect("a digest"),
            "{case}"
        );
        let protected = b64(&permguard_languages::attestation::jcs(&header()).expect("JCS"));
        assert_eq!(
            attestation["protected"],
            json!(protected),
            "{case}: the header's bytes"
        );
        assert_eq!(
            attestation["payload"],
            json!(b64(&payload.canonical().expect("JCS"))),
            "{case}: the payload's bytes"
        );
        let signature = key()
            .sign(format!("{protected}.{}", attestation["payload"].as_str().unwrap()).as_bytes())
            .expect("signed");
        assert_eq!(
            attestation["signature"],
            json!(b64(&signature)),
            "{case}: the signature"
        );

        let verified = verify(
            &serde_json::to_vec(&held["request"]).unwrap(),
            &serde_json::to_vec(&held["response"]).unwrap(),
            &pinned(),
            &expectation(&policy),
            &mut outstanding(),
        )
        .unwrap_or_else(|refusal| panic!("{case}: {refusal}"));
        assert_eq!(verified, payload, "{case}");
    }
}

/// A batch: the ids in the answer's order, its last evaluation's evidence, and every
/// evaluation's own evidence bound through the response digest.
#[test]
fn a_batch_binds_its_ids_in_order_and_every_evaluations_evidence() {
    let vectors = vectors();
    let held = &vectors["batch"];
    let request = serde_json::to_vec(&held["request"]).unwrap();
    let mut answer = held["response"].clone();
    answer.as_object_mut().unwrap().remove("attestation");
    let payload = held["payload"].clone();

    let mut reordered = payload.clone();
    reordered["request_ids"] = json!([null, "one"]);
    let response = serde_json::to_vec(&signed(&answer, &header(), &reordered)).unwrap();
    assert_eq!(
        check(&request, &response).unwrap_err().binding,
        "request_ids"
    );

    let mut first = payload.clone();
    first["evidence"] = answer["evaluations"][0]["context"]["evidence"].clone();
    let response = serde_json::to_vec(&signed(&answer, &header(), &first)).unwrap();
    assert_eq!(check(&request, &response).unwrap_err().binding, "evidence");

    let mut changed = held["response"].clone();
    changed["evaluations"][0]["context"]["evidence"]["position"]["sequence"] = json!("99");
    assert_eq!(
        check(&request, &serde_json::to_vec(&changed).unwrap())
            .unwrap_err()
            .binding,
        "response_digest",
        "the first evaluation's evidence is bound too"
    );
}

/// A pinned key of another shape under the kid the header names is no key for this artifact.
#[test]
fn a_pinned_key_of_another_shape_is_refused() {
    let (request, response) = golden();
    let policy = policy();
    let x = b64(&hex(PUBLIC));
    for (key, why) in [
        (
            Jwk::okp(KID, "Ed25519", "ES256", x.clone()),
            "another algorithm",
        ),
        (
            Jwk {
                kty: "EC".to_owned(),
                crv: Some("P-256".to_owned()),
                ..Jwk::okp(KID, "Ed25519", "EdDSA", x.clone())
            },
            "another key type",
        ),
        (
            Jwk::okp(KID, "Ed25519", "EdDSA", b64(&[7; 31])),
            "a short key",
        ),
        (
            Jwk {
                usage: "enc".to_owned(),
                ..Jwk::okp(KID, "Ed25519", "EdDSA", b64(&hex(PUBLIC)))
            },
            "another key purpose",
        ),
        (
            Jwk::okp("revoked-or-stale", "Ed25519", "EdDSA", x),
            "not the pinned kid",
        ),
    ] {
        let refusal = verify(
            &request,
            &response,
            &[key],
            &expectation(&policy),
            &mut outstanding(),
        )
        .expect_err(why);
        assert_eq!(refusal.binding, "key", "{why}: {refusal}");
    }
}

#[test]
fn a_nonce_is_spent_once_and_only_by_a_response_that_verifies() {
    let (request, response) = golden();
    let policy = policy();
    let mut nonces = outstanding();
    // A forged response first: refused, and the nonce stays outstanding.
    let mut forged: Value = serde_json::from_slice(&response).unwrap();
    forged["decision"] = json!(false);
    let forged = serde_json::to_vec(&forged).unwrap();
    let refusal = verify(
        &request,
        &forged,
        &pinned(),
        &expectation(&policy),
        &mut nonces,
    )
    .expect_err("forged");
    assert_ne!(refusal.binding, "nonce");
    verify(
        &request,
        &response,
        &pinned(),
        &expectation(&policy),
        &mut nonces,
    )
    .expect("the genuine one");
    let replay = verify(
        &request,
        &response,
        &pinned(),
        &expectation(&policy),
        &mut nonces,
    )
    .expect_err("a replay");
    assert_eq!(replay.binding, "nonce");
    // A nonce this PEP never issued.
    let stranger = verify(
        &request,
        &response,
        &pinned(),
        &expectation(&policy),
        &mut Outstanding::default(),
    )
    .expect_err("never issued");
    assert_eq!(stranger.binding, "nonce");
}

/// Each binding altered on its own, signed again under the same key: refused by name.
#[test]
fn every_binding_altered_alone_is_refused_by_name() {
    let request = request();
    let answer = answer();
    let payload = payload_for(&request, &answer);
    let request_bytes = serde_json::to_vec(&request).unwrap();

    // The payload's members, one at a time.
    let payload_cases: Vec<(&str, &'static str, Value)> = vec![
        ("audience", "audience", json!("spiffe://acme/other")),
        (
            "request_digest",
            "request_digest",
            json!(format!("sha256:{}", "d".repeat(64))),
        ),
        (
            "response_digest",
            "response_digest",
            json!(format!("sha256:{}", "e".repeat(64))),
        ),
        ("request_nonce", "nonce", json!("AQECAwQFBgcICQoLDA0ODw")),
        ("request_ids", "request_ids", json!([null])),
        ("request_ids", "request_ids", json!(["r-1", null])),
        ("decision", "decision", json!(false)),
        (
            "expires_at",
            "lifetime",
            json!(permguard_core::time::to_rfc3339(ISSUED + 301)),
        ),
        (
            "issued_at",
            "lifetime",
            json!(permguard_core::time::to_rfc3339(ISSUED + 100)),
        ),
        ("v", "payload", json!(2)),
        (
            "interface",
            "payload",
            json!(permguard_core::domains::interface::PDP_TEMPORAL_V1ALPHA1),
        ),
        ("issued_at", "payload", json!("2026-10-22T10:00:00.5Z")),
        ("extension", "payload", json!(true)),
    ];
    for (member, binding, value) in payload_cases {
        let mut altered = payload.clone();
        altered[member] = value.clone();
        let response = serde_json::to_vec(&signed(&answer, &header(), &altered)).unwrap();
        let refusal = check(&request_bytes, &response).expect_err(member);
        assert_eq!(refusal.binding, binding, "{member} = {value}: {refusal}");
    }

    // The policy state, member by member: a PEP requiring the exact state refuses another.
    for member in [
        "authority_host_id",
        "zone_id",
        "ledger_id",
        "ref",
        "commit",
        "counter",
        "profile",
    ] {
        let mut altered = payload.clone();
        altered["policy"][member] = match member {
            "authority_host_id" | "zone_id" | "ledger_id" => {
                json!("0193a1b2-c3d4-7e5f-8a9b-000000000000")
            }
            "commit" => json!(format!("sha256:{}", "f".repeat(64))),
            "counter" => json!("2"),
            _ => json!("other"),
        };
        let response = serde_json::to_vec(&signed(&answer, &header(), &altered)).unwrap();
        let refusal = check(&request_bytes, &response).expect_err(member);
        assert_eq!(refusal.binding, "policy", "{member}: {refusal}");
    }
    // Non-canonical forms of the policy state are no payload at all.
    for (member, value) in [
        (
            "authority_host_id",
            json!("01937000-0000-7000-8000-00000000A0A0"),
        ),
        ("counter", json!("01")),
        ("commit", json!(format!("sha256:{}", "B".repeat(64)))),
    ] {
        let mut altered = payload.clone();
        altered["policy"][member] = value;
        let response = serde_json::to_vec(&signed(&answer, &header(), &altered)).unwrap();
        assert_eq!(
            check(&request_bytes, &response).expect_err(member).binding,
            "payload"
        );
    }

    // The evidence: another status, another position.
    for (status, why) in [("sampled_out", "status"), ("durable", "position")] {
        let mut altered = payload.clone();
        if status == "sampled_out" {
            altered["evidence"] = json!({"mode": "best_effort", "status": "sampled_out",
                                         "record_id": null, "position": null});
        } else {
            altered["evidence"]["position"]["sequence"] = json!("8");
        }
        let response = serde_json::to_vec(&signed(&answer, &header(), &altered)).unwrap();
        assert_eq!(
            check(&request_bytes, &response).expect_err(why).binding,
            "evidence",
            "{why}"
        );
    }

    // The header's members, one at a time, and one member too many.
    let header_cases: Vec<(&str, Value, &'static str)> = vec![
        ("alg", json!("ES256"), "algorithm"),
        ("alg", json!("none"), "algorithm"),
        ("kid", json!("unbound-key"), "key"),
        (
            "typ",
            json!(permguard_core::domains::protected::DECISION_BATCH),
            "type",
        ),
        ("crit", json!(["exp"]), "header"),
    ];
    for (member, value, binding) in header_cases {
        let mut altered = header();
        altered[member] = value.clone();
        let response = serde_json::to_vec(&signed(&answer, &altered, &payload)).unwrap();
        let refusal = check(&request_bytes, &response).expect_err(member);
        assert_eq!(refusal.binding, binding, "{member} = {value}: {refusal}");
    }
}

#[test]
fn the_bytes_themselves_are_held_to_their_one_form() {
    let (request, response) = golden();
    let golden: Value = serde_json::from_slice(&response).unwrap();
    let attestation = golden["attestation"].clone();
    let with = |attestation: Value| {
        let mut response = golden.clone();
        response["attestation"] = attestation;
        serde_json::to_vec(&response).unwrap()
    };

    // The signature, one byte off.
    let mut signature = hex_of(&attestation["signature"]);
    signature[0] ^= 1;
    let mut altered = attestation.clone();
    altered["signature"] = json!(b64(&signature));
    assert_eq!(
        check(&request, &with(altered)).unwrap_err().binding,
        "signature"
    );

    // Padding, or another alphabet: not the one encoding.
    let mut altered = attestation.clone();
    altered["payload"] = json!(format!("{}=", attestation["payload"].as_str().unwrap()));
    assert_eq!(
        check(&request, &with(altered)).unwrap_err().binding,
        "encoding"
    );

    // A flattened JWS with an unprotected header, or a member missing.
    let mut altered = attestation.clone();
    altered["header"] = json!({"kid": KID});
    assert_eq!(
        check(&request, &with(altered)).unwrap_err().binding,
        "attestation"
    );
    let mut altered = attestation.clone();
    altered.as_object_mut().unwrap().remove("signature");
    assert_eq!(
        check(&request, &with(altered)).unwrap_err().binding,
        "attestation"
    );

    // The header in another member order: valid JSON, not its JCS bytes.
    let protected =
        br#"{"kid":"data-attest-vector-1","alg":"EdDSA","typ":"permguard.decision.response.v1"}"#;
    let payload = attestation["payload"].as_str().unwrap();
    let reordered = b64(protected);
    let signature = key()
        .sign(format!("{reordered}.{payload}").as_bytes())
        .expect("signed");
    let altered = json!({"protected": reordered, "payload": payload, "signature": b64(&signature)});
    assert_eq!(
        check(&request, &with(altered)).unwrap_err().binding,
        "header"
    );

    // The answer's bytes: a member named twice, a decision changed beside a valid signature.
    let doubled = String::from_utf8(response.clone()).unwrap().replacen(
        r#""decision":true"#,
        r#""decision":true,"decision":true"#,
        1,
    );
    assert_eq!(
        check(&request, doubled.as_bytes()).unwrap_err().binding,
        "response"
    );
    let mut changed = golden.clone();
    changed["context"]["policies"] = json!(["p-2"]);
    assert_eq!(
        check(&request, &serde_json::to_vec(&changed).unwrap())
            .unwrap_err()
            .binding,
        "response_digest"
    );
    // No attestation at all: an unsigned answer to a request for a signature.
    let mut unsigned = golden.clone();
    unsigned.as_object_mut().unwrap().remove("attestation");
    assert_eq!(
        check(&request, &serde_json::to_vec(&unsigned).unwrap())
            .unwrap_err()
            .binding,
        "attestation"
    );

    // The request the PEP sent, changed: another question than the one answered.
    let mut other: Value = serde_json::from_slice(&request).unwrap();
    other["request_id"] = json!("r-2");
    assert_eq!(
        check(&serde_json::to_vec(&other).unwrap(), &response)
            .unwrap_err()
            .binding,
        "request_digest"
    );
}

#[test]
fn the_lifetime_holds_within_the_advertised_skew() {
    let (request, response) = golden();
    let policy = policy();
    let at = |now: i64| {
        verify(
            &request,
            &response,
            &pinned(),
            &Expectation {
                now,
                ..expectation(&policy)
            },
            &mut outstanding(),
        )
    };
    at(ISSUED - 30).expect("issued within the skew ahead");
    at(ISSUED + 330).expect("expired within the skew");
    assert_eq!(at(ISSUED - 31).unwrap_err().binding, "lifetime");
    assert_eq!(at(ISSUED + 331).unwrap_err().binding, "lifetime");
    // A shorter advertised validity than the token's: refused.
    let refusal = verify(
        &request,
        &response,
        &pinned(),
        &Expectation {
            validity_seconds: 299,
            ..expectation(&policy)
        },
        &mut outstanding(),
    )
    .unwrap_err();
    assert_eq!(refusal.binding, "lifetime");
    // Another audience expected, and a key not pinned.
    let refusal = verify(
        &request,
        &response,
        &pinned(),
        &Expectation {
            audience: "spiffe://acme/someone-else",
            ..expectation(&policy)
        },
        &mut outstanding(),
    )
    .unwrap_err();
    assert_eq!(refusal.binding, "audience");
    let refusal = verify(
        &request,
        &response,
        &[],
        &expectation(&policy),
        &mut outstanding(),
    )
    .unwrap_err();
    assert_eq!(refusal.binding, "key");
}

fn hex_of(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_str().expect("text"))
        .expect("base64url")
}

/// A payload signed in another form than its JCS bytes, and a payload naming another nonce the
/// PEP also has outstanding: neither is the response to this request.
#[test]
fn a_payload_is_its_jcs_bytes_and_names_the_nonce_this_request_sent() {
    let request = request();
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let answer = answer();
    let payload = payload_for(&request, &answer);

    // Valid JSON of the same value, pretty-printed, and signed: not the payload's one form.
    let protected = b64(&permguard_languages::attestation::jcs(&header()).expect("JCS"));
    let pretty = b64(serde_json::to_string_pretty(&payload).unwrap().as_bytes());
    let signature = key()
        .sign(format!("{protected}.{pretty}").as_bytes())
        .expect("signed");
    let mut response = answer.clone();
    response["attestation"] =
        json!({"protected": protected, "payload": pretty, "signature": b64(&signature)});
    assert_eq!(
        check(&request_bytes, &serde_json::to_vec(&response).unwrap())
            .unwrap_err()
            .binding,
        "payload"
    );

    // Another nonce, outstanding too: the payload must name the one this request sent.
    let other = "AQECAwQFBgcICQoLDA0ODw";
    let mut altered = payload.clone();
    altered["request_nonce"] = json!(other);
    let response = serde_json::to_vec(&signed(&answer, &header(), &altered)).unwrap();
    let mut nonces = outstanding();
    nonces.issue(other);
    let policy = policy();
    let refusal = verify(
        &request_bytes,
        &response,
        &pinned(),
        &expectation(&policy),
        &mut nonces,
    )
    .unwrap_err();
    assert_eq!(refusal.binding, "nonce");
    assert!(nonces.spend(other), "a refused response spends nothing");
}
