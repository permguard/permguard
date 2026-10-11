// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The audit's golden vectors (`contracts/vectors/audit.json`, WP-3.7), computed by an independent
//! generator and reproduced here byte for byte by the Rust codecs.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use permguard_core::domains::protected;
use permguard_host::audit::checkpoint::{Anchor, Checkpoint, Keys, envelope_digest, no_checkpoint};
use permguard_host::audit::record::{AuditRecord, FactValue, genesis};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/audit.json"
    ))
    .expect("the vectors read");
    serde_json::from_str(&text).expect("the vectors parse")
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex text");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn digest(value: &Value) -> Digest {
    Digest::parse(value.as_str().expect("text")).expect("a digest")
}

const AT: u64 = 1_800_000_000;
const TRAIL: &str = "security:plane/control";

#[test]
fn the_checkpoint_is_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let host_id: [u8; 16] = hex(&v["host_id"]).try_into().expect("16 bytes");

    let record = AuditRecord {
        trail: TRAIL.to_owned(),
        seq: 0,
        operation_id: None,
        phase: None,
        host_id,
        boot_id: hex(&v["boot_id"]).try_into().expect("16 bytes"),
        component: "control-plane".to_owned(),
        action: "zone.created".to_owned(),
        principal: "catalog".to_owned(),
        resource: "plane/control".to_owned(),
        target: None,
        outcome: "ok".to_owned(),
        facts: BTreeMap::from([("count".to_owned(), FactValue::Uint(1))]),
        build: "9.9.9".to_owned(),
        config_revision: Digest::compute(b"settings"),
        at: AT,
        monotonic_offset: 1500,
        previous: genesis(),
    };
    assert_eq!(
        record.encode().expect("encodes"),
        hex(&v["record"]["bytes"])
    );
    assert_eq!(
        record.digest().expect("digest"),
        digest(&v["record"]["digest"])
    );

    let first = Checkpoint {
        trail: TRAIL.to_owned(),
        period: "2027-01-15".to_owned(),
        first_seq: 0,
        last_seq: 0,
        head_digest: record.digest().expect("digest"),
        previous_checkpoint: no_checkpoint(),
        host_id,
        key_set_epoch: 1,
        created_at: AT + 86_400,
    };
    let f = &v["checkpoint_first"];
    assert_eq!(first.encode().expect("encodes"), hex(&f["payload"]));

    // Signed under the RFC 8032 test 2 key with its kid, the envelope is the generator's.
    let seed = hex(&v["operations"]["seed"]);
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("the seed");
    assert_eq!(
        key.public_key().as_ref(),
        hex(&v["operations"]["public_key"])
    );
    let kid = v["operations"]["kid"].as_str().expect("kid");
    let sign = |payload: Vec<u8>| {
        Sign1::sign_with(
            Suite::Ed25519Sha256V1,
            protected::AUDIT_CHECKPOINT,
            kid.as_bytes(),
            payload,
            |bytes| Ok(key.sign(bytes).as_ref().to_vec()),
        )
        .expect("signed")
        .encode()
        .expect("encodes")
    };
    let first_envelope = sign(first.encode().expect("encodes"));
    assert_eq!(first_envelope, hex(&f["cose_sign1"]));
    assert_eq!(envelope_digest(&first_envelope), digest(&f["digest"]));

    let second = Checkpoint {
        period: "2027-01-16".to_owned(),
        first_seq: 1,
        last_seq: 7,
        head_digest: digest(&v["checkpoint_second"]["head"]),
        previous_checkpoint: envelope_digest(&first_envelope),
        key_set_epoch: 2,
        created_at: AT + 90_000,
        ..first.clone()
    };
    let s = &v["checkpoint_second"];
    assert_eq!(second.encode().expect("encodes"), hex(&s["payload"]));
    let second_envelope = sign(second.encode().expect("encodes"));
    assert_eq!(second_envelope, hex(&s["cose_sign1"]));
    assert_eq!(envelope_digest(&second_envelope), digest(&s["digest"]));

    // The published JWK verifies both, and each decodes to what was sealed.
    let jwks = serde_json::json!({ "keys": [v["operations"]["jwk"].clone()] }).to_string();
    let keys = Keys::from_document(&jwks).expect("the keys read");
    assert_eq!(
        keys.verify(&hex(&f["cose_sign1"]))
            .expect("verifies")
            .checkpoint,
        first
    );
    assert_eq!(
        keys.verify(&hex(&s["cose_sign1"]))
            .expect("verifies")
            .checkpoint,
        second
    );

    let anchor = Anchor {
        trail: TRAIL.to_owned(),
        low_watermark: 1,
        through: "2027-01-15".to_owned(),
        checkpoint: envelope_digest(&first_envelope),
    };
    assert_eq!(anchor.encode().expect("encodes"), hex(&v["anchor"]));
    assert_eq!(Anchor::decode(&hex(&v["anchor"])).expect("decodes"), anchor);
}

#[test]
fn a_checkpoint_signed_by_a_key_outside_the_set_is_refused_and_a_revoked_one_is_named() {
    let v = vectors();
    let envelope = hex(&v["checkpoint_first"]["cose_sign1"]);
    let jwk = v["operations"]["jwk"].clone();
    let kid = jwk["kid"].as_str().expect("kid").to_owned();

    // Another `host.operations` key: the kid is not in the set.
    let other = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).expect("a seed");
    let mut stranger = jwk.clone();
    stranger["kid"] = Value::from(format!("host.operations:{}", "A".repeat(43)));
    stranger["x"] = Value::from(base64_url(other.public_key().as_ref()));
    let keys = Keys::from_document(&serde_json::json!({ "keys": [stranger] }).to_string())
        .expect("the keys read");
    assert!(keys.verify(&envelope).is_err());

    // The right key, revoked.
    let revoked = serde_json::json!({
        "ring": "host.operations",
        "keys": [jwk.clone()],
        "revoked": [{ "kid": kid }],
    });
    // The right key, revoked since: the signature verifies and says so; whether it stands is the
    // chain's to tell.
    let signed = Keys::from_document(&revoked.to_string())
        .expect("the keys read")
        .verify(&envelope)
        .expect("the signature verifies");
    assert!(signed.revoked);
    assert_eq!(signed.kid, kid);

    // A document of another ring, or a key not under `host.operations`.
    let other_ring = serde_json::json!({ "ring": "data.attest", "keys": [jwk.clone()] });
    assert!(Keys::from_document(&other_ring.to_string()).is_err());
    let mut misnamed = jwk;
    misnamed["kid"] = Value::from(format!("data.attest:{}", "x"));
    assert!(Keys::from_document(&serde_json::json!({ "keys": [misnamed] }).to_string()).is_err());
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
