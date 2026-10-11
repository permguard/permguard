// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The plan receipts' golden vectors (`contracts/vectors/plan.json`, WP-3.9), computed by an
//! independent generator and reproduced here byte for byte by the Rust codecs.

#![allow(clippy::expect_used)]

use permguard_core::domains::protected;
use permguard_host::audit::checkpoint::Keys;
use permguard_host::operations::plan::{
    Approval, KEYS_REVOKE, PlanReceipt, approvals_required, lifetime, plan_body, plan_digest,
    read_receipt, verify_approval, verify_receipt,
};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/plan.json"
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

fn id(value: &Value) -> [u8; 16] {
    hex(value).try_into().expect("16 bytes")
}

const AT: u64 = 1_800_000_000;
const PARAMETERS: [(&str, &str); 2] = [
    ("reason", "the key left the building"),
    ("compromised_at", "1799990000"),
];

fn keys(v: &Value) -> Keys {
    let jwks = serde_json::json!({ "keys": [v["operations"]["jwk"].clone()] }).to_string();
    Keys::from_document(&jwks).expect("the keys read")
}

#[test]
fn the_receipt_and_the_approval_are_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let target = format!("data.attest:{}", "A".repeat(43));

    assert_eq!(
        plan_body(KEYS_REVOKE, &target, 3, &PARAMETERS),
        hex(&v["plan_body"]["bytes"])
    );
    let digest = plan_digest(KEYS_REVOKE, &target, 3, &PARAMETERS);
    assert_eq!(
        digest,
        Digest::parse(v["plan_body"]["digest"].as_str().expect("text")).expect("a digest")
    );

    // A key revocation under dual control: one approval, a day to collect it.
    let approvals = approvals_required(KEYS_REVOKE, true);
    let receipt = PlanReceipt {
        plan_id: id(&v["plan_id"]),
        operation: KEYS_REVOKE.to_owned(),
        target,
        revision: 3,
        principal: "spiffe://acme/operators/alice".to_owned(),
        plan_digest: digest.clone(),
        expires: AT + lifetime(approvals).as_secs(),
        nonce: id(&v["nonce"]),
        approvals_required: approvals,
        host_id: id(&v["host_id"]),
        created_at: AT,
    };
    assert_eq!(
        receipt.encode().expect("encodes"),
        hex(&v["receipt"]["payload"])
    );
    let approval = Approval {
        plan_digest: digest,
        principal: "spiffe://acme/operators/bob".to_owned(),
        approved_at: AT + 600,
        host_id: id(&v["host_id"]),
    };
    assert_eq!(
        approval.encode().expect("encodes"),
        hex(&v["approval"]["payload"])
    );

    // Signed under the RFC 8032 test 2 key with its kid, the envelopes are the generator's.
    let seed = hex(&v["operations"]["seed"]);
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("the seed");
    assert_eq!(
        key.public_key().as_ref(),
        hex(&v["operations"]["public_key"])
    );
    let kid = v["operations"]["kid"].as_str().expect("kid");
    let sign = |content_type: &str, payload: Vec<u8>| {
        Sign1::sign_with(
            Suite::Ed25519Sha256V1,
            content_type,
            kid.as_bytes(),
            payload,
            |bytes| Ok(key.sign(bytes).as_ref().to_vec()),
        )
        .expect("signed")
        .encode()
        .expect("encodes")
    };
    let receipt_envelope = sign(
        protected::OPERATION_PLAN,
        receipt.encode().expect("encodes"),
    );
    assert_eq!(receipt_envelope, hex(&v["receipt"]["cose_sign1"]));
    let approval_envelope = sign(
        protected::OPERATION_APPROVAL,
        approval.encode().expect("encodes"),
    );
    assert_eq!(approval_envelope, hex(&v["approval"]["cose_sign1"]));

    // The published JWK verifies both, and each decodes to what was signed.
    let keys = keys(&v);
    assert_eq!(
        verify_receipt(&keys, &receipt_envelope).expect("verifies"),
        receipt
    );
    assert_eq!(read_receipt(&receipt_envelope).expect("reads"), receipt);
    assert_eq!(
        verify_approval(&keys, &approval_envelope).expect("verifies"),
        approval
    );
}

#[test]
fn a_receipt_is_not_an_approval_and_an_altered_one_does_not_verify() {
    let v = vectors();
    let keys = keys(&v);
    let receipt = hex(&v["receipt"]["cose_sign1"]);
    let approval = hex(&v["approval"]["cose_sign1"]);

    // Each envelope's content type names what it is: neither stands for the other.
    assert!(verify_approval(&keys, &receipt).is_err());
    assert!(verify_receipt(&keys, &approval).is_err());
    assert!(read_receipt(&approval).is_err());

    // A receipt's payload signed under the approval's content type is not a receipt, though it
    // decodes as one.
    let key = Ed25519KeyPair::from_seed_unchecked(&hex(&v["operations"]["seed"])).expect("seed");
    let kid = v["operations"]["kid"].as_str().expect("kid");
    let mislabelled = Sign1::sign_with(
        Suite::Ed25519Sha256V1,
        protected::OPERATION_APPROVAL,
        kid.as_bytes(),
        hex(&v["receipt"]["payload"]),
        |bytes| Ok(key.sign(bytes).as_ref().to_vec()),
    )
    .expect("signed")
    .encode()
    .expect("encodes");
    assert!(read_receipt(&mislabelled).is_err());
    assert!(verify_receipt(&keys, &mislabelled).is_err());

    // One flipped payload byte breaks the signature.
    let mut altered = receipt.clone();
    let at = altered.len() - 80;
    altered[at] ^= 0x01;
    assert!(verify_receipt(&keys, &altered).is_err());
}
