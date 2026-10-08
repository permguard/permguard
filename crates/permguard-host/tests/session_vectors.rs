// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The peer session's golden vectors (`contracts/vectors/session.json`, WP-2.3), computed by an
//! independent generator and reproduced here byte for byte by the Rust codecs; the proofs a
//! verifier must refuse, a replay, a relay, a reflection and an unknown-key share, are refused.

#![allow(clippy::expect_used)]

use permguard_core::assurance::AssuranceProfile;
use permguard_core::domains::protected;
use permguard_host::identity::Verified;
use permguard_host::identity::record::{Document, subject};
use permguard_host::session::record::{
    Challenge, Hello, Operation, Role, Transcript, challenge_digest, hello_digest,
};
use permguard_host::session::verify_proof;
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::{SigningKey, Suite};
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/session.json"
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

fn fixed<const N: usize>(value: &Value) -> [u8; N] {
    hex(value).try_into().expect("the length")
}

fn key(host: &Value) -> SigningKey {
    SigningKey::ed25519_from_seed(&hex(&host["seed"]), &hex(&host["public_key"])).expect("the key")
}

/// A host as a verifier holds it once its presentation verified at epoch 1.
fn verified(host: &Value) -> Verified {
    let host_id = fixed(&host["host_id"]);
    let public_key = hex(&host["public_key"]);
    let fingerprint = host["fingerprint"].as_str().expect("text").to_owned();
    Verified {
        host_id,
        epoch: 1,
        suite: Suite::Ed25519Sha256V1,
        public_key: public_key.clone(),
        fingerprints: vec![fingerprint.clone()],
        document: Document {
            host_id,
            subject: subject(&host_id),
            epoch: 1,
            suite: Suite::Ed25519Sha256V1,
            public_key,
            fingerprint,
            last_succession: None,
            protocols: vec![protected::HOST_SESSION.to_owned()],
            revision: 1,
            issued_at: 1_800_000_000,
        },
    }
}

fn proof(key: &SigningKey, transcript: Vec<u8>) -> Vec<u8> {
    Sign1::sign_with(
        Suite::Ed25519Sha256V1,
        protected::HOST_PROOF,
        b"1",
        transcript,
        |bytes| {
            key.sign(bytes)
                .map(|signature| signature.to_vec())
                .map_err(|error| format!("{error:?}"))
        },
    )
    .expect("signed")
    .encode()
    .expect("encoded")
}

#[test]
fn the_session_messages_and_proofs_are_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let (a, b) = (&v["a"], &v["b"]);
    let hello = Hello {
        version: 1,
        host: fixed(&a["host_id"]),
        epoch: 1,
        declared_assurance: AssuranceProfile::Production,
        nonce: fixed(&v["nonce_a"]),
        operation: Operation::Enroll,
        membership_id: None,
        task: None,
    };
    let hello_bytes = hello.encode().expect("encodes");
    assert_eq!(hello_bytes, hex(&v["hello"]["bytes"]));
    assert_eq!(Hello::decode(&hello_bytes).expect("decodes"), hello);
    assert_eq!(
        hello_digest(&hello_bytes).to_string(),
        v["hello"]["digest"].as_str().expect("text")
    );
    let challenge = Challenge {
        host: fixed(&b["host_id"]),
        epoch: 1,
        declared_assurance: AssuranceProfile::Production,
        nonce: fixed(&v["nonce_b"]),
        expires: v["expires"].as_u64().expect("seconds"),
    };
    let challenge_bytes = challenge.encode().expect("encodes");
    assert_eq!(challenge_bytes, hex(&v["challenge"]["bytes"]));
    assert_eq!(
        challenge_digest(&challenge_bytes).to_string(),
        v["challenge"]["digest"].as_str().expect("text")
    );

    let initiator = Transcript {
        initiator_host: hello.host,
        responder_host: challenge.host,
        initiator_epoch: 1,
        responder_epoch: 1,
        nonce_a: hello.nonce,
        nonce_b: challenge.nonce,
        membership_id: None,
        task: None,
        operation: Operation::Enroll,
        expires_at: challenge.expires,
        tls_exporter: fixed(&v["exporter"]),
        hello_digest: hello_digest(&hello_bytes),
        challenge_digest: challenge_digest(&challenge_bytes),
        signer: Role::Initiator,
    };
    let responder = Transcript {
        signer: Role::Responder,
        ..initiator.clone()
    };
    let initiator_bytes = initiator.encode().expect("encodes");
    let responder_bytes = responder.encode().expect("encodes");
    assert_eq!(initiator_bytes, hex(&v["transcript_initiator"]));
    assert_eq!(responder_bytes, hex(&v["transcript_responder"]));
    assert_eq!(
        Transcript::decode(&responder_bytes).expect("decodes"),
        responder
    );

    let proof_a = proof(&key(a), initiator_bytes.clone());
    let proof_b = proof(&key(b), responder_bytes.clone());
    assert_eq!(proof_a, hex(&v["proof_initiator"]));
    assert_eq!(proof_b, hex(&v["proof_responder"]));
    verify_proof(&verified(a), &proof_a, &initiator_bytes).expect("B verifies A's proof");
    verify_proof(&verified(b), &proof_b, &responder_bytes).expect("A verifies B's proof");
}

/// The transcript of the vectors' session, varied: the responder, its challenge, the exporter
/// and the signer's role.
fn transcript(
    v: &Value,
    responder: &str,
    challenge: &[u8],
    exporter: &str,
    signer: Role,
) -> Vec<u8> {
    let challenge_decoded = Challenge::decode(challenge).expect("a challenge");
    Transcript {
        initiator_host: fixed(&v["a"]["host_id"]),
        responder_host: fixed(&v[responder]["host_id"]),
        initiator_epoch: 1,
        responder_epoch: challenge_decoded.epoch,
        nonce_a: fixed(&v["nonce_a"]),
        nonce_b: challenge_decoded.nonce,
        membership_id: None,
        task: None,
        operation: Operation::Enroll,
        expires_at: challenge_decoded.expires,
        tls_exporter: fixed(&v[exporter]),
        hello_digest: hello_digest(&hex(&v["hello"]["bytes"])),
        challenge_digest: challenge_digest(challenge),
        signer,
    }
    .encode()
    .expect("encodes")
}

#[test]
fn a_replayed_relayed_reflected_or_misaddressed_proof_is_refused() {
    let v = vectors();
    let cases = v["refused"].as_array().expect("the refused cases");
    let named: Vec<&str> = cases
        .iter()
        .map(|case| case["case"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        named,
        vec!["replay", "relay", "reflection", "unknown_key_share"]
    );
    let challenge = hex(&v["challenge"]["bytes"]);
    let mut v_relay = v.clone();
    v_relay["other_exporter"] = cases[1]["other_exporter"].clone();
    for case in cases {
        let name = case["case"].as_str().expect("a name");
        let proof = hex(&case["proof"]);
        let signed = Sign1::decode(&proof)
            .expect("a proof")
            .payload_unverified()
            .to_vec();
        // Each side's expected transcript and each proof's payload, rebuilt by the Rust codec
        // from the case's inputs: the refusal below is of these exact bytes.
        let (payload, expected) = match name {
            "replay" => (
                transcript(&v, "b", &challenge, "exporter", Role::Initiator),
                transcript(
                    &v,
                    "b",
                    &hex(&case["later_challenge"]),
                    "exporter",
                    Role::Initiator,
                ),
            ),
            "relay" => (
                transcript(&v, "b", &challenge, "exporter", Role::Initiator),
                transcript(&v_relay, "b", &challenge, "other_exporter", Role::Initiator),
            ),
            // B's own key, the right session, the initiator's role.
            "reflection" => (
                transcript(&v, "b", &challenge, "exporter", Role::Initiator),
                transcript(&v, "b", &challenge, "exporter", Role::Responder),
            ),
            "unknown_key_share" => (
                transcript(
                    &v,
                    "c",
                    &hex(&case["challenge_to_c"]),
                    "exporter",
                    Role::Initiator,
                ),
                transcript(&v, "b", &challenge, "exporter", Role::Initiator),
            ),
            other => panic!("an unknown case {other}"),
        };
        assert_eq!(signed, payload, "{name}: the proof's payload");
        assert_eq!(
            expected,
            hex(&case["expected"]),
            "{name}: the expected transcript"
        );
        let signer = &v[case["signer"].as_str().expect("a signer")];
        // The proof verifies over what it signed: only the transcript tells it apart.
        verify_proof(&verified(signer), &proof, &payload).expect("a genuine signature");
        let refused = verify_proof(&verified(signer), &proof, &expected).expect_err("refused");
        assert_eq!(
            refused.code,
            permguard_core::codes::host::SESSION_REFUSED,
            "{name}"
        );
    }
}
