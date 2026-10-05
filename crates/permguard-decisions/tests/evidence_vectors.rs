// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shared golden vectors of `contracts/vectors/evidence.json` (WP-0.7), reproduced by this
//! crate: decision record digests, today's decision batch byte for byte, and the input tag.
//!
//! The vectors were computed independently of this crate, from the published rules; a vector
//! changes only with a protocol version, never to make this test pass.

#![allow(clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_core::{Jwk, KeyId, KeyManager, Maintenance, Signature};
use permguard_decisions::commitment::Commitment;
use permguard_decisions::envelope::{Batch, Envelope, Signed};
use permguard_decisions::{merkle, record};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/evidence.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("the vectors are readable"))
        .expect("the vectors are JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` is text"))
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// The vectors' key: RFC 8032 section 7.1 test 1, named by its RFC 7638 thumbprint.
struct VectorKey {
    pair: Ed25519KeyPair,
    kid: String,
}

impl VectorKey {
    fn new(vectors: &Value) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&hex(text(&vectors["key"], "seed")))
            .expect("a seed");
        assert_eq!(
            pair.public_key().as_ref(),
            hex(text(&vectors["key"], "public")).as_slice()
        );
        Self {
            pair,
            kid: text(&vectors["key"], "kid").to_owned(),
        }
    }
}

impl KeyManager for VectorKey {
    fn name(&self) -> &'static str {
        "vector-key"
    }

    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        Ok(vec![Jwk::okp(
            self.kid.clone(),
            "Ed25519",
            "EdDSA",
            B64.encode(self.pair.public_key().as_ref()),
        )])
    }

    fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        Ok(KeyId::new(self.kid.clone()))
    }

    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
        Ok(Signature::new(
            KeyId::new(self.kid.clone()),
            "EdDSA",
            self.pair.sign(payload).as_ref().to_vec(),
        ))
    }

    fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
        Ok(Maintenance::default())
    }
}

#[test]
fn decision_record_digests_match_the_vectors() {
    let vectors = vectors();
    for vector in vectors["decision_record"].as_array().expect("records") {
        // A record the codec accepts, not just any JSON a digest can be taken of.
        let _read: record::Record =
            serde_json::from_value(vector["record"].clone()).expect("a decision record");
        assert_eq!(
            record::digest_of(&vector["record"]).expect("digested"),
            text(vector, "digest"),
            "{}",
            text(vector, "name")
        );
    }
}

#[test]
fn todays_decision_batch_is_reproduced_byte_for_byte_and_verifies() {
    let vectors = vectors();
    let batch = &vectors["decision_batch"];
    let records = batch["records"].as_array().expect("records");
    let digests: Vec<String> = records
        .iter()
        .map(|record| record::digest_of(record).expect("digested"))
        .collect();
    assert_eq!(
        merkle::root(&digests).as_deref(),
        batch["envelope"]["merkle_root"].as_str()
    );

    let envelope: Envelope =
        serde_json::from_value(batch["envelope"].clone()).expect("the envelope reads");
    assert_eq!(
        String::from_utf8(envelope.signed_bytes().expect("canonical")).expect("UTF-8"),
        text(batch, "envelope_jcs")
    );
    let key = VectorKey::new(&vectors);
    let signed = Signed::create(&envelope, &key).expect("signed");
    assert_eq!(
        signed.protected,
        text(batch, "protected"),
        "protected header"
    );
    assert_eq!(signed.payload, text(batch, "payload"), "payload");
    assert_eq!(signed.signature, text(batch, "signature"), "signature");

    // The vector's wire form reads back and verifies under the published key.
    let wire = serde_json::json!({
        "signature": {
            "protected": batch["protected"],
            "payload": batch["payload"],
            "signature": batch["signature"],
        },
        "records": batch["records"],
    });
    let decoded = Batch::decode(
        permguard_stream::jcs::canonicalize(&wire)
            .expect("canonical")
            .as_slice(),
    )
    .expect("the batch decodes");
    let verified = decoded
        .signature
        .verify(&key.public_keys().expect("keys"))
        .expect("the signature verifies");
    assert_eq!(verified, envelope);
}

#[test]
fn the_input_tag_matches_the_vector() {
    let vectors = vectors();
    let tag = &vectors["input_tag"];
    let commitment = Commitment::new(hex(text(tag, "key")), text(tag, "version"));
    assert_eq!(
        commitment.commit(&tag["value"]).expect("committed"),
        text(tag, "tag")
    );
}

#[test]
fn the_merkle_roots_match_the_vectors() {
    let vectors = vectors();
    for vector in vectors["merkle"].as_array().expect("merkle") {
        let leaves: Vec<String> = vector["leaves"]
            .as_array()
            .expect("leaves")
            .iter()
            .map(|leaf| leaf.as_str().expect("text").to_owned())
            .collect();
        assert_eq!(
            merkle::root(&leaves).as_deref(),
            vector["root"].as_str(),
            "{}",
            text(vector, "name")
        );
    }
}
