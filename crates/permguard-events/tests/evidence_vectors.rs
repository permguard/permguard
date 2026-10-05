// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shared golden vectors of `contracts/vectors/evidence.json` (WP-0.7), reproduced by this
//! crate: event record, occurrence and history digests, and today's event batch byte for byte.
//!
//! The vectors were computed independently of this crate, from the published rules; a vector
//! changes only with a protocol version, never to make this test pass.

#![allow(clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_core::{Jwk, KeyId, KeyManager, Maintenance, Signature};
use permguard_events::envelope::{Envelope, Signed};
use permguard_events::record;
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
fn event_digests_match_the_vectors() {
    let vectors = vectors();
    let digests = &vectors["event_digests"];
    assert_eq!(
        record::occurrence_digest_of(&digests["occurrence"]).expect("digested"),
        text(digests, "occurrence_digest")
    );
    assert_eq!(
        record::history_digest_of(&digests["history"]).expect("digested"),
        text(digests, "history_digest")
    );
    assert_eq!(
        record::digest_of(&digests["record"]).expect("digested"),
        text(digests, "record_digest")
    );

    // A record the codec accepts, bound to the occurrence and history key above.
    let read = record::validate(&digests["record"]).expect("a valid event record");
    assert_eq!(read.occurrence_digest, text(digests, "occurrence_digest"));
    assert_eq!(
        read.history_key.expect("a history key").digest,
        text(digests, "history_digest")
    );
    for record in vectors["event_batch"]["records"]
        .as_array()
        .expect("records")
    {
        record::validate(record).expect("every batch record is valid");
    }
}

#[test]
fn todays_event_batch_is_reproduced_byte_for_byte_and_verifies() {
    let vectors = vectors();
    let batch = &vectors["event_batch"];
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
    assert_eq!(signed.compact(), text(batch, "compact"));

    let read = Signed::from_compact(text(batch, "compact")).expect("the compact form reads");
    let verified = read
        .verify(&key.public_keys().expect("keys"))
        .expect("the signature verifies");
    assert_eq!(verified, envelope);
}
