// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A Host batch a test seals, as the producing Host's engine would (WP-6.2b).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_core::Jwk;
use permguard_core::keys::{KeyId, Sign, Signature};
use permguard_stream::engine::batch::{Envelope, KeyView, SealedBatch, digest_string};
use ring::signature::KeyPair as _;
use serde_json::{Value, json};

/// One Ed25519 key, as the Host's `data.attest` ring would publish it.
pub struct Key {
    pair: ring::signature::Ed25519KeyPair,
    kid: String,
}

impl Key {
    pub fn new(kid: &str) -> Self {
        let document =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .expect("a key");
        Self {
            pair: ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("parsed"),
            kid: kid.to_owned(),
        }
    }

    pub fn jwk(&self) -> Jwk {
        serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": B64.encode(self.pair.public_key().as_ref()),
            "kid": self.kid,
            "alg": "EdDSA",
            "use": "sig",
        }))
        .expect("a JWK")
    }
}

impl Sign for Key {
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
}

/// The `host-batch-v1` entry of `records` (their canonical bytes), the run `run` of the Host
/// `producer` from `first_seq`, signed under `key` as `typ`, leaves digested under `domain`.
pub fn sealed(
    key: &Key,
    typ: &str,
    domain: &str,
    producer: &str,
    run: &str,
    first_seq: u64,
    records: &[Vec<u8>],
) -> Value {
    let leaves: Vec<String> = records
        .iter()
        .map(|record| digest_string(domain, record))
        .collect();
    let last_seq = first_seq + records.len() as u64 - 1;
    let envelope = Envelope {
        descriptor_version: 1,
        stream_key: KeyView {
            plane: "data".to_owned(),
            stream_type: "events".to_owned(),
            resource: "plane/data/zone/z/ledger/l".to_owned(),
            producer_host_id: producer.to_owned(),
        },
        run: run.to_owned(),
        membership_id: None,
        epoch: None,
        first_seq,
        last_seq,
        count: records.len() as u64,
        previous_head: "sha256:00".to_owned(),
        head: leaves.last().cloned().unwrap_or_default(),
        merkle_root: permguard_stream::merkle::root(&leaves).expect("a root"),
        batch_id: format!("{run}-{first_seq}"),
        created_at: "2026-10-19T10:00:00Z".to_owned(),
        key_set_epoch: 1,
    };
    let sealed = SealedBatch::seal(key, &key.jwk(), typ, &envelope, records).expect("sealed");
    json!({"format": super::HOST_FORMAT, "signature": sealed.signature})
}
