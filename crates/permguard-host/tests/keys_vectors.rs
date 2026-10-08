// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The key ring's golden vectors (`contracts/vectors/keys.json`, WP-3.1), computed by an
//! independent generator and reproduced here byte for byte by the Rust codecs.

#![allow(clippy::expect_used)]

use permguard_core::domains::protected;
use permguard_host::keys::PublicKey;
use permguard_host::keys::record::{Binding, Entry, KeyView, Kind, State, View};
use permguard_host::keys::ring::{BINDING_LIFETIME, jwk_of, verify_binding};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::{SigningKey, Suite};
use permguard_objects::crypto::thumbprint::{self, KeySet};
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/keys.json"
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

fn text(value: &Value) -> String {
    value.as_str().expect("text").to_owned()
}

const AT: u64 = 1_800_000_000;

#[test]
fn the_ring_records_are_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let host_id: [u8; 16] = hex(&v["host_id"]).try_into().expect("16 bytes");
    let ring = text(&v["ring"]);
    let public = PublicKey {
        suite: Suite::Ed25519Sha256V1,
        bytes: hex(&v["ring_key"]["public_key"]),
    };
    let thumbprint = thumbprint::jwk_thumbprint(public.suite, &public.bytes).expect("thumbprint");
    assert_eq!(thumbprint, text(&v["thumbprint"]));
    let kid = thumbprint::kid(&ring, &thumbprint);
    assert_eq!(kid, text(&v["kid"]));
    let jwk = serde_json::to_string(&jwk_of(&kid, &public)).expect("json");
    assert_eq!(jwk, text(&v["jwk"]));

    let set = KeySet::new(&ring, 1, Suite::Ed25519Sha256V1, &[&thumbprint]).expect("a set");
    assert_eq!(set.encode().expect("encodes"), hex(&v["key_set"]["bytes"]));
    let digest = set.digest().expect("a digest");
    assert_eq!(digest.to_vec(), hex(&v["key_set"]["digest"]));

    let prepublished = Entry {
        seq: 1,
        kind: Kind::Prepublished,
        kid: kid.clone(),
        epoch: 1,
        at: AT,
        operation_id: None,
        reason: None,
        jwk: Some(jwk.clone()),
        compromised_at: None,
    };
    assert_eq!(
        prepublished.encode().expect("encodes"),
        hex(&v["journal"]["prepublished"])
    );
    let activated = Entry {
        seq: 2,
        kind: Kind::Activated,
        jwk: None,
        ..prepublished
    };
    assert_eq!(
        activated.encode().expect("encodes"),
        hex(&v["journal"]["activated"])
    );

    let view = View {
        ring: ring.clone(),
        suite: Suite::Ed25519Sha256V1,
        epoch: 1,
        key_set_digest: digest,
        keys: vec![KeyView {
            kid: kid.clone(),
            state: State::Active,
            jwk,
            prepublished_at: AT,
            activated_at: Some(AT),
            retired_at: None,
            revoked_at: None,
        }],
    };
    assert_eq!(view.encode().expect("encodes"), hex(&v["ring_view"]));
    assert_eq!(View::decode(&hex(&v["ring_view"])).expect("decodes"), view);

    let binding = Binding {
        host_id,
        ring: ring.clone(),
        epoch: 1,
        key_set_digest: digest,
        suite: Suite::Ed25519Sha256V1,
        not_before: AT,
        not_after: AT + BINDING_LIFETIME.as_secs(),
    };
    let payload = binding.encode().expect("encodes");
    assert_eq!(payload, hex(&v["binding"]["payload"]));
    let identity = SigningKey::ed25519_from_seed(
        &hex(&v["identity"]["seed"]),
        &hex(&v["identity"]["public_key"]),
    )
    .expect("the identity key");
    let envelope = Sign1::sign_with(
        Suite::Ed25519Sha256V1,
        protected::HOST_RING_BINDING,
        b"1",
        payload,
        |bytes| {
            identity
                .sign(bytes)
                .map(|signature| signature.to_vec())
                .map_err(|error| format!("{error:?}"))
        },
    )
    .expect("signed")
    .encode()
    .expect("encoded");
    assert_eq!(envelope, hex(&v["binding"]["cose_sign1"]));
    assert_eq!(
        verify_binding(
            &envelope,
            Suite::Ed25519Sha256V1,
            &hex(&v["identity"]["public_key"]),
            &host_id,
            &ring,
            AT,
        )
        .expect("the vector verifies"),
        binding
    );
}
