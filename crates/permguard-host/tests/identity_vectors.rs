// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host identity's golden vectors (`contracts/vectors/identity.json`, WP-2.2), computed by an
//! independent generator and reproduced here byte for byte by the Rust codecs.

#![allow(clippy::expect_used)]

use permguard_core::domains::protected;
use permguard_host::identity::record::{
    self, Boot, Document, Init, Succession, succession_digest, uuid_v7, witness,
};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::{SigningKey, Suite};
use permguard_objects::digest::Digest;
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/identity.json"
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

fn key(epoch: &Value) -> SigningKey {
    SigningKey::ed25519_from_seed(&hex(&epoch["seed"]), &hex(&epoch["public_key"]))
        .expect("the key")
}

fn sign(key: &SigningKey, content_type: &str, kid: &[u8], payload: Vec<u8>) -> Vec<u8> {
    Sign1::sign_with(
        Suite::Ed25519Sha256V1,
        content_type,
        kid,
        payload,
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
fn the_identity_records_are_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let host_id: [u8; 16] = hex(&v["host_id"]).try_into().expect("16 bytes");
    assert_eq!(
        uuid_v7(1_800_000_000_000, [0x11; 10]),
        host_id,
        "the UUIDv7"
    );
    assert_eq!(record::uuid_text(&host_id), text(&v["uuid"]));
    assert_eq!(record::subject(&host_id), text(&v["subject"]));
    let first = key(&v["epoch_1"]);
    let second = key(&v["epoch_2"]);
    assert_eq!(
        Digest::compute(first.public_key()).to_string(),
        text(&v["epoch_1"]["fingerprint"])
    );

    let document_1 = Document {
        host_id,
        subject: text(&v["subject"]),
        epoch: 1,
        suite: Suite::Ed25519Sha256V1,
        public_key: first.public_key().to_vec(),
        fingerprint: text(&v["epoch_1"]["fingerprint"]),
        last_succession: None,
        protocols: vec![protected::HOST_SESSION.to_owned()],
        revision: 1,
        issued_at: 1_800_000_000,
    };
    let payload = document_1.encode().expect("encodes");
    assert_eq!(payload, hex(&v["document_epoch_1"]["payload"]));
    assert_eq!(Document::decode(&payload).expect("decodes"), document_1);
    assert_eq!(
        sign(&first, protected::HOST_IDENTITY, b"1", payload),
        hex(&v["document_epoch_1"]["cose_sign1"])
    );

    let succession = Succession {
        host_id,
        from_epoch: 1,
        to_epoch: 2,
        fingerprint: text(&v["epoch_2"]["fingerprint"]),
        public_key: second.public_key().to_vec(),
        previous: record::zero_digest(),
        at: 1_800_000_100,
    };
    let payload = succession.encode().expect("encodes");
    assert_eq!(payload, hex(&v["succession_1_to_2"]["payload"]));
    assert_eq!(Succession::decode(&payload).expect("decodes"), succession);
    let envelope = sign(&first, protected::HOST_SUCCESSION, b"1", payload);
    assert_eq!(envelope, hex(&v["succession_1_to_2"]["cose_sign1"]));
    let digest = succession_digest(&envelope);
    assert_eq!(digest.to_string(), text(&v["succession_1_to_2"]["digest"]));

    let document_2 = Document {
        epoch: 2,
        public_key: second.public_key().to_vec(),
        fingerprint: text(&v["epoch_2"]["fingerprint"]),
        last_succession: Some(digest),
        revision: 2,
        issued_at: 1_800_000_100,
        ..document_1
    };
    let payload = document_2.encode().expect("encodes");
    assert_eq!(payload, hex(&v["document_epoch_2"]["payload"]));
    let envelope = sign(&second, protected::HOST_IDENTITY, b"2", payload);
    assert_eq!(envelope, hex(&v["document_epoch_2"]["cose_sign1"]));
    Sign1::decode(&envelope)
        .expect("decodes")
        .verify(
            Suite::Ed25519Sha256V1,
            second.public_key(),
            protected::HOST_IDENTITY,
        )
        .expect("verifies");

    let volume_id: [u8; 16] = hex(&v["volume_id"]).try_into().expect("16 bytes");
    let init = Init {
        host_id,
        volume_id,
        fingerprint: text(&v["epoch_1"]["fingerprint"]),
        created_at: 1_800_000_000,
    };
    let bytes = init.encode().expect("encodes");
    assert_eq!(bytes, hex(&v["init"]["bytes"]));
    assert_eq!(Init::decode(&bytes).expect("decodes"), init);
    assert_eq!(
        witness(&bytes, &volume_id, &init.fingerprint),
        text(&v["witness"])
    );

    let boot = Boot {
        boot_id: [0x33; 16],
        generation: 4,
    };
    assert_eq!(boot.encode().expect("encodes"), hex(&v["boot"]["bytes"]));
}
