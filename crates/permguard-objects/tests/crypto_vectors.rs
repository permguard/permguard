// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The cryptographic profile, frozen as vectors.
//!
//! `tests/vectors/crypto.json` holds two kinds of entry. External vectors cite their RFC or
//! specification and prove that this implementation agrees with the world. Derived vectors — the
//! `info` tuples, the key-set digest, the sealed-key binding — were computed with an independent
//! encoder and prove that another implementation of the profile would compute the same bytes. The
//! file is edited only by a change to the profile, never to make a test pass.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use permguard_objects::crypto::kdf;
use permguard_objects::crypto::mac;
use permguard_objects::crypto::seal::{self, Binding};
use permguard_objects::crypto::suite::{
    P256_HALF_ORDER, P256_ORDER, SignatureError, SigningKey, Suite,
};
use permguard_objects::crypto::thumbprint;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/crypto.json");
    let text = std::fs::read_to_string(path).expect("the vector file is readable");
    serde_json::from_str(&text).expect("the vector file is JSON")
}

fn entries<'a>(vectors: &'a Value, group: &str) -> impl Iterator<Item = &'a Value> {
    vectors[group]
        .as_array()
        .expect("a vector group is an array")
        .iter()
}

fn text<'a>(entry: &'a Value, field: &str) -> &'a str {
    entry[field].as_str().expect("a vector field is a string")
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex digits"))
        .collect()
}

fn id(value: &str) -> [u8; 16] {
    hex(value).try_into().expect("16 bytes")
}

#[test]
fn test_ed25519_reproduces_rfc_8032() {
    let vectors = vectors();
    for entry in entries(&vectors, "ed25519") {
        let name = text(entry, "name");
        let key =
            SigningKey::ed25519_from_seed(&hex(text(entry, "seed")), &hex(text(entry, "public")))
                .expect("the seed and the public key agree");
        let message = hex(text(entry, "message"));
        let signature = key.sign(&message).unwrap();

        assert_eq!(hex::encode(signature), text(entry, "signature"), "{name}");
        assert_eq!(
            Suite::Ed25519Sha256V1.verify(&hex(text(entry, "public")), &message, &signature),
            Ok(()),
            "{name}"
        );
    }
}

#[test]
fn test_p256_order_constants_and_the_published_high_s_vector_is_refused_until_normalised() {
    let vectors = vectors();
    assert_eq!(
        hex::encode(P256_ORDER),
        vectors["p256"]["order"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(P256_HALF_ORDER),
        vectors["p256"]["half_order"].as_str().unwrap()
    );
    for entry in vectors["p256"]["vectors"].as_array().unwrap() {
        let name = text(entry, "name");
        let public = hex(text(entry, "public"));
        let message = text(entry, "message").as_bytes();
        let published = hex(text(entry, "signature_as_published"));
        let low = hex(text(entry, "signature_low_s"));

        assert_eq!(
            Suite::P256Sha256V1.verify(&public, message, &published),
            Err(SignatureError::HighS),
            "{name}: the RFC publishes a high-s encoding and the profile must refuse it"
        );
        assert_eq!(
            Suite::P256Sha256V1.verify(&public, message, &low),
            Ok(()),
            "{name}: the low-s twin verifies"
        );
    }
}

#[test]
fn test_thumbprints_reproduce_rfc_8037() {
    let vectors = vectors();
    for entry in entries(&vectors, "thumbprint") {
        let name = text(entry, "name");
        let suite = Suite::from_name(text(entry, "suite")).unwrap();
        let x = base64url(text(entry, "x"));
        let thumbprint = thumbprint::jwk_thumbprint(suite, &x).unwrap();

        assert_eq!(thumbprint, text(entry, "thumbprint"), "{name}");
        assert_eq!(
            thumbprint::kid("host.identity", &thumbprint),
            text(entry, "kid"),
            "{name}"
        );
    }
}

#[test]
fn test_the_key_set_digest_matches_the_independent_encoder() {
    let vectors = vectors();
    for entry in entries(&vectors, "key_set_digest") {
        let name = text(entry, "name");
        let thumbprints: Vec<&str> = entry["thumbprints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        let digest = thumbprint::key_set_digest(
            text(entry, "ring"),
            entry["epoch"].as_u64().unwrap(),
            Suite::from_name(text(entry, "suite")).unwrap(),
            &thumbprints,
        )
        .unwrap();

        assert_eq!(hex::encode(digest), text(entry, "digest"), "{name}");
    }
}

#[test]
fn test_hkdf_reproduces_rfc_5869() {
    let vectors = vectors();
    for entry in entries(&vectors, "hkdf") {
        let name = text(entry, "name");
        let mut out = vec![0u8; entry["length"].as_u64().unwrap() as usize];
        kdf::hkdf_sha256(
            &hex(text(entry, "salt")),
            &hex(text(entry, "ikm")),
            &hex(text(entry, "info")),
            &mut out,
        )
        .unwrap();

        assert_eq!(hex::encode(out), text(entry, "okm"), "{name}");
    }
}

#[test]
fn test_kdf_info_tuples_match_the_independent_encoder() {
    let vectors = vectors();
    for entry in entries(&vectors, "kdf_info") {
        let name = text(entry, "name");
        let version = entry["version"].as_u64().unwrap();
        let info = match text(entry, "kind") {
            "host_local" => kdf::host_local_info(
                text(entry, "purpose"),
                &id(text(entry, "authority_host_id")),
                text(entry, "resource"),
                version,
            ),
            "zone_root" => kdf::zone_root_info(&id(text(entry, "zone_id")), version),
            "zone_use" => kdf::zone_use_info(
                text(entry, "purpose"),
                &id(text(entry, "zone_id")),
                &id(text(entry, "scope")),
                version,
            ),
            other => panic!("{name}: unknown kind {other}"),
        }
        .unwrap();

        assert_eq!(hex::encode(info), text(entry, "cbor"), "{name}");
    }
}

#[test]
fn test_hmac_reproduces_rfc_4231() {
    let vectors = vectors();
    for entry in entries(&vectors, "hmac") {
        let name = text(entry, "name");
        let tag = mac::hmac_sha256(&hex(text(entry, "key")), &hex(text(entry, "data"))).unwrap();

        assert_eq!(hex::encode(tag), text(entry, "tag"), "{name}");
    }
}

#[test]
fn test_aes_256_gcm_reproduces_the_gcm_specification_vectors() {
    let vectors = vectors();
    for entry in entries(&vectors, "aes256gcm") {
        let name = text(entry, "name");
        let key: [u8; 32] = hex(text(entry, "key")).try_into().unwrap();
        let nonce: [u8; 12] = hex(text(entry, "nonce")).try_into().unwrap();
        let aad = hex(text(entry, "aad"));
        let plaintext = hex(text(entry, "plaintext"));
        let sealed = seal::aes256gcm_seal(&key, &nonce, &aad, &plaintext).unwrap();

        assert_eq!(
            hex::encode(&sealed),
            text(entry, "ciphertext_and_tag"),
            "{name}"
        );
        assert_eq!(
            &*seal::aes256gcm_open(&key, &nonce, &aad, &sealed).unwrap(),
            &plaintext[..],
            "{name}"
        );
        let mut altered = sealed.clone();
        if let Some(last) = altered.last_mut() {
            *last ^= 1;
        }
        assert!(
            seal::aes256gcm_open(&key, &nonce, &aad, &altered).is_err(),
            "{name}"
        );
    }
}

#[test]
fn test_the_sealed_key_binding_matches_the_independent_encoder() {
    let vectors = vectors();
    for entry in entries(&vectors, "sealed_key_binding") {
        let name = text(entry, "name");
        let host = id(text(entry, "host_id"));
        let binding = Binding {
            host_id: &host,
            ring: text(entry, "ring"),
            kid: text(entry, "kid"),
            suite: Suite::from_name(text(entry, "suite")).unwrap(),
        };

        assert_eq!(hex::encode(binding.aad()), text(entry, "aad"), "{name}");
    }
}

fn base64url(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .expect("base64url")
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}
