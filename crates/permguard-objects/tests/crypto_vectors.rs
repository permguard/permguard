// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The cryptographic profile, frozen as vectors.
//!
//! `tests/vectors/crypto.json` holds two kinds of entry. External vectors cite their RFC or
//! specification and prove that this implementation agrees with the world. Derived vectors — the
//! thumbprint of each suite, the key-set statement and digest, every derivation with its `info`
//! tuple, the sealed-key contexts and envelope — were computed from the blueprint text with an
//! independent encoder and prove that another implementation of the profile would compute the same
//! bytes. The file is edited only by a change to the profile, never to make a test pass.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Mutex;

use permguard_objects::crypto::kdf;
use permguard_objects::crypto::mac;
use permguard_objects::crypto::random::{Entropy, EntropyUnavailable};
use permguard_objects::crypto::seal::{self, Binding, KeyWrap as _, LocalKeyWrap, SealedKey};
use permguard_objects::crypto::suite::{
    P256_HALF_ORDER, P256_ORDER, SignatureError, SigningKey, Suite,
};
use permguard_objects::crypto::thumbprint::{self, KeySet};
use serde_json::Value;
use zeroize::Zeroizing;

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
fn test_thumbprints_reproduce_rfc_8037_and_the_independent_encoder_for_each_suite() {
    let vectors = vectors();
    for entry in entries(&vectors, "thumbprint") {
        let name = text(entry, "name");
        let suite = Suite::from_name(text(entry, "suite")).unwrap();
        let thumbprint = thumbprint::jwk_thumbprint(suite, &hex(text(entry, "public"))).unwrap();
        let (ring, _) = thumbprint::split_kid(text(entry, "kid")).unwrap();

        assert_eq!(thumbprint, text(entry, "thumbprint"), "{name}");
        assert!(thumbprint::is_thumbprint(&thumbprint), "{name}");
        assert_eq!(
            thumbprint::kid(ring, &thumbprint),
            text(entry, "kid"),
            "{name}"
        );
    }
}

#[test]
fn test_the_key_set_statement_and_digest_match_the_independent_encoder() {
    let vectors = vectors();
    for entry in entries(&vectors, "key_set_digest") {
        let name = text(entry, "name");
        let thumbprints: Vec<&str> = entry["thumbprints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        let set = KeySet::new(
            text(entry, "ring"),
            entry["epoch"].as_u64().unwrap(),
            Suite::from_name(text(entry, "suite")).unwrap(),
            &thumbprints,
        )
        .unwrap();

        assert_eq!(hex::encode(set.encode()), text(entry, "cbor"), "{name}");
        assert_eq!(hex::encode(set.digest()), text(entry, "digest"), "{name}");
        assert_eq!(
            KeySet::decode(&hex(text(entry, "cbor"))).unwrap(),
            set,
            "{name}"
        );
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
fn test_every_derivation_matches_the_independent_encoder() {
    let vectors = vectors();
    for entry in entries(&vectors, "kdf") {
        let name = text(entry, "name");
        let version = entry["version"].as_u64().unwrap();
        let root = hex(text(entry, "root"));
        let salt = id(text(entry, "salt_host_id"));
        let (info, key) = match text(entry, "kind") {
            "host_local" => (
                kdf::host_local_info(
                    text(entry, "purpose"),
                    &id(text(entry, "authority_host_id")),
                    text(entry, "resource"),
                    version,
                ),
                kdf::derive_host_local(
                    &root,
                    &salt,
                    text(entry, "purpose"),
                    &id(text(entry, "authority_host_id")),
                    text(entry, "resource"),
                    version,
                ),
            ),
            "zone_root" => (
                kdf::zone_root_info(&id(text(entry, "zone_id")), version),
                kdf::derive_zone_root(&root, &salt, &id(text(entry, "zone_id")), version),
            ),
            "zone_use" => (
                kdf::zone_use_info(
                    text(entry, "purpose"),
                    &id(text(entry, "zone_id")),
                    &id(text(entry, "scope")),
                    version,
                ),
                kdf::derive_distributed_key(
                    &root,
                    &salt,
                    text(entry, "purpose"),
                    &id(text(entry, "zone_id")),
                    &id(text(entry, "scope")),
                    version,
                ),
            ),
            other => panic!("{name}: unknown kind {other}"),
        };
        let info = info.unwrap();

        assert_eq!(hex::encode(&info), text(entry, "info"), "{name}");
        assert_eq!(hex::encode(*key.unwrap()), text(entry, "key"), "{name}");
        assert_eq!(
            kdf::Info::decode(&info).unwrap().encode().unwrap(),
            info,
            "{name}"
        );
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

/// A source that answers each draw with the next fixed value, and refuses a draw it was not given.
struct Scripted(Mutex<Vec<Vec<u8>>>);

impl Scripted {
    fn new(draws: &[Vec<u8>]) -> Self {
        Self(Mutex::new(draws.iter().rev().cloned().collect()))
    }
}

impl Entropy for Scripted {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), EntropyUnavailable> {
        let next = self.0.lock().unwrap().pop().ok_or(EntropyUnavailable)?;
        assert_eq!(
            next.len(),
            buffer.len(),
            "the draws come in the documented order"
        );
        buffer.copy_from_slice(&next);
        Ok(())
    }
}

#[test]
fn test_the_sealed_key_envelope_matches_the_independent_encoder() {
    let vectors = vectors();
    for entry in entries(&vectors, "sealed_key") {
        let name = text(entry, "name");
        let host = id(text(entry, "host_id"));
        let binding = Binding {
            host_id: &host,
            ring: text(entry, "ring"),
            kid: text(entry, "kid"),
            suite: Suite::from_name(text(entry, "suite")).unwrap(),
        };
        let nonce: [u8; 12] = hex(text(entry, "unique_nonce")).try_into().unwrap();
        let kek_version = entry["kek_version"].as_u64().unwrap();
        let kek = LocalKeyWrap::new(
            text(entry, "kek_ref"),
            kek_version,
            Zeroizing::new(hex(text(entry, "kek")).try_into().unwrap()),
            Box::new(Scripted::new(&[hex(text(entry, "wrap_nonce"))])),
        );
        assert_eq!(
            kek.wrap_algorithm(),
            text(entry, "wrap_algorithm"),
            "{name}"
        );

        assert_eq!(
            hex::encode(binding.content_context(seal::CONTENT_ALGORITHM, &nonce)),
            text(entry, "content_context"),
            "{name}"
        );
        assert_eq!(
            hex::encode(
                binding
                    .wrap_context(
                        text(entry, "kek_ref"),
                        kek_version,
                        text(entry, "wrap_algorithm"),
                        seal::CONTENT_ALGORITHM,
                        &nonce
                    )
                    .unwrap()
            ),
            text(entry, "wrap_context"),
            "{name}"
        );

        // The DEK is drawn first, then the content nonce.
        let entropy = Scripted::new(&[hex(text(entry, "dek")), nonce.to_vec()]);
        let pkcs8 = hex(text(entry, "pkcs8"));
        let sealed = SealedKey::seal(&pkcs8, &binding, &kek, &entropy).unwrap();
        assert_eq!(
            hex::encode(&sealed.ciphertext),
            text(entry, "ciphertext"),
            "{name}"
        );
        assert_eq!(
            hex::encode(&sealed.wrapped_dek),
            text(entry, "wrapped_dek"),
            "{name}"
        );
        assert_eq!(
            hex::encode(sealed.encode().unwrap()),
            text(entry, "on_disk"),
            "{name}"
        );

        // The vector's own bytes open, and the key inside is the one RFC 8032 signs with.
        let public = hex(text(entry, "public"));
        let opened = SealedKey::decode(&hex(text(entry, "on_disk")))
            .unwrap()
            .open(&binding, &kek, &public)
            .unwrap();
        assert_eq!(*opened.pkcs8, pkcs8, "{name}");
        let rfc = &vectors["ed25519"][0];
        assert_eq!(
            hex::encode(opened.key.sign(&hex(text(rfc, "message"))).unwrap()),
            text(rfc, "signature"),
            "{name}"
        );
    }
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
