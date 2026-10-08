// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `kms` custody against a Transit that keeps its keys (WP-3.2): ring keys created
//! non-exportable and referenced by `<slot>.ref`, signatures that verify, a KEK whose wrap is bound
//! to its context, and the token on every request.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use permguard_host::identity::Suite;
use permguard_host::keys::custody::{Dek, Remote as _, Wrap as _};
use permguard_host::storage::Dir;
use permguard_server::custody::{Endpoint, Transit, TransitKek, WRAP_TRANSIT};

const TOKEN: &str = "s.test-token";

#[derive(Default)]
struct Held {
    /// A signing key's Transit type and PKCS#8.
    signing: BTreeMap<String, (String, Vec<u8>)>,
    deletable: BTreeMap<String, bool>,
}

/// The KEKs the operator created: `permguard-kek` as a KEK must be, `loose-kek` exportable.
const KEKS: &[(&str, bool)] = &[("permguard-kek", false), ("loose-kek", true)];
/// The versions the KEKs hold.
const KEK_VERSIONS: u64 = 3;

/// The DER of a P-256 SubjectPublicKeyInfo up to its point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// `s`, or `n − s` when `s` is low: the stand-in always answers the high-s twin, as a Transit
/// that does not normalise may.
fn high_s(signature: &mut [u8]) {
    /// The order `n` of the P-256 base point, and `n / 2`.
    const P256_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    const P256_HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    if signature[32..] > P256_HALF_ORDER[..] {
        return;
    }
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let difference = i16::from(P256_ORDER[index]) - i16::from(signature[32 + index]) - borrow;
        borrow = i16::from(difference < 0);
        signature[32 + index] = (difference + 256 * borrow) as u8;
    }
}

type Shared = Arc<Mutex<Held>>;

fn refused(status: StatusCode, why: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "errors": [why] })))
}

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("X-Vault-Token").and_then(|v| v.to_str().ok()) == Some(TOKEN)
}

/// A KEK per context: SHA-256 of a fixed master and the context, as a derived Transit key.
fn derived(context: &str) -> [u8; 32] {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        format!("master|{context}").as_bytes(),
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(digest.as_ref());
    key
}

async fn keys(
    State(held): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers) {
        return refused(StatusCode::FORBIDDEN, "permission denied");
    }
    let body = body.map(|Json(body)| body).unwrap_or(Value::Null);
    assert_eq!(body["exportable"], false, "keys are created non-exportable");
    let random = ring::rand::SystemRandom::new();
    let kind = body["type"].as_str().expect("a type").to_owned();
    let pkcs8 = match kind.as_str() {
        "ed25519" => Ed25519KeyPair::generate_pkcs8(&random)
            .expect("generated")
            .as_ref()
            .to_vec(),
        "ecdsa-p256" => EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .expect("generated")
            .as_ref()
            .to_vec(),
        other => panic!("no key type `{other}`"),
    };
    held.lock()
        .expect("lock")
        .signing
        .insert(name, (kind, pkcs8));
    (StatusCode::OK, Json(json!({ "data": null })))
}

async fn read_key(
    State(held): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers) {
        return refused(StatusCode::FORBIDDEN, "permission denied");
    }
    if let Some((_, exportable)) = KEKS.iter().find(|(kek, _)| *kek == name) {
        let keys: serde_json::Map<String, Value> = (1..=KEK_VERSIONS)
            .map(|version| (version.to_string(), json!(1_800_000_000)))
            .collect();
        return (
            StatusCode::OK,
            Json(json!({ "data": { "type": "aes256-gcm96", "derived": true,
                "exportable": exportable, "allow_plaintext_backup": false,
                "latest_version": KEK_VERSIONS, "keys": keys } })),
        );
    }
    let Some((kind, pkcs8)) = held.lock().expect("lock").signing.get(&name).cloned() else {
        return refused(StatusCode::NOT_FOUND, "no such key");
    };
    let public_key = if kind == "ed25519" {
        STANDARD.encode(
            Ed25519KeyPair::from_pkcs8(&pkcs8)
                .expect("reads")
                .public_key()
                .as_ref(),
        )
    } else {
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &ring::rand::SystemRandom::new(),
        )
        .expect("reads");
        let mut der = P256_SPKI_PREFIX.to_vec();
        der.extend_from_slice(pair.public_key().as_ref());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        )
    };
    (
        StatusCode::OK,
        Json(json!({ "data": { "type": kind, "exportable": false,
                "allow_plaintext_backup": false, "latest_version": 1,
            "keys": { "1": { "public_key": public_key } } } })),
    )
}

async fn delete_key(
    State(held): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers) {
        return refused(StatusCode::FORBIDDEN, "permission denied");
    }
    let mut held = held.lock().expect("lock");
    // As Vault does: a missing key's delete is a 400, not a 404.
    if !held.signing.contains_key(&name) {
        return refused(StatusCode::BAD_REQUEST, "no existing key could be found");
    }
    if held.deletable.get(&name) != Some(&true) {
        return refused(StatusCode::BAD_REQUEST, "deletion is not allowed");
    }
    held.signing.remove(&name);
    (StatusCode::OK, Json(json!({ "data": null })))
}

async fn config(
    State(held): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers) {
        return refused(StatusCode::FORBIDDEN, "permission denied");
    }
    let mut held = held.lock().expect("lock");
    if !held.signing.contains_key(&name) {
        return refused(StatusCode::BAD_REQUEST, "no existing key could be found");
    }
    held.deletable
        .insert(name, body["deletion_allowed"] == true);
    (StatusCode::OK, Json(json!({ "data": null })))
}

async fn sign(
    State(held): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers) {
        return refused(StatusCode::FORBIDDEN, "permission denied");
    }
    let Some((kind, pkcs8)) = held.lock().expect("lock").signing.get(&name).cloned() else {
        return refused(StatusCode::NOT_FOUND, "no such key");
    };
    assert_eq!(
        body["key_version"], 1,
        "the key's one version, never a later one"
    );
    let input = STANDARD
        .decode(body["input"].as_str().expect("input"))
        .expect("base64");
    let signature = if kind == "ed25519" {
        STANDARD.encode(
            Ed25519KeyPair::from_pkcs8(&pkcs8)
                .expect("reads")
                .sign(&input)
                .as_ref(),
        )
    } else {
        assert_eq!(body["marshaling_algorithm"], "jws", "a raw r || s");
        assert_eq!(body["hash_algorithm"], "sha2-256");
        let random = ring::rand::SystemRandom::new();
        let mut signature =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &random)
                .expect("reads")
                .sign(&random, &input)
                .expect("signed")
                .as_ref()
                .to_vec();
        high_s(&mut signature);
        URL_SAFE_NO_PAD.encode(signature)
    };
    (
        StatusCode::OK,
        Json(json!({ "data": { "signature": format!("vault:v1:{signature}") } })),
    )
}

async fn encrypt(headers: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if !authorized(&headers) {
        return refused(StatusCode::FORBIDDEN, "permission denied");
    }
    let version = body["key_version"].as_u64().unwrap_or(KEK_VERSIONS);
    let key = derived(&format!(
        "{version}|{}",
        body["context"].as_str().expect("a context")
    ));
    let plaintext = STANDARD
        .decode(body["plaintext"].as_str().expect("plaintext"))
        .expect("base64");
    let nonce = [3u8; 12];
    let sealed = permguard_objects_seal(&key, &nonce, &plaintext);
    let mut out = nonce.to_vec();
    out.extend(sealed);
    (
        StatusCode::OK,
        Json(
            json!({ "data": { "ciphertext": format!("vault:v{version}:{}", STANDARD.encode(out)) } }),
        ),
    )
}

async fn decrypt(headers: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if !authorized(&headers) {
        return refused(StatusCode::FORBIDDEN, "permission denied");
    }
    let text = body["ciphertext"].as_str().expect("ciphertext");
    let (version, encoded) = text
        .strip_prefix("vault:v")
        .and_then(|rest| rest.split_once(':'))
        .expect("a Transit ciphertext");
    let key = derived(&format!(
        "{version}|{}",
        body["context"].as_str().expect("a context")
    ));
    let bytes = STANDARD.decode(encoded).expect("base64");
    let nonce: [u8; 12] = bytes[..12].try_into().expect("a nonce");
    match permguard_objects_open(&key, &nonce, &bytes[12..]) {
        Some(plaintext) => (
            StatusCode::OK,
            Json(json!({ "data": { "plaintext": STANDARD.encode(plaintext) } })),
        ),
        None => refused(
            StatusCode::BAD_REQUEST,
            "cipher: message authentication failed",
        ),
    }
}

fn permguard_objects_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a key"));
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::empty(),
        &mut in_out,
    )
    .expect("sealed");
    in_out
}

fn permguard_objects_open(key: &[u8; 32], nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let mut in_out = sealed.to_vec();
    let opened = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::empty(),
            &mut in_out,
        )
        .ok()?;
    Some(opened.to_vec())
}

/// A Transit on a loopback port, with a thread of its own.
fn transit(token: &str) -> Arc<Transit> {
    let held: Shared = Arc::new(Mutex::new(Held::default()));
    let router = axum::Router::new()
        .route(
            "/v1/transit/keys/{name}",
            post(keys).get(read_key).delete(delete_key),
        )
        .route("/v1/transit/keys/{name}/config", post(config))
        .route("/v1/transit/sign/{name}", post(sign))
        .route("/v1/transit/encrypt/{name}", post(encrypt))
        .route("/v1/transit/decrypt/{name}", post(decrypt))
        .with_state(held);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    listener.set_nonblocking(true).expect("non-blocking");
    let address = listener.local_addr().expect("an address");
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("a listener");
            axum::serve(listener, router).await.expect("served");
        });
    });
    Transit::start(Endpoint {
        address: format!("http://{address}"),
        mount: "transit".to_owned(),
        token: Zeroizing::new(token.to_owned()),
        ca: None,
    })
    .expect("the client starts")
}

fn scratch(tag: &str) -> Dir {
    let path = std::env::temp_dir().join(format!(
        "permguard-transit-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("created");
    Dir::open(&path).expect("opens")
}

#[test]
fn a_ring_key_lives_in_transit_and_signs_there() {
    let dir = scratch("keys");
    let mount = transit(TOKEN);
    let keys = mount
        .provider("host.operations", Dir::open(dir.path()).expect("opens"))
        .expect("a provider");
    let (slot, public) = keys
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("created");
    assert_eq!(
        slot,
        permguard_host::keys::thumbprint_of(&public).expect("a thumbprint")
    );
    let reference = std::fs::read_to_string(dir.path().join(format!("{slot}.ref")))
        .expect("the reference is kept");
    assert!(reference.starts_with("pg-host-operations-"), "{reference}");
    assert_eq!(keys.slots().expect("listed"), vec![slot.clone()]);
    assert_eq!(
        keys.public(&slot, Suite::Ed25519Sha256V1).expect("read"),
        public
    );
    let signature = keys
        .sign(&slot, Suite::Ed25519Sha256V1, b"payload")
        .expect("signed");
    Suite::Ed25519Sha256V1
        .verify(&public.bytes, b"payload", &signature)
        .expect("verifies");
    keys.destroy(&slot).expect("destroyed");
    assert!(keys.slots().expect("listed").is_empty());
    assert!(keys.sign(&slot, Suite::Ed25519Sha256V1, b"x").is_err());

    // A destroy interrupted after Transit deleted the key completes.
    let (slot, _) = keys
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("created");
    let name = std::fs::read_to_string(dir.path().join(format!("{slot}.ref"))).expect("kept");
    let other_dir = scratch("other");
    let other = mount
        .provider(
            "control.attest",
            Dir::open(other_dir.path()).expect("opens"),
        )
        .expect("a provider");
    // A reference to another ring's live key is refused before Transit is asked.
    let (other_slot, _) = other
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("created");
    let other_name =
        std::fs::read_to_string(other_dir.path().join(format!("{other_slot}.ref"))).expect("kept");
    std::fs::write(dir.path().join(format!("{other_slot}.ref")), &other_name).expect("written");
    let refused = keys
        .sign(&other_slot, Suite::Ed25519Sha256V1, b"m")
        .expect_err("another ring's key");
    assert!(
        refused.to_string().contains("names no key of this ring"),
        "{refused}"
    );
    keys.destroy(&slot).expect("destroyed");
    std::fs::write(dir.path().join(format!("{slot}.ref")), &name).expect("restored");
    keys.destroy(&slot)
        .expect("a key already gone is destroyed");
}

#[test]
fn a_p256_signature_from_transit_is_brought_to_low_s() {
    let keys = transit(TOKEN)
        .provider("data.attest", scratch("p256"))
        .expect("a provider");
    let (slot, public) = keys
        .generate_addressed(Suite::P256Sha256V1)
        .expect("created");
    for round in 0..8u8 {
        let signature = keys
            .sign(&slot, Suite::P256Sha256V1, &[round])
            .expect("signed");
        Suite::P256Sha256V1
            .verify(&public.bytes, &[round], &signature)
            .expect("verifies: the stand-in answered high-s, the provider normalised it");
    }
}

#[test]
fn a_transit_kek_binds_its_context_and_a_wrong_token_is_refused() {
    let mount = transit(TOKEN);
    let kek = TransitKek::open(Arc::clone(&mount), "permguard-kek", 3).expect("a KEK");
    assert_eq!(kek.wrap_algorithm(), WRAP_TRANSIT);
    let dek = Dek::from_unwrapped(Zeroizing::new([5u8; 32]));
    let wrapped = kek.wrap(&dek, b"context").expect("wrapped");
    assert!(wrapped.starts_with(b"vault:v3:"));
    assert_eq!(
        kek.unwrap(3, &wrapped, b"context")
            .expect("unwrapped")
            .expose(),
        &[5u8; 32]
    );
    assert!(
        kek.unwrap(3, &wrapped, b"another").is_err(),
        "the context is bound"
    );
    assert!(
        kek.unwrap(2, &wrapped, b"context").is_err(),
        "the version is checked"
    );
    let older = TransitKek::open(Arc::clone(&mount), "permguard-kek", 2).expect("a KEK");
    assert!(
        older.unwrap(2, &wrapped, b"context").is_err(),
        "a ciphertext under version 3 is not version 2's"
    );
    // The KEK's version is the Transit key version the wrap asks for.
    let under_two = older.wrap(&dek, b"context").expect("wrapped");
    assert!(under_two.starts_with(b"vault:v2:"));
    assert_eq!(
        older
            .unwrap(2, &under_two, b"context")
            .expect("unwrapped")
            .expose(),
        &[5u8; 32]
    );
    assert!(
        TransitKek::open(Arc::clone(&mount), "permguard-kek", 4).is_err(),
        "a version the key does not hold"
    );
    assert!(
        TransitKek::open(Arc::clone(&mount), "loose-kek", 1).is_err(),
        "an exportable key is no KEK"
    );

    let stranger = transit("s.other");
    let keys = stranger
        .provider("host.operations", scratch("stranger"))
        .expect("a provider");
    assert!(keys.generate_addressed(Suite::Ed25519Sha256V1).is_err());
}
