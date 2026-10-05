// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shared golden vectors of `contracts/vectors/evidence.json` (WP-0.7), reproduced by this
//! crate: today's signed head statement byte for byte, and the key-set digest vectors it cites.
//!
//! The vectors were computed independently of this crate, from the published rules; a vector
//! changes only with a protocol version, never to make this test pass.

#![allow(clippy::expect_used)]

use permguard_objects::digest::Digest;
use permguard_objects::statement::{HeadStatement, SignedHead};
use ring::signature::Ed25519KeyPair;
use serde_json::Value;

fn read(relative: &str) -> Value {
    let path = format!("{}/../../{relative}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect("the vectors are readable"))
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

#[test]
fn todays_head_statement_is_reproduced_byte_for_byte_and_verifies() {
    let vectors = read("contracts/vectors/evidence.json");
    let vector = &vectors["head_statement"];
    let statement = HeadStatement {
        zone: text(vector, "zone").to_owned(),
        ledger: text(vector, "ledger").to_owned(),
        r#ref: text(vector, "ref").to_owned(),
        digest: Digest::parse(text(vector, "digest")).expect("a digest"),
        counter: vector["counter"].as_u64().expect("a counter"),
        signed_at: vector["signed_at"].as_i64().expect("a time"),
    };
    assert_eq!(
        statement.encode().expect("encoded"),
        hex(text(vector, "payload"))
    );

    let key =
        Ed25519KeyPair::from_seed_unchecked(&hex(text(&vectors["key"], "seed"))).expect("a seed");
    let signed =
        SignedHead::sign(&statement, &key, text(vector, "kid").as_bytes()).expect("signed");
    let bytes = signed.encode().expect("encoded");
    assert_eq!(bytes, hex(text(vector, "cose_sign1")));

    let read = SignedHead::decode(&hex(text(vector, "cose_sign1"))).expect("the vector decodes");
    assert_eq!(
        read.verify(&hex(text(&vectors["key"], "public")))
            .expect("verifies"),
        statement
    );
}

#[test]
fn the_key_set_digest_vectors_the_shared_file_cites_exist() {
    let vectors = read("contracts/vectors/evidence.json");
    let cited = &vectors["key_set_digest"];
    let crypto = read(text(cited, "file"));
    assert!(
        crypto[text(cited, "section")]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "the cited section holds the vectors `crypto_vectors.rs` reproduces"
    );
}
