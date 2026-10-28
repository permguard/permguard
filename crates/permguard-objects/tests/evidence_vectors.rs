// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shared golden vectors of `contracts/vectors/evidence.json` (WP-0.7), reproduced by this
//! crate: the key-set digest vectors it cites. The head statement's vectors moved to
//! `contracts/vectors/notp.json` with its target form (WP-7.1).
//!
//! The vectors were computed independently of this crate, from the published rules; a vector
//! changes only with a protocol version, never to make this test pass.

#![allow(clippy::expect_used)]

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
