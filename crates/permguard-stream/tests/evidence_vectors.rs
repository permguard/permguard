// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shared golden vectors of `contracts/vectors/evidence.json` (WP-0.7), reproduced by this
//! crate: today's cursor (v1) and its filter digest, and the batch Merkle roots.
//!
//! The vectors were computed independently of this crate, from the published rules; a vector
//! changes only with a protocol version, never to make this test pass. Cursor v1 is the deployed
//! form: its MAC covers the encoded body with no domain prefix (owner decision, status.md).

#![allow(clippy::expect_used)]

use permguard_stream::cursor::{Cursor, CursorKey, Position, filter_digest};
use permguard_stream::frontier::Frontier;
use permguard_stream::merkle;
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

#[test]
fn todays_cursor_is_reproduced_byte_for_byte_and_opens() {
    let vectors = vectors();
    let vector = &vectors["cursor_v1"];
    assert_eq!(
        filter_digest(&vector["filters"]),
        text(vector, "filter_digest")
    );

    let fields = &vector["cursor"];
    let mut cursor = Cursor::beginning(
        text(fields, "api"),
        text(fields, "scope"),
        text(fields, "filters"),
        None,
    );
    cursor.advance(
        "data-plane-7f3a",
        Position {
            segment: 1,
            offset: 2,
        },
    );
    cursor.frontier = Frontier::of("data-plane-7f3a", 3);
    assert_eq!(
        serde_json::to_string(&cursor).expect("encoded"),
        text(vector, "body")
    );

    let key_bytes = hex(text(vector, "key"));
    let key = CursorKey::new(&key_bytes, &[]).expect("a key");
    let token = cursor.seal(&key).expect("sealed");
    assert_eq!(token, text(vector, "token"));

    let opened = Cursor::open(
        text(vector, "token"),
        &key,
        text(fields, "api"),
        text(fields, "scope"),
        text(fields, "filters"),
    )
    .expect("the vector's token opens");
    assert_eq!(opened, cursor);
}

/// WP-5.5, H-12: the version 2 cursor is the generator's bytes, opens for its own read until it
/// expires, and the version 1 token still opens through its own codec.
#[test]
fn the_version_2_cursor_is_reproduced_byte_for_byte_and_bounded() {
    let vectors = vectors();
    let vector = &vectors["cursor_v2"];
    let payload = &vector["payload"];
    let mut cursor = Cursor::beginning(
        text(payload, "api"),
        text(payload, "concrete_resource"),
        text(payload, "filter_digest"),
        None,
    );
    cursor.advance(
        "data-plane-7f3a",
        Position {
            segment: 1,
            offset: 2,
        },
    );
    cursor.frontier = Frontier::of("data-plane-7f3a", 3);
    let key = CursorKey::new(&hex(text(vector, "key")), &[]).expect("a key");
    let issued_at = vector["issued_at"].as_u64().expect("a time");
    let lifetime =
        std::time::Duration::from_secs(vector["lifetime_secs"].as_u64().expect("a lifetime"));
    let token = cursor.seal_v2(&key, issued_at, lifetime).expect("sealed");
    assert_eq!(token, text(vector, "token"));

    let open = |at: u64| {
        Cursor::open_any(
            text(vector, "token"),
            &key,
            text(payload, "api"),
            text(payload, "concrete_resource"),
            text(payload, "filter_digest"),
            at,
        )
    };
    let opened = open(issued_at).expect("the vector's token opens");
    assert_eq!(opened.positions, cursor.positions);
    assert_eq!(opened.frontier, cursor.frontier);
    assert_eq!(
        open(issued_at + lifetime.as_secs()),
        Err(permguard_stream::cursor::CursorError::Forged),
        "expired"
    );

    // The version 1 vector, through `open_any`, as a reader holding an old offset presents it.
    let v1 = &vectors["cursor_v1"];
    let fields = &v1["cursor"];
    assert!(
        Cursor::open_any(
            text(v1, "token"),
            &CursorKey::new(&hex(text(v1, "key")), &[]).expect("a key"),
            text(fields, "api"),
            text(fields, "scope"),
            text(fields, "filters"),
            u64::MAX,
        )
        .is_ok()
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
