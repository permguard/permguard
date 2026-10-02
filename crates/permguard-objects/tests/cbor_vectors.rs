// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The canonical-CBOR profile, frozen as vectors.
//!
//! `tests/vectors/cbor.json` is the contract another implementation reproduces: every `canonical`
//! entry decodes and re-encodes to the same bytes, every `refused` entry is refused with the stated
//! error. The file is edited only by a change to the profile, never to make a test pass.

#![allow(clippy::expect_used)]

use permguard_objects::cbor::{CborError, decode_canonical, encode};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/cbor.json");
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

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex digits"))
        .collect()
}

fn error_name(error: &CborError) -> &'static str {
    match error {
        CborError::Truncated => "Truncated",
        CborError::Unsupported(_) => "Unsupported",
        CborError::NotShortest => "NotShortest",
        CborError::KeyOrder => "KeyOrder",
        CborError::Utf8 => "Utf8",
        CborError::NotCanonical => "NotCanonical",
        CborError::TrailingBytes => "TrailingBytes",
        CborError::IntRange => "IntRange",
        CborError::Depth => "Depth",
    }
}

#[test]
fn test_every_canonical_vector_decodes_and_reproduces_its_bytes() {
    let vectors = vectors();
    for entry in entries(&vectors, "canonical") {
        let name = text(entry, "name");
        let input = bytes(text(entry, "hex"));
        let value = decode_canonical(&input)
            .unwrap_or_else(|error| panic!("{name}: the bytes must decode, got {error}"));
        assert_eq!(encode(&value), input, "{name}: encoding is a fixed point");
    }
}

#[test]
fn test_every_refused_vector_is_refused_with_its_named_error() {
    let vectors = vectors();
    for entry in entries(&vectors, "refused") {
        let name = text(entry, "name");
        match decode_canonical(&bytes(text(entry, "hex"))) {
            Ok(value) => panic!("{name}: accepted as {value:?}"),
            Err(error) => assert_eq!(error_name(&error), text(entry, "error"), "{name}: {error}"),
        }
    }
}
