// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The canonical-JSON profile, frozen as vectors.
//!
//! `tests/vectors/jcs.json` is the contract another implementation reproduces: every `canonical`
//! entry must parse and canonicalise to the stated bytes, every `refused` entry must be refused
//! with the stated error, and every `not_canonical` entry must parse but fail the byte-identity
//! check. The file is edited only by a change to the profile, never to make a test pass.

#![allow(clippy::expect_used)]

use permguard_stream::jcs::{CanonicalError, canonicalize, decode_canonical, parse_strict};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/jcs.json");
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

fn error_name(error: &CanonicalError) -> &'static str {
    match error {
        CanonicalError::OutOfRange(_) => "OutOfRange",
        CanonicalError::DuplicateName(_) => "DuplicateName",
        CanonicalError::Syntax(_) => "Syntax",
        CanonicalError::NotCanonical => "NotCanonical",
    }
}

#[test]
fn test_every_canonical_vector_parses_and_reproduces_its_bytes() {
    let vectors = vectors();
    for entry in entries(&vectors, "canonical") {
        let name = text(entry, "name");
        let parsed = parse_strict(text(entry, "input").as_bytes())
            .unwrap_or_else(|error| panic!("{name}: the input must parse, got {error}"));
        let canonical = canonicalize(&parsed).expect("the parsed value canonicalises");
        assert_eq!(
            String::from_utf8(canonical.clone()).expect("canonical bytes are UTF-8"),
            text(entry, "canonical"),
            "{name}"
        );
        assert_eq!(
            decode_canonical(&canonical).expect("canonical bytes decode"),
            parsed,
            "{name}: canonical bytes are a fixed point"
        );
    }
}

#[test]
fn test_every_refused_vector_is_refused_with_its_named_error() {
    let vectors = vectors();
    for entry in entries(&vectors, "refused") {
        let name = text(entry, "name");
        match parse_strict(text(entry, "input").as_bytes()) {
            Ok(value) => panic!("{name}: accepted as {value}"),
            Err(error) => assert_eq!(error_name(&error), text(entry, "error"), "{name}: {error}"),
        }
    }
}

#[test]
fn test_every_not_canonical_vector_parses_but_fails_byte_identity() {
    let vectors = vectors();
    for entry in entries(&vectors, "not_canonical") {
        let name = text(entry, "name");
        let input = text(entry, "input").as_bytes();
        parse_strict(input)
            .unwrap_or_else(|error| panic!("{name}: the input must parse, got {error}"));
        assert_eq!(
            decode_canonical(input),
            Err(CanonicalError::NotCanonical),
            "{name}"
        );
    }
}
