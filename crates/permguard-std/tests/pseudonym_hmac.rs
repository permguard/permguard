#![cfg(feature = "pseudonym")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a pseudonym discloses, and what rotating the key does to it.
//!
//! Here rather than beside the code because the properties worth proving are comparative — the same
//! value twice, two different values, the same value under two keys — and each needs its own fixture.

use permguard_core::Pseudonymizer;
use permguard_std::pseudonym::HmacPseudonymizer;

const KEY: &str = "0123456789abcdef0123456789abcdef";
const OTHER_KEY: &str = "fedcba9876543210fedcba9876543210";

fn pseudonymizer() -> HmacPseudonymizer {
    HmacPseudonymizer::new(KEY.as_bytes(), "v1")
}

#[test]
fn test_the_same_value_always_yields_the_same_token() {
    let pseudonymizer = pseudonymizer();

    assert_eq!(
        pseudonymizer.pseudonymize("nicola@nitroagility.com"),
        pseudonymizer.pseudonymize("nicola@nitroagility.com")
    );
}

#[test]
fn test_different_values_yield_different_tokens() {
    let pseudonymizer = pseudonymizer();

    assert_ne!(
        pseudonymizer.pseudonymize("a@example.com"),
        pseudonymizer.pseudonymize("b@example.com")
    );
}

#[test]
fn test_a_token_discloses_neither_the_value_nor_its_length() {
    let pseudonymizer = pseudonymizer();

    let short = pseudonymizer.pseudonymize("a@b.c");
    let long = pseudonymizer.pseudonymize("a-very-long-account-identifier@example.com");

    assert!(!short.contains("a@b.c"));
    assert_eq!(short.len(), long.len());
}

#[test]
fn test_a_token_names_the_key_version_that_produced_it() {
    let token = pseudonymizer().pseudonymize("a@example.com");

    assert!(token.starts_with("v1:"));
    assert_eq!(pseudonymizer().key_version(), "v1");
}

#[test]
fn test_rotating_the_key_severs_correlation() {
    let before = HmacPseudonymizer::new(KEY.as_bytes(), "v1").pseudonymize("a@example.com");
    let after = HmacPseudonymizer::new(OTHER_KEY.as_bytes(), "v2").pseudonymize("a@example.com");

    assert_ne!(before, after);
    assert!(before.starts_with("v1:"));
    assert!(after.starts_with("v2:"));
}

#[test]
fn test_the_same_key_under_a_new_version_is_still_a_new_token() {
    // The version is part of what a reader keys on, so bumping it alone must not silently keep
    // the old correlation readable under a new name.
    let first = HmacPseudonymizer::new(KEY.as_bytes(), "v1").pseudonymize("a@example.com");
    let second = HmacPseudonymizer::new(KEY.as_bytes(), "v2").pseudonymize("a@example.com");

    assert_ne!(first, second);
    assert_eq!(
        first.trim_start_matches("v1:"),
        second.trim_start_matches("v2:"),
        "only the prefix should differ when the key is unchanged"
    );
}

#[test]
fn test_the_token_is_hex_of_the_expected_width() {
    let token = pseudonymizer().pseudonymize("a@example.com");
    let digest = token.trim_start_matches("v1:");

    assert_eq!(digest.len(), 32, "128 bits, hex encoded");
    assert!(
        digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
}

#[test]
fn test_it_is_usable_through_the_trait_object() {
    let pseudonymizer: Box<dyn Pseudonymizer> = Box::new(pseudonymizer());

    assert!(
        pseudonymizer
            .pseudonymize("a@example.com")
            .starts_with("v1:")
    );
}
