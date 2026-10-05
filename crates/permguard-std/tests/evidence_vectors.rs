// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shared golden vectors of `contracts/vectors/evidence.json` (WP-0.7), reproduced by this
//! crate: today's audit pseudonym.
//!
//! Today's pseudonym is HMAC-SHA256 over the identifier with no domain and an undivided key; the
//! resource-derived target is frozen by the audit engine (WP-3.5), as status.md records.

#![allow(clippy::expect_used)]

use permguard_core::Pseudonymizer as _;
use permguard_std::pseudonym::HmacPseudonymizer;
use serde_json::Value;

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` is text"))
}

#[test]
fn todays_pseudonym_matches_the_vector() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/evidence.json"
    );
    let vectors: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the vectors are readable"))
            .expect("the vectors are JSON");
    let vector = &vectors["pseudonym"];
    let key: Vec<u8> = (0..text(vector, "key").len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text(vector, "key")[at..at + 2], 16).expect("hex"))
        .collect();
    let pseudonymizer = HmacPseudonymizer::new(&key, text(vector, "key_version"));
    assert_eq!(
        pseudonymizer.pseudonymize(text(vector, "identifier")),
        text(vector, "pseudonym")
    );
}
