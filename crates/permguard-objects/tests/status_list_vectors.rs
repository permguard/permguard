// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The status list codec against `contracts/vectors/status-list.json`: the four test vectors of
//! `draft-ietf-oauth-status-list-21` appendix C, which `contracts/vectors/status_list.py` checks
//! with the standard library. Decoding each gives exactly the statuses it lists, every other
//! entry 0; encoding the decoded list and decoding it again gives the same list, and a list
//! larger than its bound is refused while it decompresses.
//!
//! The encoded bytes are not the draft's: the pure-Rust DEFLATE backend compresses as well as
//! zlib at its highest level but not to the same bytes, and the draft asks only that a list
//! decode to its entries. Any decoder reads ours, as ours reads the draft's.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use permguard_objects::status_list::{ENTRIES, StatusList, StatusListError};
use serde_json::Value;

struct Vector {
    bits: u8,
    size: usize,
    statuses: BTreeMap<String, u8>,
    lst: String,
}

fn vectors() -> Vec<Vector> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/vectors/status-list.json");
    let document: Value =
        serde_json::from_slice(&std::fs::read(path).expect("the vectors read")).expect("JSON");
    let vectors: Vec<Vector> = document["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(|vector| Vector {
            bits: u8::try_from(vector["bits"].as_u64().expect("bits")).expect("small"),
            size: usize::try_from(vector["size"].as_u64().expect("size")).expect("small"),
            statuses: vector["statuses"]
                .as_object()
                .expect("statuses")
                .iter()
                .map(|(index, value)| {
                    (
                        index.clone(),
                        u8::try_from(value.as_u64().expect("a value")).expect("small"),
                    )
                })
                .collect(),
            lst: vector["lst"].as_str().expect("lst").to_owned(),
        })
        .collect();
    assert_eq!(vectors.len(), 4, "1, 2, 4 and 8 bits");
    vectors
}

#[test]
fn every_draft_vector_decodes_to_exactly_its_statuses() {
    for vector in vectors() {
        let list = StatusList::decode(vector.bits, &vector.lst, 1 << 20, ENTRIES)
            .expect("the vector decodes");
        assert_eq!(list.len(), vector.size, "{} bits", vector.bits);
        let statuses: BTreeMap<usize, u8> = vector
            .statuses
            .iter()
            .map(|(index, value)| (index.parse().expect("an index"), *value))
            .collect();
        for index in 0..list.len() {
            assert_eq!(
                list.get(index).expect("in range"),
                statuses.get(&index).copied().unwrap_or(0),
                "{} bits, index {index}",
                vector.bits
            );
        }
    }
}

#[test]
fn a_list_written_entry_by_entry_encodes_to_what_decodes_back() {
    for vector in vectors() {
        let mut list = StatusList::new(vector.bits, vector.size).expect("a list");
        for (index, value) in &vector.statuses {
            list.set(index.parse().expect("an index"), *value)
                .expect("written");
        }
        let encoded = list.encode().expect("encodes");
        let decoded = StatusList::decode(vector.bits, &encoded, 1 << 20, ENTRIES).expect("decodes");
        assert_eq!(decoded, list, "{} bits", vector.bits);
        // The draft's own bytes decode to the same list as ours.
        let theirs =
            StatusList::decode(vector.bits, &vector.lst, 1 << 20, ENTRIES).expect("decodes");
        assert_eq!(theirs, list, "{} bits", vector.bits);
    }
}

#[test]
fn a_list_past_its_bound_is_refused_while_it_decompresses() {
    let vector = vectors()
        .into_iter()
        .find(|vector| vector.bits == 2)
        .expect("2 bits");
    // The list holds 2^20 entries; a reader bound to fewer refuses it.
    assert!(matches!(
        StatusList::decode(2, &vector.lst, 1 << 20, ENTRIES / 2),
        Err(StatusListError::TooLarge(_))
    ));
    // An encoded form past its bound is refused before it is decoded.
    assert!(matches!(
        StatusList::decode(2, &vector.lst, 16, ENTRIES),
        Err(StatusListError::TooLarge(_))
    ));
    // Not base64url, not ZLIB, an unknown width: refused.
    for (bits, lst) in [(2, "not base64!"), (2, "AAAA"), (3, vector.lst.as_str())] {
        assert!(
            StatusList::decode(bits, lst, 1 << 20, ENTRIES).is_err(),
            "{bits} {lst}"
        );
    }
}

#[test]
fn an_entry_is_bounded_by_its_width_and_the_list() {
    let mut list = StatusList::new(2, 8).expect("a list");
    list.set(7, 3).expect("the last entry");
    assert_eq!(list.get(7), Ok(3));
    assert_eq!(list.set(8, 1), Err(StatusListError::Index(8)));
    assert_eq!(list.set(0, 4), Err(StatusListError::Value(4)));
    // Writing one entry leaves its neighbours as they were.
    list.set(6, 1).expect("written");
    list.set(6, 2).expect("written");
    assert_eq!(
        (list.get(5), list.get(6), list.get(7)),
        (Ok(0), Ok(2), Ok(3))
    );
    assert!(StatusList::new(3, 8).is_err());
}
