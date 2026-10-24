// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use super::*;

fn manifest() -> Manifest {
    Manifest {
        host_id: [7; 16],
        exported_at: 1_800_000_000,
        zone_id: "0199a8f0-0000-7000-8000-000000000001".to_owned(),
        zone_name: "delivery".to_owned(),
        ledgers: vec![ExportedLedger {
            id: "0199a8f0-0000-7000-8000-000000000002".to_owned(),
            name: "release-pipeline".to_owned(),
            default_ref: "main".to_owned(),
            refs: vec![ExportedRef {
                name: "main".to_owned(),
                counter: 3,
                head: Digest::compute(b"a head"),
            }],
            objects: 12,
            statements: 1,
        }],
        bundle_digest: bundle_digest(b"the bundle"),
        bundle_bytes: 10,
    }
}

/// WP-7.10: a manifest round trips and is closed: another version, an unknown label, a ledger or
/// a ref named twice, a malformed digest or an oversized manifest is refused.
#[test]
fn a_manifest_round_trips_and_is_closed() {
    let held = manifest();
    let bytes = held.encode().expect("encodes");
    assert_eq!(Manifest::decode(&bytes).expect("reads"), held);

    let Value::Map(pairs) = cbor::decode_canonical(&bytes).expect("cbor") else {
        panic!("a map");
    };
    let encode = |pairs: Vec<(Value, Value)>| cbor::encode(&Value::Map(pairs)).expect("encodes");
    let mut extra = pairs.clone();
    extra.push((Value::Int(8), Value::Int(0)));
    assert!(Manifest::decode(&encode(extra)).is_err());
    let mut other = pairs.clone();
    other[0].1 = Value::Int(2);
    let refused = Manifest::decode(&encode(other)).expect_err("another version");
    assert!(refused.contains("version 2"), "{refused}");
    let mut digest = pairs.clone();
    digest[5].1 = Value::Text("sha256:not-hex".to_owned());
    assert!(Manifest::decode(&encode(digest)).is_err());

    let mut twice = held.clone();
    twice.ledgers.push(twice.ledgers[0].clone());
    assert!(Manifest::decode(&twice.encode().expect("encodes")).is_err());
    let mut refs = held.clone();
    let again = refs.ledgers[0].refs[0].clone();
    refs.ledgers[0].refs.push(again);
    assert!(Manifest::decode(&refs.encode().expect("encodes")).is_err());
    // A ledger named twice by id alone, or by name alone.
    let mut by_id = held.clone();
    let mut again = by_id.ledgers[0].clone();
    again.name = "another".to_owned();
    by_id.ledgers.push(again);
    assert!(Manifest::decode(&by_id.encode().expect("encodes")).is_err());
    let mut by_name = held.clone();
    let mut again = by_name.ledgers[0].clone();
    again.id = "another-id".to_owned();
    by_name.ledgers.push(again);
    assert!(Manifest::decode(&by_name.encode().expect("encodes")).is_err());
    // A text past its bound is neither written nor read.
    let mut long = held.clone();
    long.zone_name = "z".repeat(MAX_TEXT_BYTES + 1);
    assert!(long.encode().is_err());
    let mut zone_name = pairs.clone();
    zone_name[3].1 = Value::Map(vec![
        (Value::Int(1), Value::Text("zone-id".to_owned())),
        (Value::Int(2), Value::Text("z".repeat(MAX_TEXT_BYTES + 1))),
    ]);
    assert!(Manifest::decode(&encode(zone_name)).is_err());
    let mut fit = held.clone();
    fit.zone_name = "z".repeat(MAX_TEXT_BYTES);
    assert_eq!(
        Manifest::decode(&fit.encode().expect("encodes")).expect("reads"),
        fit
    );
    let mut empty = held.clone();
    empty.zone_name = String::new();
    assert!(empty.encode().is_err());
    assert!(Manifest::decode(&vec![0; MAX_MANIFEST_BYTES + 1]).is_err());
}

/// WP-7.10: the bundle digest is domain-separated: it is not the bundle's plain SHA-256, and it
/// moves with every byte.
#[test]
fn the_bundle_digest_is_domain_separated() {
    assert_ne!(bundle_digest(b"bundle"), Digest::compute(b"bundle"));
    assert_ne!(bundle_digest(b"bundle"), bundle_digest(b"bundlf"));
    assert_eq!(bundle_digest(b"bundle"), bundle_digest(b"bundle"));
}

/// WP-7.10: an envelope past what a manifest can take is refused before anything is parsed.
#[test]
fn an_oversized_envelope_is_refused_before_it_is_read() {
    let refused = verify(
        &vec![0; MAX_MANIFEST_BYTES + 64 * 1024 + 1],
        &[],
        &[],
        "pin",
    )
    .expect_err("too large");
    assert!(refused.contains("at most"), "{refused}");
    let parsed = verify(&vec![0; MAX_MANIFEST_BYTES + 64 * 1024], &[], &[], "pin")
        .expect_err("not a bundle");
    assert!(!parsed.contains("at most"), "{parsed}");
}
