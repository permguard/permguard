// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A batch, signed and verified the way the two planes actually do it.
//!
//! Against a real key ring rather than a stub: a stub agrees with itself by
//! construction, and the properties worth pinning here — that the signature
//! covers the head, that an unknown `kid` cannot be attributed, that the
//! algorithm is not negotiable — are exactly the ones a stub would not test.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::time::Duration;

use permguard_core::KeyManager;
use permguard_decisions::envelope::{Envelope, Signed};
use permguard_decisions::record::{
    Body, Build, Commitments, GENESIS, MarkerBody, Record, Sampling, Stream, VERSION,
};
use permguard_decisions::{chain, merkle};
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use serde_json::Value;

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-batch-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&root);

    root
}

fn ring(tag: &str) -> DirectoryKeyManager {
    let keys = DirectoryKeyManager::new(
        scratch(tag),
        KeyPolicy {
            publish_ahead: Duration::from_secs(0),
            rotate_every: Duration::from_secs(3600),
            retain: Duration::from_secs(3600),
            verify_retain: Duration::from_secs(7200),
        },
    );
    keys.maintain().expect("the ring produces a key");

    keys
}

fn run(count: u64) -> Vec<Value> {
    let mut records = Vec::new();
    let mut prev = GENESIS.to_owned();
    for seq in 1..=count {
        let record = Record {
            v: VERSION,
            stream: Stream::new("plane", "inst"),
            seq,
            prev: prev.clone(),
            at: "2026-08-24T10:00:00Z".to_owned(),
            body: Body::Marker(Box::new(MarkerBody {
                predecessor: None,
                pdp: Build {
                    version: "0.1.0".to_owned(),
                    build: None,
                    engines: None,
                },
                sampling: Sampling {
                    permits: "1.0".to_owned(),
                },
                commitments: Commitments {
                    alg: "HMAC-SHA256".to_owned(),
                    key_version: "v1".to_owned(),
                },
            })),
        };
        prev = record.digest().expect("it digests");
        records.push(record.to_value().expect("it renders"));
    }

    records
}

fn envelope_for(records: &[Value], previous_head: &str) -> Envelope {
    let verified = chain::verify(records, None).expect("it is a chain");
    let leaves: Vec<String> = records
        .iter()
        .map(|record| permguard_decisions::digest_of(record).expect("it digests"))
        .collect();

    Envelope {
        stream: verified.stream,
        first_seq: verified.first_seq,
        last_seq: verified.last_seq,
        count: records.len() as u64,
        previous_head: previous_head.to_owned(),
        head: verified.head,
        merkle_root: merkle::root(&leaves).expect("a non-empty batch has a root"),
        sampling: Sampling {
            permits: "1.0".to_owned(),
        },
        at: "2026-08-24T10:00:01Z".to_owned(),
    }
}

#[test]
fn a_batch_verifies_against_the_published_key_set() {
    let keys = ring("verify");
    let records = run(10);
    let signed = Signed::create(&envelope_for(&records, GENESIS), &keys).expect("it signs");

    let attested = signed
        .verify(&keys.public_keys().expect("published"))
        .expect("it verifies");
    assert_eq!((attested.first_seq, attested.last_seq), (1, 10));
    assert_eq!(
        attested.head,
        permguard_decisions::digest_of(&records[9]).expect("it digests"),
        "the head is the digest of the last record, which the chain binds the rest to"
    );
}

#[test]
fn altering_one_record_of_a_signed_batch_is_detected_without_signing_each_record() {
    let keys = ring("altered");
    let mut records = run(10);
    let signed = Signed::create(&envelope_for(&records, GENESIS), &keys).expect("it signs");
    let attested = signed
        .verify(&keys.public_keys().expect("published"))
        .expect("it verifies");

    // A record in the middle, changed after the fact.
    records[4]["at"] = serde_json::json!("2030-01-01T00:00:00Z");

    assert!(
        chain::verify(&records, None).is_err(),
        "the chain refuses it — one signature per batch is enough because of this"
    );
    let leaves: Vec<String> = records
        .iter()
        .map(|record| permguard_decisions::digest_of(record).expect("it digests"))
        .collect();
    assert_ne!(
        merkle::root(&leaves).expect("a root"),
        attested.merkle_root,
        "and so does the tree a scoped reader checks against"
    );
}

#[test]
fn a_signature_from_a_key_nobody_published_cannot_be_attributed() {
    let ours = ring("ours");
    let theirs = ring("theirs");
    let signed = Signed::create(&envelope_for(&run(3), GENESIS), &theirs).expect("it signs");

    assert!(
        signed
            .verify(&ours.public_keys().expect("published"))
            .is_err(),
        "a batch is only worth what the key set says about the key that signed it"
    );
}

#[test]
fn the_algorithm_is_not_something_the_header_gets_to_choose() {
    let keys = ring("alg");
    let mut signed = Signed::create(&envelope_for(&run(3), GENESIS), &keys).expect("it signs");

    // The classic attack: rewrite the header and hope the verifier obeys it.
    use base64::Engine as _;
    signed.protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"none","kid":"anything"}"#);

    assert!(
        signed
            .verify(&keys.public_keys().expect("published"))
            .is_err(),
        "the verifier requires the algorithm it signs with, rather than honouring the one it is told"
    );
}

#[test]
fn a_batch_that_omits_records_inside_its_own_range_is_refused_before_any_signature() {
    let keys = ring("count");
    let mut envelope = envelope_for(&run(10), GENESIS);
    envelope.count = 9;

    assert!(
        Signed::create(&envelope, &keys).is_err(),
        "a signature over a lie is still a lie: the shape is checked first"
    );
}

#[test]
fn continuity_between_batches_is_checkable_and_not_merely_asserted() {
    let keys = ring("continuity");
    let records = run(20);
    let first = envelope_for(&records[..10], GENESIS);
    let second = envelope_for(&records[10..], &first.head);

    let signed = Signed::create(&second, &keys).expect("it signs");
    let attested = signed
        .verify(&keys.public_keys().expect("published"))
        .expect("it verifies");

    assert_eq!(
        attested.previous_head, first.head,
        "a verifier can join two batches without holding what is between them"
    );
    assert!(
        chain::verify(&records[10..], Some(&first.head)).is_ok(),
        "and the records themselves continue where the previous batch stopped"
    );
}
