// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The NOTP target's golden vectors (`contracts/vectors/notp.json`, WP-7.1), computed by an
//! independent generator and reproduced here: the ref states and their digests, the head statement
//! binding the authority, the ref digest and the ring set, the messages carrying them, and the
//! manifest's interfaces with the encodings a reader refuses.

#![allow(clippy::expect_used)]

use permguard_notp::{
    CommitPushRequest, CommitPushResponse, ExpectedRef, GetRefResponse, NegotiatePullRequest,
    NegotiatePushRequest, NegotiatePushResponse, ObjectClaim,
};
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;
use permguard_objects::manifest::Manifest;
use permguard_objects::refstate::RefState;
use permguard_objects::statement::{Freshness, HeadStatement, SignedHead, check_freshness};
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/notp.json"
    ))
    .expect("the vectors read");
    serde_json::from_str(&text).expect("the vectors parse")
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex text");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn digest(value: &Value) -> Digest {
    Digest::parse(value.as_str().expect("a digest")).expect("a digest")
}

#[test]
fn the_ref_states_and_their_digests_are_the_generators() {
    let v = vectors();
    let r = &v["ref_state"];
    let first = RefState::first(digest(&r["head_1"]));
    assert_eq!(first.encode().expect("encodes"), hex(&r["first"]));
    assert_eq!(
        first.ref_digest().expect("a digest"),
        digest(&r["first_digest"])
    );
    let second = first.successor(digest(&r["head_2"])).expect("a successor");
    assert_eq!(second.encode().expect("encodes"), hex(&r["second"]));
    assert_eq!(
        second.ref_digest().expect("a digest"),
        digest(&r["second_digest"])
    );
    assert_eq!(
        RefState::decode(&hex(&r["second"])).expect("decodes"),
        second
    );
}

#[test]
fn the_head_statement_binds_the_authority_the_ref_digest_and_the_ring_set() {
    let v = vectors();
    let h = &v["head_statement"];
    let statement = HeadStatement {
        zone: h["zone"].as_str().expect("a zone").to_owned(),
        ledger: h["ledger"].as_str().expect("a ledger").to_owned(),
        r#ref: h["ref"].as_str().expect("a ref").to_owned(),
        digest: digest(&v["ref_state"]["head_2"]),
        counter: h["counter"].as_u64().expect("a counter"),
        signed_at: h["signed_at"].as_i64().expect("a time"),
        authority_host_id: hex(&h["authority_host_id"]).try_into().expect("16 bytes"),
        ref_digest: digest(&v["ref_state"]["second_digest"]),
        ring_epoch: h["ring_epoch"].as_u64().expect("an epoch"),
        key_set_digest: digest(&h["key_set_digest"]),
    };
    assert_eq!(statement.encode().expect("encodes"), hex(&h["payload"]));
    let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&hex(&Value::from(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )))
    .expect("the seed");
    let kid = v["kid"].as_str().expect("a kid").as_bytes();
    let signed = SignedHead::sign(&statement, &key, kid).expect("signed");
    assert_eq!(signed.encode().expect("encodes"), hex(&h["cose_sign1"]));
    let read = SignedHead::decode(&hex(&h["cose_sign1"])).expect("decodes");
    assert_eq!(
        read.verify(Suite::Ed25519Sha256V1, &hex(&v["public"]))
            .expect("verifies"),
        statement
    );
    // The verdicts over the ref digest: the first state then the second advance; the second
    // again is a retry; the first presented after it a rollback; another state at its counter an
    // equivocation.
    let first = digest(&v["ref_state"]["first_digest"]);
    let second = digest(&v["ref_state"]["second_digest"]);
    assert_eq!(check_freshness(None, (1, &first)), Freshness::Newer);
    assert_eq!(
        check_freshness(Some((1, &first)), (2, &second)),
        Freshness::Newer
    );
    assert_eq!(
        check_freshness(Some((2, &second)), (2, &second)),
        Freshness::Same
    );
    assert_eq!(
        check_freshness(Some((2, &second)), (1, &first)),
        Freshness::Rollback
    );
    assert_eq!(
        check_freshness(Some((2, &second)), (2, &first)),
        Freshness::Equivocation
    );
}

#[test]
fn the_messages_are_the_generators_bytes() {
    let v = vectors();
    let m = &v["messages"];
    let r = &v["ref_state"];
    let transfer: [u8; 16] = hex(&m["transfer_id"]).try_into().expect("16 bytes");
    let expected = ExpectedRef {
        counter: 1,
        digest: digest(&r["first_digest"]),
    };
    let negotiate = NegotiatePushRequest {
        r#ref: "refs/heads/main".to_owned(),
        new_head: digest(&r["head_2"]),
        expected_ref: Some(expected.clone()),
        closure: vec![ObjectClaim {
            digest: Digest::compute(b"object"),
            size: 120,
        }],
        request_id: "push-1".to_owned(),
    };
    assert_eq!(
        negotiate.encode().expect("encodes"),
        hex(&m["negotiate_push"])
    );
    assert_eq!(
        NegotiatePushRequest::decode(&hex(&m["negotiate_push"])).expect("decodes"),
        negotiate
    );
    let answer = NegotiatePushResponse {
        missing: vec![Digest::compute(b"object")],
        max_batch_bytes: 1_048_576,
        max_batch_objects: 256,
        compression: Some("deflate".to_owned()),
        transfer_id: transfer,
        reservation: 4096,
        expiry: 1_791_195_000,
    };
    assert_eq!(
        answer.encode().expect("encodes"),
        hex(&m["negotiate_push_answer"])
    );
    let commit = CommitPushRequest {
        r#ref: "refs/heads/main".to_owned(),
        new_head: digest(&r["head_2"]),
        expected_ref: Some(expected.clone()),
        transfer_id: transfer,
        request_id: "commit-1".to_owned(),
    };
    assert_eq!(commit.encode().expect("encodes"), hex(&m["commit_push"]));
    let statement = hex(&v["head_statement"]["cose_sign1"]);
    let committed = CommitPushResponse {
        head: digest(&r["head_2"]),
        counter: 2,
        statement: statement.clone(),
        ref_digest: digest(&r["second_digest"]),
    };
    assert_eq!(
        committed.encode().expect("encodes"),
        hex(&m["commit_push_answer"])
    );
    let get = GetRefResponse {
        head: digest(&r["head_2"]),
        counter: 2,
        statement,
        ref_digest: digest(&r["second_digest"]),
    };
    assert_eq!(get.encode().expect("encodes"), hex(&m["get_ref_answer"]));
    let pull = NegotiatePullRequest {
        r#ref: "refs/heads/main".to_owned(),
        at: None,
        have: Vec::new(),
        checkpoint: Some(expected),
    };
    assert_eq!(pull.encode().expect("encodes"), hex(&m["negotiate_pull"]));
    // Today's `expected_old` is refused by the target reader.
    assert!(NegotiatePushRequest::decode(&hex(&m["retired_expected_old"])).is_err());
}

#[test]
fn the_manifests_interfaces_are_frozen_with_their_refusals() {
    let v = vectors();
    let m = &v["manifest"];
    let manifest = Manifest::decode(&hex(&m["interfaces"])).expect("the manifest decodes");
    assert_eq!(
        manifest.partitions["policies"].interfaces,
        vec![
            permguard_objects::manifest::PROFILE_PDP_NATIVE_V1.to_owned(),
            permguard_objects::manifest::PROFILE_PDP_TEMPORAL_V1ALPHA1.to_owned()
        ]
    );
    assert_eq!(manifest.encode().expect("encodes"), hex(&m["interfaces"]));
    let legacy = Manifest::decode(&hex(&m["legacy"])).expect("the legacy manifest decodes");
    assert!(legacy.partitions["policies"].interfaces.is_empty());
    assert_eq!(legacy.encode().expect("encodes"), hex(&m["legacy"]));
    assert_eq!(
        permguard_objects::manifest::implicit_partitions(&legacy),
        vec!["policies"]
    );
    for refused in [
        "unsorted",
        "duplicate",
        "empty",
        "not_promised",
        "unknown_key",
    ] {
        assert!(
            Manifest::decode(&hex(&m[refused])).is_err(),
            "the `{refused}` manifest decoded"
        );
    }
}
