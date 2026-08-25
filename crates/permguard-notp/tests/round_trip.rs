// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every message survives an encode/decode round trip, with and without its
//! optional fields — the property the whole protocol rests on: two parties
//! reading the same bytes must build the same message. And a malformed body
//! is a refusal, never a default.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use permguard_notp::*;
use permguard_objects::digest::Digest;

#[test]
fn the_push_messages_round_trip() {
    let d1 = Digest::compute(b"1");
    let d2 = Digest::compute(b"2");

    let req = NegotiatePushRequest {
        r#ref: "main".into(),
        new_head: d1.clone(),
        expected_old: Some(d2.clone()),
        closure: vec![ObjectClaim {
            digest: d1.clone(),
            size: 42,
        }],
    };
    assert_eq!(NegotiatePushRequest::decode(&req.encode()).unwrap(), req);

    // The creation case: no expected old head, and the optional is omitted.
    let creation = NegotiatePushRequest {
        expected_old: None,
        ..req.clone()
    };
    assert_eq!(
        NegotiatePushRequest::decode(&creation.encode()).unwrap(),
        creation
    );

    let resp = NegotiatePushResponse {
        missing: vec![d1.clone()],
        max_batch_bytes: 1,
        max_batch_objects: 2,
        compression: Some("deflate".into()),
    };
    assert_eq!(NegotiatePushResponse::decode(&resp.encode()).unwrap(), resp);

    let up = UploadObjectsRequest {
        objects: vec![vec![1, 2], vec![]],
        compression: None,
    };
    assert_eq!(UploadObjectsRequest::decode(&up.encode()).unwrap(), up);

    let upr = UploadObjectsResponse {
        received: vec![d1.clone(), d2.clone()],
    };
    assert_eq!(UploadObjectsResponse::decode(&upr.encode()).unwrap(), upr);

    let commit = CommitPushRequest {
        r#ref: "main".into(),
        new_head: d1.clone(),
        expected_old: None,
    };
    assert_eq!(CommitPushRequest::decode(&commit.encode()).unwrap(), commit);

    let committed = CommitPushResponse {
        head: d1,
        counter: 7,
        statement: vec![9],
    };
    assert_eq!(
        CommitPushResponse::decode(&committed.encode()).unwrap(),
        committed
    );
}

#[test]
fn the_pull_messages_round_trip() {
    let d1 = Digest::compute(b"1");
    let d2 = Digest::compute(b"2");

    let pull = NegotiatePullRequest {
        r#ref: "main".into(),
        at: Some(d2.clone()),
        have: vec![d1.clone()],
    };
    assert_eq!(NegotiatePullRequest::decode(&pull.encode()).unwrap(), pull);

    let answer = NegotiatePullResponse {
        head: d1.clone(),
        counter: 3,
        statement: vec![1],
        missing: vec![d2],
        max_batch_bytes: 10,
        max_batch_objects: 20,
        compression: Some("deflate".into()),
    };
    assert_eq!(
        NegotiatePullResponse::decode(&answer.encode()).unwrap(),
        answer
    );

    let fetch = FetchObjectsRequest {
        digests: vec![d1],
        accept_compression: Some("deflate".into()),
    };
    assert_eq!(FetchObjectsRequest::decode(&fetch.encode()).unwrap(), fetch);

    let fetched = FetchObjectsResponse {
        objects: vec![vec![3, 4]],
        compression: None,
    };
    assert_eq!(
        FetchObjectsResponse::decode(&fetched.encode()).unwrap(),
        fetched
    );
}

#[test]
fn malformed_bodies_are_refused() {
    assert!(NegotiatePushRequest::decode(&[0x00]).is_err());
    assert!(FetchObjectsRequest::decode(b"not cbor").is_err());
    // A body of the right shape but the wrong field types is still a refusal.
    assert!(
        CommitPushResponse::decode(
            &NegotiatePushResponse {
                missing: vec![],
                max_batch_bytes: 1,
                max_batch_objects: 1,
                compression: None,
            }
            .encode()
        )
        .is_err()
    );
}
