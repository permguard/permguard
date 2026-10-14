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
        expected_ref: Some(ExpectedRef {
            counter: 3,
            digest: d2.clone(),
        }),
        closure: vec![ObjectClaim {
            digest: d1.clone(),
            size: 42,
        }],
        request_id: "push-1".into(),
    };
    assert_eq!(
        NegotiatePushRequest::decode(&req.encode().expect("it encodes")).unwrap(),
        req
    );

    // The creation case: no expected ref, and the optional is omitted.
    let creation = NegotiatePushRequest {
        expected_ref: None,
        ..req.clone()
    };
    assert_eq!(
        NegotiatePushRequest::decode(&creation.encode().expect("it encodes")).unwrap(),
        creation
    );

    let resp = NegotiatePushResponse {
        missing: vec![d1.clone()],
        max_batch_bytes: 1,
        max_batch_objects: 2,
        compression: Some("deflate".into()),
        transfer_id: [1; 16],
        reservation: 4096,
        expiry: 1_791_195_000,
    };
    assert_eq!(
        NegotiatePushResponse::decode(&resp.encode().expect("it encodes")).unwrap(),
        resp
    );

    let up = UploadObjectsRequest {
        objects: vec![vec![1, 2], vec![]],
        compression: None,
        transfer_id: [1; 16],
    };
    assert_eq!(
        UploadObjectsRequest::decode(&up.encode().expect("it encodes")).unwrap(),
        up
    );

    let upr = UploadObjectsResponse {
        received: vec![d1.clone(), d2.clone()],
        remaining: 12,
    };
    assert_eq!(
        UploadObjectsResponse::decode(&upr.encode().expect("it encodes")).unwrap(),
        upr
    );

    let commit = CommitPushRequest {
        r#ref: "main".into(),
        new_head: d1.clone(),
        expected_ref: None,
        transfer_id: [1; 16],
        request_id: "commit-1".into(),
    };
    assert_eq!(
        CommitPushRequest::decode(&commit.encode().expect("it encodes")).unwrap(),
        commit
    );

    let committed = CommitPushResponse {
        head: d1,
        counter: 7,
        statement: vec![9],
        ref_digest: d2,
    };
    assert_eq!(
        CommitPushResponse::decode(&committed.encode().expect("it encodes")).unwrap(),
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
        checkpoint: Some(ExpectedRef {
            counter: 2,
            digest: d1.clone(),
        }),
    };
    assert_eq!(
        NegotiatePullRequest::decode(&pull.encode().expect("it encodes")).unwrap(),
        pull
    );

    let answer = NegotiatePullResponse {
        head: d1.clone(),
        counter: 3,
        statement: vec![1],
        missing: vec![d2.clone()],
        max_batch_bytes: 10,
        max_batch_objects: 20,
        compression: Some("deflate".into()),
        transfer_id: [2; 16],
        ref_digest: d2,
        expiry: 1_791_195_000,
    };
    assert_eq!(
        NegotiatePullResponse::decode(&answer.encode().expect("it encodes")).unwrap(),
        answer
    );

    let fetch = FetchObjectsRequest {
        digests: vec![d1],
        accept_compression: Some("deflate".into()),
        transfer_id: [2; 16],
    };
    assert_eq!(
        FetchObjectsRequest::decode(&fetch.encode().expect("it encodes")).unwrap(),
        fetch
    );

    let fetched = FetchObjectsResponse {
        objects: vec![vec![3, 4]],
        compression: None,
        expiry: 1_791_195_000,
    };
    assert_eq!(
        FetchObjectsResponse::decode(&fetched.encode().expect("it encodes")).unwrap(),
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
                transfer_id: [1; 16],
                reservation: 1,
                expiry: 1,
            }
            .encode()
            .expect("it encodes")
        )
        .is_err()
    );
}
