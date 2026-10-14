// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every NOTP message is a closed envelope: a label the reader does not know is refused, never
//! skipped, so a field a later version adds cannot be dropped by a reader that cannot honour it.

use permguard_notp::pull::*;
use permguard_notp::push::*;
use permguard_notp::{ExpectedRef, TransferId};
use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

fn digest() -> Digest {
    Digest::compute(b"x")
}

fn expected() -> Option<ExpectedRef> {
    Some(ExpectedRef {
        counter: 1,
        digest: digest(),
    })
}

const TRANSFER: TransferId = [7; 16];

/// The same bytes with one more top-level label, `99`, re-encoded canonically.
fn with_unknown_label(bytes: &[u8]) -> Vec<u8> {
    let Value::Map(mut pairs) = cbor::decode_canonical(bytes).expect("a message decodes") else {
        panic!("a message is a map");
    };
    pairs.push((Value::Int(99), Value::Int(1)));
    cbor::encode(&Value::Map(pairs)).expect("the extended message encodes")
}

macro_rules! closed {
    ($($message:expr => $kind:ty),* $(,)?) => {{
        $(
            let bytes = $message.encode().expect("the message encodes");
            assert!(<$kind>::decode(&bytes).is_ok(), "{} decodes as written", stringify!($kind));
            assert!(
                <$kind>::decode(&with_unknown_label(&bytes)).is_err(),
                "{} accepted an unknown label",
                stringify!($kind)
            );
        )*
    }};
}

#[test]
fn test_every_message_refuses_an_unknown_label() {
    closed! {
        NegotiatePushRequest {
            r#ref: "main".to_owned(),
            new_head: digest(),
            expected_ref: expected(),
            closure: vec![ObjectClaim { digest: digest(), size: 1 }],
            request_id: "push-1".to_owned(),
        } => NegotiatePushRequest,
        NegotiatePushResponse {
            missing: vec![digest()],
            max_batch_bytes: 1,
            max_batch_objects: 1,
            compression: Some("deflate".to_owned()),
            transfer_id: TRANSFER,
            reservation: 10,
            expiry: 20,
        } => NegotiatePushResponse,
        UploadObjectsRequest { objects: vec![vec![1]], compression: None, transfer_id: TRANSFER }
            => UploadObjectsRequest,
        UploadObjectsResponse { received: vec![digest()], remaining: 1 } => UploadObjectsResponse,
        CommitPushRequest {
            r#ref: "main".to_owned(),
            new_head: digest(),
            expected_ref: None,
            transfer_id: TRANSFER,
            request_id: "commit-1".to_owned(),
        } => CommitPushRequest,
        CommitPushResponse { head: digest(), counter: 1, statement: vec![1], ref_digest: digest() }
            => CommitPushResponse,
        GetRefResponse { head: digest(), counter: 1, statement: vec![1], ref_digest: digest() }
            => GetRefResponse,
        NegotiatePullRequest {
            r#ref: "main".to_owned(),
            at: Some(digest()),
            have: vec![],
            checkpoint: expected(),
        } => NegotiatePullRequest,
        NegotiatePullResponse {
            head: digest(),
            counter: 1,
            statement: vec![1],
            missing: vec![],
            max_batch_bytes: 1,
            max_batch_objects: 1,
            compression: None,
            transfer_id: TRANSFER,
            ref_digest: digest(),
            expiry: 20,
        } => NegotiatePullResponse,
        FetchObjectsRequest { digests: vec![digest()], accept_compression: None, transfer_id: TRANSFER }
            => FetchObjectsRequest,
        FetchObjectsResponse { objects: vec![vec![1]], compression: None, expiry: 20 }
            => FetchObjectsResponse,
    }
}

/// An unknown label inside a closure entry or an expected ref is refused too: closed at every
/// level.
#[test]
fn test_a_closure_entry_or_an_expected_ref_refuses_an_unknown_label() {
    let request = NegotiatePushRequest {
        r#ref: "main".to_owned(),
        new_head: digest(),
        expected_ref: expected(),
        closure: vec![ObjectClaim {
            digest: digest(),
            size: 1,
        }],
        request_id: "push-1".to_owned(),
    };
    for label in [4, 5] {
        let Value::Map(mut pairs) =
            cbor::decode_canonical(&request.encode().expect("encodes")).expect("decodes")
        else {
            panic!("a map");
        };
        for (key, value) in &mut pairs {
            if *key != Value::Int(label) {
                continue;
            }
            match value {
                Value::Array(entries) => {
                    if let Some(Value::Map(entry)) = entries.first_mut() {
                        entry.push((Value::Int(99), Value::Int(1)));
                    }
                }
                Value::Map(entry) => entry.push((Value::Int(99), Value::Int(1))),
                _ => {}
            }
        }
        let bytes = cbor::encode(&Value::Map(pairs)).expect("encodes");
        assert!(
            NegotiatePushRequest::decode(&bytes).is_err(),
            "label {label}"
        );
    }
}

/// Today's `expected_old`, label 3 of a negotiation and a commit, is retired: refused.
#[test]
fn test_the_retired_expected_old_is_refused() {
    let commit = CommitPushRequest {
        r#ref: "main".to_owned(),
        new_head: digest(),
        expected_ref: None,
        transfer_id: TRANSFER,
        request_id: "commit-1".to_owned(),
    };
    let Value::Map(mut pairs) =
        cbor::decode_canonical(&commit.encode().expect("encodes")).expect("decodes")
    else {
        panic!("a map");
    };
    pairs.push((Value::Int(3), Value::Text(digest().to_string())));
    let bytes = cbor::encode(&Value::Map(pairs)).expect("encodes");
    assert!(CommitPushRequest::decode(&bytes).is_err());
}

/// A request id outside its grammar and a transfer id of another length are refused.
#[test]
fn test_request_and_transfer_ids_are_held_to_their_form() {
    let commit = CommitPushRequest {
        r#ref: "main".to_owned(),
        new_head: digest(),
        expected_ref: None,
        transfer_id: TRANSFER,
        request_id: String::new(),
    };
    assert!(CommitPushRequest::decode(&commit.encode().expect("encodes")).is_err());
    let long = CommitPushRequest {
        request_id: "x".repeat(129),
        ..commit.clone()
    };
    assert!(CommitPushRequest::decode(&long.encode().expect("encodes")).is_err());
    let Value::Map(mut pairs) = cbor::decode_canonical(
        &CommitPushRequest {
            request_id: "ok".to_owned(),
            ..commit
        }
        .encode()
        .expect("encodes"),
    )
    .expect("decodes") else {
        panic!("a map");
    };
    for (key, value) in &mut pairs {
        if *key == Value::Int(5) {
            *value = Value::Bytes(vec![1; 15]);
        }
    }
    let bytes = cbor::encode(&Value::Map(pairs)).expect("encodes");
    assert!(CommitPushRequest::decode(&bytes).is_err());
}
