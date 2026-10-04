// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every NOTP message is a closed envelope: a label the reader does not know is refused, never
//! skipped, so a field a later version adds cannot be dropped by a reader that cannot honour it.

use permguard_notp::pull::*;
use permguard_notp::push::*;
use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

fn digest() -> Digest {
    Digest::compute(b"x")
}

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
            expected_old: Some(digest()),
            closure: vec![ObjectClaim { digest: digest(), size: 1 }],
        } => NegotiatePushRequest,
        NegotiatePushResponse {
            missing: vec![digest()],
            max_batch_bytes: 1,
            max_batch_objects: 1,
            compression: Some("deflate".to_owned()),
        } => NegotiatePushResponse,
        UploadObjectsRequest { objects: vec![vec![1]], compression: None } => UploadObjectsRequest,
        UploadObjectsResponse { received: vec![digest()] } => UploadObjectsResponse,
        CommitPushRequest { r#ref: "main".to_owned(), new_head: digest(), expected_old: None }
            => CommitPushRequest,
        CommitPushResponse { head: digest(), counter: 1, statement: vec![1] } => CommitPushResponse,
        NegotiatePullRequest { r#ref: "main".to_owned(), at: Some(digest()), have: vec![] }
            => NegotiatePullRequest,
        NegotiatePullResponse {
            head: digest(),
            counter: 1,
            statement: vec![1],
            missing: vec![],
            max_batch_bytes: 1,
            max_batch_objects: 1,
            compression: None,
        } => NegotiatePullResponse,
        FetchObjectsRequest { digests: vec![digest()], accept_compression: None }
            => FetchObjectsRequest,
        FetchObjectsResponse { objects: vec![vec![1]], compression: None } => FetchObjectsResponse,
    }
}

/// An unknown label inside a closure entry is refused too: closed at every level.
#[test]
fn test_a_closure_entry_refuses_an_unknown_label() {
    let request = NegotiatePushRequest {
        r#ref: "main".to_owned(),
        new_head: digest(),
        expected_old: None,
        closure: vec![ObjectClaim {
            digest: digest(),
            size: 1,
        }],
    };
    let Value::Map(mut pairs) =
        cbor::decode_canonical(&request.encode().expect("encodes")).expect("decodes")
    else {
        panic!("a map");
    };
    for (key, value) in &mut pairs {
        if *key == Value::Int(4)
            && let Value::Array(entries) = value
            && let Some(Value::Map(entry)) = entries.first_mut()
        {
            entry.push((Value::Int(99), Value::Int(1)));
        }
    }
    let bytes = cbor::encode(&Value::Map(pairs)).expect("encodes");
    assert!(NegotiatePushRequest::decode(&bytes).is_err());
}
