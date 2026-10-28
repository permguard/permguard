// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use permguard_notp::{
    CommitPushRequest, CommitPushResponse, ExpectedRef, FetchObjectsRequest, FetchObjectsResponse,
    GetRefResponse, NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest,
    NegotiatePushResponse, ObjectClaim, UploadObjectsRequest, UploadObjectsResponse,
};
use permguard_objects::Digest;
use proptest::collection::vec;
use proptest::prelude::*;

fn digest() -> impl Strategy<Value = Digest> {
    vec(any::<u8>(), 0..64).prop_map(|bytes| Digest::compute(&bytes))
}

fn ref_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,16}".prop_map(String::from)
}

fn request_id() -> impl Strategy<Value = String> {
    "[a-z0-9-]{1,32}".prop_map(String::from)
}

fn compression() -> impl Strategy<Value = Option<String>> {
    prop::option::of(Just("deflate".to_owned()))
}

fn expected() -> impl Strategy<Value = Option<ExpectedRef>> {
    prop::option::of(
        (1u64..1_000_000, digest()).prop_map(|(counter, digest)| ExpectedRef { counter, digest }),
    )
}

proptest! {
    #[test]
    fn push_negotiation_round_trips(
        r#ref in ref_name(),
        new_head in digest(),
        expected_ref in expected(),
        claims in vec((digest(), 0u64..1_000_000), 0..8),
        request_id in request_id(),
    ) {
        let request = NegotiatePushRequest {
            r#ref,
            new_head,
            expected_ref,
            closure: claims
                .into_iter()
                .map(|(digest, size)| ObjectClaim { digest, size })
                .collect(),
            request_id,
        };

        prop_assert_eq!(NegotiatePushRequest::decode(&request.encode().expect("it encodes")).unwrap(), request);
    }

    #[test]
    fn pull_negotiation_round_trips(
        r#ref in ref_name(),
        at in prop::option::of(digest()),
        have in vec(digest(), 0..8),
        checkpoint in expected(),
    ) {
        let request = NegotiatePullRequest { r#ref, at, have, checkpoint };

        prop_assert_eq!(NegotiatePullRequest::decode(&request.encode().expect("it encodes")).unwrap(), request);
    }

    #[test]
    fn object_batches_round_trip(
        digests in vec(digest(), 0..8),
        objects in vec(vec(any::<u8>(), 0..64), 0..8),
        compression in compression(),
        transfer_id in any::<[u8; 16]>(),
        expiry in 0u64..u64::from(u32::MAX),
    ) {
        let fetch = FetchObjectsRequest {
            digests,
            accept_compression: compression.clone(),
            transfer_id,
        };
        let upload = UploadObjectsRequest {
            objects: objects.clone(),
            compression: compression.clone(),
            transfer_id,
        };
        let fetched = FetchObjectsResponse {
            objects,
            compression,
            expiry,
        };

        prop_assert_eq!(FetchObjectsRequest::decode(&fetch.encode().expect("it encodes")).unwrap(), fetch);
        prop_assert_eq!(UploadObjectsRequest::decode(&upload.encode().expect("it encodes")).unwrap(), upload);
        prop_assert_eq!(FetchObjectsResponse::decode(&fetched.encode().expect("it encodes")).unwrap(), fetched);
    }

    #[test]
    fn push_and_pull_responses_round_trip(
        digests in vec(digest(), 0..8),
        max_batch_bytes in 0u64..1_000_000,
        max_batch_objects in 0u64..1_000,
        compression in compression(),
        counter in 0u64..1_000_000,
        statement in vec(any::<u8>(), 0..64),
        transfer_id in any::<[u8; 16]>(),
        reservation in 0u64..1_000_000,
        expiry in 0u64..u64::from(u32::MAX),
        ref_digest in digest(),
    ) {
        let push = NegotiatePushResponse {
            missing: digests.clone(),
            max_batch_bytes,
            max_batch_objects,
            compression: compression.clone(),
            transfer_id,
            reservation,
            expiry,
        };
        let pull = NegotiatePullResponse {
            head: digests.first().cloned().unwrap_or_else(|| Digest::compute(b"head")),
            counter,
            statement: statement.clone(),
            missing: digests,
            max_batch_bytes,
            max_batch_objects,
            compression,
            transfer_id,
            ref_digest: ref_digest.clone(),
            expiry,
        };
        let get = GetRefResponse {
            head: ref_digest.clone(),
            counter,
            statement,
            ref_digest,
        };

        prop_assert_eq!(NegotiatePushResponse::decode(&push.encode().expect("it encodes")).unwrap(), push);
        prop_assert_eq!(NegotiatePullResponse::decode(&pull.encode().expect("it encodes")).unwrap(), pull);
        prop_assert_eq!(GetRefResponse::decode(&get.encode().expect("it encodes")).unwrap(), get);
    }

    #[test]
    fn commit_messages_round_trip(
        r#ref in ref_name(),
        new_head in digest(),
        expected_ref in expected(),
        counter in 0u64..1_000_000,
        statement in vec(any::<u8>(), 0..64),
        transfer_id in any::<[u8; 16]>(),
        request_id in request_id(),
        ref_digest in digest(),
    ) {
        let request = CommitPushRequest {
            r#ref,
            new_head: new_head.clone(),
            expected_ref,
            transfer_id,
            request_id,
        };
        let response = CommitPushResponse {
            head: new_head,
            counter,
            statement,
            ref_digest,
        };

        prop_assert_eq!(CommitPushRequest::decode(&request.encode().expect("it encodes")).unwrap(), request);
        prop_assert_eq!(CommitPushResponse::decode(&response.encode().expect("it encodes")).unwrap(), response);
    }

    #[test]
    fn received_response_round_trips(received in vec(digest(), 0..8), remaining in 0u64..1_000_000) {
        let response = UploadObjectsResponse { received, remaining };

        prop_assert_eq!(UploadObjectsResponse::decode(&response.encode().expect("it encodes")).unwrap(), response);
    }
}
