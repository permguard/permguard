// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    ObjectClaim, UploadObjectsRequest, UploadObjectsResponse,
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

fn compression() -> impl Strategy<Value = Option<String>> {
    prop::option::of(Just("deflate".to_owned()))
}

proptest! {
    #[test]
    fn push_negotiation_round_trips(
        r#ref in ref_name(),
        new_head in digest(),
        expected_old in prop::option::of(digest()),
        claims in vec((digest(), 0u64..1_000_000), 0..8),
    ) {
        let request = NegotiatePushRequest {
            r#ref,
            new_head,
            expected_old,
            closure: claims
                .into_iter()
                .map(|(digest, size)| ObjectClaim { digest, size })
                .collect(),
        };

        prop_assert_eq!(NegotiatePushRequest::decode(&request.encode()).unwrap(), request);
    }

    #[test]
    fn pull_negotiation_round_trips(
        r#ref in ref_name(),
        at in prop::option::of(digest()),
        have in vec(digest(), 0..8),
    ) {
        let request = NegotiatePullRequest { r#ref, at, have };

        prop_assert_eq!(NegotiatePullRequest::decode(&request.encode()).unwrap(), request);
    }

    #[test]
    fn object_batches_round_trip(
        digests in vec(digest(), 0..8),
        objects in vec(vec(any::<u8>(), 0..64), 0..8),
        compression in compression(),
    ) {
        let fetch = FetchObjectsRequest {
            digests,
            accept_compression: compression.clone(),
        };
        let upload = UploadObjectsRequest {
            objects: objects.clone(),
            compression: compression.clone(),
        };
        let fetched = FetchObjectsResponse {
            objects,
            compression,
        };

        prop_assert_eq!(FetchObjectsRequest::decode(&fetch.encode()).unwrap(), fetch);
        prop_assert_eq!(UploadObjectsRequest::decode(&upload.encode()).unwrap(), upload);
        prop_assert_eq!(FetchObjectsResponse::decode(&fetched.encode()).unwrap(), fetched);
    }

    #[test]
    fn push_and_pull_responses_round_trip(
        digests in vec(digest(), 0..8),
        max_batch_bytes in 0u64..1_000_000,
        max_batch_objects in 0u64..1_000,
        compression in compression(),
        counter in 0u64..1_000_000,
        statement in vec(any::<u8>(), 0..64),
    ) {
        let push = NegotiatePushResponse {
            missing: digests.clone(),
            max_batch_bytes,
            max_batch_objects,
            compression: compression.clone(),
        };
        let pull = NegotiatePullResponse {
            head: digests.first().cloned().unwrap_or_else(|| Digest::compute(b"head")),
            counter,
            statement,
            missing: digests,
            max_batch_bytes,
            max_batch_objects,
            compression,
        };

        prop_assert_eq!(NegotiatePushResponse::decode(&push.encode()).unwrap(), push);
        prop_assert_eq!(NegotiatePullResponse::decode(&pull.encode()).unwrap(), pull);
    }

    #[test]
    fn commit_messages_round_trip(
        r#ref in ref_name(),
        new_head in digest(),
        expected_old in prop::option::of(digest()),
        counter in 0u64..1_000_000,
        statement in vec(any::<u8>(), 0..64),
    ) {
        let request = CommitPushRequest {
            r#ref,
            new_head: new_head.clone(),
            expected_old,
        };
        let response = CommitPushResponse {
            head: new_head,
            counter,
            statement,
        };

        prop_assert_eq!(CommitPushRequest::decode(&request.encode()).unwrap(), request);
        prop_assert_eq!(CommitPushResponse::decode(&response.encode()).unwrap(), response);
    }

    #[test]
    fn received_response_round_trips(received in vec(digest(), 0..8)) {
        let response = UploadObjectsResponse { received };

        prop_assert_eq!(UploadObjectsResponse::decode(&response.encode()).unwrap(), response);
    }
}
