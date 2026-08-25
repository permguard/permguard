// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    UploadObjectsRequest, UploadObjectsResponse,
};

fuzz_target!(|data: &[u8]| {
    let _ = NegotiatePushRequest::decode(data);
    let _ = NegotiatePushResponse::decode(data);
    let _ = UploadObjectsRequest::decode(data);
    let _ = UploadObjectsResponse::decode(data);
    let _ = CommitPushRequest::decode(data);
    let _ = CommitPushResponse::decode(data);
    let _ = NegotiatePullRequest::decode(data);
    let _ = NegotiatePullResponse::decode(data);
    let _ = FetchObjectsRequest::decode(data);
    let _ = FetchObjectsResponse::decode(data);
});
