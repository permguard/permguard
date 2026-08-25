// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How the engine reaches a server. One trait, mirroring the six NOTP
//! operations plus what a client needs around them: resolving names to
//! GUIDs, and the key ring the head statements verify against. The CLI
//! implements it over HTTP; tests implement it over an in-process engine;
//! the data plane brings its own.

use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    UploadObjectsRequest, UploadObjectsResponse,
};

/// The advertised state of one ref.
#[derive(Debug, Clone)]
pub struct RefAnswer {
    pub head: String,
    pub counter: u64,
    /// The COSE_Sign1 envelope of the head statement.
    pub statement: Vec<u8>,
}

/// A remote ledger, addressed and authenticated by the implementation.
pub trait Remote {
    /// Resolves the zone and ledger the caller named (name or GUID) to
    /// their permanent GUIDs.
    fn resolve(&self, zone: &str, ledger: &str) -> Result<(String, String), String>;

    /// The key ring verifying head statements: the JWKS document bytes.
    fn keyring(&self) -> Result<Vec<u8>, String>;

    /// The advertised ref, when it exists.
    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String>;

    fn negotiate_push(
        &self,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String>;
    fn upload(&self, request: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String>;
    fn commit_push(&self, request: &CommitPushRequest) -> Result<CommitPushResponse, String>;
    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String>;
    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String>;
}
