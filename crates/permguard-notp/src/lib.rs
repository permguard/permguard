#![forbid(unsafe_code)]
#![deny(clippy::all)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! NOTP — the Negotiated Object Transfer Protocol: how objects move between
//! a client and a server.
//!
//! This crate is the wire, and only the wire: the messages in the canonical
//! CBOR profile — the REST framing
//! (`application/vnd.permguard.notp.v1+cbor`) and the shape gRPC mirrors.
//! One encoder and one decoder per message, shared by every party, because
//! canonical bytes are the contract: two implementations of the same
//! message are two dialects that eventually disagree.
//!
//! What the messages *carry* is [`permguard_objects`] — digests, and the
//! codec the bodies are framed in. The dependency goes one way only: the
//! protocol knows the objects, the objects know no protocol.

pub mod codec;
pub mod pull;
pub mod push;

pub use codec::WireError;
pub use pull::{
    FetchObjectsRequest, FetchObjectsResponse, NegotiatePullRequest, NegotiatePullResponse,
};
pub use push::{
    CommitPushRequest, CommitPushResponse, NegotiatePushRequest, NegotiatePushResponse,
    ObjectClaim, UploadObjectsRequest, UploadObjectsResponse,
};

/// The REST media type of every NOTP body.
pub const MEDIA_TYPE: &str = "application/vnd.permguard.notp.v1+cbor";
