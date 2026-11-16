#![forbid(unsafe_code)]
#![deny(clippy::all)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The client side of a Permguard control plane, for everything that is not
//! the plane itself: the CLI today, the data plane's mirror next.
//!
//! | Layer | What it is |
//! | --- | --- |
//! | [`endpoint`], [`tls`] | where a server is and what it takes to trust it — one URL, and the scheme decides the transport |
//! | [`http`], [`grpc`] | the two transports, behaving identically: same framing, same negotiated compression, same discovery check, same error taxonomy |
//! | [`remote`], [`catalog`] | what can be asked: the six NOTP verbs, and the zone/ledger catalog |
//! | [`host`] | the Host listener over REST and gRPC: status and identity today (TC-1) |
//! | [`store`], [`objects`], [`checkpoint`] | where the local half lives, and what it holds |
//! | [`verify`], [`pull`] | the proof discipline, and the fetch cycle that respects it |
//!
//! **Pull only, on purpose.** The push verbs are on the wire and anybody may
//! call them, but the logic here builds a *mirror*: it learns the last
//! commit, fetches what it lacks, proves the closure and the signature, and
//! moves a checkpoint. Nothing here knows about source files, a manifest or
//! a workspace — that is the CLI's authoring layer, one level up.
//!
//! Authentication and authorization are deliberately **not** here yet: today
//! a client presents TLS material (and mutual TLS where a deployment asks
//! for it), and when tokens arrive they arrive for every consumer at once,
//! in [`tls`]'s neighbour module — designed once, for the community and the
//! enterprise editions together.

/// The most bytes this crate will accept in one answer, on either transport.
///
/// A client that reads whatever the socket delivers hands the server a lever
/// over its memory — and "the server" includes a compromised one, which is
/// exactly the peer the verification downstream exists for. The number is
/// generous next to everything these protocols carry (NOTP batches default to
/// 8 MiB, decision pages to 1000 records) and exists to bound a lie, not to
/// tune a transfer.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

// A surface is called over a transport: a build that selects one and neither transport is an
// invalid profile, refused here rather than left to answer every URL with a refusal.
#[cfg(all(
    any(
        feature = "catalog",
        feature = "notp",
        feature = "decisions",
        feature = "events",
        feature = "pdp",
        feature = "temporal",
        feature = "host",
        feature = "authority",
        feature = "documents"
    ),
    not(any(feature = "http", feature = "grpc"))
))]
compile_error!(
    "permguard-client: a surface is selected and no transport; select `http`, `grpc` or both"
);

pub mod encode;
pub mod endpoint;
pub mod failure;
pub mod narrate;
pub mod tls;
pub mod transport;

// The transports.
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub(crate) mod rest;

// The generated contracts the gRPC transport speaks, where the surfaces name them.
#[cfg(all(
    feature = "grpc",
    any(
        feature = "authority",
        feature = "documents",
        feature = "authority-refresh"
    )
))]
pub mod authority_v1;
#[cfg(all(feature = "grpc", any(feature = "host", feature = "peer")))]
pub mod host_v1;
#[cfg(feature = "grpc")]
pub mod pdp_v1;
#[cfg(feature = "grpc")]
pub mod v1;

// The surfaces.
#[cfg(feature = "pdp")]
pub mod attestation;
#[cfg(feature = "authority")]
pub mod authority;
#[cfg(feature = "authority-refresh")]
pub mod authority_refresh;
#[cfg(feature = "catalog")]
pub mod catalog;
#[cfg(feature = "notp")]
pub mod connect;
#[cfg(feature = "decisions")]
pub mod decisions;
#[cfg(all(feature = "decisions", feature = "grpc"))]
pub mod decisions_grpc;
#[cfg(feature = "documents")]
pub mod documents;
#[cfg(feature = "events")]
pub mod events;
#[cfg(all(feature = "events", feature = "grpc"))]
pub mod events_grpc;
#[cfg(feature = "host")]
pub mod host;
#[cfg(all(feature = "host", feature = "grpc"))]
mod host_proto;
#[cfg(feature = "pdp")]
pub mod pdp;
#[cfg(feature = "peer")]
pub mod peer;
#[cfg(all(feature = "notp", feature = "http"))]
pub mod remote_http;
#[cfg(feature = "temporal")]
pub mod temporal;
#[cfg(feature = "authority")]
pub mod token_source;

// The verified local mirror is `permguard-mirror`'s; its modules stay reachable from here, where the
// command line and Permguard Admin already name them.
pub use permguard_mirror::{checkpoint, objects, pull, remote, store, verify};

#[cfg(feature = "notp")]
pub use connect::AnyRemote;
pub use endpoint::Endpoint;
pub use narrate::Narrator;
pub use permguard_mirror::{FsStore, RefAnswer, Remote, Store};
pub use tls::TlsOptions;
