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

pub mod catalog;
pub mod checkpoint;
pub mod connect;
pub mod decisions;
pub mod decisions_grpc;
pub mod encode;
pub mod endpoint;
pub mod events;
pub mod events_grpc;
pub mod grpc;
pub mod http;
pub mod narrate;
pub mod objects;
/// The generated `permguard.control.v1` stubs, from the plane's own
/// `proto/`. Public so the wire tests can stand a fake server on the same
/// contract this client calls.
pub mod pdp;
pub mod pdp_v1;
pub mod pull;
pub mod remote;
pub mod remote_http;
pub mod store;
pub mod temporal;
pub mod tls;
pub mod v1;
pub mod verify;

pub use connect::AnyRemote;
pub use endpoint::Endpoint;
pub use narrate::Narrator;
pub use remote::{RefAnswer, Remote};
pub use store::{FsStore, Store};
pub use tls::TlsOptions;
