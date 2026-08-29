// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event store: the only supported remote source for reading events back.
//!
//! # Why the control plane and not the plane that wrote them
//!
//! A data plane's journal is a *shipping buffer*. It holds what the loaded policies still read and
//! what has not yet been acknowledged, and nothing more — so a read there would answer differently
//! depending on which plane it reached, and would answer nothing at all for a ledger whose events
//! have been shipped and evicted. The whole history is here, across every producer that
//! contributed to it, and that is the only place a question about the past has one answer.
//!
//! # Verbatim, always
//!
//! Records and envelopes are stored exactly as the producer signed them. Never deserialized and
//! re-serialized: a re-rendered record is a different byte string, and a different byte string has
//! a different digest, and a digest that does not match is indistinguishable from tampering. The
//! store parses records to *index* them and copies bytes to store them.
//!
//! # The files
//!
//! | File | Owns |
//! | --- | --- |
//! | [`store`] | the layout, the append, the tenant views and the event-type index |
//! | [`ingest`] | verifying a signed batch and making it durable before acknowledging it |
//! | [`read`] | the bounded, filtered read, over the shared stream-window contract |
//! | [`retention`] | dropping sealed segments while keeping what proves the rest |
//! | [`http`] / [`grpc`] | the two transports, over one facade and one validation path |
//! | [`measure`] | what it counts about itself |
//!
//! # What is not here
//!
//! No private key material. The store archives the *public* keys a batch was signed under, so a
//! record stays verifiable after its producer has rotated a dozen times; nothing it holds could
//! sign anything.

pub mod configuration;
pub mod grpc;
pub mod http;
pub mod ingest;
pub mod measure;
pub mod read;
pub mod retention;
pub mod store;

pub use ingest::{Accepted, Refused};
pub use store::EventStore;
