#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The headless runtime of a Host (the crate boundaries refactoring, RD-15): what a Host runs for
//! itself, off the request path, whoever serves it.
//!
//! | Module          | What it runs                                                                  |
//! | --------------- | ----------------------------------------------------------------------------- |
//! | [`composition`] | the Host opened on its volume, its Planes registered, the server host run     |
//! | [`host`]        | the server host that starts every service, waits, and ends them in order      |
//! | [`planes`]      | the configuration sections and the streams of the Planes a composition runs   |
//! | [`banner`]      | the text a start announces the build with                                     |
//! | [`time`]        | the clock's observer and its periodic pass, and the key rings' clock          |
//! | [`checkpoints`] | the audit trails' sealing sweep, and the legacy audit chain laid out at start |
//! | [`objectives`]  | readiness held while a measured lag or headroom is past its objective         |
//! | [`stream_gc`]   | the streams' garbage collection                                               |
//! | [`shipping`]    | the streams an incomplete drain left, and the local ship tasks                |
//! | [`repin`]       | the re-pin pass of a coordinator and of a member                              |
//! | [`dormancy`]    | members silent past their thresholds suspended, then revoked                  |
//! | [`zone`]        | the zone keys a member receives and confirms                                  |
//! | [`join`]        | a member joining the coordinator its configured invitation names              |
//! | [`witness`]     | the external witness a silent key change is checked against                   |
//!
//! Nothing here listens, connects or exports: each service takes the Host's handles it works on,
//! and runs on the Tokio runtime of whoever calls it. What reaches the network, the peer sessions,
//! a KMS and the Authority Plane, is an adapter the build composes: the server's, in a server.

pub mod banner;
pub mod checkpoints;
pub mod composition;
pub mod dormancy;
pub mod host;
pub mod join;
pub mod objectives;
pub mod planes;
pub mod repin;
pub mod shipping;
pub mod stream_gc;
pub mod time;
pub mod witness;
pub mod zone;

pub use composition::{AuthorityObserving, AuthoritySource, Composition, ReloadHandler};
