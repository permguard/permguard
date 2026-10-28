// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The release benchmark (TS-3, H-09): what a release measured, on what, and the capacity read off
//! it.
//!
//! | Module     | What it does                                                                         |
//! | ---------- | ------------------------------------------------------------------------------------ |
//! | [`report`] | the `permguard.bench.report.v1` document, the published objective and the capacity     |
//! | [`probe`]  | the platform, the storage's flush cost, and the server's CPU and peak RSS per step     |
//! | [`server`] | the release's own server started on loopback, and the example dataset applied to it  |
//! | [`load`]   | closed-loop HTTP and gRPC clients, one connection each, timing every answer          |
//! | [`run`]    | one run end to end, every interface, evidence mode and workload                      |
//! | [`gate`]   | the serving gate: the objective with its headroom, typed refusals, no network (TS-4) |
//!
//! The binary is `permguard-bench`; `bench/README.md` says how a release runs it and how a
//! deployment reads its own capacity off a report.

pub mod gate;
pub mod load;
pub mod probe;
pub mod report;
pub mod run;
pub mod server;
