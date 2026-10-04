// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance harness: what every plane must prove the same way, written once.
//!
//! | Module                 | Proves                                                                         |
//! | ---------------------- | ------------------------------------------------------------------------------ |
//! | [`parity`]             | a request answered over REST and over gRPC gets the same `{class, code}` or the same canonical value |
//! | [`fault`]              | how a test asks for an fsync failure, a full disk or a clock jump              |
//! | [`contracts`]            | the checked-in schemas, CBOR registries and code ownership match the code      |
//! | [`schema`]               | a REST wire type and its OpenAPI schema agree both ways                        |
//! | [`boundaries`]         | every untrusted decoder is registered, bounded and fuzzed, and nothing registered is dangling |
//! | `tests/crash.rs`       | a spool and a journal killed with `SIGKILL` at random points reopen to a valid chain and `STATE` |
//! | `tests/log_fields.rs`  | no log field carries a payload, credential, principal or tenant name (P10 classification) |
//! | `tests/release_scripts.rs` | the release's provenance verification, archive extraction and rebuild comparison behave as the release builder relies on |
//!
//! The crate is a test dependency only. Nothing shipped links it, so it may start servers, spawn
//! processes and inject faults freely.

pub mod boundaries;
pub mod contracts;
pub mod fault;
pub mod parity;
pub mod schema;
