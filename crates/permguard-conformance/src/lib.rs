// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance harness: what every plane must prove the same way, written once.
//!
//! | Module                     | Proves                                                                                                                   |
//! | -------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
//! | [`bench`]                  | the release benchmark: what a release measured, on what, and the capacity read off it (TS-3)                             |
//! | [`parity`]                 | a request answered over REST and over gRPC gets the same `{class, code}` or the same canonical value                     |
//! | [`fault`]                  | how a test asks for an fsync failure, a full disk or a clock jump                                                        |
//! | [`contracts`]              | the checked-in schemas, CBOR registries and code ownership match the code                                                |
//! | [`schema`]                 | a REST wire type and its OpenAPI schema agree both ways                                                                  |
//! | [`boundaries`]             | every untrusted decoder is registered, bounded and fuzzed, and nothing registered is dangling                            |
//! | [`catalog_writers`]        | only the catalog facade, inside the WP-3.6 transaction, calls the catalog's writing methods                              |
//! | `tests/crash.rs`           | a spool and a journal killed with `SIGKILL` at random points reopen to a valid chain and `STATE`                         |
//! | `tests/log_fields.rs`      | no log field carries a payload, credential, principal or tenant name (P10 classification)                                |
//! | `tests/release_scripts.rs` | the release's provenance verification, archive extraction and rebuild comparison behave as the release builder relies on |
//!
//! The crate is a test dependency only. Nothing shipped links it, so it may start servers, spawn
//! processes and inject faults freely.

pub mod bench;
pub mod boundaries;
pub mod catalog_writers;
pub mod contracts;
pub mod durability;
pub mod fault;
pub mod mutations;
pub mod parity;
pub mod schema;
