// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The library half of the CLI: what the commands do, without a terminal. The binary in
//! `main.rs` is this library plus the arguments a person types and the output a person or a
//! script reads; a program that embeds the CLI, Permguard Admin, calls the same code. The library
//! never prints, prompts, reads standard input or exits.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

/// The version of the CLI this library is, the release it was built from: what a program that
/// embeds it reports as the Permguard it runs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod check;
pub mod decisions;
pub mod engine;
pub mod events;
pub mod host_proof;
pub mod token;
