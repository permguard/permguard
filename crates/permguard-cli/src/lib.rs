// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The library half of the CLI: what the commands do, without a terminal. The binary in
//! `main.rs` is this library plus the arguments a person types and the output a person or a
//! script reads; a program that embeds the CLI, Permguard Admin, calls the same code. The library
//! never prints, prompts, reads standard input or exits.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

/// The version of the CLI this library is, as every Permguard binary reports it: the release tag
/// stamped at build time, or the workspace version for a build nobody stamped. What a program that
/// embeds it reports as the Permguard it runs.
pub const VERSION: &str = permguard_core::build::VERSION;

mod args;
mod banner;
mod client_token;
mod commands;
mod config;
mod confirm;
mod decision_out;
mod discover;
mod event_out;
mod failure;
mod inspect;
mod narrator;
mod output;
mod reference;
mod session;
mod settings;
mod style;
mod target;
mod trace;
mod version;
mod workspace_out;

pub mod check;
/// A service account's credential material, read as `iam credentials create` reads it: the calls
/// Permguard Admin makes (18-identities § 9).
pub mod credentials;
pub mod decisions;
pub mod engine;
pub mod events;
pub mod host_proof;
pub mod shell;

/// A roles file planned and run against a Host, as `iam roles apply` does: the library calls
/// Permguard Admin makes (18-identities § 5).
pub mod roles {
    pub use crate::commands::roles_apply::{Plan, plan_roles, run_roles};
}

pub use crate::failure::{
    EXIT_NOT_READY, EXIT_READY, EXIT_SOFTWARE, EXIT_UNAVAILABLE, EXIT_UNREACHABLE, EXIT_USAGE,
};
mod streams;
pub mod token;
