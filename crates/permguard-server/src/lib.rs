// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Permguard server host, its service registry, and the command line that drives them.
//!
//! The crate carries no branding and picks no implementation. [`App`] is handed a
//! [`ProductIdentity`](permguard_core::ProductIdentity) and the collaborators it should run against, so a
//! downstream binary presents its own product, reuses [`Command`] as-is, adds commands of its own by
//! flattening it into a larger `clap` enum, and registers its own
//! [`Service`](permguard_core::Service) implementations.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

pub mod app;
pub mod banner;
pub mod command;
pub mod host;
pub mod logging;
pub mod plane;
pub mod signal;
pub mod witness;

pub use app::App;
pub use banner::Banner;
pub use command::{Action, AuditCommand, Cli, Command, KeysCommand, ServeArgs};
pub use host::{DefaultServerHost, LAST_START_KEY};
pub use plane::{PlaneModule, PlaneServer, addresses_for_plane, build_settings};
