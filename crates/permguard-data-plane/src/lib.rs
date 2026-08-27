#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

mod api;
pub mod authz;
pub mod decisions;
pub mod mirrors;
mod service;
/// The generated `permguard.data.v1` server stubs, compiled from the one `proto/` root.
///
/// Public because they *are* the contract this plane serves: a test that drives the PDP over a
/// real socket needs the same service definition the server mounts, and a hand-written stand-in
/// would prove only that the stand-in works.
pub mod v1;

pub use service::{DataPlaneModule, module};
