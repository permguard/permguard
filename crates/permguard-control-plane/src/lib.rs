#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

mod api;
mod catalog;
mod notp;

// The server half of NOTP — the transfer engine with its commit acceptance
// invariants, and the on-disk store of one ledger. Public, not `pub(crate)`,
// for one reason only: the CLI's integration tests drive a real in-process
// server through it. No production crate imports the control plane.
pub mod decisions;
pub mod engine;
pub mod gc;
pub mod inventory;
mod service;
pub mod store;
mod v1;
mod wire;

pub use service::{ControlPlaneModule, module};
