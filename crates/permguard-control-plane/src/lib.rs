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
pub mod events;
pub mod gc;
mod handles;
pub mod inventory;
mod service;
pub mod store;
mod v1;
pub mod verify;
mod wire;

pub use service::{ControlPlaneModule, module};

/// The refusal of a catalog or ledger change that was made and whose `security` audit record
/// could not be written: never answered as success, never undone (WP-3.6, owner decision of
/// 2026-10-07). The caller reads the state before it retries.
pub(crate) fn unrecorded(error: impl std::fmt::Display) -> permguard_core::ApiError {
    permguard_core::ApiError::new(
        permguard_core::ErrorClass::Internal,
        permguard_core::codes::host::MUTATION_UNRECORDED,
        "the change was made and its audit record could not be written: read the current state \
         before retrying",
    )
    .with_internal(error.to_string())
}
