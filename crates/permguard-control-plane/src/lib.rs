#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Control Plane's domain: the catalog of zones and ledgers, the content-addressed ledger
//! store and its NOTP engine, and the stores of the evidence the data planes ship. It serves
//! nothing and listens nowhere; its routes over HTTP and gRPC, its module for the composition and
//! its binary are `permguard-control-plane-server`'s (the crate boundaries refactoring, RD-3).

pub mod catalog;
pub mod decisions;
pub mod engine;
pub mod events;
pub mod evidence;
pub mod gc;
pub mod handles;
pub mod inventory;
pub mod members;
pub mod notp;
pub mod plane;
pub mod query;
pub mod refusal;
pub mod store;
pub mod transfer;
pub mod verify;

/// The Plane's id, as configuration spells it.
pub const PLANE: &str = "control";
/// The component name its logs and metrics carry.
pub const COMPONENT: &str = "control-plane";

/// The refusal of a catalog or ledger change that was made and whose `security` audit record
/// could not be written: never answered as success, never undone (WP-3.6, owner decision of
/// 2026-10-07). The caller reads the state before it retries.
pub fn unrecorded(error: impl std::fmt::Display) -> permguard_core::ApiError {
    permguard_core::ApiError::new(
        permguard_core::ErrorClass::Internal,
        permguard_core::codes::host::MUTATION_UNRECORDED,
        "the change was made and its audit record could not be written: read the current state \
         before retrying",
    )
    .with_internal(error.to_string())
}
