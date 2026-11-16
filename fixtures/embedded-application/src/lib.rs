#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A reference application embedding the Permguard Data Plane (`11-refactoring/1-dependencies.md`,
//! Verification requirements): one dependency, `permguard-data-plane` with no default feature, and
//! the languages its features select.
//!
//! It is built outside the repository's workspace, once per named profile, so what it links is
//! what an application's own manifest would link: Cargo unifies the features of whatever is built
//! together, and here nothing else is.

use permguard_data_plane::embedded::{Capabilities, DataPlane, Runtime, StartError};

/// Starts the Data Plane over what the application composed, on the caller's runtime.
pub async fn embed(capabilities: Capabilities) -> Result<Runtime, StartError> {
    DataPlane::builder(capabilities).start().await
}
