#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

mod api;
pub mod authz;
pub mod decisions;
pub mod mirrors;
mod service;
mod v1;

pub use service::{DataPlaneModule, module};
