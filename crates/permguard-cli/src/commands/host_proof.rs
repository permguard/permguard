// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `host-batch-v1` entries of a read's `proof[]`: the library's, re-exported for the commands
//! and their tests, with the batch a test seals beside them.

pub use permguard_cli::host_proof::*;

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
