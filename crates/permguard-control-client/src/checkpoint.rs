// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The persisted `(head, counter)` checkpoint of one ref — the client half
//! of the rollback/equivocation protection. Where it lives is the caller's
//! business (`.permguard/refs` for a workspace, the volume for a data
//! plane); this module owns only its shape and its durability.

use serde::{Deserialize, Serialize};

use crate::store::Store;

/// What was last accepted for one ref, and must never silently regress.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub head: String,
    pub counter: u64,
}

/// Reads the checkpoint at `path`, `None` when nothing was accepted yet.
pub fn read(store: &dyn Store, path: &str) -> Result<Option<Checkpoint>, String> {
    match store.read(path)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("the checkpoint at {path} does not parse: {error}")),
    }
}

/// Writes the checkpoint at `path` — only ever after the whole closure is
/// present and the head statement verified; callers own that ordering.
pub fn write(store: &dyn Store, path: &str, checkpoint: &Checkpoint) -> Result<(), String> {
    let bytes = serde_json::to_vec(checkpoint)
        .map_err(|error| format!("describing the checkpoint: {error}"))?;
    store.write(path, &bytes)
}
