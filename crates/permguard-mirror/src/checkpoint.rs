// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The persisted `(head, counter, ref_digest)` checkpoint of one ref — the client half
//! of the rollback/equivocation protection. Where it lives is the caller's
//! business (`.permguard/refs` for a workspace, the volume for a data
//! plane); this module owns only its shape and its durability.

use serde::{Deserialize, Serialize};

use crate::store::Store;

/// What was last accepted for one ref, and must never silently regress.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub head: String,
    pub counter: u64,
    /// The `ref_digest` of the accepted state (WP-7.1); absent in a checkpoint written before
    /// it, whose next verdict falls back to the head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_digest: Option<String>,
    /// The Host whose head statement vouched for this state, a lowercase hyphenated UUID
    /// (WP-6.6b): what a signed decision response names as the policy's authority. Absent in a
    /// checkpoint written before it; such a mirror signs no response until its next pull.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_host_id: Option<String>,
    /// The ref the statement signed, as the tracked ref names it (WP-6.6b).
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// The epoch of the ring the accepted statement was signed under (WP-7.2b): what ring
    /// continuity is checked against. Absent in a checkpoint written before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_epoch: Option<u64>,
    /// The digest of that ring's key set, as `sha256:<hex>` (WP-7.2b).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_set_digest: Option<String>,
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
