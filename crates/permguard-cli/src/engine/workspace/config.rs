// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `.permguard/config` — TOML: the remotes, the tracked ledger, the format
//! version. Never edited by hand; every field additive from here on.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use permguard_control_client::Store;

pub const CONFIG_PATH: &str = ".permguard/config";
pub const HEAD_PATH: &str = ".permguard/HEAD";

/// The `.permguard` layout this build reads and writes. Bumped only when the
/// layout itself changes shape (v2: objects at rest are zlib-compressed);
/// additive fields never bump it.
pub const FORMAT_VERSION: u32 = 2;

/// One named remote: a URL, and optionally its own trust.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteConfig {
    pub url: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "tls-ca-file"
    )]
    pub tls_ca_file: Option<String>,
}

/// The ledger this workspace tracks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LedgerConfig {
    pub remote: String,
    /// As given: name or GUID.
    pub zone: String,
    pub ledger: String,
    /// The resolved GUIDs, recorded at checkout — what signed head
    /// statements are verified against.
    #[serde(default, rename = "zone-id")]
    pub zone_id: String,
    #[serde(default, rename = "ledger-id")]
    pub ledger_id: String,
}

/// The whole file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WorkspaceConfig {
    pub version: u32,
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger: Option<LedgerConfig>,
}

impl WorkspaceConfig {
    pub fn new() -> Self {
        Self {
            version: FORMAT_VERSION,
            remotes: BTreeMap::new(),
            ledger: None,
        }
    }

    pub fn load(store: &dyn Store) -> Result<Option<Self>, String> {
        match store.read(CONFIG_PATH)? {
            None => Ok(None),
            Some(bytes) => {
                let text = String::from_utf8(bytes)
                    .map_err(|_| "the workspace config is not UTF-8".to_owned())?;
                let config: Self = toml::from_str(&text)
                    .map_err(|error| format!("the workspace config does not parse: {error}"))?;
                if config.version != FORMAT_VERSION {
                    return Err(format!(
                        "this .permguard was written as layout v{}; this CLI speaks v{}. \
                         Use a matching CLI, or re-clone the ledger into a fresh directory",
                        config.version, FORMAT_VERSION
                    ));
                }
                Ok(Some(config))
            }
        }
    }

    pub fn save(&self, store: &dyn Store) -> Result<(), String> {
        let text = toml::to_string_pretty(self)
            .map_err(|error| format!("describing the workspace config: {error}"))?;
        store.write(CONFIG_PATH, text.as_bytes())
    }
}

/// The current ref, e.g. `main`.
pub fn read_head(store: &dyn Store) -> Result<Option<String>, String> {
    Ok(store
        .read(HEAD_PATH)?
        .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned()))
}

pub fn write_head(store: &dyn Store, r#ref: &str) -> Result<(), String> {
    store.write(HEAD_PATH, format!("{ref}\n", ref = r#ref).as_bytes())
}

/// The persisted `(head, counter)` checkpoint of one ref — the client half
/// of the rollback/equivocation protection. The type is the NOTP client's;
/// the workspace only decides where it lives.
pub use permguard_control_client::checkpoint::Checkpoint;

/// Where one ref's checkpoint lives inside `.permguard`.
pub fn checkpoint_path(r#ref: &str) -> String {
    ref_path(r#ref)
}

fn ref_path(r#ref: &str) -> String {
    format!(".permguard/refs/{ref}", ref = r#ref)
}

pub fn read_checkpoint(store: &dyn Store, r#ref: &str) -> Result<Option<Checkpoint>, String> {
    permguard_control_client::checkpoint::read(store, &ref_path(r#ref))
}

pub fn write_checkpoint(
    store: &dyn Store,
    r#ref: &str,
    checkpoint: &Checkpoint,
) -> Result<(), String> {
    permguard_control_client::checkpoint::write(store, &ref_path(r#ref), checkpoint)
}
