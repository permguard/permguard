// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What an offline command needs of the server's start (WP-3.2, owner decision of 2026-10-08):
//! the configuration read as `serve` reads it, and the custody it builds over a volume.
//!
//! The offline `permguard host` commands open the Host identity's keys where `serve` keeps them:
//! a `file` volume through its key-encryption key, a token or a KMS through the same clients, so a
//! command run with the server's configuration sees the keys the server signs with.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use permguard_core::{Config, ConfigFile, Layers};
use permguard_host::keys::custody::Custodian;
use permguard_host::storage::volume::Volume;

/// The configuration `serve` reads from `file` and the environment, validated. The Planes'
/// sections are not an offline command's: they are left unread.
pub fn config(version: &'static str, file: Option<&Path>) -> Result<Config> {
    let settings = match file {
        Some(path) => ConfigFile::load(path)
            .with_context(|| format!("reading the configuration file {}", path.display()))?
            .settings(),
        None => Vec::new(),
    };
    let config = Config::from_layers(
        crate::plane::build_settings(version),
        Vec::<String>::new(),
        Layers::new()
            .with_file(settings)
            .with_environment(std::env::vars()),
    )?;
    config.validate().context("checking the configuration")?;
    Ok(config)
}

/// The custodian `serve` builds for `config` over `volume`: its secret store, its KMS and token
/// clients, its key-encryption keys witnessed on the volume.
pub fn custodian(config: &Config, volume: &Volume) -> Result<Arc<Custodian>> {
    let secrets = crate::plane::factories::secret_store_for(config)?;
    crate::app::custodian_for(config, secrets.as_deref(), volume)
}
