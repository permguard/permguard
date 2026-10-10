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

/// What provisions the identity a reset makes on `volume` (WP-4.1): the identity's custody, its
/// keys bound to the `host_id` the reset mints, as `serve` composes it.
pub fn provisioner(
    custodian: &Arc<Custodian>,
    volume: &Volume,
    suite: permguard_host::identity::Suite,
) -> Result<permguard_host::identity::reset::Provisioner> {
    use permguard_host::identity::{self, IdentityError};
    let (_, keys) = identity::directories(volume).context("the identity directory")?;
    let keys = keys.path().to_path_buf();
    let custodian = Arc::clone(custodian);
    Ok(Arc::new(move |host_id| {
        let stored = identity::stored_public(permguard_host::storage::Dir::open(&keys)?);
        custodian
            .provider(
                permguard_host::keys::ring::HOST_IDENTITY,
                *host_id,
                permguard_host::storage::Dir::open(&keys)?,
                stored,
                suite,
            )
            .map(|(provider, _)| provider)
            .map_err(IdentityError::from)
    }))
}

/// The key rings `serve` composes on `volume`, opened as it opens them for the Host `host_id`
/// (WP-4.1): what an offline reset signs the manifests that end its coordinated memberships with,
/// `host.operations` first, and retires with the identity. `binder` is the identity open, absent
/// while a reset is completed.
pub fn rings(
    config: &Config,
    volume: &Volume,
    host_id: [u8; 16],
    binder: Option<Arc<dyn permguard_host::keys::ring::Binder>>,
    custodian: &Arc<Custodian>,
    time: Arc<permguard_host::time::TimeGuard>,
) -> Result<Vec<Arc<permguard_host::keys::ring::Ring>>> {
    let opener = permguard_host::keys::registry::Opener {
        volume,
        host_id,
        custodian: Arc::clone(custodian),
        time,
        binder,
        recorder: None,
        profile: config.assurance().profile(),
    };
    Ok([
        crate::plane::factories::key_manager_for(config, &opener)?,
        crate::plane::factories::control_signing_keys_for(config, &opener)?,
        crate::plane::factories::data_signing_keys_for(config, &opener)?,
    ]
    .into_iter()
    .flatten()
    .collect())
}
