// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The offline commands on the `postgresql-s3` backend (iteration 03, WP-28.1): the stores a
//! stopped server keeps in its database and its bucket, opened from its configuration.
//!
//! The backend's adapter is the official binary's (`shared-backend`): a program that embeds the
//! command line as a library, Permguard Admin, links none and is told so.

use std::path::Path;

use crate::failure::Failure;

/// The shared backend `config` names, opened, its schema the build's; `None` when the
/// configuration keeps its state on a volume.
pub(crate) fn open(
    config: &permguard_core::Config,
) -> Result<Option<permguard_host::backend::Shared>, Failure> {
    if config.storage_backend().has_volume() {
        return Ok(None);
    }
    opened(config).map(Some)
}

#[cfg(feature = "shared-backend")]
fn opened(config: &permguard_core::Config) -> Result<permguard_host::backend::Shared, Failure> {
    let secrets = permguard_offline::factories::secret_store_for(config)
        .map_err(|error| Failure::usage(format!("the secret store: {error:#}")))?;
    permguard_s3::backend::open(config, secrets.as_deref()).map_err(|error| {
        Failure::unavailable(format!(
            "opening the `{}` storage backend: {error:#}",
            config.storage_backend().as_str()
        ))
    })
}

#[cfg(not(feature = "shared-backend"))]
fn opened(config: &permguard_core::Config) -> Result<permguard_host::backend::Shared, Failure> {
    Err(unsupported(config))
}

/// The refusal of a build that links no shared backend: Permguard Admin's, which embeds the
/// command line as a library.
#[cfg(not(feature = "shared-backend"))]
fn unsupported(config: &permguard_core::Config) -> Failure {
    Failure::usage(permguard_core::volume::unsupported(
        config.storage_backend(),
        "this build of the command line",
    ))
    .named(
        "conflict",
        permguard_core::codes::storage::BACKEND_UNSUPPORTED,
    )
}

/// The configuration an offline command on the shared backend reads: `--server-config`, the
/// server's own file.
pub(crate) fn config_of(server_config: Option<&Path>) -> Result<permguard_core::Config, Failure> {
    super::offline_ops::server_config_of(server_config)
}

/// What `migrate import` answers: the deployment the database now keeps, and each store carried.
#[derive(Debug, serde::Serialize)]
pub(crate) struct Imported {
    /// The volume's id, which the deployment keeps and the Host identity names.
    deployment: String,
    stores: Vec<ImportedStore>,
}

#[derive(Debug, serde::Serialize)]
struct ImportedStore {
    store: &'static str,
    records: usize,
}

impl crate::output::Report for Imported {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Imported into postgresql-s3")?;
        writeln!(out, "deployment  {}", self.deployment)?;
        for store in &self.stores {
            writeln!(out, "{:<22}{}", store.store, store.records)?;
        }
        Ok(())
    }
}

/// `permguard migrate import` (iteration 03, WP-28.1): the stopped volume at `volume` into the
/// `postgresql-s3` backend the server's configuration names, its working directory the volume.
pub(crate) fn import(
    volume: &Path,
    server_config: Option<&Path>,
    trace: &crate::trace::Trace,
) -> Result<Imported, Failure> {
    let config = config_of(server_config)?;
    if config.storage_backend().has_volume() {
        return Err(Failure::usage(format!(
            "the configuration keeps its state on a volume, `{}`: name the server's configuration \
             on `postgresql-s3`",
            config.storage_backend().as_str()
        )));
    }
    let same = |path: &Path| std::fs::canonicalize(path).ok();
    if same(volume).is_none() || same(volume) != same(config.working_dir()) {
        return Err(Failure::usage(format!(
            "the configuration's working directory is {}, not the volume {}: on `postgresql-s3` it \
             keeps the instance's own files, those of the volume it was, and the import reads the \
             volume's Planes from it",
            config.working_dir().display(),
            volume.display()
        )));
    }
    imported(&config, volume, trace)
}

#[cfg(feature = "shared-backend")]
fn imported(
    config: &permguard_core::Config,
    volume: &Path,
    trace: &crate::trace::Trace,
) -> Result<Imported, Failure> {
    let held = super::host::claim(volume, trace)?;
    let host_id = permguard_host::identity::host_id_of(&held)
        .map_err(|error| Failure::unavailable(format!("reading the Host identity: {error}")))?
        .ok_or_else(|| {
            Failure::usage(
                "the volume holds no Host identity: a server never started on it, and there is \
                 nothing to import",
            )
        })?;
    let custodian = permguard_offline::volume::custodian(config, &held)
        .map_err(|error| Failure::usage(format!("the custody of the keys: {error:#}")))?;
    let sealer = custodian
        .sealer(host_id)
        .map_err(|error| Failure::usage(format!("the custody of the secrets: {error}")))?;
    let secrets = permguard_offline::factories::secret_store_for(config)
        .map_err(|error| Failure::usage(format!("the secret store: {error:#}")))?;
    let connected =
        permguard_s3::backend::connect(config, secrets.as_deref()).map_err(|error| {
            Failure::unavailable(format!("opening the `postgresql-s3` backend: {error:#}"))
        })?;
    let imported =
        permguard_s3::import::volume(config, &held, &connected, std::sync::Arc::new(sealer))
            .map_err(|error| Failure::unavailable(format!("importing the volume: {error:#}")))?;
    trace.say(format!(
        "imported {} store(s) of the volume",
        imported.stores.len()
    ));
    Ok(Imported {
        deployment: permguard_host::identity::record::uuid_text(&imported.deployment),
        stores: imported
            .stores
            .into_iter()
            .map(|(store, records)| ImportedStore { store, records })
            .collect(),
    })
}

#[cfg(not(feature = "shared-backend"))]
fn imported(
    config: &permguard_core::Config,
    _volume: &Path,
    _trace: &crate::trace::Trace,
) -> Result<Imported, Failure> {
    Err(unsupported(config))
}
