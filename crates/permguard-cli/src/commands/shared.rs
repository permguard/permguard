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
    Err(Failure::usage(permguard_core::volume::unsupported(
        config.storage_backend(),
        "this build of the command line",
    ))
    .named(
        "conflict",
        permguard_core::codes::storage::BACKEND_UNSUPPORTED,
    ))
}

/// The configuration an offline command on the shared backend reads: `--server-config`, the
/// server's own file.
pub(crate) fn config_of(server_config: Option<&Path>) -> Result<permguard_core::Config, Failure> {
    super::offline_ops::server_config_of(server_config)
}
