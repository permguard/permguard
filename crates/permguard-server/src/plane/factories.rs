// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the composition root builds for a plane process: the build metadata,
//! the audit sink, the catalog, and the signing rings — each read from the
//! materialized configuration, each optional, none of them constructed
//! anywhere else.

use std::sync::Arc;

use permguard_core::{
    AuditDestination, AuditSink, BuildSettings, Config, SecretProvider, SecretStore, brand, build,
};
use permguard_host::identity::Suite;
use permguard_host::keys::registry::Opener;
use permguard_host::keys::ring::{CONTROL_ATTEST, DATA_ATTEST, HOST_OPERATIONS, Policy, Ring};
use permguard_std::catalog::FileCatalog;
use permguard_std::secrets::{DirectorySecretStore, EnvironmentSecretStore};

/// Build metadata from the standard Permguard environment variables.
pub fn build_settings(version: &'static str) -> BuildSettings {
    BuildSettings::new(
        version,
        option_env!("PERMGUARD_COPYRIGHT_YEAR").unwrap_or(brand::PERMGUARD_COPYRIGHT_YEAR),
        option_env!("PERMGUARD_COPYRIGHT_HOLDER").unwrap_or(brand::PERMGUARD_COPYRIGHT_HOLDER),
    )
    .with_commit(build::COMMIT)
}

pub(crate) fn audit_sink_for(
    binary_name: &'static str,
    config: &Config,
) -> anyhow::Result<Option<Arc<dyn AuditSink>>> {
    // The audit engine writes every record to its trails on the volume whatever the destination
    // (WP-3.5, owner decision of 2026-10-07): `tracing` also emits each one into the log stream
    // through the build's default sink, and `file`, whose JSON-lines sink the engine replaced,
    // adds nothing. Trails the JSON sink wrote stay readable by `audit verify`.
    let _ = binary_name;
    match config.audit_destination() {
        AuditDestination::Tracing | AuditDestination::File => Ok(None),
    }
}

/// The catalog of zones and ledgers, kept on the volume beside everything else the server owns.
///
/// `data/zones` under the working directory: the control plane's durable state, in the same volume
/// the audit trail and the key ring already live in — one directory to mount, one to back up.
pub(crate) fn catalog_for(
    config: &Config,
) -> anyhow::Result<Option<Arc<dyn permguard_core::Catalog>>> {
    Ok(Some(Arc::new(FileCatalog::new(config.zones_directory()))))
}

/// The lifecycle every Host ring follows: one discipline for every ring this deployment
/// rotates. A retired key stays in the published set for `retain`, which covers the audit
/// retention outside development (WP-3.1).
pub(crate) fn ring_policy(config: &Config) -> Policy {
    Policy {
        publish_ahead: config.keys_publish_ahead(),
        rotate_every: config.keys_rotate_every(),
        retain: config.keys_retain(),
    }
}

/// The Control Plane's ring, `control.attest`, under `host/keys`: it signs what the Control
/// Plane serves, NOTP head statements today. Its legacy directory (`keys/control` on the
/// volume, or the configured one) is migrated once.
pub(crate) fn control_signing_keys_for(
    config: &Config,
    rings: &Opener<'_>,
) -> anyhow::Result<Option<Arc<Ring>>> {
    if !config.control_signing_keys_enabled() {
        return Ok(None);
    }

    Ok(Some(rings.open(
        CONTROL_ATTEST,
        Suite::Ed25519Sha256V1,
        ring_policy(config),
        Some(&config.control_signing_keys_directory()),
    )?))
}

/// The Data Plane's ring, `data.attest`, under `host/keys`: it signs decision and event batches
/// and, when asked, decision responses. Its legacy directory is migrated once.
pub(crate) fn data_signing_keys_for(
    config: &Config,
    rings: &Opener<'_>,
) -> anyhow::Result<Option<Arc<Ring>>> {
    if !config.data_signing_keys_enabled() {
        return Ok(None);
    }

    Ok(Some(rings.open(
        DATA_ATTEST,
        Suite::Ed25519Sha256V1,
        ring_policy(config),
        Some(&config.data_signing_keys_directory()),
    )?))
}

/// The Host's operations ring, `host.operations`, under `host/keys`: no Plane is handed it.
/// Its legacy directory is migrated once.
pub(crate) fn key_manager_for(
    config: &Config,
    rings: &Opener<'_>,
) -> anyhow::Result<Option<Arc<Ring>>> {
    Ok(Some(rings.open(
        HOST_OPERATIONS,
        Suite::Ed25519Sha256V1,
        ring_policy(config),
        Some(&config.operations_keys_directory()),
    )?))
}

pub(crate) fn secret_store_for(config: &Config) -> anyhow::Result<Option<Box<dyn SecretStore>>> {
    Ok(match config.secrets_provider() {
        SecretProvider::None => None,
        SecretProvider::Directory => Some(Box::new(DirectorySecretStore::new(
            config.secrets_directory(),
        ))),
        SecretProvider::Environment => {
            if !config.development_mode() {
                // Allowed — the deployment decides — and said out loud: a process's environment is
                // readable through /proc by anything sharing the user, and inherited by every child.
                // A production posture normally mounts secrets as files or brings a real store.
                tracing::warn!(
                    event.name = "secrets.environment_outside_development",
                    component = "server",
                    "secrets are resolved from the environment and development_mode is off: \
                     the environment is readable via /proc and inherited by child processes"
                );
            }

            Some(Box::new(EnvironmentSecretStore::new(
                config.secrets_env_prefix(),
            )))
        }
    })
}
