// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the composition root builds for a plane process: the build metadata,
//! the audit sink, the catalog, and the signing rings — each read from the
//! materialized configuration, each optional, none of them constructed
//! anywhere else.

use std::sync::Arc;

use permguard_core::{
    AuditDestination, AuditSink, BuildSettings, Config, KeyManager, SecretProvider, SecretStore,
    brand, build,
};
use permguard_std::audit::FileAuditSink;
use permguard_std::catalog::FileCatalog;
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
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
    keys: Option<&Arc<dyn KeyManager>>,
) -> anyhow::Result<Option<Arc<dyn AuditSink>>> {
    match config.audit_destination() {
        AuditDestination::Tracing => Ok(None),
        AuditDestination::File => {
            let mut sink = FileAuditSink::new(
                config.audit_directory(),
                binary_name,
                config.version(),
                config.audit_retention(),
            );

            if let Some(keys) = keys {
                sink = sink.sealed_by(Arc::clone(keys));
            }

            sink.prepare()?;

            Ok(Some(Arc::new(sink)))
        }
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

/// The lifecycle every plane signing ring follows: the operations ring's policy, one discipline for
/// every ring this deployment rotates.
pub(crate) fn plane_signing_policy(config: &Config) -> KeyPolicy {
    KeyPolicy {
        publish_ahead: config.keys_publish_ahead(),
        rotate_every: config.keys_rotate_every(),
        retain: config.keys_retain(),
        verify_retain: config.audit_retention(),
    }
}

/// The control plane's signing ring: `keys/control` on the volume, deliberately separate from the
/// operations ring that seals the audit trail — different duty, different rotation, different
/// blast radius. It signs what the control plane serves: git-like head statements today.
pub(crate) fn control_signing_keys_for(
    config: &Config,
) -> anyhow::Result<Option<Arc<dyn KeyManager>>> {
    if !config.control_signing_keys_enabled() {
        return Ok(None);
    }

    Ok(Some(Arc::new(DirectoryKeyManager::new(
        config.control_signing_keys_directory(),
        plane_signing_policy(config),
    ))))
}

/// The data plane's signing ring: `keys/data` on the volume — it will sign the decision responses
/// the data plane returns. Part of the model like the control plane's ring: enabled with
/// `operations.keys` unless the deployment says otherwise.
pub(crate) fn data_signing_keys_for(
    config: &Config,
) -> anyhow::Result<Option<Arc<dyn KeyManager>>> {
    if !config.data_signing_keys_enabled() {
        return Ok(None);
    }

    Ok(Some(Arc::new(DirectoryKeyManager::new(
        config.data_signing_keys_directory(),
        plane_signing_policy(config),
    ))))
}

pub(crate) fn key_manager_for(config: &Config) -> anyhow::Result<Option<Arc<dyn KeyManager>>> {
    Ok(Some(Arc::new(DirectoryKeyManager::new(
        config.operations_keys_directory(),
        KeyPolicy {
            publish_ahead: config.keys_publish_ahead(),
            rotate_every: config.keys_rotate_every(),
            retain: config.keys_retain(),
            verify_retain: config.audit_retention(),
        },
    ))))
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
