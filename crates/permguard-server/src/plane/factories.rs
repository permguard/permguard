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
use permguard_host::keys::ring::{
    CONTROL_ATTEST, DATA_ATTEST, HOST_OPERATIONS, IAM_TOKENS, Policy, Ring,
};
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

/// The IAM Host's ring, `iam.tokens`, under `host/keys` (iteration 02, WP-11.3): it signs access
/// tokens and status list tokens at the token endpoint, never on a decision path, so any custody
/// may hold it; `regulated` keeps it in a PKCS#11 token or a KMS, and no profile but `development`
/// keeps it in plaintext. Opened only by the Host of a Server running a Control Plane.
pub(crate) fn iam_tokens_keys_for(
    config: &Config,
    rings: &Opener<'_>,
) -> anyhow::Result<Arc<Ring>> {
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::config::KeyCustody;

    let custody = config.keys_custody_of(IAM_TOKENS);
    let profile = config.assurance().profile();
    if profile == AssuranceProfile::Regulated
        && !matches!(custody, KeyCustody::Pkcs11 | KeyCustody::Kms)
    {
        anyhow::bail!(
            "the `regulated` profile keeps `{IAM_TOKENS}` in a PKCS#11 token or a KMS, and its \
             custody is `{}`: set {} (operations.keys.rings.\"iam.tokens\".custody)",
            custody.as_str(),
            permguard_core::config::SETTING_KEYS_TOKENS_CUSTODY
        );
    }
    if profile != AssuranceProfile::Development && custody == KeyCustody::Development {
        anyhow::bail!(
            "`{IAM_TOKENS}` is under the `development` custody, plaintext files, which the `{}` \
             profile refuses",
            profile.as_str()
        );
    }
    Ok(rings.open(
        IAM_TOKENS,
        Suite::Ed25519Sha256V1,
        ring_policy(config),
        None,
    )?)
}

/// The capability a Host reports degraded while `iam.tokens` is kept in files on its volume.
pub(crate) const TOKEN_CUSTODY: &str = "token-custody";

/// What the IAM Host says while `iam.tokens` is in `file` custody under `production`
/// (`2-security/8` Profiles): envelope-encrypted files on the volume, which `production` admits
/// and reports, since the ring signs every member's tokens. `None` under any other custody or
/// profile: plaintext and `regulated`'s other custodies are refused at start.
pub(crate) fn iam_tokens_custody_advice(config: &Config) -> Option<String> {
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::config::KeyCustody;

    (config.assurance().profile() == AssuranceProfile::Production
        && config.keys_custody_of(IAM_TOKENS) == KeyCustody::File)
        .then(|| {
            format!(
                "`{IAM_TOKENS}` signs every member's tokens and is kept in files on this volume: \
                 keep it in a PKCS#11 token or a KMS ({})",
                permguard_core::config::SETTING_KEYS_TOKENS_CUSTODY
            )
        })
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::BuildSettings;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::config::{
        Layers, SETTING_ASSURANCE_PROFILE, SETTING_KEYS_CUSTODY, SETTING_KEYS_TOKENS_CUSTODY,
    };
    use permguard_host::storage::volume::Volume;

    fn config(settings: &[(&str, &str)]) -> Config {
        Config::from_layers(
            BuildSettings::new("1.2.3", "2026", "Build Holder"),
            [] as [&str; 0],
            Layers::new().with_file(
                settings
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect::<Vec<_>>(),
            ),
        )
        .expect("the layers build a config")
    }

    fn opened(tag: &str, config: &Config) -> anyhow::Result<Arc<Ring>> {
        let root = std::env::temp_dir().join(format!(
            "pg-iam-tokens-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch directory");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let opener = Opener {
            volume: &volume,
            host_id: [7; 16],
            custodian: Arc::new(permguard_host::keys::custody::Custodian::development()),
            time: Arc::new(permguard_host::time::TimeGuard::system(
                std::time::Duration::from_secs(30),
            )),
            binder: None,
            recorder: None,
            profile: AssuranceProfile::Development,
        };
        iam_tokens_keys_for(config, &opener)
    }

    /// `production` admits `iam.tokens` in `file` custody and says so; no other custody or
    /// profile is reported.
    #[test]
    fn file_custody_of_iam_tokens_is_reported_under_production_only() {
        let advice = |profile: &str, custody: &str| {
            iam_tokens_custody_advice(&config(&[
                (SETTING_ASSURANCE_PROFILE, profile),
                (permguard_core::config::SETTING_KEYS_TOKENS_CUSTODY, custody),
            ]))
        };
        let said = advice("production", "file").expect("reported");
        assert!(said.contains("PKCS#11 token or a KMS"), "{said}");
        assert_eq!(advice("production", "kms"), None);
        assert_eq!(advice("production", "pkcs11"), None);
        assert_eq!(advice("development", "file"), None);
        assert_eq!(advice("regulated", "kms"), None);
    }

    /// WP-11.3: under `development` the IAM Host opens `iam.tokens` with any custody.
    #[test]
    fn the_iam_tokens_ring_opens_under_development() {
        let ring = opened(
            "development",
            &config(&[(SETTING_ASSURANCE_PROFILE, "development")]),
        )
        .expect("the ring opens");
        assert_eq!(ring.id(), IAM_TOKENS);
    }

    /// `regulated` keeps the ring in a token or a KMS, whatever the Host's custody; and no profile
    /// but `development` keeps it in plaintext. Refused before anything is opened.
    #[test]
    fn regulated_or_plaintext_custody_of_iam_tokens_is_refused() {
        for (tag, settings, says) in [
            (
                "regulated-file",
                vec![
                    (SETTING_ASSURANCE_PROFILE, "regulated"),
                    (SETTING_KEYS_CUSTODY, "pkcs11"),
                    (SETTING_KEYS_TOKENS_CUSTODY, "file"),
                ],
                "PKCS#11 token or a KMS",
            ),
            (
                "production-development",
                vec![
                    (SETTING_ASSURANCE_PROFILE, "production"),
                    (SETTING_KEYS_TOKENS_CUSTODY, "development"),
                ],
                "plaintext",
            ),
        ] {
            let refused = opened(tag, &config(&settings)).expect_err(tag);
            assert!(format!("{refused:#}").contains(says), "{tag}: {refused:#}");
        }
    }
}
