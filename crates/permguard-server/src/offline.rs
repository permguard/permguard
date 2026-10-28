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

/// The fewest bytes a recovery key holds (TS-5).
pub const MIN_RECOVERY_KEY_BYTES: usize = 16;

/// The id of the recovery key `config` names (TS-5): the fingerprint of the key
/// `operations.backup.recovery_key` resolves to, through the deployment's secret store, or the
/// qualified provider's `recovery_key_id` when no key is named. A stated id that is not the
/// resolved key's fingerprint is refused. `None` when neither is configured.
pub fn recovery_key_id(config: &Config) -> Result<Option<String>> {
    let store = crate::plane::factories::secret_store_for(config)?;
    recovery_key_id_from(config, store.as_deref())
}

/// [`recovery_key_id`], resolving through `store`: the one `serve` already holds.
pub fn recovery_key_id_from(
    config: &Config,
    store: Option<&dyn permguard_core::secrets::SecretStore>,
) -> Result<Option<String>> {
    let Some(reference) = config.backup_recovery_key() else {
        return Ok(config.backup_recovery_key_id().map(str::to_owned));
    };
    // Separate from every other key the deployment names: the recovery key outlives them.
    let others = [
        ("operations.keys.kek_ref", config.keys_kek_ref()),
        ("operations.keys.kms.token_ref", config.keys_kms_token_ref()),
        (
            "operations.secrets.coordinator_root_ref",
            config.secrets_coordinator_root_ref(),
        ),
        (
            "operations.audit.pseudonym.key_ref",
            config.audit_pseudonym_key_ref(),
        ),
    ];
    if let Some((key, _)) = others
        .iter()
        .find(|(_, other)| other.is_some_and(|other| other.name() == reference.name()))
    {
        anyhow::bail!(
            "{}: operations.backup.recovery_key names `{}`, which {key} names too: backups are \
             encrypted under a key of their own",
            permguard_core::codes::storage::RECOVERY_KEY_SHARED,
            reference.name()
        );
    }
    let store = store.ok_or_else(|| {
        anyhow::anyhow!(
            "{}: operations.backup.recovery_key names `{}`, and no secret store is configured \
             to resolve it",
            permguard_core::codes::storage::RECOVERY_KEY_MISSING,
            reference.name()
        )
    })?;
    let key = store.resolve(reference).map_err(|error| {
        anyhow::anyhow!(
            "{}: resolving the recovery key `{}`: {error}",
            permguard_core::codes::storage::RECOVERY_KEY_MISSING,
            reference.name()
        )
    })?;
    // A fingerprint of a short key leaves with every manifest and could be searched for: the key
    // is at least 128 bits.
    if key.len() < MIN_RECOVERY_KEY_BYTES {
        anyhow::bail!(
            "{}: the recovery key `{}` holds {} bytes, fewer than {MIN_RECOVERY_KEY_BYTES}: use \
             at least 128 random bits",
            permguard_core::codes::storage::RECOVERY_KEY_WEAK,
            reference.name(),
            key.len()
        );
    }
    let id = permguard_host::operations::backup::recovery_key_id(key.expose());
    if let Some(stated) = config.backup_recovery_key_id()
        && stated != id
    {
        anyhow::bail!(
            "{}: operations.backup.recovery_key_id states `{stated}`, and the key \
             operations.backup.recovery_key resolves is `{id}`: state the key's fingerprint, or \
             leave the id out",
            permguard_core::codes::storage::RECOVERY_KEY_MISMATCH
        );
    }
    Ok(Some(id))
}

/// From `production` (TS-5) every backup is encrypted under a recovery key, under a declared
/// encryption profile, kept for a declared retention and destroyed by a tested procedure: each
/// is required. Answers the shortfalls; empty, the policy is complete.
pub fn backup_policy_shortfalls(
    config: &Config,
    recovery_key_id: Option<&str>,
) -> Vec<&'static str> {
    [
        // A provider's `recovery_key_id` alone is a string this build cannot verify against any
        // key: from `production` the key itself is named, and resolved here.
        (
            "operations.backup.recovery_key",
            recovery_key_id.is_none() || config.backup_recovery_key().is_none(),
        ),
        (
            "operations.backup.encryption_profile",
            config.backup_encryption_profile().is_none(),
        ),
        (
            "operations.backup.retention",
            config.backup_retention().is_none(),
        ),
        (
            "operations.backup.destruction",
            config.backup_destruction().is_none(),
        ),
    ]
    .into_iter()
    .filter_map(|(key, missing)| missing.then_some(key))
    .collect()
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::secrets::{Secret, SecretRef, SecretStore};

    use super::*;

    /// One secret, `recovery`, and nothing else.
    struct OneKey(&'static [u8]);

    impl SecretStore for OneKey {
        fn name(&self) -> &'static str {
            "one-key"
        }

        fn resolve(&self, reference: &SecretRef) -> permguard_core::secrets::Result<Secret> {
            if reference.name() == "recovery" {
                Ok(Secret::new(self.0.to_vec()))
            } else {
                Err(permguard_core::error::SecretError::NotFound {
                    reference: reference.name().to_owned(),
                })
            }
        }
    }

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_layers(
            crate::plane::build_settings("test"),
            Vec::<String>::new(),
            Layers::new().with_file(
                pairs
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect::<Vec<_>>(),
            ),
        )
        .expect("the configuration builds")
    }

    use permguard_core::config::{
        SETTING_BACKUP_DESTRUCTION, SETTING_BACKUP_ENCRYPTION_PROFILE, SETTING_BACKUP_RECOVERY_KEY,
        SETTING_BACKUP_RECOVERY_KEY_ID, SETTING_BACKUP_RETENTION,
    };

    /// TS-5: the recovery-key id is the resolved key's fingerprint; a stated id must be it; a
    /// provider's id stands alone; a key that cannot be resolved is refused, never skipped.
    #[test]
    fn the_recovery_key_id_is_the_resolved_key_s_fingerprint() {
        let store = OneKey(b"the recovery key");
        let fingerprint = permguard_host::operations::backup::recovery_key_id(b"the recovery key");
        let named = config(&[(SETTING_BACKUP_RECOVERY_KEY, "recovery")]);
        assert_eq!(
            recovery_key_id_from(&named, Some(&store)).expect("resolves"),
            Some(fingerprint.clone())
        );
        let stated = config(&[
            (SETTING_BACKUP_RECOVERY_KEY, "recovery"),
            (SETTING_BACKUP_RECOVERY_KEY_ID, fingerprint.as_str()),
        ]);
        assert_eq!(
            recovery_key_id_from(&stated, Some(&store)).expect("the same id"),
            Some(fingerprint)
        );
        let wrong = config(&[
            (SETTING_BACKUP_RECOVERY_KEY, "recovery"),
            (SETTING_BACKUP_RECOVERY_KEY_ID, "sha256:another"),
        ]);
        let refused = recovery_key_id_from(&wrong, Some(&store)).expect_err("another id");
        assert!(
            refused.to_string().starts_with("recovery_key_mismatch"),
            "{refused}"
        );
        let provider = config(&[(SETTING_BACKUP_RECOVERY_KEY_ID, "kms:recovery")]);
        assert_eq!(
            recovery_key_id_from(&provider, None).expect("a provider's id"),
            Some("kms:recovery".to_owned())
        );
        let missing = config(&[(SETTING_BACKUP_RECOVERY_KEY, "elsewhere")]);
        let refused = recovery_key_id_from(&missing, Some(&store)).expect_err("not found");
        assert!(
            refused.to_string().starts_with("recovery_key_missing"),
            "{refused}"
        );
        let refused = recovery_key_id_from(&named, None).expect_err("no store");
        assert!(
            refused.to_string().starts_with("recovery_key_missing"),
            "{refused}"
        );
        assert_eq!(
            recovery_key_id_from(&config(&[]), None).expect("none"),
            None
        );
    }

    /// TS-5: a recovery key shorter than 128 bits, or one another key of the deployment names, is
    /// refused: its fingerprint leaves with every manifest, and it outlives the other keys.
    #[test]
    fn a_weak_or_shared_recovery_key_is_refused() {
        let weak = OneKey(b"fifteen bytes!!");
        let named = config(&[(SETTING_BACKUP_RECOVERY_KEY, "recovery")]);
        let refused = recovery_key_id_from(&named, Some(&weak)).expect_err("weak");
        assert!(
            refused.to_string().starts_with("recovery_key_weak"),
            "{refused}"
        );
        let shared = config(&[
            (SETTING_BACKUP_RECOVERY_KEY, "recovery"),
            (
                permguard_core::config::SETTING_SECRETS_COORDINATOR_ROOT_REF,
                "recovery",
            ),
        ]);
        let refused =
            recovery_key_id_from(&shared, Some(&OneKey(b"the recovery key"))).expect_err("shared");
        assert!(
            refused.to_string().starts_with("recovery_key_shared"),
            "{refused}"
        );
    }

    /// TS-5: the policy names every missing part, and nothing once all four are declared.
    #[test]
    fn the_backup_policy_names_what_is_missing() {
        assert_eq!(backup_policy_shortfalls(&config(&[]), None).len(), 4);
        let complete = config(&[
            (SETTING_BACKUP_ENCRYPTION_PROFILE, "aes-256-gcm"),
            (SETTING_BACKUP_RETENTION, "90d"),
            (SETTING_BACKUP_DESTRUCTION, "DESTROY-2026-01"),
        ]);
        let keyed = config(&[
            (SETTING_BACKUP_RECOVERY_KEY, "recovery"),
            (SETTING_BACKUP_ENCRYPTION_PROFILE, "aes-256-gcm"),
            (SETTING_BACKUP_RETENTION, "90d"),
            (SETTING_BACKUP_DESTRUCTION, "DESTROY-2026-01"),
        ]);
        assert!(backup_policy_shortfalls(&keyed, Some("sha256:id")).is_empty());
        // A provider's id alone proves no key this build can resolve.
        assert_eq!(
            backup_policy_shortfalls(&complete, Some("kms:recovery")),
            ["operations.backup.recovery_key"]
        );
        assert_eq!(
            backup_policy_shortfalls(&complete, None),
            ["operations.backup.recovery_key"]
        );
    }
}
