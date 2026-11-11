// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `GET /host/v1/config/effective` and `GET /host/v1/config/revisions`, under `config.read`.
//!
//! The effective configuration is the settings the layers supplied, each with the layer it came
//! from, secrets masked before the document is built: the facade never holds a secret value. The
//! static configuration is revision `0`; a dynamic journal of revisions arrives with the
//! configuration packages, and until then `/config/revisions` is `not_served_yet`.

use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, operations};
use permguard_core::config::{EffectiveSetting, SettingOrigin};
use permguard_core::redact::MASK;

use super::{HostApi, Refusal};

/// One effective setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    /// The setting's key, as the environment spells it.
    pub key: String,
    /// Its value in force, or the mask when the key names a secret; `null` when unset with no
    /// default.
    pub value: Option<String>,
    /// Whether `value` is the mask.
    pub masked: bool,
    /// `default` (the image's), `file`, `environment` or `command_line`.
    pub origin: String,
    /// `startup` (varies per instance) or `static` (one file for every instance).
    pub class: String,
}

/// The effective configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effective {
    /// `0`: the static configuration this process started with.
    pub revision: u64,
    pub settings: Vec<Setting>,
}

impl Effective {
    /// Builds the document from every setting in force, masking what [`is_secret`] names.
    pub fn of(settings: impl IntoIterator<Item = EffectiveSetting>) -> Self {
        Self {
            revision: 0,
            settings: settings
                .into_iter()
                .map(|setting| {
                    let masked = is_secret(&setting.key) && setting.value.is_some();
                    Setting {
                        value: if masked {
                            Some(MASK.to_owned())
                        } else {
                            setting.value
                        },
                        masked,
                        origin: setting
                            .origin
                            .map_or("default", SettingOrigin::as_str)
                            .to_owned(),
                        class: setting.class.as_str().to_owned(),
                        key: setting.key,
                    }
                })
                .collect(),
        }
    }
}

/// Whether a setting's value is secret-bearing and is masked in the document.
///
/// The document only ever holds the settings this build reads (`Config::supplied_settings`),
/// never the rest of the process environment, so this decides among known keys. A path to a
/// private key is a path, not the key, and stays readable: an operator reading the document
/// needs to see which file the process uses; so does a secret *reference*, which names material
/// without carrying it, and the prefix under which secrets are read from the environment. A
/// value that *is* a credential — a password or passphrase, a secret, a token, a header line —
/// is masked, and so is any `*_KEY` value that is not a TLS key path. The secret store's own
/// settings (`PERMGUARD_SECRETS_*`: provider, directory, prefix) configure where secrets are
/// read from and carry none.
pub fn is_secret(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    // The secret store's own configuration — its provider, directory and prefix — and a key
    // reference name material without carrying it.
    if upper.starts_with("PERMGUARD_SECRETS_") || upper.ends_with("_KEY_REF") {
        return false;
    }
    ["PASS", "SECRET", "TOKEN", "HEADERS", "CREDENTIAL"]
        .iter()
        .any(|word| upper.contains(word))
        || (upper.ends_with("_KEY") && !upper.ends_with("_TLS_KEY"))
}

impl HostApi {
    /// `GET /host/v1/config/effective`.
    pub fn effective_config(&self, actor: &Actor) -> Result<Effective, Refusal> {
        let _admitted = self.admit(actor, operations::CONFIG_READ)?;
        Ok(self.effective.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::api::testing::{actor, admin, facade};
    use permguard_core::config::SettingClass;

    fn setting(key: &str, value: Option<&str>, origin: Option<SettingOrigin>) -> EffectiveSetting {
        EffectiveSetting {
            key: key.to_owned(),
            value: value.map(str::to_owned),
            origin,
            class: SettingClass::Static,
        }
    }

    #[test]
    fn secrets_are_masked_by_key_and_paths_are_not() {
        let effective = Effective::of([
            setting(
                "PERMGUARD_ADMIN_TLS_KEY",
                Some("tls/server.key"),
                Some(SettingOrigin::File),
            ),
            setting(
                "PERMGUARD_OTEL_HEADERS",
                Some("authorization=Bearer x"),
                Some(SettingOrigin::Environment),
            ),
            setting(
                "PERMGUARD_ISSUER",
                Some("https://a"),
                Some(SettingOrigin::CommandLine),
            ),
            setting("PERMGUARD_LOG_LEVEL", Some("info"), None),
            setting("PERMGUARD_UNSET_SECRET_KEY", None, None),
        ]);
        assert_eq!(effective.revision, 0);
        assert_eq!(
            effective.settings[0].value.as_deref(),
            Some("tls/server.key")
        );
        assert!(!effective.settings[0].masked);
        assert_eq!(effective.settings[0].origin, "file");
        assert_eq!(effective.settings[1].value.as_deref(), Some(MASK));
        assert!(effective.settings[1].masked);
        assert_eq!(effective.settings[1].origin, "environment");
        assert_eq!(effective.settings[2].origin, "command_line");
        assert_eq!(effective.settings[3].origin, "default");
        assert_eq!(effective.settings[3].class, "static");
        assert!(
            effective.settings[4].value.is_none() && !effective.settings[4].masked,
            "an unset secret has nothing to mask"
        );
        assert!(is_secret("PERMGUARD_VAULT_PASSWORD"));
        assert!(is_secret("PERMGUARD_STORE_PASSPHRASE"));
        assert!(is_secret("PERMGUARD_CLIENT_SECRET"));
        assert!(is_secret("SOME_API_KEY"));
        assert!(!is_secret("PERMGUARD_AUDIT_PSEUDONYM_KEY_REF"));
        assert!(!is_secret("PERMGUARD_SECRETS_ENV_PREFIX"));
        assert!(!is_secret("PERMGUARD_SECRETS_PROVIDER"));
        assert!(!is_secret("PERMGUARD_CONTROL_HTTP_TLS_KEY"));
    }

    #[test]
    fn the_effective_configuration_is_gated() {
        let api = facade("config");
        assert!(api.effective_config(&admin()).is_ok());
        assert!(matches!(
            api.effective_config(&actor("sa:other")),
            Err(Refusal::Denied(_))
        ));
    }
}
