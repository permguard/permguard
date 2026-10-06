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
use permguard_core::config::SettingOrigin;
use permguard_core::redact::MASK;

use super::{HostApi, Refusal};

/// One effective setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    /// The setting's key, as the environment spells it.
    pub key: String,
    /// Its value, or the mask when the key names a secret.
    pub value: String,
    /// Whether `value` is the mask.
    pub masked: bool,
    /// `file`, `environment` or `command_line`.
    pub origin: String,
}

/// The effective configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effective {
    /// `0`: the static configuration this process started with.
    pub revision: u64,
    pub settings: Vec<Setting>,
}

impl Effective {
    /// Builds the document from what the layers supplied, masking what [`is_secret`] names.
    pub fn from_supplied<'a>(
        supplied: impl IntoIterator<Item = (&'a str, &'a str, SettingOrigin)>,
    ) -> Self {
        Self {
            revision: 0,
            settings: supplied
                .into_iter()
                .map(|(key, value, origin)| {
                    let masked = is_secret(key);
                    Setting {
                        key: key.to_owned(),
                        value: if masked {
                            MASK.to_owned()
                        } else {
                            value.to_owned()
                        },
                        masked,
                        origin: origin.as_str().to_owned(),
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

    /// `GET /host/v1/config/revisions`: the dynamic journal arrives with the configuration
    /// packages.
    pub fn config_revisions(&self, actor: &Actor) -> Result<std::convert::Infallible, Refusal> {
        let _admitted = self.admit(actor, operations::CONFIG_READ)?;
        Err(Refusal::not_served_yet(
            "the dynamic configuration journal",
            "the configuration packages (WP-3.x)",
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::api::testing::{actor, admin, facade};

    #[test]
    fn secrets_are_masked_by_key_and_paths_are_not() {
        let effective = Effective::from_supplied([
            (
                "PERMGUARD_ADMIN_TLS_KEY",
                "tls/server.key",
                SettingOrigin::File,
            ),
            (
                "PERMGUARD_OTEL_HEADERS",
                "authorization=Bearer x",
                SettingOrigin::Environment,
            ),
            ("PERMGUARD_ISSUER", "https://a", SettingOrigin::CommandLine),
        ]);
        assert_eq!(effective.revision, 0);
        assert_eq!(effective.settings[0].value, "tls/server.key");
        assert!(!effective.settings[0].masked);
        assert_eq!(effective.settings[0].origin, "file");
        assert_eq!(effective.settings[1].value, MASK);
        assert!(effective.settings[1].masked);
        assert_eq!(effective.settings[1].origin, "environment");
        assert_eq!(effective.settings[2].origin, "command_line");
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
    fn the_configuration_routes_are_gated_and_the_revisions_are_not_served_yet() {
        let api = facade("config");
        assert!(api.effective_config(&admin()).is_ok());
        assert!(matches!(
            api.effective_config(&actor("spiffe://acme/other")),
            Err(Refusal::Denied(_))
        ));
        let revisions = api.config_revisions(&admin()).expect_err("not yet");
        assert_eq!(
            revisions.error().expect("refusal").code(),
            permguard_core::codes::host::NOT_SERVED_YET
        );
    }
}
