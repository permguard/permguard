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
    /// What the setting does not do, where its name says more than it bounds (BUG-0215); absent
    /// for most.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The note a setting carries in the effective configuration: what it does not do, where its
/// name says more than it bounds.
pub fn note_of(key: &str) -> Option<&'static str> {
    match key {
        permguard_core::config::SETTING_EVENTS_MAX_BYTES => Some(
            "bounds the event records no required subscription has acknowledged; with no \
             membership nothing is owed, and the Host event stream keeps its history whatever \
             this says",
        ),
        permguard_core::config::SETTING_EVENTS_SEGMENT_BYTES => Some(
            "sizes the legacy event journals only: the Host event stream keeps its own segments",
        ),
        _ => None,
    }
}

/// One `host.authz.public` grant in force: what anybody may do without a credential (BUG-0202).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicGrant {
    /// The operations granted, each a registered operation.
    pub operations: Vec<String>,
    /// The resources granted on, as the configuration spells the selector.
    pub selector: String,
    /// The resource types granted on; `*` for any.
    pub resource_types: Vec<String>,
}

/// The effective configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effective {
    /// `0`: the static configuration this process started with.
    pub revision: u64,
    pub settings: Vec<Setting>,
    /// The public grants in force, empty when every request needs a credential. A structured
    /// section of the file, with no variable of its own, so it is not among `settings`; the
    /// assurance block names the relaxations it amounts to. Absent from a Host older than
    /// it, which read as none.
    #[serde(default)]
    pub public_grants: Vec<PublicGrant>,
}

impl Effective {
    /// The document with the public grants in force beside the settings.
    pub fn with_public_grants(mut self, grants: impl IntoIterator<Item = PublicGrant>) -> Self {
        self.public_grants = grants.into_iter().collect();
        self
    }

    /// Builds the document from every setting in force, masking what [`is_secret`] names.
    pub fn of(settings: impl IntoIterator<Item = EffectiveSetting>) -> Self {
        Self {
            revision: 0,
            public_grants: Vec::new(),
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
                        note: note_of(&setting.key).map(str::to_owned),
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

    /// BUG-0215: the events bounds say what they do not do, in the effective configuration.
    #[test]
    fn the_events_bounds_carry_what_they_do_not_bound() {
        let max = note_of(permguard_core::config::SETTING_EVENTS_MAX_BYTES).expect("a note");
        assert!(max.contains("no required subscription") && max.contains("no membership"));
        let segment =
            note_of(permguard_core::config::SETTING_EVENTS_SEGMENT_BYTES).expect("a note");
        assert!(segment.contains("legacy"));
        assert_eq!(note_of("PERMGUARD_LOG_LEVEL"), None);
        let json = serde_json::to_value(Setting {
            key: "PERMGUARD_LOG_LEVEL".to_owned(),
            value: None,
            masked: false,
            origin: "default".to_owned(),
            class: "static".to_owned(),
            note: None,
        })
        .expect("JSON");
        assert!(
            json.get("note").is_none(),
            "absent where there is none: {json}"
        );
    }
}
