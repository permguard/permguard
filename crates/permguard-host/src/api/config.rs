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

/// One transition of a dynamic Host journal (WP-2.9, owner decision of 2026-10-07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    /// The journal: `grants` today; memberships and key actions with their packages.
    pub journal: String,
    pub revision: u64,
    /// `issue`, `revoke` or `expire` for the grants.
    pub operation: String,
    /// What the transition is about: a grant id.
    pub target: String,
    /// RFC 3339.
    pub at: String,
    pub by: String,
}

/// `GET /host/v1/config/revisions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revisions {
    /// Newest first.
    pub revisions: Vec<Revision>,
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

    /// `GET /host/v1/config/revisions`: the transitions of the Host's dynamic journals, newest
    /// first (owner decision, 2026-10-07): the grants today, memberships and key actions with
    /// their packages.
    pub fn config_revisions(&self, actor: &Actor) -> Result<Revisions, Refusal> {
        let _admitted = self.admit(actor, operations::CONFIG_READ)?;
        let store = self.store()?;
        let history = store.history().map_err(|error| {
            Refusal::Api(
                permguard_core::ApiError::new(
                    permguard_core::ErrorClass::Unavailable,
                    permguard_core::codes::common::UNAVAILABLE,
                    "the grant journal could not be read",
                )
                .with_internal(error.to_string()),
            )
        })?;
        let mut revisions: Vec<Revision> = history
            .into_iter()
            .map(|change| Revision {
                journal: "grants".to_owned(),
                revision: change.revision,
                operation: change.operation.to_owned(),
                target: change.grant_id.to_string(),
                at: permguard_core::time::to_rfc3339(i64::try_from(change.at).unwrap_or(i64::MAX)),
                by: change.by,
            })
            .collect();
        revisions.reverse();
        Ok(Revisions { revisions })
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

    #[tokio::test]
    async fn the_configuration_routes_are_gated_and_the_revisions_list_the_grant_journal() {
        let api = facade("config");
        assert!(api.effective_config(&admin()).is_ok());
        assert!(matches!(
            api.effective_config(&actor("spiffe://acme/other")),
            Err(Refusal::Denied(_))
        ));
        assert!(matches!(
            api.config_revisions(&actor("spiffe://acme/other")),
            Err(Refusal::Denied(_))
        ));
        let created = api
            .create_grant(
                &admin(),
                crate::api::CreateGrant {
                    request_id: "r1".to_owned(),
                    expected_revision: None,
                    principal: "spiffe://acme/alice".to_owned(),
                    operations: vec![permguard_core::authz::operations::CATALOG_READ.to_owned()],
                    selector: "plane/control/*".to_owned(),
                    resource_types: Vec::new(),
                    constraints: Default::default(),
                    expires_at: None,
                },
            )
            .await
            .expect("created");
        let revisions = api.config_revisions(&admin()).expect("listed").revisions;
        assert_eq!(
            revisions.len(),
            2,
            "the test administrator and alice's grant"
        );
        assert_eq!(revisions[0].journal, "grants");
        assert_eq!(revisions[0].operation, "issue");
        assert_eq!(revisions[0].target, created.grant.grant_id);
        assert_eq!(revisions[0].revision, created.receipt.revision);
        assert_eq!(revisions[0].by, crate::api::testing::ADMIN, "who issued it");
        assert!(
            chrono_like(&revisions[0].at),
            "RFC 3339: {}",
            revisions[0].at
        );
        assert!(
            revisions[0].revision > revisions[1].revision,
            "newest first"
        );
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`-shaped: the time is rendered, not left empty or raw seconds.
    fn chrono_like(at: &str) -> bool {
        let bytes = at.as_bytes();
        at.len() >= 20 && bytes[4] == b'-' && bytes[10] == b'T' && at.ends_with('Z')
    }
}
