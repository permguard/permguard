// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The custody a volume's key rings are opened through, built from the configuration as `serve`
//! builds it, so an offline command sees the keys the server signs with.

use std::sync::Arc;

use anyhow::{Context, Result};
use permguard_core::Config;
use permguard_core::secrets::SecretStore;

/// Builds the key ring the effective configuration names.
///
/// It hands back an `Arc` rather than a `Box` because a key ring is maintained by work that outlives
/// any single call — see [`ServerContext::with_keys`](permguard_core::ServerContext::with_keys).
/// Resolves the root `reference` names at the text `version` (`vN`), witnessed in `witnesses`; the
/// errors name the reference and never the material (WP-3.3).
pub fn resolve_root(
    secrets: &dyn SecretStore,
    witnesses: &permguard_host::secrets::Witnesses,
    reference: &permguard_core::SecretRef,
    version: &str,
    what: &str,
    role: &str,
) -> Result<permguard_host::secrets::Root> {
    let version: permguard_host::secrets::KeyVersion = version
        .parse()
        .map_err(|error| anyhow::anyhow!("{error}"))
        .with_context(|| format!("reading the version of {what}"))?;
    permguard_host::secrets::resolve(secrets, witnesses, reference, version, role)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .with_context(|| {
            format!(
                "resolving {what} `{}` from the {} secret store",
                reference.name(),
                secrets.name()
            )
        })
}

/// The PKCS#11 token of the `pkcs11` custody (WP-3.2), when this build has the `pkcs11` feature.
#[cfg(feature = "pkcs11")]
struct Token(Arc<crate::custody::pkcs11::Hsm>);

#[cfg(feature = "pkcs11")]
impl Token {
    fn remote(&self) -> Arc<dyn permguard_host::keys::custody::Remote> {
        Arc::new(crate::custody::pkcs11::SharedHsm(Arc::clone(&self.0)))
    }

    fn kek(
        &self,
        label: &str,
        version: u64,
    ) -> Result<Arc<dyn permguard_host::keys::custody::Wrap>> {
        Ok(Arc::new(crate::custody::pkcs11::HsmKek::open(
            Arc::clone(&self.0),
            label,
            version,
        )?))
    }
}

#[cfg(feature = "pkcs11")]
fn token_for(config: &Config, secrets: Option<&dyn SecretStore>) -> Result<Token> {
    let module = config
        .keys_pkcs11_module()
        .context("the `pkcs11` custody needs `operations.keys.pkcs11.module`")?;
    let label = config
        .keys_pkcs11_token_label()
        .context("the `pkcs11` custody needs `operations.keys.pkcs11.token_label`")?;
    let reference = config
        .keys_pkcs11_pin_ref()
        .context("the `pkcs11` custody needs `operations.keys.pkcs11.pin_ref`")?;
    let secrets = secrets.context(
        "the token PIN is resolved from the secret store, and this build resolved none: set \
         `operations.secrets.provider`",
    )?;
    let pin = secrets
        .resolve(reference)
        .with_context(|| format!("resolving the token PIN `{}`", reference.name()))?;
    let pin = zeroize::Zeroizing::new(
        std::str::from_utf8(pin.expose())
            .context("the token PIN is text")?
            .trim()
            .to_owned(),
    );
    Ok(Token(crate::custody::pkcs11::Hsm::open(
        crate::custody::pkcs11::Token {
            module: std::path::PathBuf::from(module),
            label: label.to_owned(),
            pin,
        },
    )?))
}

/// Without the `pkcs11` feature, no token: the custody is refused by name.
#[cfg(not(feature = "pkcs11"))]
struct Token;

#[cfg(not(feature = "pkcs11"))]
impl Token {
    fn remote(&self) -> Arc<dyn permguard_host::keys::custody::Remote> {
        unreachable!("no token is ever opened without the `pkcs11` feature")
    }

    fn kek(
        &self,
        _label: &str,
        _version: u64,
    ) -> Result<Arc<dyn permguard_host::keys::custody::Wrap>> {
        unreachable!("no token is ever opened without the `pkcs11` feature")
    }
}

#[cfg(not(feature = "pkcs11"))]
fn token_for(_config: &Config, _secrets: Option<&dyn SecretStore>) -> Result<Token> {
    anyhow::bail!(
        "the `pkcs11` custody needs a build with the `pkcs11` feature; this one was built without \
         it"
    )
}

/// The Vault Transit client of the `kms` custody (WP-3.2), when this build has the `kms` feature.
#[cfg(feature = "kms")]
struct Kms(Arc<crate::custody::Transit>);

#[cfg(feature = "kms")]
impl Kms {
    fn remote(&self) -> Arc<dyn permguard_host::keys::custody::Remote> {
        Arc::clone(&self.0) as _
    }

    fn kek(
        &self,
        name: &str,
        version: u64,
    ) -> Result<Arc<dyn permguard_host::keys::custody::Wrap>> {
        Ok(Arc::new(crate::custody::TransitKek::open(
            Arc::clone(&self.0),
            name,
            version,
        )?))
    }
}

/// The Vault Transit client of the `kms` custody (WP-3.2): its token from the secret store.
#[cfg(feature = "kms")]
fn transit_for(config: &Config, secrets: Option<&dyn SecretStore>) -> Result<Kms> {
    let address = config.keys_kms_address().context(
        "the `kms` custody reaches a Vault, and `operations.keys.kms.address` names none",
    )?;
    let reference = config
        .keys_kms_token_ref()
        .context("the `kms` custody authenticates with `operations.keys.kms.token_ref`")?;
    let secrets = secrets.context(
        "the KMS token is resolved from the secret store, and this build resolved none: set \
         `operations.secrets.provider`",
    )?;
    let token = secrets
        .resolve(reference)
        .with_context(|| format!("resolving the KMS token `{}`", reference.name()))?;
    let token = zeroize::Zeroizing::new(
        std::str::from_utf8(token.expose())
            .context("the KMS token is text")?
            .trim()
            .to_owned(),
    );
    Ok(Kms(crate::custody::Transit::start(
        crate::custody::Endpoint {
            address: address.to_owned(),
            mount: config.keys_kms_mount().to_owned(),
            token,
            ca: config.keys_kms_ca(),
        },
    )?))
}

/// Without the `kms` feature, no client: the custody is refused by name.
#[cfg(not(feature = "kms"))]
struct Kms;

#[cfg(not(feature = "kms"))]
impl Kms {
    fn remote(&self) -> Arc<dyn permguard_host::keys::custody::Remote> {
        unreachable!("no KMS is ever reached without the `kms` feature")
    }

    fn kek(
        &self,
        _name: &str,
        _version: u64,
    ) -> Result<Arc<dyn permguard_host::keys::custody::Wrap>> {
        unreachable!("no KMS is ever reached without the `kms` feature")
    }
}

#[cfg(not(feature = "kms"))]
fn transit_for(_config: &Config, _secrets: Option<&dyn SecretStore>) -> Result<Kms> {
    anyhow::bail!(
        "the `kms` custody needs a build with the `kms` feature; this one was built without it"
    )
}

/// Each ring's provider from its custody (WP-3.2, owner decisions of 2026-10-08): the
/// key-encryption key of the `file` custody resolved from the secret store and witnessed,
/// with the previous one a rotation leaves behind.
pub fn custodian_for(
    config: &Config,
    secrets: Option<&dyn SecretStore>,
    witnesses: &permguard_host::secrets::Witnesses,
) -> Result<Arc<permguard_host::keys::custody::Custodian>> {
    use permguard_core::config::KeyCustody;
    use permguard_host::keys::ring::{
        AUTHORITY_TOKENS, CONTROL_ATTEST, DATA_ATTEST, HOST_IDENTITY, HOST_OPERATIONS,
    };

    // Every ring this build may open: a ring missing here would fall to the plaintext custody.
    let custodies: Vec<(&'static str, KeyCustody)> = [
        HOST_IDENTITY,
        HOST_OPERATIONS,
        CONTROL_ATTEST,
        DATA_ATTEST,
        AUTHORITY_TOKENS,
    ]
    .into_iter()
    .map(|ring| (ring, config.keys_custody_of(ring)))
    .collect();
    let host_custody = config.keys_custody();
    let uses = |wanted: KeyCustody| {
        config
            .keys_custodies()
            .iter()
            .any(|(_, custody)| *custody == wanted)
    };
    // The KMS, when a ring or the KEK lives there: one client for both.
    let kms = if uses(KeyCustody::Kms)
        || (uses(KeyCustody::File)
            && config.keys_kek_provider() == permguard_core::config::KekProvider::Kms)
    {
        Some(transit_for(config, secrets)?)
    } else {
        None
    };
    // The PKCS#11 token, when a ring or the KEK lives there.
    let hsm = if uses(KeyCustody::Pkcs11)
        || (uses(KeyCustody::File)
            && config.keys_kek_provider() == permguard_core::config::KekProvider::Pkcs11)
    {
        Some(token_for(config, secrets)?)
    } else {
        None
    };
    let keks = if uses(KeyCustody::File) {
        keks_for(config, secrets, witnesses, kms.as_ref(), hsm.as_ref())
            .map(Some)
            .map_err(|error| format!("{error:#}"))
    } else {
        Ok(None)
    };
    let mut custodian = permguard_host::keys::custody::Custodian::new(
        move |ring| {
            custodies
                .iter()
                .find(|(held, _)| *held == ring)
                // A ring this list does not name takes the Host's custody, never plaintext.
                .map_or(host_custody, |(_, custody)| *custody)
        },
        keks,
    );
    if let Some(kms) = kms {
        custodian = custodian.with_kms(kms.remote());
    }
    if let Some(hsm) = hsm {
        custodian = custodian.with_hsm(hsm.remote());
    }
    Ok(Arc::new(custodian))
}

/// The key-encryption key of the `file` custody, and the previous one.
fn keks_for(
    config: &Config,
    secrets: Option<&dyn SecretStore>,
    witnesses: &permguard_host::secrets::Witnesses,
    kms: Option<&Kms>,
    hsm: Option<&Token>,
) -> Result<permguard_host::keys::custody::Keks> {
    use permguard_core::config::KekProvider;
    use permguard_host::keys::custody::Wrap as KeyWrap;
    use permguard_host::keys::custody::{Keks, SecretKek};

    match config.keys_kek_provider() {
        KekProvider::Secret => {}
        KekProvider::Kms => {
            let transit = kms.context("the KEK is in the KMS, and no KMS is configured")?;
            let version = |text: &str| -> Result<u64> {
                text.parse::<permguard_host::secrets::KeyVersion>()
                    .map(|version| version.get())
                    .map_err(|error| anyhow::anyhow!("{error}"))
            };
            let reference = config.keys_kek_ref().context(
                "the KEK in the KMS is the Transit key `operations.keys.kek_ref` names, and it \
                 names none",
            )?;
            let current: Arc<dyn KeyWrap> =
                transit.kek(reference.name(), version(config.keys_kek_version())?)?;
            let previous = match config.keys_previous_kek() {
                Some((reference, previous)) => {
                    Some(transit.kek(reference.name(), version(previous)?)?)
                }
                None => None,
            };
            return Ok(Keks { current, previous });
        }
        KekProvider::Pkcs11 => {
            let token = hsm.context("the KEK is in a PKCS#11 token, and none is configured")?;
            let reference = config.keys_kek_ref().context(
                "the KEK in the token is the AES key `operations.keys.kek_ref` labels, and it \
                 names none",
            )?;
            let version = |text: &str| -> Result<u64> {
                text.parse::<permguard_host::secrets::KeyVersion>()
                    .map(|version| version.get())
                    .map_err(|error| anyhow::anyhow!("{error}"))
            };
            let current = token.kek(reference.name(), version(config.keys_kek_version())?)?;
            let previous = match config.keys_previous_kek() {
                Some((reference, previous)) => {
                    Some(token.kek(reference.name(), version(previous)?)?)
                }
                None => None,
            };
            return Ok(Keks { current, previous });
        }
    }
    let secrets = secrets.context(
        "the `file` custody resolves its key-encryption key from the secret store, and this \
         build resolved none: set `operations.secrets.provider`",
    )?;
    let reference = config.keys_kek_ref().context(
        "the `file` custody seals every private key under a key-encryption key, and \
         `operations.keys.kek_ref` names none",
    )?;
    let kek = |reference: &permguard_core::SecretRef, version: &str, what: &str| {
        let root = resolve_root(
            secrets,
            witnesses,
            reference,
            version,
            what,
            "key-encryption",
        )?;
        let kek = SecretKek::from_root(reference.name(), &root)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok::<Arc<dyn KeyWrap>, anyhow::Error>(Arc::new(kek))
    };
    let current = kek(
        reference,
        config.keys_kek_version(),
        "the key-encryption key",
    )?;
    let previous = match config.keys_previous_kek() {
        Some((reference, version)) => {
            Some(kek(reference, version, "the previous key-encryption key")?)
        }
        None => None,
    };
    Ok(Keks { current, previous })
}

/// A build without the `kms` feature carries no client to a KMS: a configuration that names that
/// custody is refused by name, before any ring is opened, and never falls back to another custody.
#[cfg(all(test, not(feature = "kms")))]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::config::{
        Layers, SETTING_ASSURANCE_PROFILE, SETTING_KEYS_CUSTODY, SETTING_KEYS_KMS_ADDRESS,
    };
    use permguard_core::{BuildSettings, Config};

    use super::custodian_for;

    #[test]
    fn test_a_kms_custody_is_refused_by_name_in_a_build_without_the_adapter() {
        let config = Config::from_layers(
            BuildSettings::new("1.2.3", "2026", "Build Holder"),
            [""; 0],
            Layers::new().with_file(
                [
                    (SETTING_ASSURANCE_PROFILE, "development"),
                    (SETTING_KEYS_CUSTODY, "kms"),
                    (SETTING_KEYS_KMS_ADDRESS, "https://vault.example:8200"),
                ]
                .map(|(key, value)| (key.to_owned(), value.to_owned())),
            ),
        )
        .expect("the layers build a config");
        let root =
            std::env::temp_dir().join(format!("permguard-offline-test-kms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let volume = permguard_host::storage::volume::Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("a volume");

        let witnesses = permguard_host::secrets::Witnesses::open(&volume).expect("the witnesses");
        let refused = match custodian_for(&config, None, &witnesses) {
            Ok(_) => panic!("a custody this build cannot reach was accepted"),
            Err(refused) => format!("{refused:#}"),
        };

        assert!(
            refused.contains("the `kms` custody needs a build with the `kms` feature"),
            "{refused}"
        );
    }
}
