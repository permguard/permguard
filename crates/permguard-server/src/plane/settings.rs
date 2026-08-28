// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a plane reads its listeners and its ring from: the setting keys, the
//! bundles that group them per plane, the configuration-file sections that
//! feed them, and the TLS material they resolve to.
//!
//! Every key is declared here and nowhere else, so the file, the
//! environment and the flags cannot disagree about a name.

use anyhow::{Context, Result};
use serde::Deserialize;

use permguard_core::decisions::{
    DecisionStoreSection, DecisionsSection, IncludeSection, LogDestination,
};
use permguard_core::mirrors::{MirrorSource, MirrorsSection};
use permguard_core::storage::StorageSection;
use permguard_core::{Config, TlsSettings, TlsVersion, Value};

use super::{PlaneAddresses, PlaneService};

/// Runtime setting key for the comma-separated list of planes to host in this process.
pub const SETTING_RUNTIME_PLANES: &str = "PERMGUARD_RUNTIME_PLANES";

/// Runtime setting keys for control-plane public addresses.
/// Where this plane tells the world to reach it. See [`SETTING_DATA_HTTP_ADVERTISED_URL`].
pub const SETTING_CONTROL_HTTP_ADVERTISED_URL: &str = "PERMGUARD_CONTROL_HTTP_ADVERTISED_URL";
pub const SETTING_CONTROL_HTTP_ENABLED: &str = "PERMGUARD_CONTROL_HTTP_ENABLED";
pub const SETTING_CONTROL_HTTP_ADDR: &str = "PERMGUARD_CONTROL_HTTP_ADDR";
pub const SETTING_CONTROL_HTTP_TLS_ENABLED: &str = "PERMGUARD_CONTROL_HTTP_TLS_ENABLED";
pub const SETTING_CONTROL_HTTP_TLS_CERT: &str = "PERMGUARD_CONTROL_HTTP_TLS_CERT";
pub const SETTING_CONTROL_HTTP_TLS_KEY: &str = "PERMGUARD_CONTROL_HTTP_TLS_KEY";
pub const SETTING_CONTROL_HTTP_TLS_CLIENT_CA: &str = "PERMGUARD_CONTROL_HTTP_TLS_CLIENT_CA";
pub const SETTING_CONTROL_HTTP_TLS_CRL: &str = "PERMGUARD_CONTROL_HTTP_TLS_CRL";
pub const SETTING_CONTROL_HTTP_TLS_MIN_VERSION: &str = "PERMGUARD_CONTROL_HTTP_TLS_MIN_VERSION";
pub const SETTING_CONTROL_HTTP_TLS_ALLOW: &str = "PERMGUARD_CONTROL_HTTP_TLS_ALLOW";
pub const SETTING_CONTROL_GRPC_ENABLED: &str = "PERMGUARD_CONTROL_GRPC_ENABLED";
pub const SETTING_CONTROL_GRPC_ADDR: &str = "PERMGUARD_CONTROL_GRPC_ADDR";
pub const SETTING_CONTROL_GRPC_TLS_ENABLED: &str = "PERMGUARD_CONTROL_GRPC_TLS_ENABLED";
pub const SETTING_CONTROL_GRPC_TLS_CERT: &str = "PERMGUARD_CONTROL_GRPC_TLS_CERT";
pub const SETTING_CONTROL_GRPC_TLS_KEY: &str = "PERMGUARD_CONTROL_GRPC_TLS_KEY";
pub const SETTING_CONTROL_GRPC_TLS_CLIENT_CA: &str = "PERMGUARD_CONTROL_GRPC_TLS_CLIENT_CA";
pub const SETTING_CONTROL_GRPC_TLS_CRL: &str = "PERMGUARD_CONTROL_GRPC_TLS_CRL";
pub const SETTING_CONTROL_GRPC_TLS_MIN_VERSION: &str = "PERMGUARD_CONTROL_GRPC_TLS_MIN_VERSION";
pub const SETTING_CONTROL_GRPC_TLS_ALLOW: &str = "PERMGUARD_CONTROL_GRPC_TLS_ALLOW";

/// Runtime setting keys for data-plane public addresses.
/// Where this plane tells the world to reach it, when that is not where it binds.
///
/// A listener binds an address; a discovery document publishes one; behind a Service, an Ingress
/// or a load balancer they are not the same string. `0.0.0.0` in particular is a *listening*
/// address and nothing can dial it — a document naming it sends every client that follows a link
/// nowhere.
pub const SETTING_DATA_HTTP_ADVERTISED_URL: &str = "PERMGUARD_DATA_HTTP_ADVERTISED_URL";
pub const SETTING_DATA_HTTP_ENABLED: &str = "PERMGUARD_DATA_HTTP_ENABLED";
pub const SETTING_DATA_HTTP_ADDR: &str = "PERMGUARD_DATA_HTTP_ADDR";
pub const SETTING_DATA_HTTP_TLS_ENABLED: &str = "PERMGUARD_DATA_HTTP_TLS_ENABLED";
pub const SETTING_DATA_HTTP_TLS_CERT: &str = "PERMGUARD_DATA_HTTP_TLS_CERT";
pub const SETTING_DATA_HTTP_TLS_KEY: &str = "PERMGUARD_DATA_HTTP_TLS_KEY";
pub const SETTING_DATA_HTTP_TLS_CLIENT_CA: &str = "PERMGUARD_DATA_HTTP_TLS_CLIENT_CA";
pub const SETTING_DATA_HTTP_TLS_CRL: &str = "PERMGUARD_DATA_HTTP_TLS_CRL";
pub const SETTING_DATA_HTTP_TLS_MIN_VERSION: &str = "PERMGUARD_DATA_HTTP_TLS_MIN_VERSION";
pub const SETTING_DATA_HTTP_TLS_ALLOW: &str = "PERMGUARD_DATA_HTTP_TLS_ALLOW";
pub const SETTING_DATA_GRPC_ENABLED: &str = "PERMGUARD_DATA_GRPC_ENABLED";
pub const SETTING_DATA_GRPC_ADDR: &str = "PERMGUARD_DATA_GRPC_ADDR";
pub const SETTING_DATA_GRPC_TLS_ENABLED: &str = "PERMGUARD_DATA_GRPC_TLS_ENABLED";
pub const SETTING_DATA_GRPC_TLS_CERT: &str = "PERMGUARD_DATA_GRPC_TLS_CERT";
pub const SETTING_DATA_GRPC_TLS_KEY: &str = "PERMGUARD_DATA_GRPC_TLS_KEY";
pub const SETTING_DATA_GRPC_TLS_CLIENT_CA: &str = "PERMGUARD_DATA_GRPC_TLS_CLIENT_CA";
pub const SETTING_DATA_GRPC_TLS_CRL: &str = "PERMGUARD_DATA_GRPC_TLS_CRL";
pub const SETTING_DATA_GRPC_TLS_MIN_VERSION: &str = "PERMGUARD_DATA_GRPC_TLS_MIN_VERSION";
pub const SETTING_DATA_GRPC_TLS_ALLOW: &str = "PERMGUARD_DATA_GRPC_TLS_ALLOW";

#[derive(Debug, Clone, Copy)]
pub struct PlaneSettingKeys {
    /// Which plane these keys belong to, so a block that only one plane can
    /// answer for — `mirrors`, `decisions`, `storage` — is refused on the other by name.
    id: &'static str,
    http: PlaneEndpointKeys,
    grpc: PlaneEndpointKeys,
    /// The plane's signing ring: whether it is composed, and where it lives.
    keys_enabled: &'static str,
    keys_directory: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneEndpointKeys {
    pub(crate) enabled: &'static str,
    pub(crate) addr: &'static str,
    /// Where this endpoint is advertised, when it differs from where it binds. Empty for gRPC:
    /// discovery documents publish HTTP addresses, and there is nothing to advertise for a
    /// surface no document links to.
    pub(crate) advertised_url: Option<&'static str>,
    pub(crate) tls: PlaneTlsKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneTlsKeys {
    pub(crate) enabled: &'static str,
    pub(crate) cert: &'static str,
    pub(crate) key: &'static str,
    pub(crate) client_ca: &'static str,
    pub(crate) crl: &'static str,
    pub(crate) allow: &'static str,
    pub(crate) min_version: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PlaneSection {
    pub(crate) name: &'static str,
    pub(crate) keys: PlaneSettingKeys,
}

impl PlaneSettingKeys {
    pub const CONTROL: Self = Self {
        id: "control",
        http: PlaneEndpointKeys {
            enabled: SETTING_CONTROL_HTTP_ENABLED,
            addr: SETTING_CONTROL_HTTP_ADDR,
            advertised_url: Some(SETTING_CONTROL_HTTP_ADVERTISED_URL),
            tls: PlaneTlsKeys {
                enabled: SETTING_CONTROL_HTTP_TLS_ENABLED,
                cert: SETTING_CONTROL_HTTP_TLS_CERT,
                key: SETTING_CONTROL_HTTP_TLS_KEY,
                client_ca: SETTING_CONTROL_HTTP_TLS_CLIENT_CA,
                crl: SETTING_CONTROL_HTTP_TLS_CRL,
                allow: SETTING_CONTROL_HTTP_TLS_ALLOW,
                min_version: SETTING_CONTROL_HTTP_TLS_MIN_VERSION,
            },
        },
        grpc: PlaneEndpointKeys {
            enabled: SETTING_CONTROL_GRPC_ENABLED,
            addr: SETTING_CONTROL_GRPC_ADDR,
            advertised_url: None,
            tls: PlaneTlsKeys {
                enabled: SETTING_CONTROL_GRPC_TLS_ENABLED,
                cert: SETTING_CONTROL_GRPC_TLS_CERT,
                key: SETTING_CONTROL_GRPC_TLS_KEY,
                client_ca: SETTING_CONTROL_GRPC_TLS_CLIENT_CA,
                crl: SETTING_CONTROL_GRPC_TLS_CRL,
                allow: SETTING_CONTROL_GRPC_TLS_ALLOW,
                min_version: SETTING_CONTROL_GRPC_TLS_MIN_VERSION,
            },
        },
        keys_enabled: permguard_core::config::SETTING_CONTROL_KEYS_ENABLED,
        keys_directory: permguard_core::config::SETTING_CONTROL_KEYS_DIRECTORY,
    };

    pub const DATA: Self = Self {
        id: "data",
        http: PlaneEndpointKeys {
            enabled: SETTING_DATA_HTTP_ENABLED,
            addr: SETTING_DATA_HTTP_ADDR,
            advertised_url: Some(SETTING_DATA_HTTP_ADVERTISED_URL),
            tls: PlaneTlsKeys {
                enabled: SETTING_DATA_HTTP_TLS_ENABLED,
                cert: SETTING_DATA_HTTP_TLS_CERT,
                key: SETTING_DATA_HTTP_TLS_KEY,
                client_ca: SETTING_DATA_HTTP_TLS_CLIENT_CA,
                crl: SETTING_DATA_HTTP_TLS_CRL,
                allow: SETTING_DATA_HTTP_TLS_ALLOW,
                min_version: SETTING_DATA_HTTP_TLS_MIN_VERSION,
            },
        },
        grpc: PlaneEndpointKeys {
            enabled: SETTING_DATA_GRPC_ENABLED,
            addr: SETTING_DATA_GRPC_ADDR,
            advertised_url: None,
            tls: PlaneTlsKeys {
                enabled: SETTING_DATA_GRPC_TLS_ENABLED,
                cert: SETTING_DATA_GRPC_TLS_CERT,
                key: SETTING_DATA_GRPC_TLS_KEY,
                client_ca: SETTING_DATA_GRPC_TLS_CLIENT_CA,
                crl: SETTING_DATA_GRPC_TLS_CRL,
                allow: SETTING_DATA_GRPC_TLS_ALLOW,
                min_version: SETTING_DATA_GRPC_TLS_MIN_VERSION,
            },
        },
        keys_enabled: permguard_core::config::SETTING_DATA_KEYS_ENABLED,
        keys_directory: permguard_core::config::SETTING_DATA_KEYS_DIRECTORY,
    };

    pub(crate) const fn addresses(self) -> PlaneAddresses {
        PlaneAddresses::settings(self.http, self.grpc)
    }

    pub(crate) const fn settings(self) -> [&'static str; 21] {
        let http = self.http.settings();
        let grpc = self.grpc.settings();

        [
            http[0],
            http[1],
            http[2],
            http[3],
            http[4],
            http[5],
            http[6],
            http[7],
            http[8],
            grpc[0],
            grpc[1],
            grpc[2],
            grpc[3],
            grpc[4],
            grpc[5],
            grpc[6],
            grpc[7],
            grpc[8],
            self.keys_enabled,
            self.keys_directory,
            // HTTP only: a discovery document publishes HTTP addresses.
            match self.http.advertised_url {
                Some(key) => key,
                None => self.http.addr,
            },
        ]
    }
}

impl PlaneEndpointKeys {
    pub(crate) const fn settings(self) -> [&'static str; 9] {
        [
            self.enabled,
            self.addr,
            self.tls.enabled,
            self.tls.cert,
            self.tls.key,
            self.tls.client_ca,
            self.tls.crl,
            self.tls.allow,
            self.tls.min_version,
        ]
    }
}

/// Returns the default setting-backed addresses for a known plane id.
pub const fn addresses_for_plane(id: &str) -> Option<PlaneAddresses> {
    match id.as_bytes() {
        b"control" => Some(PlaneSettingKeys::CONTROL.addresses()),
        b"data" => Some(PlaneSettingKeys::DATA.addresses()),
        _ => None,
    }
}

pub(crate) fn declared_settings_for(planes: &[PlaneService]) -> Vec<&'static str> {
    let mut settings = vec![SETTING_RUNTIME_PLANES];

    for section in section_settings_for(planes) {
        settings.extend(section.keys.settings());
    }

    settings
}

pub(crate) fn section_settings_for(planes: &[PlaneService]) -> Vec<PlaneSection> {
    let mut sections = Vec::new();

    for plane in planes {
        match plane.module.id() {
            "control"
                if !sections
                    .iter()
                    .any(|section: &PlaneSection| section.name == "controlPlane") =>
            {
                sections.push(PlaneSection {
                    name: "controlPlane",
                    keys: PlaneSettingKeys::CONTROL,
                });
            }
            "data"
                if !sections
                    .iter()
                    .any(|section: &PlaneSection| section.name == "dataPlane") =>
            {
                sections.push(PlaneSection {
                    name: "dataPlane",
                    keys: PlaneSettingKeys::DATA,
                });
            }
            _ => {}
        }
    }

    sections
}

pub(crate) fn runtime_settings(value: &Value) -> Result<Vec<(String, String)>> {
    let section: RuntimeSection =
        serde_norway::from_value(value.clone()).context("parsing the runtime section")?;

    Ok(section
        .planes
        .map(|planes| {
            vec![(
                SETTING_RUNTIME_PLANES.to_owned(),
                planes.into_setting_value(),
            )]
        })
        .unwrap_or_default())
}

pub fn plane_settings(value: &Value, keys: PlaneSettingKeys) -> Result<Vec<(String, String)>> {
    let section: PlaneSectionConfig =
        serde_norway::from_value(value.clone()).context("parsing a plane section")?;
    let mut settings = Vec::new();

    if let Some(public) = section.public {
        push_endpoint_settings(&mut settings, keys.http, public.http.as_ref());
        push_endpoint_settings(&mut settings, keys.grpc, public.grpc.as_ref());

        if matches!(public.http, Some(EndpointSection::Addr(_)))
            && public.grpc.is_none()
            && let Some(addr) = public.http.as_ref().and_then(EndpointSection::addr)
        {
            settings.push((keys.grpc.addr.to_owned(), addr));
        }
    }

    // Mirroring is the data plane's own business: it is the plane that answers
    // decisions that needs the policies, and a control plane has nothing to
    // mirror. Saying so under the wrong plane is a mistake worth a refusal
    // rather than a block that is silently never read.
    if let Some(mirrors) = &section.mirrors {
        if keys.id != "data" {
            anyhow::bail!(
                "`mirrors` belongs to the data plane: mirroring is the data plane's own business, \
                 and a control plane has nothing to mirror"
            );
        }
        settings.extend(mirrors.settings());
    }

    // `decisions` is the one block both planes declare, because it is one
    // subject seen from its two ends: under `dataPlane` it is where decisions
    // are made and recorded, under `controlPlane` where they are received and
    // kept. Each plane parses its own shape, so a member that belongs to the
    // other is refused by name rather than silently ignored.
    if let Some(decisions) = &section.decisions {
        if keys.id == "data" {
            let section: DecisionsSection = serde_norway::from_value(decisions.clone())
                .context("parsing `dataPlane.decisions`")?;
            settings.extend(section.settings());
        } else {
            let section: DecisionStoreSection = serde_norway::from_value(decisions.clone())
                .context("parsing `controlPlane.decisions`")?;
            settings.extend(section.settings());
        }
    }

    if let Some(storage) = &section.storage {
        if keys.id != "control" {
            anyhow::bail!(
                "`storage` belongs to the control plane: it maintains the ledgers, and only the \
                 control plane owns those"
            );
        }
        settings.extend(storage.settings());
    }

    if let Some(signing) = section.keys {
        if let Some(enabled) = signing.enabled {
            settings.push((keys.keys_enabled.to_owned(), enabled));
        }
        if let Some(directory) = signing.directory {
            settings.push((keys.keys_directory.to_owned(), directory));
        }
    }

    Ok(settings)
}

fn push_endpoint_settings(
    settings: &mut Vec<(String, String)>,
    keys: PlaneEndpointKeys,
    endpoint: Option<&EndpointSection>,
) {
    let Some(endpoint) = endpoint else {
        return;
    };

    if let Some(enabled) = endpoint.enabled() {
        settings.push((keys.enabled.to_owned(), enabled));
    }

    if let Some(addr) = endpoint.addr() {
        settings.push((keys.addr.to_owned(), addr));
    }

    if let (Some(key), Some(url)) = (keys.advertised_url, endpoint.advertised_url()) {
        settings.push(((*key).to_owned(), url));
    }

    if let Some(tls) = endpoint.tls() {
        push_tls_settings(settings, keys.tls, tls);
    }
}

fn push_tls_settings(settings: &mut Vec<(String, String)>, keys: PlaneTlsKeys, tls: &TlsSection) {
    if let Some(enabled) = &tls.enabled {
        settings.push((keys.enabled.to_owned(), enabled.as_setting_value()));
    }

    // A list is one setting whose value has lines in it: `dn:` entries contain commas, so the
    // newline is the only safe separator.
    let allow = tls
        .allow
        .as_ref()
        .filter(|entries| !entries.is_empty())
        .map(|entries| entries.join("\n"));

    for (key, value) in [
        (keys.cert, tls.cert.as_ref()),
        (keys.key, tls.key.as_ref()),
        (keys.client_ca, tls.client_ca.as_ref()),
        (keys.crl, tls.crl.as_ref()),
        (keys.allow, allow.as_ref()),
        (keys.min_version, tls.min_version.as_ref()),
    ] {
        if let Some(value) = value {
            settings.push((key.to_owned(), value.clone()));
        }
    }
}

/// The servers the data plane follows, out of its own section.
///
/// Structured, not flat: a list of servers with their patterns has no sensible
/// single-variable form, so it arrives beside the layered settings rather than
/// through them.
pub fn mirror_sources(value: &Value) -> Result<Vec<MirrorSource>> {
    let section: PlaneSectionConfig =
        serde_norway::from_value(value.clone()).context("parsing a plane section")?;

    Ok(section
        .mirrors
        .as_ref()
        .map(MirrorsSection::sources)
        .unwrap_or_default())
}

/// Where this plane ships decision records, and what it may record of a caller.
///
/// Structured, so it comes from the file rather than the layered pipeline: a
/// server with its own trust material has no single-variable form, and an
/// allow-list of attribute names has none either.
pub fn log_destination(value: &Value) -> Result<(Option<LogDestination>, IncludeSection)> {
    let section: PlaneSectionConfig =
        serde_norway::from_value(value.clone()).context("parsing a plane section")?;
    let Some(decisions) = section.decisions.as_ref() else {
        return Ok((None, IncludeSection::default()));
    };
    let decisions: DecisionsSection =
        serde_norway::from_value(decisions.clone()).context("parsing `dataPlane.decisions`")?;

    Ok((decisions.destination(), decisions.include().clone()))
}

/// The producers a control plane accepts decision records from.
///
/// Structured, so it comes from the file only: a list of key-set paths has no
/// sensible single-variable form.
pub fn producer_keys(value: &Value) -> Result<Vec<String>> {
    let section: PlaneSectionConfig =
        serde_norway::from_value(value.clone()).context("parsing a plane section")?;
    let Some(decisions) = section.decisions.as_ref() else {
        return Ok(Vec::new());
    };
    let decisions: DecisionStoreSection =
        serde_norway::from_value(decisions.clone()).context("parsing `controlPlane.decisions`")?;

    Ok(decisions.producer_keys().to_vec())
}

pub(crate) fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => anyhow::bail!("`{other}` is not a boolean: expected true or false"),
    }
}

pub(crate) fn tls_for(config: &Config, keys: PlaneTlsKeys) -> Result<Option<TlsSettings>> {
    let has_setting = [
        keys.enabled,
        keys.cert,
        keys.key,
        keys.client_ca,
        keys.crl,
        keys.allow,
        keys.min_version,
    ]
    .into_iter()
    .any(|key| config.setting(key).is_some());

    if !has_setting {
        return Ok(config.public_tls());
    }

    if let Some(enabled) = config.setting(keys.enabled)
        && !parse_bool(enabled).with_context(|| format!("reading {}", keys.enabled))?
    {
        return Ok(None);
    }

    let cert = config.setting(keys.cert);
    let key = config.setting(keys.key);

    let mut tls = match (cert, key) {
        (Some(cert), Some(key)) => TlsSettings::new(cert, key),
        (None, None) => {
            anyhow::bail!(
                "{} is enabled but no certificate and key are configured",
                keys.enabled
            );
        }
        (Some(_), None) => anyhow::bail!("{} is set but {} is not", keys.cert, keys.key),
        (None, Some(_)) => anyhow::bail!("{} is set but {} is not", keys.key, keys.cert),
    };

    if let Some(client_ca) = config.setting(keys.client_ca) {
        tls = tls.with_client_ca(client_ca);
    }

    if let Some(crl) = config.setting(keys.crl) {
        tls = tls.with_crl(crl);
    }

    if let Some(value) = config.setting(keys.allow) {
        let allow: Vec<permguard_core::AllowedPeer> = value
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::parse)
            .collect::<Result<_>>()
            .with_context(|| format!("reading {}", keys.allow))?;

        if !allow.is_empty() && tls.client_ca().is_none() {
            anyhow::bail!(
                "{} names peers this endpoint answers but {} demands no client certificate: an \
                 allow list with no identity to check is a list nothing can satisfy",
                keys.allow,
                keys.client_ca
            );
        }

        tls = tls.with_allow(allow);
    }

    if let Some(min_version) = config.setting(keys.min_version) {
        tls = tls.with_min_version(
            min_version
                .parse::<TlsVersion>()
                .with_context(|| format!("reading {}", keys.min_version))?,
        );
    }

    let tls = tls.resolved_in(config.working_dir());
    let tls = if config.tls_reload() {
        tls.with_reload(config.tls_reload_interval())
    } else {
        tls.without_reload()
    };

    Ok(Some(tls))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSection {
    #[serde(default)]
    planes: Option<PlaneList>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PlaneList {
    List(Vec<String>),
    Text(String),
}

impl PlaneList {
    fn into_setting_value(self) -> String {
        match self {
            Self::List(planes) => planes.join(","),
            Self::Text(value) => value,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlaneSectionConfig {
    #[serde(default)]
    public: Option<PlanePublicSection>,
    /// What this plane mirrors, and how often. Data plane only — see
    /// [`plane_settings`].
    #[serde(default)]
    mirrors: Option<MirrorsSection>,
    /// The decision log, from whichever end this plane is: what the decision
    /// path may spend and what it records (`dataPlane`), or where the records
    /// are received and kept (`controlPlane`). Held untyped so each plane
    /// parses its own shape — see [`plane_settings`].
    #[serde(default)]
    decisions: Option<Value>,
    /// The store's own maintenance — reclaiming what nothing references.
    /// Control plane only: it is the plane that owns the ledgers.
    #[serde(default)]
    storage: Option<StorageSection>,
    /// The plane's signing ring — the ring that signs what this plane answers, never the
    /// operations ring that seals the audit trail.
    #[serde(default)]
    keys: Option<PlaneKeysSection>,
}

/// A plane's signing-ring block: whether the ring is composed, and where it lives. The lifecycle
/// (publish-ahead, rotation, retention) follows `operations.keys` — one discipline for every ring.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaneKeysSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    directory: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanePublicSection {
    #[serde(default)]
    http: Option<EndpointSection>,
    #[serde(default)]
    grpc: Option<EndpointSection>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
// Boxed because the two arms are lopsided — a bare address is a string, the settings form now
// carries an advertised URL on top of the TLS block — and this is deserialized once at startup,
// where an indirection costs nothing and the size of the enum matters even less.
enum EndpointSection {
    Addr(String),
    Settings(Box<EndpointSettings>),
}

impl EndpointSection {
    fn enabled(&self) -> Option<String> {
        match self {
            Self::Addr(_) => None,
            Self::Settings(settings) => settings
                .enabled
                .as_ref()
                .map(EndpointValue::as_setting_value),
        }
    }

    fn addr(&self) -> Option<String> {
        match self {
            Self::Addr(addr) => Some(addr.clone()),
            Self::Settings(settings) => settings.addr.clone(),
        }
    }

    fn tls(&self) -> Option<&TlsSection> {
        match self {
            Self::Addr(_) => None,
            Self::Settings(settings) => settings.tls.as_ref(),
        }
    }

    /// Where this endpoint is advertised, when it differs from where it binds.
    fn advertised_url(&self) -> Option<String> {
        match self {
            Self::Addr(_) => None,
            Self::Settings(settings) => settings.advertised_url.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSettings {
    #[serde(default)]
    enabled: Option<EndpointValue>,
    #[serde(default)]
    addr: Option<String>,
    /// What the discovery documents publish, when that is not `addr`. A pod binds `0.0.0.0` and
    /// is reached at its Service; the two are different strings and both have to be stated.
    #[serde(default)]
    advertised_url: Option<String>,
    #[serde(default)]
    tls: Option<TlsSection>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsSection {
    #[serde(default)]
    enabled: Option<EndpointValue>,
    #[serde(default)]
    cert: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    client_ca: Option<String>,
    #[serde(default)]
    crl: Option<String>,
    /// Who, of everybody `client_ca` signed, this endpoint answers: `cn:`, `dn:` or `sha256:`
    /// entries. Empty means the handshake is the whole decision.
    #[serde(default)]
    allow: Option<Vec<String>>,
    #[serde(default)]
    min_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EndpointValue {
    Bool(bool),
    Text(String),
}

impl EndpointValue {
    fn as_setting_value(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Text(value) => value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn value(text: &str) -> Value {
        serde_norway::from_str(text).expect("the YAML parses")
    }

    #[test]
    fn runtime_section_names_enabled_planes() {
        assert_eq!(
            runtime_settings(&value("planes: [control, data]")).expect("runtime parses"),
            vec![(SETTING_RUNTIME_PLANES.to_owned(), "control,data".to_owned())]
        );
    }

    #[test]
    fn plane_section_maps_public_protocols_to_declared_settings() {
        assert_eq!(
            plane_settings(
                &value(
                    "public:\n  http:\n    enabled: true\n    addr: 127.0.0.1:7556\n  grpc:\n    enabled: false\n"
                ),
                PlaneSettingKeys::CONTROL,
            )
            .expect("plane section parses"),
            vec![
                (SETTING_CONTROL_HTTP_ENABLED.to_owned(), "true".to_owned()),
                (
                    SETTING_CONTROL_HTTP_ADDR.to_owned(),
                    "127.0.0.1:7556".to_owned()
                ),
                (SETTING_CONTROL_GRPC_ENABLED.to_owned(), "false".to_owned()),
            ]
        );
    }

    #[test]
    fn a_bare_http_address_also_defaults_grpc_to_the_same_address() {
        assert_eq!(
            plane_settings(
                &value("public:\n  http: 127.0.0.1:7656\n"),
                PlaneSettingKeys::DATA,
            )
            .expect("plane section parses"),
            vec![
                (
                    SETTING_DATA_HTTP_ADDR.to_owned(),
                    "127.0.0.1:7656".to_owned()
                ),
                (
                    SETTING_DATA_GRPC_ADDR.to_owned(),
                    "127.0.0.1:7656".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn the_data_plane_mirrors_block_becomes_settings_and_the_control_plane_refuses_it() {
        let block = "mirrors:\n  enabled: \"true\"\n  interval: \"15s\"\n  servers:\n    - url: \"http://127.0.0.1:7556\"\n";

        assert_eq!(
            plane_settings(&value(block), PlaneSettingKeys::DATA).expect("the data plane mirrors"),
            vec![
                (
                    permguard_core::config::SETTING_MIRRORS_ENABLED.to_owned(),
                    "true".to_owned()
                ),
                (
                    permguard_core::config::SETTING_MIRRORS_INTERVAL.to_owned(),
                    "15s".to_owned()
                ),
            ]
        );

        let refused = plane_settings(&value(block), PlaneSettingKeys::CONTROL)
            .expect_err("a control plane has nothing to mirror")
            .to_string();
        assert!(refused.contains("belongs to the data plane"), "{refused}");
    }

    #[test]
    fn the_control_plane_storage_block_becomes_settings_and_the_data_plane_refuses_it() {
        let block = "storage:\n  gc:\n    enabled: \"true\"\n    grace: 24h\n";

        assert_eq!(
            plane_settings(&value(block), PlaneSettingKeys::CONTROL)
                .expect("the control plane maintains its ledgers"),
            vec![
                (
                    permguard_core::config::SETTING_GC_ENABLED.to_owned(),
                    "true".to_owned()
                ),
                (
                    permguard_core::config::SETTING_GC_GRACE.to_owned(),
                    "24h".to_owned()
                ),
            ]
        );

        let refused = plane_settings(&value(block), PlaneSettingKeys::DATA)
            .expect_err("a data plane owns no ledgers")
            .to_string();
        assert!(
            refused.contains("belongs to the control plane"),
            "{refused}"
        );
    }

    #[test]
    fn the_servers_arrive_as_structured_configuration_with_their_trust_material() {
        let sources = mirror_sources(&value(
            "mirrors:\n  servers:\n    - url: \"grpcs://control:7557\"\n      zones: [\"acme-.*\"]\n      tls:\n        ca_file: tls/ca.pem\n",
        ))
        .expect("the servers parse");

        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url, "grpcs://control:7557");
        assert_eq!(sources[0].zones, vec!["acme-.*".to_owned()]);
        assert_eq!(sources[0].tls.ca_file.as_deref(), Some("tls/ca.pem"));

        // A section with no `mirrors` block follows nothing, and says so plainly.
        assert!(
            mirror_sources(&value("public:\n  http: 127.0.0.1:7656\n"))
                .expect("a plane may mirror nothing")
                .is_empty()
        );
    }

    #[test]
    fn endpoint_tls_maps_to_protocol_specific_settings() {
        assert_eq!(
            plane_settings(
                &value(
                    "public:\n  grpc:\n    addr: 127.0.0.1:7557\n    tls:\n      enabled: true\n      cert: tls/grpc.pem\n      key: tls/grpc.key\n      client_ca: tls/clients.pem\n      crl: tls/clients.crl\n      min_version: '1.3'\n"
                ),
                PlaneSettingKeys::CONTROL,
            )
            .expect("plane section parses"),
            vec![
                (
                    SETTING_CONTROL_GRPC_ADDR.to_owned(),
                    "127.0.0.1:7557".to_owned()
                ),
                (SETTING_CONTROL_GRPC_TLS_ENABLED.to_owned(), "true".to_owned()),
                (
                    SETTING_CONTROL_GRPC_TLS_CERT.to_owned(),
                    "tls/grpc.pem".to_owned()
                ),
                (
                    SETTING_CONTROL_GRPC_TLS_KEY.to_owned(),
                    "tls/grpc.key".to_owned()
                ),
                (
                    SETTING_CONTROL_GRPC_TLS_CLIENT_CA.to_owned(),
                    "tls/clients.pem".to_owned()
                ),
                (
                    SETTING_CONTROL_GRPC_TLS_CRL.to_owned(),
                    "tls/clients.crl".to_owned()
                ),
                (
                    SETTING_CONTROL_GRPC_TLS_MIN_VERSION.to_owned(),
                    "1.3".to_owned()
                ),
            ]
        );
    }
}
