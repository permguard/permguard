// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the well-known documents say: which planes this process actually
//! serves, and where each one describes itself.
//!
//! Everything here resolves from the same configuration the listeners bind
//! with — one source of truth, so a document and a socket can never
//! disagree about what is exposed.

use permguard_core::Config;

use super::settings::{SETTING_RUNTIME_PLANES, addresses_for_plane};

/// One plane's entry in the server-configuration document.
///
/// The document composes from what is actually loaded: a plane that is not
/// selected by the runtime, or has no HTTP address, contributes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPlane {
    /// The plane's public name — `control-plane` or `data-plane`, the same
    /// words the logs and metrics use, so a bare ambiguous `control` never
    /// names a plane on a wire.
    pub id: &'static str,
    /// The plane's HTTP base URL, scheme included — `https` when the plane's
    /// HTTP surface resolved TLS, `http` otherwise.
    pub http_base: String,
}

/// Which plane, as a value rather than a string.
///
/// # Why this is not a `&str`
///
/// Four places matched on a plane id and wrote `_ => data-plane`, so every typo, every future
/// plane and every empty string was silently the data plane — and the answer was a plausible
/// document about the wrong process. A closed set makes the wrong id unrepresentable, and
/// [`PlaneId::parse`] makes the boundary where a string becomes one explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneId {
    Control,
    Data,
}

impl PlaneId {
    /// The id as configuration and modules spell it: `control`, `data`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
        }
    }

    /// The name a document and a log line use, which is not the same word.
    pub const fn public_name(self) -> &'static str {
        match self {
            Self::Control => "control-plane",
            Self::Data => "data-plane",
        }
    }

    /// Where this plane is told to advertise itself.
    pub const fn advertised_url_setting(self) -> &'static str {
        match self {
            Self::Control => crate::plane::SETTING_CONTROL_HTTP_ADVERTISED_URL,
            Self::Data => crate::plane::SETTING_DATA_HTTP_ADVERTISED_URL,
        }
    }

    /// The plane a module id names, or `None` for a name this build does not host.
    pub fn parse(id: &str) -> Option<Self> {
        match id {
            "control" => Some(Self::Control),
            "data" => Some(Self::Data),
            _ => None,
        }
    }
}

/// The planes this process serves over HTTP, and the address each publishes.
///
/// # Where it binds and where it is reached are two different things
///
/// A listener binds an address; a document publishes one. Behind a Kubernetes Service, an Ingress
/// or a load balancer they are not the same string — and `0.0.0.0` is not a string at all as far
/// as a client is concerned: it is how a process says *every interface*, and nothing can dial it.
/// A document naming it sends every client that follows a link nowhere, which is worse than
/// publishing no link, because the client has no way to tell.
///
/// So a plane may be told what to advertise, and that is what it advertises. Absent that, the
/// address it binds is the best available guess and is used — correct for a process reachable at
/// the address it listens on, which is every local run and plenty of deployments.
///
/// The **scheme** comes from that endpoint's own TLS settings, never from a global one: a plane
/// serving HTTPS while its document says `http://` is a document that cannot be followed either.
pub fn discovered_planes(config: &Config) -> Vec<DiscoveredPlane> {
    const KNOWN: [&str; 2] = ["control", "data"];

    let mut planes = Vec::new();
    for id in KNOWN {
        if !plane_enabled(config, id) {
            continue;
        }
        let Some(addresses) = addresses_for_plane(id) else {
            continue;
        };
        let Ok(Some(addr)) = addresses.http.resolve(config) else {
            continue;
        };
        let scheme = match addresses.http_tls.resolve(config) {
            Ok(Some(_)) => "https",
            _ => "http",
        };
        let Some(plane) = PlaneId::parse(id) else {
            continue;
        };
        let advertised =
            advertised_url(config, plane).unwrap_or_else(|| format!("{scheme}://{addr}"));

        planes.push(DiscoveredPlane {
            id: plane.public_name(),
            http_base: advertised,
        });
    }
    planes
}

/// The planes this process serves over gRPC alone: enabled, a gRPC address, no HTTP one.
///
/// The endpoint's scheme follows its own TLS settings, like every published address here.
fn grpc_only_planes(config: &Config) -> Vec<(&'static str, String)> {
    const KNOWN: [&str; 2] = ["control", "data"];

    let mut planes = Vec::new();
    for id in KNOWN {
        if !plane_enabled(config, id) {
            continue;
        }
        let Some(addresses) = addresses_for_plane(id) else {
            continue;
        };
        if matches!(addresses.http.resolve(config), Ok(Some(_))) {
            continue;
        }
        let Ok(Some(addr)) = addresses.grpc.resolve(config) else {
            continue;
        };
        let scheme = match addresses.grpc_tls.resolve(config) {
            Ok(Some(_)) => "https",
            _ => "http",
        };
        let Some(plane) = PlaneId::parse(id) else {
            continue;
        };

        planes.push((plane.public_name(), format!("{scheme}://{addr}")));
    }

    planes
}

/// What this plane was told to advertise, when it was told anything.
///
/// A trailing slash is trimmed: every caller of this appends a path, and `…//v1/zones` is not the
/// address anybody meant.
fn advertised_url(config: &Config, plane: PlaneId) -> Option<String> {
    config
        .setting(plane.advertised_url_setting())
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(|url| url.trim_end_matches('/').to_owned())
}

/// Whether an address is one a client could dial, or only one a process can bind.
///
/// `0.0.0.0` and `[::]` mean *every interface* to a listener and nothing at all to a caller. A
/// deployment that binds one without saying what to advertise publishes links nobody can follow,
/// and the only moment anybody can be told is startup.
pub fn is_wildcard_address(addr: &str) -> bool {
    let host = if let Some(rest) = addr.strip_prefix('[') {
        // `[::]:7443` — bracketed, so the host ends at the bracket and the colons inside it are
        // the address's own.
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else {
        match addr.rsplit_once(':') {
            // A port is digits. Anything else after the last colon means the colons belong to a
            // bare IPv6 address, which is the whole string.
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                // …unless the part before it still holds colons, in which case this is bare IPv6
                // too and the "port" is one of its groups.
                if host.contains(':') { addr } else { host }
            }
            _ => addr,
        }
    };

    matches!(host, "0.0.0.0" | "::" | "" | "[::]")
}

/// The planes whose published address nobody can dial, for the warning at startup.
pub fn unroutable_planes(config: &Config) -> Vec<&'static str> {
    discovered_planes(config)
        .into_iter()
        .filter(|plane| {
            plane
                .http_base
                .split_once("://")
                .is_some_and(|(_, rest)| is_wildcard_address(rest))
        })
        .map(|plane| plane.id)
        .collect()
}

/// The HTTP base URL (`scheme://addr`) the Server Host operations surface answers on.
///
/// What the deployment advertises wins; the bound address is the fallback, with the scheme its
/// own TLS settings imply — exactly the rule the planes follow, because a link that cannot be
/// followed is the same mistake on any surface.
pub fn host_http_base(config: &Config) -> Option<String> {
    if let Some(advertised) = config.telemetry_advertised_url() {
        return Some(advertised.to_owned());
    }

    let addr = config.telemetry_addr()?;
    let scheme = match config.telemetry_tls() {
        Some(_) => "https",
        None => "http",
    };

    Some(format!("{scheme}://{addr}"))
}

/// The HTTP base URL (`scheme://addr`) one plane answers on, when it is
/// loaded and has an HTTP address — for a plane module composing its own
/// configuration document.
pub fn plane_http_base(config: &Config, plane: PlaneId) -> Option<String> {
    discovered_planes(config)
        .into_iter()
        .find(|held| held.id == plane.public_name())
        .map(|held| held.http_base)
}

/// The `GET /v1/streams` discovery route: every evidence stream this plane declares, enabled or
/// not.
///
/// "Not here" and "here, turned off" are different answers, and a caller deciding where to read
/// needs the second one — a disabled stream is listed with `enabled: false` rather than omitted.
/// The directories stay out: discovery says what a plane serves, never how its volume is laid
/// out.
pub fn streams_route(streams: Vec<permguard_stream::StreamDescriptor>) -> axum::Router {
    use axum::routing::get;

    let document = serde_json::json!({
        "streams": streams
            .iter()
            .map(permguard_stream::StreamDescriptor::public_view)
            .collect::<Vec<_>>(),
    })
    .to_string();

    axum::Router::new().route(
        "/v1/streams",
        get(move || {
            let document = document.clone();
            async move {
                use axum::response::IntoResponse as _;
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    document,
                )
                    .into_response()
            }
        }),
    )
}

/// Where one interface publishes what it offers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InterfaceLink {
    /// The address of that interface's own configuration document.
    pub configuration: String,
}

/// One plane's own configuration document — what that plane's public port answers at
/// `/.well-known/server-configuration`: itself, and nothing else. A client configured to talk to a
/// plane discovers that plane; the cross-plane registry is the process's business and lives on the
/// telemetry surface.
///
/// # Why this is a type and not a `format!`
///
/// It used to be a hand-written JSON string, and a plane that needed to add a field to it had to
/// slice the closing brace off the text and concatenate — which is not composition, it is string
/// surgery on a document, and it carried a fallback that returned the *unextended* document when
/// the surgery did not find what it expected. A discovery document silently missing the half a
/// caller came for is worse than an error: the caller concludes the plane offers nothing there.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlaneConfiguration {
    /// `control-plane` or `data-plane`.
    pub plane: String,
    /// Where this plane's signing keys are published.
    pub jwks_uri: String,
    /// Where this plane lists the evidence streams it declares, enabled or not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streams_endpoint: Option<String>,
    /// The interfaces this plane exposes, each pointing at its own configuration. Absent when a
    /// plane exposes none, rather than present and empty: nothing to follow is not an empty list
    /// of things to follow.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub interfaces: std::collections::BTreeMap<String, InterfaceLink>,
}

/// One plane's own configuration: who it is, and what it signs with.
///
/// Interfaces are added by whoever serves them — the plane knows its own name and keys, and only
/// the module that mounts an interface knows that it did.
pub fn plane_configuration(config: &Config, plane: PlaneId) -> PlaneConfiguration {
    let jwks_uri = discovered_planes(config)
        .into_iter()
        .find(|held| held.id == plane.public_name())
        .map(|held| format!("{}/{}/keys", held.http_base, held.id))
        .unwrap_or_default();

    let streams_endpoint = discovered_planes(config)
        .into_iter()
        .find(|held| held.id == plane.public_name())
        .map(|held| format!("{}/v1/streams", held.http_base));

    PlaneConfiguration {
        plane: plane.public_name().to_owned(),
        jwks_uri,
        streams_endpoint,
        interfaces: std::collections::BTreeMap::new(),
    }
}

/// The process-level registry, as JSON text — what the Server Host operations surface
/// answers at `/.well-known/server-configuration`: every plane this process
/// hosts, each pointing at **its own** configuration document. Pointers,
/// never copies: the plane's well-known is the single source of truth, and
/// the registry only says where the truths are.
pub fn server_configuration_document(config: &Config) -> String {
    let mut planes: std::collections::BTreeMap<String, PlaneLink> = discovered_planes(config)
        .into_iter()
        .map(|plane| {
            (
                plane.id.to_owned(),
                PlaneLink {
                    server_configuration: Some(format!(
                        "{}/.well-known/server-configuration",
                        plane.http_base
                    )),
                    grpc_endpoint: None,
                },
            )
        })
        .collect();

    // A plane serving only gRPC carries no well-known of its own, and omitting it entirely
    // would make the registry claim the process hosts less than it does. It is listed by its
    // endpoint instead, which is everything there is to say about it.
    for (id, endpoint) in grpc_only_planes(config) {
        planes.entry(id.to_owned()).or_insert(PlaneLink {
            server_configuration: None,
            grpc_endpoint: Some(endpoint),
        });
    }

    let registry = ServerConfiguration {
        planes,
        // The Host's own keys, when the deployment publishes any: the one field of this document
        // that is the process's rather than a plane's, because the operations ring seals what the
        // whole process did.
        jwks_uri: config
            .keys_enabled()
            .then(|| host_http_base(config))
            .flatten()
            .map(|base| format!("{base}/server-host/keys")),
    };

    // A document assembled from values cannot be malformed by one of them; a document assembled
    // from string pieces can, and the pieces here are addresses out of configuration. There is no
    // exploitable injection today — the addresses are parsed before they reach this — but a
    // discovery document built with `push_str` is one field away from being one, and the rest of
    // this module stopped doing that.
    //
    // The fallback is unreachable: this is a map of strings to a struct of one string, and
    // `serde_json` fails only on a non-string map key or a non-finite float, neither of which this
    // type can hold. It is written as an empty registry rather than a panic because a telemetry
    // surface answering "no planes" is a worse answer than a process that dies, but only just —
    // and unlike the fallbacks removed elsewhere, nothing here can reach it.
    serde_json::to_string(&registry).unwrap_or_else(|_| String::from("{\"planes\":{}}"))
}

/// Where one plane publishes its own document.
///
/// A plane serving HTTP points at its own well-known; a plane serving only gRPC has no document
/// to point at, so the registry names its gRPC endpoint instead — served but unlisted would be a
/// plane the discovery contract lies about.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlaneLink {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_endpoint: Option<String>,
}

/// The process-level registry: every plane this process hosts, by name, and where the process's
/// own operational keys are published.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerConfiguration {
    pub planes: std::collections::BTreeMap<String, PlaneLink>,
    /// The operations ring as a JWKS, when this deployment publishes keys at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
}

pub(crate) fn plane_enabled(config: &Config, id: &str) -> bool {
    config
        .setting(SETTING_RUNTIME_PLANES)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|plane| !plane.is_empty())
                .any(|plane| plane == id)
        })
        .unwrap_or(true)
}

#[cfg(test)]
mod document_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::plane::build_settings;
    use crate::plane::settings::*;

    /// A configuration shaped like a real deployment: both planes on their
    /// conventional ports, everything else defaulted.
    pub(super) fn config_with(pairs: &[(&str, &str)]) -> Config {
        let mut declared = vec![SETTING_RUNTIME_PLANES];
        declared.extend(PlaneSettingKeys::CONTROL.settings());
        declared.extend(PlaneSettingKeys::DATA.settings());
        Config::from_layers(
            build_settings("0.0.0-test"),
            declared,
            permguard_core::config::Layers {
                file: pairs
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
                ..Default::default()
            },
        )
        .expect("the test configuration builds")
    }

    #[test]
    fn both_planes_are_discovered_with_their_http_bases() {
        let config = config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7443"),
        ]);

        let planes = discovered_planes(&config);
        let ids: Vec<&str> = planes.iter().map(|plane| plane.id).collect();
        assert_eq!(ids, vec!["control-plane", "data-plane"]);
        assert_eq!(planes[0].http_base, "http://127.0.0.1:6443");
    }

    #[test]
    fn a_disabled_plane_never_appears_in_discovery() {
        let config = config_with(&[
            (SETTING_RUNTIME_PLANES, "control"),
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7443"),
        ]);

        let planes = discovered_planes(&config);
        assert_eq!(planes.len(), 1);
        assert_eq!(planes[0].id, "control-plane");
        assert!(plane_http_base(&config, PlaneId::Data).is_none());
    }

    #[test]
    fn the_plane_document_names_itself_and_its_keys() {
        let config = config_with(&[(SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443")]);

        let document = serde_json::to_string(&plane_configuration(&config, PlaneId::Control))
            .expect("the plane configuration serializes");
        assert!(
            document.contains("\"plane\":\"control-plane\""),
            "{document}"
        );
        assert!(
            document.contains("http://127.0.0.1:6443/control-plane/keys"),
            "{document}"
        );
    }

    #[test]
    fn the_registry_points_at_each_plane_and_copies_nothing() {
        let config = config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7443"),
        ]);

        let registry = server_configuration_document(&config);
        assert!(
            registry.contains(
                "\"control-plane\":{\"server_configuration\":\"http://127.0.0.1:6443/.well-known/server-configuration\"}"
            ),
            "{registry}"
        );
        assert!(registry.contains("\"data-plane\""), "{registry}");
        // Pointers, never copies: a plane's own keys and endpoints live in the plane's document.
        assert!(!registry.contains("control-plane/keys"), "{registry}");
        assert!(!registry.contains("data-plane/keys"), "{registry}");
    }

    #[test]
    fn the_registry_names_the_host_keys_when_the_deployment_publishes_any() {
        let config = config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
            (
                permguard_core::config::SETTING_TELEMETRY_ADDR,
                "127.0.0.1:5443",
            ),
            (permguard_core::config::SETTING_KEYS_ENABLED, "true"),
        ]);

        let registry = server_configuration_document(&config);
        assert!(
            registry.contains("\"jwks_uri\":\"http://127.0.0.1:5443/server-host/keys\""),
            "{registry}"
        );
    }

    #[test]
    fn the_host_advertised_url_wins_over_the_bound_address() {
        let config = config_with(&[
            (
                permguard_core::config::SETTING_TELEMETRY_ADDR,
                "0.0.0.0:5443",
            ),
            (
                permguard_core::config::SETTING_TELEMETRY_ADVERTISED_URL,
                "https://ops.example.com/",
            ),
        ]);

        assert_eq!(
            host_http_base(&config).as_deref(),
            Some("https://ops.example.com"),
            "advertised, trimmed of its trailing slash"
        );
    }

    #[test]
    fn a_grpc_only_plane_is_listed_by_its_endpoint() {
        // Served but unlisted would be a plane the discovery contract lies about.
        let config = config_with(&[(SETTING_DATA_GRPC_ADDR, "127.0.0.1:7443")]);

        let registry = server_configuration_document(&config);
        assert!(
            registry.contains("\"data-plane\":{\"grpc_endpoint\":\"http://127.0.0.1:7443\"}"),
            "{registry}"
        );
    }

    #[test]
    fn a_plane_with_http_is_listed_by_its_document_not_its_grpc_endpoint() {
        // The plane's own well-known already names its transports; the registry points, never
        // copies.
        let config = config_with(&[
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7443"),
            (SETTING_DATA_GRPC_ADDR, "127.0.0.1:7444"),
        ]);

        let registry = server_configuration_document(&config);
        assert!(
            registry.contains(
                "\"data-plane\":{\"server_configuration\":\"http://127.0.0.1:7443/.well-known/server-configuration\"}"
            ),
            "{registry}"
        );
    }

    #[test]
    fn a_tls_plane_discovers_as_https() {
        let config = config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
            // The scheme follows the material: a plane with a certificate is https.
            (SETTING_CONTROL_HTTP_TLS_CERT, "certs/control.pem"),
            (SETTING_CONTROL_HTTP_TLS_KEY, "certs/control.key"),
        ]);

        assert_eq!(
            plane_http_base(&config, PlaneId::Control).expect("the plane is discovered"),
            "https://127.0.0.1:6443"
        );
    }

    #[test]
    fn addresses_are_known_for_both_planes_and_nothing_else() {
        assert!(addresses_for_plane("control").is_some());
        assert!(addresses_for_plane("data").is_some());
        assert!(addresses_for_plane("edge").is_none());
    }

    #[test]
    fn plane_sections_map_the_signing_ring_settings() {
        let parsed = plane_settings(
            &serde_norway::from_str("keys:\n  enabled: \"true\"\n  directory: keys/control\n")
                .expect("the YAML parses"),
            PlaneSettingKeys::CONTROL,
        )
        .expect("the section parses");

        assert!(parsed.contains(&(
            permguard_core::config::SETTING_CONTROL_KEYS_ENABLED.to_owned(),
            "true".to_owned()
        )));
        assert!(parsed.contains(&(
            permguard_core::config::SETTING_CONTROL_KEYS_DIRECTORY.to_owned(),
            "keys/control".to_owned()
        )));
    }

    #[test]
    fn every_plane_key_is_a_declared_setting() {
        for key in [
            SETTING_CONTROL_HTTP_ADDR,
            SETTING_CONTROL_GRPC_ADDR,
            SETTING_DATA_HTTP_ADDR,
            SETTING_DATA_GRPC_ADDR,
        ] {
            assert!(
                PlaneSettingKeys::CONTROL.settings().contains(&key)
                    || PlaneSettingKeys::DATA.settings().contains(&key),
                "{key} is not declared by any plane"
            );
        }
    }
}

#[cfg(test)]
mod advertisement_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::plane::{
        SETTING_CONTROL_HTTP_ADDR, SETTING_DATA_HTTP_ADDR, SETTING_DATA_HTTP_ADVERTISED_URL,
    };

    #[test]
    fn a_wildcard_bind_is_recognised_and_a_real_address_is_not() {
        for wildcard in ["0.0.0.0:7443", "[::]:7443", "0.0.0.0", "::"] {
            assert!(is_wildcard_address(wildcard), "{wildcard}");
        }
        for routable in [
            "127.0.0.1:7443",
            "permguard-data-plane:7443",
            "10.0.0.4:7443",
        ] {
            assert!(!is_wildcard_address(routable), "{routable}");
        }
    }

    /// What a plane publishes is what it was told to publish, not where it binds.
    #[test]
    fn an_advertised_url_replaces_the_bind_address_everywhere() {
        let config = document_tests::config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
            (SETTING_DATA_HTTP_ADDR, "0.0.0.0:7443"),
            (SETTING_DATA_HTTP_ADVERTISED_URL, "https://pdp.example.com/"),
        ]);

        assert_eq!(
            plane_http_base(&config, PlaneId::Data).expect("the data plane is discovered"),
            "https://pdp.example.com",
            "the trailing slash is trimmed, because every caller appends a path"
        );
        // And the plane that was told nothing still falls back to its bind address.
        assert_eq!(
            plane_http_base(&config, PlaneId::Control).expect("the control plane is discovered"),
            "http://0.0.0.0:6443"
        );
    }

    /// The one that was not told is the one an operator has to hear about.
    #[test]
    fn a_wildcard_bind_without_an_advertised_url_is_reported() {
        let config = document_tests::config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
            (SETTING_DATA_HTTP_ADDR, "0.0.0.0:7443"),
            (SETTING_DATA_HTTP_ADVERTISED_URL, "https://pdp.example.com"),
        ]);

        assert_eq!(
            unroutable_planes(&config),
            vec!["control-plane"],
            "the data plane says where to reach it; the control plane does not"
        );

        // Told, both of them: nothing to report.
        let told = document_tests::config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
            (SETTING_DATA_HTTP_ADDR, "0.0.0.0:7443"),
            (SETTING_DATA_HTTP_ADVERTISED_URL, "https://pdp.example.com"),
        ]);
        assert!(unroutable_planes(&told).is_empty());
    }
}
