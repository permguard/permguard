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

/// The planes this process serves over HTTP, resolved from the same
/// configuration the listeners bind with — the one source of truth, so the
/// document and the sockets cannot disagree.
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
        planes.push(DiscoveredPlane {
            id: match id {
                "control" => "control-plane",
                _ => "data-plane",
            },
            http_base: format!("{scheme}://{addr}"),
        });
    }
    planes
}

/// The HTTP base URL (`scheme://addr`) one plane answers on, when it is
/// loaded and has an HTTP address — for a plane module composing its own
/// configuration document.
pub fn plane_http_base(config: &Config, plane_id: &str) -> Option<String> {
    let public_name = match plane_id {
        "control" => "control-plane",
        _ => "data-plane",
    };
    discovered_planes(config)
        .into_iter()
        .find(|plane| plane.id == public_name)
        .map(|plane| plane.http_base)
}

/// One plane's own configuration document, as JSON text — what that plane's
/// public port answers at `/.well-known/server-configuration`: itself, and
/// nothing else. A client configured to talk to a plane discovers that
/// plane; the cross-plane registry is the process's business and lives on
/// the telemetry surface.
pub fn plane_configuration_document(config: &Config, plane_id: &str) -> String {
    let public_name = match plane_id {
        "control" => "control-plane",
        _ => "data-plane",
    };
    let jwks = discovered_planes(config)
        .into_iter()
        .find(|plane| plane.id == public_name)
        .map(|plane| format!("{}/{}/keys", plane.http_base, plane.id))
        .unwrap_or_default();
    format!("{{\"plane\":\"{public_name}\",\"jwks_uri\":\"{jwks}\"}}")
}

/// The process-level registry, as JSON text — what the telemetry surface
/// answers at `/.well-known/server-configuration`: every plane this process
/// hosts, each pointing at **its own** configuration document. Pointers,
/// never copies: the plane's well-known is the single source of truth, and
/// the registry only says where the truths are.
pub fn server_configuration_document(config: &Config) -> String {
    let mut out = String::from("{\"planes\":{");
    let planes = discovered_planes(config);
    for (at, plane) in planes.iter().enumerate() {
        if at > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "\"{}\":{{\"server_configuration\":\"{}/.well-known/server-configuration\"}}",
            plane.id, plane.http_base
        ));
    }
    out.push_str("}}");
    out
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
    fn config_with(pairs: &[(&str, &str)]) -> Config {
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
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:7556"),
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7656"),
        ]);

        let planes = discovered_planes(&config);
        let ids: Vec<&str> = planes.iter().map(|plane| plane.id).collect();
        assert_eq!(ids, vec!["control-plane", "data-plane"]);
        assert_eq!(planes[0].http_base, "http://127.0.0.1:7556");
    }

    #[test]
    fn a_disabled_plane_never_appears_in_discovery() {
        let config = config_with(&[
            (SETTING_RUNTIME_PLANES, "control"),
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:7556"),
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7656"),
        ]);

        let planes = discovered_planes(&config);
        assert_eq!(planes.len(), 1);
        assert_eq!(planes[0].id, "control-plane");
        assert!(plane_http_base(&config, "data").is_none());
    }

    #[test]
    fn the_plane_document_names_itself_and_its_keys() {
        let config = config_with(&[(SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:7556")]);

        let document = plane_configuration_document(&config, "control");
        assert!(
            document.contains("\"plane\":\"control-plane\""),
            "{document}"
        );
        assert!(
            document.contains("http://127.0.0.1:7556/control-plane/keys"),
            "{document}"
        );
    }

    #[test]
    fn the_registry_points_at_each_plane_and_copies_nothing() {
        let config = config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:7556"),
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7656"),
        ]);

        let registry = server_configuration_document(&config);
        assert!(
            registry.contains(
                "\"control-plane\":{\"server_configuration\":\"http://127.0.0.1:7556/.well-known/server-configuration\"}"
            ),
            "{registry}"
        );
        assert!(registry.contains("\"data-plane\""), "{registry}");
        // Pointers, never copies: no jwks, no endpoints, only the well-known.
        assert!(!registry.contains("jwks"), "{registry}");
    }

    #[test]
    fn a_tls_plane_discovers_as_https() {
        let config = config_with(&[
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:7556"),
            // The scheme follows the material: a plane with a certificate is https.
            (SETTING_CONTROL_HTTP_TLS_CERT, "certs/control.pem"),
            (SETTING_CONTROL_HTTP_TLS_KEY, "certs/control.key"),
        ]);

        assert_eq!(
            plane_http_base(&config, "control").expect("the plane is discovered"),
            "https://127.0.0.1:7556"
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
