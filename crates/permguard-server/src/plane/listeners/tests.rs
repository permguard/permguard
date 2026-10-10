// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_core::config::{
    SETTING_ADMIN_ADDR, SETTING_ADMIN_ALLOW, SETTING_ADMIN_TLS_CERT, SETTING_ADMIN_TLS_CLIENT_CA,
    SETTING_ADMIN_TLS_KEY, SETTING_ASSURANCE_PROFILE, SETTING_PUBLIC_TLS_TERMINATED_UPSTREAM,
    SETTING_TELEMETRY_ADDR,
};
use permguard_core::listener::ListenerAuthentication;

use super::*;
use crate::plane::build_settings;
use crate::plane::settings::*;

fn config_with(pairs: &[(&str, &str)]) -> Config {
    let mut declared = vec![SETTING_RUNTIME_PLANES, SETTING_RUNTIME_OPTIONAL_PLANES];
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

/// The planes the first-party binaries register.
fn first_party() -> Vec<(&'static str, PlaneAddresses)> {
    ["control", "data"]
        .into_iter()
        .map(|id| (id, addresses_for_plane(id).expect("a known plane")))
        .collect()
}

fn refusal(pairs: &[(&str, &str)]) -> String {
    format!(
        "{:#}",
        check(&config_with(pairs), &first_party()).expect_err("this listener is refused")
    )
}

#[test]
fn a_plane_public_listener_in_the_clear_beyond_loopback_is_refused_from_production() {
    for profile in ["production", "regulated"] {
        for address in ["0.0.0.0:6443", "10.0.0.7:6443", "permguard:6443"] {
            let why = refusal(&[
                (SETTING_ASSURANCE_PROFILE, profile),
                (SETTING_RUNTIME_PLANES, "control"),
                (SETTING_CONTROL_HTTP_ADDR, address),
                (SETTING_CONTROL_GRPC_ADDR, address),
            ]);
            assert!(
                why.contains("control-http-grpc"),
                "{profile} {address}: {why}"
            );
            assert!(why.contains(address), "{why}");
            assert!(
                why.contains(permguard_core::domains::assurance::RELAX_TLS_TERMINATED_UPSTREAM),
                "{why}"
            );
        }
    }
    // Split, the gRPC listener alone in the clear is refused by its own name.
    let why = refusal(&[
        (SETTING_RUNTIME_PLANES, "data"),
        (SETTING_DATA_HTTP_ADDR, "0.0.0.0:7443"),
        (SETTING_DATA_HTTP_TLS_CERT, "tls/server.pem"),
        (SETTING_DATA_HTTP_TLS_KEY, "tls/server.key"),
        (SETTING_DATA_GRPC_ADDR, "0.0.0.0:7444"),
        (SETTING_DATA_GRPC_TLS_ENABLED, "false"),
    ]);
    assert!(why.contains("data-grpc"), "{why}");
}

#[test]
fn a_listener_in_the_clear_starts_on_loopback_in_development_or_declared_upstream() {
    for pairs in [
        // Loopback: nothing beyond the host reaches it.
        vec![
            (SETTING_RUNTIME_PLANES, "control"),
            (SETTING_CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
        ],
        // Development: the startup log and the published report say it.
        vec![
            (SETTING_ASSURANCE_PROFILE, "development"),
            (SETTING_RUNTIME_PLANES, "control"),
            (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
        ],
        // A declaration on the endpoint, the HTTP and gRPC halves of one address alike.
        vec![
            (SETTING_RUNTIME_PLANES, "control"),
            (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
            (SETTING_CONTROL_GRPC_ADDR, "0.0.0.0:6443"),
            (SETTING_CONTROL_HTTP_TLS_TERMINATED_UPSTREAM, "true"),
            (SETTING_CONTROL_GRPC_TLS_TERMINATED_UPSTREAM, "true"),
        ],
        // The process's declaration, which an endpoint stating none follows.
        vec![
            (SETTING_RUNTIME_PLANES, "control"),
            (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
            (SETTING_PUBLIC_TLS_TERMINATED_UPSTREAM, "true"),
        ],
        // TLS the process serves.
        vec![
            (SETTING_RUNTIME_PLANES, "control"),
            (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
            (SETTING_CONTROL_HTTP_TLS_CERT, "tls/server.pem"),
            (SETTING_CONTROL_HTTP_TLS_KEY, "tls/server.key"),
            (SETTING_CONTROL_GRPC_TLS_CERT, "tls/server.pem"),
            (SETTING_CONTROL_GRPC_TLS_KEY, "tls/server.key"),
        ],
    ] {
        check(&config_with(&pairs), &first_party())
            .unwrap_or_else(|error| panic!("{pairs:?}: {error:#}"));
    }
    // One half of a shared address declared, the other not: two policies on one socket.
    let why = refusal(&[
        (SETTING_RUNTIME_PLANES, "control"),
        (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
        (SETTING_CONTROL_GRPC_ADDR, "0.0.0.0:6443"),
        (SETTING_CONTROL_HTTP_TLS_TERMINATED_UPSTREAM, "true"),
    ]);
    assert!(why.contains("different TLS policies"), "{why}");
}

#[test]
fn a_declared_upstream_termination_beside_tls_is_refused() {
    for profile in ["development", "production"] {
        let why = refusal(&[
            (SETTING_ASSURANCE_PROFILE, profile),
            (SETTING_RUNTIME_PLANES, "data"),
            (SETTING_DATA_HTTP_ADDR, "127.0.0.1:7443"),
            (SETTING_DATA_GRPC_ADDR, "127.0.0.1:7444"),
            (SETTING_DATA_HTTP_TLS_CERT, "tls/server.pem"),
            (SETTING_DATA_HTTP_TLS_KEY, "tls/server.key"),
            (SETTING_DATA_HTTP_TLS_TERMINATED_UPSTREAM, "true"),
        ]);
        assert!(why.contains("data-http"), "{profile}: {why}");
        assert!(why.contains("state one of them"), "{profile}: {why}");
    }
}

#[test]
fn the_listeners_publish_their_class_and_authentication_sorted_by_name() {
    let config = config_with(&[
        (SETTING_ASSURANCE_PROFILE, "development"),
        (SETTING_TELEMETRY_ADDR, "127.0.0.1:5443"),
        (SETTING_ADMIN_ADDR, "127.0.0.1:5444"),
        (SETTING_ADMIN_TLS_CERT, "tls/admin.pem"),
        (SETTING_ADMIN_TLS_KEY, "tls/admin.key"),
        (SETTING_ADMIN_TLS_CLIENT_CA, "tls/ca.pem"),
        (SETTING_ADMIN_ALLOW, "cn:operator"),
        (SETTING_CONTROL_HTTP_ADDR, "0.0.0.0:6443"),
        (SETTING_CONTROL_GRPC_ADDR, "0.0.0.0:6443"),
        (SETTING_CONTROL_HTTP_TLS_TERMINATED_UPSTREAM, "true"),
        (SETTING_CONTROL_GRPC_TLS_TERMINATED_UPSTREAM, "true"),
        (SETTING_DATA_HTTP_ADDR, "0.0.0.0:7443"),
        (SETTING_DATA_HTTP_TLS_CERT, "tls/server.pem"),
        (SETTING_DATA_HTTP_TLS_KEY, "tls/server.key"),
        (SETTING_DATA_HTTP_TLS_CLIENT_CA, "tls/ca.pem"),
        (SETTING_DATA_HTTP_TLS_ALLOW, "cn:pep"),
        (SETTING_DATA_HTTP_TLS_MIN_VERSION, "1.2"),
        (SETTING_DATA_GRPC_ADDR, "0.0.0.0:7444"),
        (SETTING_DATA_GRPC_TLS_ENABLED, "false"),
    ]);
    let reports = listeners(&config);
    let shape: Vec<(&str, &str, &str, bool, Option<&str>)> = reports
        .iter()
        .map(|report| {
            (
                report.name.as_str(),
                report.class.as_str(),
                report.authentication.as_str(),
                report.client_allow,
                report.tls_min_version,
            )
        })
        .collect();
    assert_eq!(
        shape,
        [
            (
                "control-http-grpc",
                "plane_public",
                "upstream_tls",
                false,
                None
            ),
            ("data-grpc", "plane_public", "none", false, None),
            ("data-http", "plane_public", "mutual_tls", true, Some("1.2")),
            ("host-api", "host", "mutual_tls", true, Some("1.3")),
            ("telemetry", "telemetry", "none", false, None),
        ]
    );
    assert_eq!(
        crate::host_api::COMPONENT,
        permguard_core::listener::HOST_LISTENER
    );
    // Nothing a report carries names where the listener is.
    let json = serde_json::to_string(&reports).expect("serializes");
    for address in [
        "6443",
        "7443",
        "7444",
        "5443",
        "5444",
        "0.0.0.0",
        "127.0.0.1",
    ] {
        assert!(!json.contains(address), "{json}");
    }
    assert!(reports.iter().all(
        |report| report.authentication != ListenerAuthentication::Tls
            || report.tls_min_version.is_some()
    ));
}

#[test]
fn a_plane_registered_under_other_addresses_is_checked_as_registered() {
    use permguard_core::config::{SETTING_PUBLIC_GRPC_ADDR, SETTING_PUBLIC_HTTP_ADDR};
    // A composition serving a plane on the process `public.*` listener, or under its own id: the
    // check follows what was registered, not the two planes it knows by name.
    let config = config_with(&[
        (SETTING_RUNTIME_PLANES, "control,edge"),
        (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:8443"),
        (SETTING_PUBLIC_GRPC_ADDR, "0.0.0.0:8443"),
    ]);
    for id in ["control", "edge"] {
        let why = format!(
            "{:#}",
            check(&config, &[(id, PlaneAddresses::config_public())])
                .expect_err("the clear beyond loopback")
        );
        assert!(why.contains(&format!("{id}-http-grpc")), "{why}");
    }
    let declared = config_with(&[
        (SETTING_RUNTIME_PLANES, "edge"),
        (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:8443"),
        (SETTING_PUBLIC_TLS_TERMINATED_UPSTREAM, "true"),
    ]);
    check(&declared, &[("edge", PlaneAddresses::config_public())]).expect("declared upstream");
}

#[test]
fn an_endpoint_takes_the_process_declaration_only_where_it_takes_the_process_tls() {
    use permguard_core::config::{SETTING_PUBLIC_TLS_CERT, SETTING_PUBLIC_TLS_KEY};
    // The process declares upstream termination; one endpoint serves TLS of its own: that one is
    // TLS, not a contradiction.
    let config = config_with(&[
        (SETTING_RUNTIME_PLANES, "data"),
        (SETTING_PUBLIC_TLS_TERMINATED_UPSTREAM, "true"),
        (SETTING_DATA_HTTP_ADDR, "0.0.0.0:7443"),
        (SETTING_DATA_HTTP_TLS_CERT, "tls/server.pem"),
        (SETTING_DATA_HTTP_TLS_KEY, "tls/server.key"),
        (SETTING_DATA_GRPC_ADDR, "0.0.0.0:7444"),
    ]);
    check(&config, &first_party()).expect("TLS on one, upstream on the other");
    let shape: Vec<(String, &str)> = listeners(&config)
        .into_iter()
        .map(|report| (report.name, report.authentication.as_str()))
        .collect();
    assert_eq!(
        shape,
        [
            ("data-grpc".to_owned(), "upstream_tls"),
            ("data-http".to_owned(), "tls"),
        ]
    );
    // The process serves TLS; one endpoint says only that something upstream terminates it: that
    // one serves the clear, not the process's TLS.
    let config = config_with(&[
        (SETTING_RUNTIME_PLANES, "data"),
        (SETTING_PUBLIC_TLS_CERT, "tls/server.pem"),
        (SETTING_PUBLIC_TLS_KEY, "tls/server.key"),
        (SETTING_DATA_HTTP_ADDR, "0.0.0.0:7443"),
        (SETTING_DATA_HTTP_TLS_TERMINATED_UPSTREAM, "true"),
        (SETTING_DATA_GRPC_ADDR, "0.0.0.0:7444"),
    ]);
    check(&config, &first_party()).expect("upstream on one, the process TLS on the other");
    let shape: Vec<(String, &str)> = listeners(&config)
        .into_iter()
        .map(|report| (report.name, report.authentication.as_str()))
        .collect();
    assert_eq!(
        shape,
        [
            ("data-grpc".to_owned(), "tls"),
            ("data-http".to_owned(), "upstream_tls"),
        ]
    );
}
