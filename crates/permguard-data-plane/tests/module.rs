// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The data plane module, exercised the way the host mounts it: metadata,
//! then its HTTP surface through the router — info, health, discovery.

#![allow(clippy::expect_used)]

use http::Request;
use http_body_util::BodyExt as _;
use permguard_core::{Config, ProductIdentity, ServerContext};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use tower::ServiceExt as _;

fn identity() -> ProductIdentity {
    ProductIdentity::new("permguard-data-plane", "Permguard", "tagline", "about", "")
}

async fn get(router: axum::Router, path: &str) -> (u16, String) {
    let answer = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("a request builds"),
        )
        .await
        .expect("the router answers");
    let status = answer.status().as_u16();
    let body = answer
        .into_body()
        .collect()
        .await
        .expect("the body reads")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[test]
fn module_metadata_identifies_data_plane() {
    let module = permguard_data_plane::module();

    assert_eq!(module.id(), "data");
    assert_eq!(module.component(), "data-plane");
    assert_eq!(module.description(), "data plane");
}

/// A configuration with both planes on their conventional ports.
fn deployed() -> Config {
    Config::from_layers(
        permguard_server::plane::build_settings("0.0.0-test"),
        vec![
            permguard_server::plane::SETTING_RUNTIME_PLANES,
            permguard_server::plane::SETTING_CONTROL_HTTP_ADDR,
            permguard_server::plane::SETTING_DATA_HTTP_ADDR,
        ],
        permguard_core::config::Layers {
            file: [
                (
                    permguard_server::plane::SETTING_CONTROL_HTTP_ADDR.to_owned(),
                    "127.0.0.1:7556".to_owned(),
                ),
                (
                    permguard_server::plane::SETTING_DATA_HTTP_ADDR.to_owned(),
                    "127.0.0.1:7656".to_owned(),
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    )
    .expect("the test configuration builds")
}

#[tokio::test]
async fn the_http_surface_answers_info_health_and_discovery() {
    // A configuration shaped like a real deployment, because discovery is about addresses: with no
    // public address configured, a plane publishes a document whose links are empty, and a test
    // asserting on that would be asserting nothing about what a client actually receives.
    let config = deployed();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);
    let module = permguard_data_plane::module();

    let (status, info) = get(module.http_routes(&context), "/").await;
    assert_eq!(status, 200);
    assert!(info.contains("\"plane\":\"data\""), "{info}");

    let (status, version) = get(module.http_routes(&context), "/version").await;
    assert_eq!(status, 200);
    assert!(version.contains("version"), "{version}");

    let (status, health) = get(module.http_routes(&context), "/health").await;
    assert_eq!(status, 200);
    assert!(health.contains("live"), "{health}");

    // Discovery, followed rather than pattern-matched. `contains` on a JSON body proves a
    // substring is somewhere in the text; a client does not read a substring, it reads a field and
    // then goes where the field points. So this walks the same two hops a client walks, and would
    // catch a link that is present but wrong — which is exactly what a `contains` check cannot.
    let (status, discovery) = get(
        module.http_routes(&context),
        "/.well-known/server-configuration",
    )
    .await;
    assert_eq!(status, 200);
    let discovery: serde_json::Value =
        serde_json::from_str(&discovery).expect("the plane's document is JSON");
    assert_eq!(discovery["plane"], serde_json::json!("data-plane"));
    assert!(
        discovery["jwks_uri"]
            .as_str()
            .is_some_and(|uri| uri.ends_with("/data-plane/keys")),
        "{discovery}"
    );

    // The plane names the interface it exposes, and says where that interface describes itself.
    let interface = permguard_languages::request::INTERFACE;
    let link = discovery["interfaces"][interface]["configuration"]
        .as_str()
        .unwrap_or_else(|| panic!("the plane links to `{interface}`: {discovery}"))
        .to_owned();
    assert!(
        link.ends_with(permguard_languages::request::CONFIGURATION_PATH),
        "the link points at this interface's own configuration: {link}"
    );

    // Follow it. A link nobody can follow is worse than no link.
    let path = link
        .rfind("/.well-known/")
        .map(|at| link[at..].to_owned())
        .unwrap_or(link);
    let (status, configuration) = get(module.http_routes(&context), &path).await;
    assert_eq!(status, 200, "the link the plane published answers");
    let configuration: serde_json::Value =
        serde_json::from_str(&configuration).expect("the interface's document is JSON");
    assert_eq!(configuration["interface"], serde_json::json!(interface));

    // And what it advertises is mounted: an endpoint a caller configures itself from must answer.
    for endpoint in ["evaluation", "evaluations"] {
        let advertised = configuration["endpoints"][endpoint]
            .as_str()
            .unwrap_or_else(|| panic!("`{endpoint}` is advertised: {configuration}"));
        let route = advertised
            .find("/access/")
            .map(|at| &advertised[at..])
            .unwrap_or(advertised);
        let (status, _) = get(module.http_routes(&context), route).await;
        assert_ne!(
            status, 404,
            "`{endpoint}` is advertised at {advertised} and not mounted"
        );
    }

    let (status, keys) = get(module.http_routes(&context), "/data-plane/keys").await;
    assert_eq!(status, 200);
    assert!(keys.contains("keys"), "{keys}");
}

#[tokio::test]
async fn the_grpc_surface_mounts() {
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);

    // Mounting is the assertion: a service that cannot compose panics here.
    let _routes = permguard_data_plane::module().grpc_routes(&context);
}
