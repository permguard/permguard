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
                    "127.0.0.1:6443".to_owned(),
                ),
                (
                    permguard_server::plane::SETTING_DATA_HTTP_ADDR.to_owned(),
                    "127.0.0.1:7443".to_owned(),
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

    // The stream declarations, disabled ones included: "not here" and "here, turned off" are
    // different answers, and this deployment has the temporal interface off.
    let (status, streams) = get(module.http_routes(&context), "/v1/streams").await;
    assert_eq!(status, 200);
    assert!(
        streams.contains("\"stream_type\":\"decisions\"")
            && streams.contains("\"stream_type\":\"events\""),
        "{streams}"
    );
    assert!(streams.contains("\"enabled\":false"), "{streams}");

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

/// The same deployment, plus whatever settings a test wants to say.
fn deployed_with(extra: &[(&str, &str)]) -> Config {
    let mut file: Vec<(String, String)> = vec![
        (
            permguard_server::plane::SETTING_CONTROL_HTTP_ADDR.to_owned(),
            "127.0.0.1:6443".to_owned(),
        ),
        (
            permguard_server::plane::SETTING_DATA_HTTP_ADDR.to_owned(),
            "127.0.0.1:7443".to_owned(),
        ),
    ];
    for (name, value) in extra {
        file.push(((*name).to_owned(), (*value).to_owned()));
    }

    Config::from_layers(
        permguard_server::plane::build_settings("0.0.0-test"),
        vec![
            permguard_server::plane::SETTING_RUNTIME_PLANES,
            permguard_server::plane::SETTING_CONTROL_HTTP_ADDR,
            permguard_server::plane::SETTING_DATA_HTTP_ADDR,
        ],
        permguard_core::config::Layers {
            file,
            ..Default::default()
        },
    )
    .expect("the test configuration builds")
}

/// The temporal interface takes two switches, and one is not enough.
///
/// # What this is actually about
///
/// `events.enabled` is a statement about disks: *this plane keeps a durable event history*.
/// `experimental.dogwood.enabled` is a statement about contracts: *this deployment accepts shapes
/// that may still change*. The temporal interface needs both, so that a deployment which opted
/// into neither cannot reach an unstable contract by turning on the one that sounds like storage.
///
/// The half-said combination is the interesting one. Serving it as nothing would leave an operator
/// with a plane that looks configured, answers 404, and says nothing about which switch is missing
/// — so it stops the process instead, by name.
#[test]
fn the_temporal_interface_needs_both_switches_and_says_so_when_it_has_one() {
    use permguard_core::config::{SETTING_EVENTS_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD};

    let module = permguard_data_plane::module();

    // Neither: nothing to check and nothing served.
    let neither = deployed();
    assert!(module.startup_check(&neither).is_ok());

    // History on, the contract not accepted: refused, naming both settings.
    let half = deployed_with(&[(SETTING_EVENTS_ENABLED, "true")]);
    let refused = module
        .startup_check(&half)
        .expect_err("a plane configured half-way does not start");
    let said = refused.to_string();
    assert!(said.contains("experimental.dogwood.enabled"), "{said}");
    assert!(said.contains("dataPlane.events.enabled"), "{said}");

    // The contract accepted and no history: an ordinary Dogwood-capable plane that keeps none.
    let policies_only = deployed_with(&[(SETTING_EXPERIMENTAL_DOGWOOD, "true")]);
    assert!(module.startup_check(&policies_only).is_ok());
}

/// A plane that does not serve the temporal interface does not advertise it either.
///
/// A discovery document is a promise about what answers here. Listing an interface a client then
/// cannot reach is the failure the three-layer discovery chain exists to prevent, so the link and
/// the route are decided by one predicate rather than by two that could drift.
#[tokio::test]
async fn discovery_lists_the_temporal_interface_only_where_it_is_served() {
    use permguard_core::config::SETTING_EVENTS_ENABLED;

    let temporal = permguard_languages::temporal::INTERFACE;
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();

    let off = deployed();
    let context = ServerContext::new(identity(), &off, &storage, &audit);
    let (status, document) = get(
        permguard_data_plane::module().http_routes(&context),
        "/.well-known/server-configuration",
    )
    .await;
    assert_eq!(status, 200);
    let document: serde_json::Value = serde_json::from_str(&document).expect("JSON");
    assert!(
        document["interfaces"][temporal].is_null(),
        "a plane that does not serve it does not name it: {document}"
    );

    // Half-said is refused at startup; a document is not even reached. Asserted here too, because
    // the two checks are what keep "advertised" and "served" the same set.
    let half = deployed_with(&[(SETTING_EVENTS_ENABLED, "true")]);
    let context = ServerContext::new(identity(), &half, &storage, &audit);
    let (status, document) = get(
        permguard_data_plane::module().http_routes(&context),
        "/.well-known/server-configuration",
    )
    .await;
    assert_eq!(status, 200);
    let document: serde_json::Value = serde_json::from_str(&document).expect("JSON");
    assert!(
        document["interfaces"][temporal].is_null(),
        "half-configured is not served, so it is not advertised: {document}"
    );
}
