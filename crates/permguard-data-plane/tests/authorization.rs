// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-21 on the data plane (WP-2.4): an evaluation without a grant is `401`, and a public grant
//! on the exact ledger lets the request through to the decision path.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use permguard_core::authz::{Selector, operations};
use permguard_core::config::SETTING_WORKING_DIR;
use permguard_core::{Config, PlaneContext, ProductIdentity, ServerContext};
use permguard_host::authz::PublicGrant;
use permguard_host::composition::{Authorization, Host};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use tower::ServiceExt as _;

fn scratch(tag: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("permguard-data-authz-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

fn identity() -> ProductIdentity {
    ProductIdentity::new("permguard-data-plane", "Permguard", "tagline", "about", "")
}

fn router(tag: &str, public: &[PublicGrant]) -> axum::Router {
    let volume = scratch(tag);
    let config: &'static Config = Box::leak(Box::new(
        Config::from_layers(
            permguard_core::config::BuildSettings::new(
                "0.0.0-test",
                "2022",
                "Nitro Agility S.r.l.",
            ),
            vec![permguard_server::plane::SETTING_DATA_HTTP_ADDR],
            permguard_core::config::Layers::new().with_environment(vec![
                (
                    SETTING_WORKING_DIR.to_owned(),
                    volume.to_string_lossy().into_owned(),
                ),
                (
                    permguard_server::plane::SETTING_DATA_HTTP_ADDR.to_owned(),
                    "127.0.0.1:7443".to_owned(),
                ),
            ]),
        )
        .expect("the configuration builds"),
    ));
    let storage: &'static MemoryStorage = Box::leak(Box::new(MemoryStorage::new()));
    let audit: &'static RecordingAuditSink = Box::leak(Box::new(RecordingAuditSink::new()));
    let module = permguard_data_plane::module();
    let registration = Host::builder()
        .authorization(Arc::new(Authorization::public_only(public)))
        .build()
        .register(module.declaration(config))
        .expect("the data plane registers");
    let server: &'static ServerContext<'static> = Box::leak(Box::new(
        ServerContext::new(identity(), config, storage, audit)
            .with_plane_handles("data", Arc::new(registration)),
    ));
    module
        .http_routes(&PlaneContext::new(server, "data"))
        .layer(permguard_transport::ActorLayer::new(Arc::new(
            permguard_core::NoRules,
        )))
}

async fn evaluate(router: &axum::Router, body: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(permguard_languages::request::EVALUATION_PATH)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_owned()))
        .expect("a request");
    let response = router.clone().oneshot(request).await.expect("answered");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body reads")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

const REQUEST: &str = r#"{"zone":"acme","ledger":"main","subject":{"type":"user","id":"u"},"resource":{"type":"doc","id":"d"},"action":{"name":"read"}}"#;

#[tokio::test]
async fn a_router_without_the_authentication_boundary_is_closed_even_to_public_grants() {
    // Built without the layer on purpose: no actor is decided, so nobody is anonymous.
    let volume = scratch("no-boundary");
    let config: &'static Config = Box::leak(Box::new(
        Config::from_layers(
            permguard_core::config::BuildSettings::new(
                "0.0.0-test",
                "2022",
                "Nitro Agility S.r.l.",
            ),
            vec![permguard_server::plane::SETTING_DATA_HTTP_ADDR],
            permguard_core::config::Layers::new().with_environment(vec![
                (
                    SETTING_WORKING_DIR.to_owned(),
                    volume.to_string_lossy().into_owned(),
                ),
                (
                    permguard_server::plane::SETTING_DATA_HTTP_ADDR.to_owned(),
                    "127.0.0.1:7443".to_owned(),
                ),
            ]),
        )
        .expect("the configuration builds"),
    ));
    let storage: &'static MemoryStorage = Box::leak(Box::new(MemoryStorage::new()));
    let audit: &'static RecordingAuditSink = Box::leak(Box::new(RecordingAuditSink::new()));
    let module = permguard_data_plane::module();
    let registration = Host::builder()
        .authorization(Arc::new(Authorization::permissive()))
        .build()
        .register(module.declaration(config))
        .expect("the data plane registers");
    let server: &'static ServerContext<'static> = Box::leak(Box::new(
        ServerContext::new(identity(), config, storage, audit)
            .with_plane_handles("data", Arc::new(registration)),
    ));
    let bare = module.http_routes(&PlaneContext::new(server, "data"));
    let (status, body) = evaluate(&bare, REQUEST).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn f21_an_evaluation_without_a_grant_is_401_before_any_policy_runs() {
    let router = router("closed", &[]);
    let (status, body) = evaluate(&router, REQUEST).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(body["code"], "unauthenticated");
    assert!(body.get("class").is_none());
}

#[tokio::test]
async fn a_public_grant_under_the_plane_lets_the_request_reach_the_decision_path() {
    let router = router(
        "public",
        &[PublicGrant::new(
            &[operations::DECISION_EVALUATE],
            Selector::parse("plane/data/*").expect("a selector"),
        )],
    );
    let (status, body) = evaluate(&router, REQUEST).await;
    // Authorized, and then the decision path's own answer: no mirror serves `acme/main` here.
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(body["class"], "not_found");
}

/// WP-2.8: the plane's decider loads partitions under the configured assurance profile, which is
/// `production` when the configuration states none, never the `development` a bare decider has.
/// One test in this binary touches the plane's decider, which is built once per process.
#[test]
fn the_plane_decider_loads_under_the_configured_assurance_profile() {
    let volume = scratch("assurance-profile");
    let config: &'static Config = Box::leak(Box::new(
        Config::from_layers(
            permguard_core::config::BuildSettings::new(
                "0.0.0-test",
                "2022",
                "Nitro Agility S.r.l.",
            ),
            vec![permguard_server::plane::SETTING_DATA_HTTP_ADDR],
            permguard_core::config::Layers::new().with_environment(vec![(
                SETTING_WORKING_DIR.to_owned(),
                volume.to_string_lossy().into_owned(),
            )]),
        )
        .expect("the configuration builds"),
    ));
    let storage: &'static MemoryStorage = Box::leak(Box::new(MemoryStorage::new()));
    let audit: &'static RecordingAuditSink = Box::leak(Box::new(RecordingAuditSink::new()));
    let server: &'static ServerContext<'static> = Box::leak(Box::new(ServerContext::new(
        identity(),
        config,
        storage,
        audit,
    )));
    let decider = permguard_data_plane::authz::decider(&PlaneContext::new(server, "data"));
    assert_eq!(
        decider.profile(),
        permguard_core::assurance::AssuranceProfile::Production
    );
}
