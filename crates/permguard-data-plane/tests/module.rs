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

#[tokio::test]
async fn the_http_surface_answers_info_health_and_discovery() {
    let config = Config::default();
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

    let (status, discovery) = get(
        module.http_routes(&context),
        "/.well-known/server-configuration",
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        discovery.contains("\"plane\":\"data-plane\""),
        "{discovery}"
    );
    assert!(discovery.contains("jwks_uri"), "{discovery}");

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
