// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-7.5b, IFACE-06: the evaluation interfaces over gRPC are served where their partial parity
//! with REST is permitted, and not where the assurance in force requires the strict protobuf
//! decoder this build does not have. A binary of its own: the plane's decider is built once per
//! process, and only the served case builds it.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use http::Request;
use http_body_util::BodyExt as _;
use permguard_core::config::{SETTING_ASSURANCE_PROFILE, SETTING_WORKING_DIR};
use permguard_core::{Config, PlaneContext, ProductIdentity, ServerContext};
use permguard_host::composition::{Authorization, Host};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use tower::ServiceExt as _;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-data-grpc-evaluation-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// The plane's gRPC routes under `profile`.
fn grpc_routes(tag: &str, profile: &str) -> axum::Router {
    let volume = scratch(tag);
    let config: &'static Config = Box::leak(Box::new(
        Config::from_layers(
            permguard_core::config::BuildSettings::new(
                "0.0.0-test",
                "2022",
                "Nitro Agility S.r.l.",
            ),
            vec![permguard_server::plane::SETTING_DATA_GRPC_ADDR],
            permguard_core::config::Layers::new().with_environment(vec![
                (
                    SETTING_WORKING_DIR.to_owned(),
                    volume.to_string_lossy().into_owned(),
                ),
                (SETTING_ASSURANCE_PROFILE.to_owned(), profile.to_owned()),
                (
                    permguard_server::plane::SETTING_DATA_GRPC_ADDR.to_owned(),
                    "127.0.0.1:7444".to_owned(),
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
        ServerContext::new(
            ProductIdentity::new("permguard-data-plane", "Permguard", "tagline", "about", ""),
            config,
            storage,
            audit,
        )
        .with_plane_handles("data", Arc::new(registration)),
    ));
    module.grpc_routes(&PlaneContext::new(server, "data"))
}

/// The `grpc-status` one unary call to `path` ends with, an empty message as its request.
async fn status_of(router: &axum::Router, path: &str) -> String {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        // One uncompressed frame holding the empty message.
        .body(axum::body::Body::from(vec![0u8, 0, 0, 0, 0]))
        .expect("a request");
    let response = router.clone().oneshot(request).await.expect("answered");
    let in_headers = response
        .headers()
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let collected = response
        .into_body()
        .collect()
        .await
        .expect("the body reads");
    in_headers
        .or_else(|| {
            collected
                .trailers()
                .and_then(|trailers| trailers.get("grpc-status"))
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .expect("a gRPC status")
}

const EVALUATE: &str = "/permguard.data.v1.PolicyDecisionPoint/Evaluate";
const SUBMIT: &str = "/permguard.data.v1.TemporalPolicyDecisionPoint/SubmitEvent";
const INFO: &str = "/permguard.data.v1.DataPlane/GetInfo";
/// `UNIMPLEMENTED`: the answer for a service that is not mounted.
const UNIMPLEMENTED: &str = "12";

#[tokio::test]
async fn regulated_serves_no_evaluation_interface_over_grpc_and_production_does() {
    let regulated = grpc_routes("regulated", "regulated");
    assert_eq!(
        status_of(&regulated, EVALUATE).await,
        UNIMPLEMENTED,
        "no strict decoder: the evaluation interface is not served over gRPC"
    );
    // Not served by this configuration either way; under `regulated` the early return keeps it
    // off even where it would be.
    assert_eq!(
        status_of(&regulated, SUBMIT).await,
        UNIMPLEMENTED,
        "nor the temporal interface"
    );
    assert_ne!(
        status_of(&regulated, INFO).await,
        UNIMPLEMENTED,
        "the plane's own service stays"
    );

    let production = grpc_routes("production", "production");
    assert_ne!(
        status_of(&production, EVALUATE).await,
        UNIMPLEMENTED,
        "served, with its partial parity published"
    );
}
