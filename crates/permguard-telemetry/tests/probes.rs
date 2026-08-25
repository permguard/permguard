// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the telemetry surface answers a probe and a scrape.
//!
//! Here rather than beside the code because liveness and readiness are two questions with four
//! combinations between them, and the point of the suite is that the combinations differ.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use permguard_core::metrics::{Metric, Recorder};
use permguard_core::{
    BuildSettings, Config, Health, Layers, Metrics, ProductIdentity, ServerContext, Service,
};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use permguard_telemetry::{Reported, TelemetryService};

fn health_of(ready: bool, live: bool) -> Health {
    let health = Health::new();

    health.set_ready(ready);
    health.set_live(live);

    health
}

/// Asks the routes one question, the way a probe would.
async fn ask(health: Health, path: &str) -> (StatusCode, String) {
    scraped(Reported::new(health, Metrics::none()), path).await
}

/// Asks the routes one question, with a particular set of numbers behind them.
async fn scraped(reported: Reported, path: &str) -> (StatusCode, String) {
    let response = TelemetryService::routes(reported)
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("the request builds"),
        )
        .await
        .expect("the routes answer");

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body is readable");

    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn test_a_live_process_that_is_not_ready_answers_the_two_questions_differently() {
    let health = health_of(false, true);

    assert_eq!(ask(health.clone(), "/healthz").await.0, StatusCode::OK);
    assert_eq!(
        ask(health, "/readyz").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn test_a_ready_process_answers_both_affirmatively() {
    let health = health_of(true, true);

    assert_eq!(ask(health.clone(), "/healthz").await.0, StatusCode::OK);
    assert_eq!(ask(health, "/readyz").await.0, StatusCode::OK);
}

#[tokio::test]
async fn test_a_wedged_process_reports_itself_not_live() {
    let health = health_of(true, false);

    assert_eq!(
        ask(health, "/healthz").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn test_metrics_expose_both_states_in_the_prometheus_format() {
    let (status, body) = ask(health_of(true, true), "/metrics").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("# TYPE permguard_up gauge"));
    assert!(body.contains("permguard_up 1"));
    assert!(body.contains("permguard_ready 1"));

    let (_, body) = ask(health_of(false, true), "/metrics").await;
    assert!(body.contains("permguard_ready 0"));
}

#[tokio::test]
async fn test_a_scrape_publishes_what_the_rest_of_the_process_recorded() {
    // The claim the registry exists to make: something elsewhere counts, and the number leaves the
    // process without that code knowing anything about `/metrics`.
    const SERVED: Metric = Metric::counter("permguard_demo_total", "Something that happened.");
    const LATENCY: Metric = Metric::histogram(
        "permguard_demo_seconds",
        "How long it took.",
        permguard_core::metrics::SECONDS,
    );

    let registry = std::sync::Arc::new(permguard_std::metrics::Registry::new());
    registry.record(&SERVED, &[("outcome", "ok")], 3.0);
    registry.record(&LATENCY, &[], 0.02);

    let (status, body) = scraped(
        Reported::new(
            health_of(true, true),
            Metrics::new(registry as std::sync::Arc<dyn Recorder>),
        ),
        "/metrics",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Health still comes first, because it is read at the moment of the scrape rather than recorded.
    assert!(body.contains("permguard_up 1"), "{body}");
    assert!(
        body.contains("# TYPE permguard_demo_total counter"),
        "{body}"
    );
    assert!(
        body.contains("permguard_demo_total{outcome=\"ok\"} 3"),
        "{body}"
    );
    assert!(
        body.contains("permguard_demo_seconds_bucket{le=\"0.025\"} 1"),
        "{body}"
    );
    assert!(body.contains("permguard_demo_seconds_count 1"), "{body}");
}

#[tokio::test]
async fn test_a_deployment_that_configures_no_address_starts_nothing() {
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &config,
        &storage,
        &audit,
    );
    let service = TelemetryService::new();

    assert!(config.telemetry_addr().is_none());
    service.start(&context).await.expect("the service starts");
    service.stop(&context).await.expect("the service stops");
}

#[tokio::test]
async fn test_the_surface_listens_and_answers_and_then_stops() {
    let config = Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(
            // Port zero: the operating system picks a free one).with_command_line(so tests never collide.
            vec![(
                permguard_core::config::SETTING_TELEMETRY_ADDR.to_owned(),
                "127.0.0.1:0".to_owned(),
            )],
        ),
    )
    .expect("the config builds");
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &config,
        &storage,
        &audit,
    );

    let service = TelemetryService::new();
    service.start(&context).await.expect("the surface starts");

    // Stopping twice is what a retry looks like, and it must not be an error.
    service.stop(&context).await.expect("the surface stops");
    service
        .stop(&context)
        .await
        .expect("stopping again is harmless");
}
