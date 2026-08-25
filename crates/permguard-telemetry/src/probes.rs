// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the surface answers: liveness, readiness, and the exposition a scraper reads.
//!
//! Free functions rather than methods, because a build that assembles its own HTTP surface should be
//! able to mount these somewhere else instead of reimplementing what "ready" means.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

use permguard_core::metrics::{Metric, Sample};
use permguard_core::{Health, Metrics};

use crate::exposition;

/// Whether the process reports itself live.
///
/// Declared here rather than recorded into the registry, because it is not a measurement — it is the
/// health state, which is authoritative and read at the moment of the scrape. Writing it into the
/// registry would mean publishing whatever it was the last time something remembered to update it.
const UP: Metric = Metric::gauge("permguard_up", "Whether the process reports itself live.");

/// Whether the process is willing to be sent work.
const READY: Metric = Metric::gauge(
    "permguard_ready",
    "Whether the process is willing to be sent work.",
);

/// What the probes read: the health the host writes, and the numbers everything else recorded.
#[derive(Clone)]
pub struct Reported {
    health: Health,
    metrics: Metrics,
}

impl Reported {
    /// Assembles what the probes answer from.
    pub fn new(health: Health, metrics: Metrics) -> Self {
        Self { health, metrics }
    }
}

/// The process-level server-configuration route: serves the registry
/// document the composition built — every plane this process hosts and each
/// plane's endpoints.
pub fn configuration_route(document: String) -> Router {
    use axum::http::header;
    use axum::response::IntoResponse as _;

    Router::new().route(
        "/.well-known/server-configuration",
        get(move || {
            let document = document.clone();
            async move { ([(header::CONTENT_TYPE, "application/json")], document).into_response() }
        }),
    )
}

/// Builds the routes this surface answers on.
pub fn routes(reported: Reported) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(reported)
}

/// Answers whether the process is wedged. A failure here means *restart me*.
async fn healthz(State(reported): State<Reported>) -> (StatusCode, &'static str) {
    if reported.health.is_live() {
        (StatusCode::OK, "live\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not live\n")
    }
}

/// Answers whether the process should be sent work. False from the first instant of shutdown.
async fn readyz(State(reported): State<Reported>) -> (StatusCode, &'static str) {
    if reported.health.is_ready() {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

/// The Prometheus exposition: the two health states, then everything the process recorded.
///
/// Always 200, even when the process reports itself unhealthy. A scrape that fails is a scrape with no
/// numbers in it, and the numbers explaining *why* something is unhealthy are exactly the ones wanted
/// at that moment.
async fn metrics(State(reported): State<Reported>) -> (StatusCode, String) {
    let mut samples = vec![
        Sample {
            metric: UP,
            labels: Vec::new(),
            reading: permguard_core::Reading::Value(f64::from(u8::from(reported.health.is_live()))),
        },
        Sample {
            metric: READY,
            labels: Vec::new(),
            reading: permguard_core::Reading::Value(f64::from(u8::from(
                reported.health.is_ready(),
            ))),
        },
    ];
    samples.extend(reported.metrics.snapshot());

    (StatusCode::OK, exposition::render(&samples))
}
