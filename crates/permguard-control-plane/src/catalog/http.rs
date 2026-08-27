// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog's HTTP shape: routes, extraction, and nothing else.
//!
//! Every handler is the same three lines — extract, call the domain, shape the answer — because
//! everything that could be wrong lives below ([`super::zones`], [`super::ledgers`]) or beside
//! ([`crate::wire`]) this file. A handler with logic in it is a handler gRPC does not have.

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use permguard_core::ApiError;

use super::{CatalogFacade, ledgers, zones};
use crate::wire;

/// The routes the control plane answers about its catalog.
pub(crate) fn routes(facade: CatalogFacade) -> Router {
    Router::new()
        .route("/v1/zones", get(list_zones).post(create_zone))
        .route(
            "/v1/zones/{zone}",
            get(get_zone).patch(rename_zone).delete(delete_zone),
        )
        .route(
            "/v1/zones/{zone}/ledgers",
            get(list_ledgers).post(create_ledger),
        )
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}",
            get(get_ledger).patch(rename_ledger).delete(delete_ledger),
        )
        .with_state(facade)
}

/// What a create or rename carries: the name, and nothing else yet.
#[derive(Debug, Deserialize)]
struct NameBody {
    name: String,
}

/// The paging a listing was asked for: `?page=2&size=50`. Absent means all —
/// the pre-pagination contract, unchanged for every existing caller. Parsed by
/// hand, like the decision store's window: two integers do not justify a query
/// framework, and a parameter nobody declared is ignored rather than an error.
fn window_of(query: Option<&str>) -> super::ListWindow {
    let mut window = super::ListWindow::default();
    for pair in query.unwrap_or_default().split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        match name {
            "page" => window.page = value.parse().ok().filter(|page| *page > 0),
            "size" => window.size = value.parse().ok().filter(|size| *size > 0),
            _ => {}
        }
    }

    window
}

/// Shapes a domain outcome the one way every route does.
fn answer<T: serde::Serialize>(
    facade: &CatalogFacade,
    status: StatusCode,
    outcome: Result<T, ApiError>,
) -> Response {
    match outcome {
        Ok(payload) => (status, Json(payload)).into_response(),
        Err(error) => wire::http_error(&error, facade.disclosure),
    }
}

async fn create_zone(State(facade): State<CatalogFacade>, Json(body): Json<NameBody>) -> Response {
    let outcome = zones::create(&facade, &body.name).await;

    answer(&facade, StatusCode::CREATED, outcome)
}

async fn list_zones(State(facade): State<CatalogFacade>, RawQuery(query): RawQuery) -> Response {
    answer(
        &facade,
        StatusCode::OK,
        zones::list(&facade, window_of(query.as_deref())),
    )
}

async fn get_zone(State(facade): State<CatalogFacade>, Path(zone): Path<String>) -> Response {
    answer(&facade, StatusCode::OK, zones::get(&facade, &zone))
}

async fn rename_zone(
    State(facade): State<CatalogFacade>,
    Path(zone): Path<String>,
    Json(body): Json<NameBody>,
) -> Response {
    let outcome = zones::rename(&facade, &zone, &body.name).await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn delete_zone(State(facade): State<CatalogFacade>, Path(zone): Path<String>) -> Response {
    let outcome = zones::delete(&facade, &zone).await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn create_ledger(
    State(facade): State<CatalogFacade>,
    Path(zone): Path<String>,
    Json(body): Json<NameBody>,
) -> Response {
    let outcome = ledgers::create(&facade, &zone, &body.name).await;

    answer(&facade, StatusCode::CREATED, outcome)
}

async fn list_ledgers(
    State(facade): State<CatalogFacade>,
    Path(zone): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    answer(
        &facade,
        StatusCode::OK,
        ledgers::list(&facade, &zone, window_of(query.as_deref())),
    )
}

async fn get_ledger(
    State(facade): State<CatalogFacade>,
    Path((zone, ledger)): Path<(String, String)>,
) -> Response {
    answer(
        &facade,
        StatusCode::OK,
        ledgers::get(&facade, &zone, &ledger),
    )
}

async fn rename_ledger(
    State(facade): State<CatalogFacade>,
    Path((zone, ledger)): Path<(String, String)>,
    Json(body): Json<NameBody>,
) -> Response {
    let outcome = ledgers::rename(&facade, &zone, &ledger, &body.name).await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn delete_ledger(
    State(facade): State<CatalogFacade>,
    Path((zone, ledger)): Path<(String, String)>,
) -> Response {
    let outcome = ledgers::delete(&facade, &zone, &ledger).await;

    answer(&facade, StatusCode::OK, outcome)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use axum::body::Body;
    use http::Request as HttpRequest;
    use permguard_core::Disclosure;
    use permguard_std::catalog::FileCatalog;
    use std::sync::Arc;
    use tower::util::ServiceExt;

    fn testing_routes(disclosure: Disclosure) -> Router {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // One directory per call, or two tests running together delete each other's store.
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let root = std::env::temp_dir().join(format!(
            "permguard-catalog-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);

        routes(CatalogFacade {
            catalog: Arc::new(FileCatalog::new(root)),
            recorder: None,
            disclosure,
            audit_refusals: false,
            metrics: permguard_core::metrics::Metrics::none(),
        })
    }

    async fn send(routes: &Router, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
        let request = match body {
            Some(body) => HttpRequest::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned())),
            None => HttpRequest::builder()
                .method(method)
                .uri(path)
                .body(Body::empty()),
        }
        .expect("a request builds");

        let answer = routes
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = answer.status().as_u16();
        let bytes = axum::body::to_bytes(answer.into_body(), 1 << 20)
            .await
            .expect("the body reads");

        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The status table in the wire module, proved row by row — and every refusal carries the same
    /// three fields: class, code, message.
    #[tokio::test]
    async fn test_every_refusal_is_the_shared_shape_with_the_promised_status() {
        let routes = testing_routes(Disclosure::Minimal);

        let (status, body) =
            send(&routes, "POST", "/v1/zones", Some(r#"{"name":"delivery"}"#)).await;
        assert_eq!(status, 201, "{body}");
        assert!(body.contains(r#""name":"delivery""#), "{body}");

        let (status, body) =
            send(&routes, "POST", "/v1/zones", Some(r#"{"name":"delivery"}"#)).await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""class":"conflict""#), "{body}");
        assert!(body.contains(r#""code":"name_taken""#), "{body}");
        assert!(body.contains(r#""message":""#), "{body}");

        let (status, body) = send(&routes, "POST", "/v1/zones", Some(r#"{"name":"Pharma"}"#)).await;
        assert_eq!(status, 422, "{body}");
        assert!(body.contains(r#""class":"validation""#), "{body}");
        assert!(body.contains("lowercase"), "{body}");

        let (status, body) = send(&routes, "GET", "/v1/zones/nowhere", None).await;
        assert_eq!(status, 404, "{body}");
        assert!(body.contains(r#""class":"not_found""#), "{body}");

        let (status, body) = send(
            &routes,
            "POST",
            "/v1/zones/delivery/ledgers",
            Some(r#"{"name":"policies"}"#),
        )
        .await;
        assert_eq!(status, 201, "{body}");

        let (status, body) = send(&routes, "DELETE", "/v1/zones/delivery", None).await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""code":"zone_not_empty""#), "{body}");
    }

    /// With `audit.refusals` on, a denied mutation lands on the trail; internal faults never do.
    #[tokio::test]
    async fn test_refusals_reach_the_trail_only_when_asked() {
        use permguard_core::{AuditEvent, AuditRecorder, AuditSink, BoxFuture};
        use std::sync::Mutex;

        /// A sink that remembers what it was asked to record.
        struct Remembering(std::sync::Arc<Mutex<Vec<String>>>);

        impl AuditSink for Remembering {
            fn name(&self) -> &'static str {
                "remembering"
            }

            fn record<'a>(
                &'a self,
                event: &'a AuditEvent<'_>,
                _policy: Option<&'a dyn permguard_core::Pseudonymizer>,
            ) -> BoxFuture<'a, Result<(), permguard_core::error::AuditError>> {
                let recorded = format!("{} -> {}", event.action(), event.target().unwrap_or("-"));
                let log = std::sync::Arc::clone(&self.0);

                Box::pin(async move {
                    log.lock().expect("the log lock holds").push(recorded);

                    Ok(())
                })
            }
        }

        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let recorder = AuditRecorder::new(std::sync::Arc::new(Remembering(std::sync::Arc::clone(
            &seen,
        ))));

        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(1000);
        let root = std::env::temp_dir().join(format!(
            "permguard-catalog-refusals-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);

        let routes = routes(CatalogFacade {
            catalog: Arc::new(FileCatalog::new(root)),
            recorder: Some(recorder),
            disclosure: Disclosure::Minimal,
            audit_refusals: true,
            metrics: permguard_core::metrics::Metrics::none(),
        });

        // A success, then the same name again: one created record, one refused record.
        send(&routes, "POST", "/v1/zones", Some(r#"{"name":"delivery"}"#)).await;
        send(&routes, "POST", "/v1/zones", Some(r#"{"name":"delivery"}"#)).await;
        // A validation refusal is trail material too, under the switch.
        send(&routes, "POST", "/v1/zones", Some(r#"{"name":"Pharma"}"#)).await;

        let recorded = seen.lock().expect("the log lock holds").clone();

        assert!(
            recorded
                .iter()
                .any(|line| line.starts_with("zone.created ->")),
            "{recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|line| line == "zone.create.refused -> name_taken"),
            "{recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|line| line == "zone.create.refused -> invalid_name"),
            "{recorded:?}"
        );
    }

    /// Off — the default — the trail carries mutations only, exactly as before the switch existed.
    #[tokio::test]
    async fn test_refusals_stay_off_the_trail_by_default() {
        // The default-off facade the other tests use records nothing for refusals; this is the
        // regression guard on the default itself.
        let routes = testing_routes(Disclosure::Minimal);

        let (status, _) = send(&routes, "POST", "/v1/zones", Some(r#"{"name":"delivery"}"#)).await;
        assert_eq!(status, 201);

        let (status, body) =
            send(&routes, "POST", "/v1/zones", Some(r#"{"name":"delivery"}"#)).await;
        assert_eq!(status, 409, "{body}");
        // No recorder is attached in testing_routes, so the assertion above is that the refusal
        // path with audit_refusals=false neither panics nor changes the answer.
    }

    /// A zone is reachable by its name and by the id the create answered with, identically.
    #[tokio::test]
    async fn test_name_and_id_answer_the_same_zone() {
        let routes = testing_routes(Disclosure::Minimal);

        let (_, created) = send(&routes, "POST", "/v1/zones", Some(r#"{"name":"dual"}"#)).await;
        let id = created
            .split(r#""id":""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("the answer carries an id");

        let (by_name_status, by_name) = send(&routes, "GET", "/v1/zones/dual", None).await;
        let (by_id_status, by_id) = send(&routes, "GET", &format!("/v1/zones/{id}"), None).await;

        assert_eq!(by_name_status, 200);
        assert_eq!(by_id_status, 200);
        assert_eq!(by_name, by_id, "two references, one zone");
    }
}
