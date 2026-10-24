// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog's HTTP shape: routes, extraction, and nothing else.
//!
//! Every handler is the same three lines — extract, call the domain, shape the answer — because
//! everything that could be wrong lives below ([`super::zones`], [`super::ledgers`]) or beside
//! ([`crate::wire`]) this file. A handler with logic in it is a handler gRPC does not have.

use axum::body::Bytes;
use axum::extract::{FromRequest, Path, RawQuery, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use permguard_core::{ApiError, ErrorClass, codes};
use permguard_transport::ActorOf;

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
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/archive",
            post(archive_ledger),
        )
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/restore",
            post(restore_ledger),
        )
        .with_state(facade)
}

/// What a create or rename carries (WP-7.3a, owner decision of 2026-10-20): the name, the request
/// id a retry repeats, and for a rename the revision it expects. A closed body: a member it does
/// not name is refused, never ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameBody {
    name: String,
    request_id: String,
    #[serde(default)]
    expected_revision: Option<u64>,
}

/// A rename's expected revision, required; a create's refused, a new record having none.
fn revision_of(body: &NameBody, required: bool) -> Result<Option<u64>, ApiError> {
    match (body.expected_revision, required) {
        (Some(revision), true) => positive(revision).map(Some),
        (None, false) => Ok(None),
        (None, true) => Err(ApiError::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            "a change of a record names its `expected_revision`, the revision it was read at",
        )),
        (Some(_), false) => Err(ApiError::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            "a create has no `expected_revision`: the record does not exist yet",
        )),
    }
}

/// A delete's `request_id` and `expected_revision`, strict typed query parameters, both required.
fn deletion_of(query: Option<&str>) -> Result<(String, u64), ApiError> {
    let query = crate::query::parse(query, &["request_id", "expected_revision"], &[])?;
    let missing = |name: &str| {
        ApiError::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            format!("a delete names its `{name}`"),
        )
    };
    let request_id = query
        .value("request_id")
        .ok_or_else(|| missing("request_id"))?;
    let revision = query
        .number("expected_revision")?
        .ok_or_else(|| missing("expected_revision"))?;
    Ok((request_id, positive(revision)?))
}

/// A revision a change names: 1 or more, records starting at 1, so 0 names none and is refused.
fn positive(revision: u64) -> Result<u64, ApiError> {
    if revision == 0 {
        return Err(ApiError::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            "`expected_revision` is 1 or more: a record starts at revision 1",
        ));
    }
    Ok(revision)
}

/// A [`NameBody`] read from the request. A body that is not one — not declared
/// `application/json`, malformed JSON, a missing `name`, an unknown or repeated member — is
/// refused in the shared `{class, code, message}` shape as `invalid_argument`, not in the
/// extractor's own plain-text answer.
///
/// The media type is checked first and on purpose: a browser sends a `text/plain` POST
/// cross-site without a preflight, carrying the client certificate the catalog authenticates
/// with, so a body accepted whatever its type would let any page rename a zone.
struct Named(NameBody);

impl FromRequest<CatalogFacade> for Named {
    type Rejection = Response;

    async fn from_request(request: Request, facade: &CatalogFacade) -> Result<Self, Response> {
        closed(request, facade, "a name")
            .await
            .map(Named)
            .map_err(|refusal| *refusal)
    }
}

/// What an archive or a restore carries (WP-7.3b, owner decision of 2026-10-21): the request id
/// a retry repeats and the revision the ledger was read at, both required. Closed, as
/// [`NameBody`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateBody {
    request_id: String,
    expected_revision: u64,
}

/// A [`StateBody`] read from the request, refused as a [`Named`] body is.
struct Stating(StateBody);

impl FromRequest<CatalogFacade> for Stating {
    type Rejection = Response;

    async fn from_request(request: Request, facade: &CatalogFacade) -> Result<Self, Response> {
        closed(request, facade, "a state change")
            .await
            .map(Stating)
            .map_err(|refusal| *refusal)
    }
}

/// A closed JSON body of type `T`, `what` naming it in the refusal; the refusal boxed, being
/// a whole response.
async fn closed<T: serde::de::DeserializeOwned>(
    request: Request,
    facade: &CatalogFacade,
    what: &str,
) -> Result<T, Box<Response>> {
    let refuse = |message: String| {
        Box::new(wire::http_error(
            &ApiError::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                message,
            ),
            facade.disclosure,
        ))
    };
    let json = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return Err(refuse(
            "the body must be declared `Content-Type: application/json`".to_owned(),
        ));
    }
    let bytes = Bytes::from_request(request, facade)
        .await
        .map_err(|rejection| Box::new(rejection.into_response()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| refuse(format!("the body is not {what}: {error}")))
}

/// The paging a listing was asked for: `?page=1&size=50`, pages counted from 0. Absent means
/// all. Strict (WP-7.3a): a parameter nobody declared, one given twice, or a value that is not a
/// number is refused.
fn window_of(query: Option<&str>) -> Result<super::ListWindow, ApiError> {
    let query = crate::query::parse(query, &["page", "size"], &[])?;
    Ok(super::ListWindow::of(
        query.number("page")?,
        query.number("size")?,
    ))
}

/// Shapes a domain outcome the one way every route does.
fn answer<T: serde::Serialize>(
    facade: &CatalogFacade,
    status: StatusCode,
    outcome: Result<T, wire::Refusal>,
) -> Response {
    match outcome {
        Ok(payload) => (status, Json(payload)).into_response(),
        Err(refusal) => wire::http_refusal(&refusal, facade.disclosure),
    }
}

async fn create_zone(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Named(body): Named,
) -> Response {
    if let Err(error) = revision_of(&body, false) {
        return wire::http_error(&error, facade.disclosure);
    }
    let outcome = zones::create(&facade, &actor, &body.name, &body.request_id).await;

    answer(&facade, StatusCode::CREATED, outcome)
}

async fn list_zones(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let window = match window_of(query.as_deref()) {
        Ok(window) => window,
        Err(error) => return wire::http_error(&error, facade.disclosure),
    };
    answer(
        &facade,
        StatusCode::OK,
        zones::list(&facade, &actor, window),
    )
}

async fn get_zone(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path(zone): Path<String>,
) -> Response {
    answer(&facade, StatusCode::OK, zones::get(&facade, &actor, &zone))
}

async fn rename_zone(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path(zone): Path<String>,
    Named(body): Named,
) -> Response {
    let revision = match revision_of(&body, true) {
        Ok(revision) => revision.unwrap_or_default(),
        Err(error) => return wire::http_error(&error, facade.disclosure),
    };
    let outcome = zones::rename(
        &facade,
        &actor,
        &zone,
        &body.name,
        revision,
        &body.request_id,
    )
    .await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn delete_zone(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path(zone): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let (request_id, revision) = match deletion_of(query.as_deref()) {
        Ok(asked) => asked,
        Err(error) => return wire::http_error(&error, facade.disclosure),
    };
    let outcome = zones::delete(&facade, &actor, &zone, revision, &request_id).await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn create_ledger(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path(zone): Path<String>,
    Named(body): Named,
) -> Response {
    if let Err(error) = revision_of(&body, false) {
        return wire::http_error(&error, facade.disclosure);
    }
    let outcome = ledgers::create(&facade, &actor, &zone, &body.name, &body.request_id).await;

    answer(&facade, StatusCode::CREATED, outcome)
}

async fn list_ledgers(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path(zone): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    answer(
        &facade,
        StatusCode::OK,
        match window_of(query.as_deref()) {
            Ok(window) => ledgers::list(&facade, &actor, &zone, window),
            Err(error) => Err(error.into()),
        },
    )
}

async fn get_ledger(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
) -> Response {
    answer(
        &facade,
        StatusCode::OK,
        ledgers::get_served(&facade, &actor, &zone, &ledger),
    )
}

async fn rename_ledger(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    Named(body): Named,
) -> Response {
    let revision = match revision_of(&body, true) {
        Ok(revision) => revision.unwrap_or_default(),
        Err(error) => return wire::http_error(&error, facade.disclosure),
    };
    let outcome = ledgers::rename(
        &facade,
        &actor,
        &zone,
        &ledger,
        &body.name,
        revision,
        &body.request_id,
    )
    .await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn archive_ledger(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    Stating(body): Stating,
) -> Response {
    let revision = match positive(body.expected_revision) {
        Ok(revision) => revision,
        Err(error) => return wire::http_error(&error, facade.disclosure),
    };
    let outcome =
        ledgers::archive(&facade, &actor, &zone, &ledger, revision, &body.request_id).await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn restore_ledger(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    Stating(body): Stating,
) -> Response {
    let revision = match positive(body.expected_revision) {
        Ok(revision) => revision,
        Err(error) => return wire::http_error(&error, facade.disclosure),
    };
    let outcome =
        ledgers::restore(&facade, &actor, &zone, &ledger, revision, &body.request_id).await;

    answer(&facade, StatusCode::OK, outcome)
}

async fn delete_ledger(
    State(facade): State<CatalogFacade>,
    ActorOf(actor): ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let (request_id, revision) = match deletion_of(query.as_deref()) {
        Ok(asked) => asked,
        Err(error) => return wire::http_error(&error, facade.disclosure),
    };
    let outcome = ledgers::delete(&facade, &actor, &zone, &ledger, revision, &request_id).await;

    answer(&facade, StatusCode::OK, outcome)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// The routes behind the boundary every served surface has (WP-2.4): nobody presents a
    /// credential here, so every request is anonymous and the permissive authorization admits it.
    fn routes(facade: CatalogFacade) -> Router {
        super::routes(facade).layer(permguard_transport::ActorLayer::new(std::sync::Arc::new(
            permguard_core::NoRules,
        )))
    }
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
            host: None,
            authorization: std::sync::Arc::new(
                permguard_host::composition::Authorization::permissive(),
            ),
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
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

    /// A create or rename body naming `name`, under a request id no other call in the run uses.
    fn named(name: &str) -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        serde_json::json!({
            "name": name,
            "request_id": format!("named-{}", NEXT.fetch_add(1, Ordering::SeqCst)),
        })
        .to_string()
    }

    /// The status table in the wire module, proved row by row — and every refusal carries the same
    /// three fields: class, code, message.
    #[tokio::test]
    async fn test_every_refusal_is_the_shared_shape_with_the_promised_status() {
        let routes = testing_routes(Disclosure::Minimal);

        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 201, "{body}");
        assert!(body.contains(r#""name":"delivery""#), "{body}");

        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""class":"conflict""#), "{body}");
        assert!(body.contains(r#""code":"name_taken""#), "{body}");
        assert!(body.contains(r#""message":""#), "{body}");

        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("Pharma"))).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains(r#""class":"validation""#), "{body}");
        assert!(body.contains("lowercase"), "{body}");

        let (status, body) = send(&routes, "GET", "/v1/zones/nowhere", None).await;
        assert_eq!(status, 404, "{body}");
        assert!(body.contains(r#""class":"not_found""#), "{body}");

        let (status, body) = send(
            &routes,
            "POST",
            "/v1/zones/delivery/ledgers",
            Some(&named("policies")),
        )
        .await;
        assert_eq!(status, 201, "{body}");

        let (status, body) = send(
            &routes,
            "DELETE",
            "/v1/zones/delivery?request_id=r-delete&expected_revision=1",
            None,
        )
        .await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""code":"zone_not_empty""#), "{body}");
    }

    /// A create or rename body is closed: an unknown member, a repeated one, a missing `name` or
    /// `request_id`, a create naming a revision and malformed JSON are each refused as
    /// `invalid_argument` in the shared shape, and nothing is created (WP-7.3a).
    #[tokio::test]
    async fn test_a_name_body_is_closed_and_refused_in_the_shared_shape() {
        let routes = testing_routes(Disclosure::Minimal);
        for body in [
            r#"{"name":"delivery","request_id":"r-1","extra":1}"#,
            r#"{"name":"delivery","name":"other","request_id":"r-1"}"#,
            r#"{"request_id":"r-1"}"#,
            r#"{"name":"delivery"}"#,
            r#"{"name":"delivery","request_id":""}"#,
            r#"{"name":"delivery","request_id":"r-1","revision":1}"#,
            // A create names no revision: there is none to expect yet.
            r#"{"name":"delivery","request_id":"r-1","expected_revision":1}"#,
            r#"{"name":"#,
        ] {
            let (status, answer) = send(&routes, "POST", "/v1/zones", Some(body)).await;
            assert_eq!(status, 400, "{body}: {answer}");
            assert!(
                answer.contains(r#""class":"validation""#),
                "{body}: {answer}"
            );
            assert!(
                answer.contains(r#""code":"invalid_argument""#),
                "{body}: {answer}"
            );
        }
        // A cross-site `text/plain` POST needs no preflight; a body not declared JSON is refused
        // before it is read, and so is one that declares nothing.
        for media in [
            Some("text/plain"),
            Some("application/x-www-form-urlencoded"),
            None,
        ] {
            let mut request = HttpRequest::builder().method("POST").uri("/v1/zones");
            if let Some(media) = media {
                request = request.header("content-type", media);
            }
            let request = request
                .body(Body::from(r#"{"name":"delivery"}"#))
                .expect("a request builds");
            let answer = routes
                .clone()
                .oneshot(request)
                .await
                .expect("the router answers");
            assert_eq!(answer.status().as_u16(), 400, "{media:?}");
            let bytes = axum::body::to_bytes(answer.into_body(), 1 << 20)
                .await
                .expect("the body reads");
            let body = String::from_utf8_lossy(&bytes);
            assert!(
                body.contains(r#""code":"invalid_argument""#),
                "{media:?}: {body}"
            );
        }
        let (status, answer) = send(&routes, "GET", "/v1/zones/delivery", None).await;
        assert_eq!(status, 404, "nothing was created: {answer}");
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
            host: None,
            authorization: std::sync::Arc::new(
                permguard_host::composition::Authorization::permissive(),
            ),
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
            catalog: Arc::new(FileCatalog::new(root)),
            recorder: Some(crate::handles::audit_for_tests(recorder)),
            disclosure: Disclosure::Minimal,
            audit_refusals: true,
            metrics: permguard_core::metrics::Metrics::none(),
        });

        // A success, then the same name again: the success is the transaction's record, not this
        // trail's (WP-7.3a), the refusal is this trail's.
        send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        // A validation refusal is trail material too, under the switch.
        send(&routes, "POST", "/v1/zones", Some(&named("Pharma"))).await;

        let recorded = seen.lock().expect("the log lock holds").clone();

        assert!(
            !recorded.iter().any(|line| line.contains("zone.created")),
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

    /// What the transaction's phases land on, in a test: `(action, phase, target)` of each, and a
    /// phase to refuse.
    #[derive(Default)]
    struct Trail {
        records: std::sync::Mutex<Vec<(String, &'static str, Option<String>)>>,
        refuse: std::sync::Mutex<Option<&'static str>>,
    }

    impl permguard_host::operations::mutation::Projection for Trail {
        fn project(&self, event: &permguard_core::AuditEvent<'_>) -> Result<(), String> {
            let (_, phase) = event.operation().expect("every record names its operation");
            if *self.refuse.lock().expect("lock") == Some(phase.as_str()) {
                return Err("the trail is full".to_owned());
            }
            self.records.lock().expect("lock").push((
                event.action().to_owned(),
                phase.as_str(),
                event.target().map(str::to_owned),
            ));
            Ok(())
        }
    }

    /// A scratch directory of its own for each call.
    fn scratch(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(3000);
        let root = std::env::temp_dir().join(format!(
            "permguard-catalog-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// The routes over `catalog`, every change in a transaction over `trail` on `root`'s volume.
    fn transacted(
        root: &std::path::Path,
        catalog: Arc<dyn permguard_core::Catalog>,
        trail: &Arc<Trail>,
    ) -> Router {
        let mutations = crate::handles::catalog_mutations_over(
            &root.join("host"),
            Arc::clone(trail) as Arc<dyn permguard_host::operations::mutation::Projection>,
        );
        routes(CatalogFacade {
            host: None,
            authorization: Arc::new(permguard_host::composition::Authorization::permissive()),
            mutations: super::super::recovered(mutations, &catalog),
            catalog,
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::metrics::Metrics::none(),
        })
    }

    /// WP-7.8: under a backup barrier a catalog change is refused `unavailable`, nothing written;
    /// once the barrier is lowered the same request succeeds.
    #[tokio::test]
    async fn a_backup_barrier_holds_a_catalog_change() {
        let root = scratch("barrier");
        let trail = Arc::new(Trail::default());
        let catalog: Arc<dyn permguard_core::Catalog> =
            Arc::new(FileCatalog::new(root.join("catalog")));
        let volume = permguard_host::storage::volume::Volume::claim(
            &root.join("host"),
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("the volume");
        let engine = Arc::new(
            permguard_host::operations::mutation::Mutations::open(
                &volume,
                Arc::clone(&trail) as Arc<dyn permguard_host::operations::mutation::Projection>,
                Arc::new(permguard_host::time::TimeGuard::system(
                    std::time::Duration::from_secs(30),
                )),
            )
            .expect("the transaction"),
        );
        let mutations = permguard_host::composition::MutationHandle::new(
            Arc::clone(&engine),
            crate::catalog::CATALOG_DOMAIN,
        );
        let routes = routes(CatalogFacade {
            host: None,
            authorization: Arc::new(permguard_host::composition::Authorization::permissive()),
            mutations: super::super::recovered(mutations, &catalog),
            catalog: Arc::clone(&catalog),
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::metrics::Metrics::none(),
        });
        engine
            .quiesce(
                std::time::Instant::now() + std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(1),
            )
            .expect("the barrier");
        let (status, refused) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 503, "{refused}");
        assert!(refused.contains("\"unavailable\""), "{refused}");
        assert!(refused.contains("backup"), "{refused}");
        engine.release();
        let (status, created) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 201, "{created}");
    }

    /// WP-7.3a, owner decisions of 2026-10-20: a create, a rename and a delete are each an
    /// operation of the WP-3.6 transaction, an intent then an applied record under the phased
    /// `catalog.*` action, its target the record; the store keeps the operation id, the wire never
    /// carries it.
    #[tokio::test]
    async fn a_catalog_mutation_is_an_operation_of_the_transaction() {
        let root = scratch("transaction");
        let trail = Arc::new(Trail::default());
        let catalog: Arc<dyn permguard_core::Catalog> =
            Arc::new(FileCatalog::new(root.join("catalog")));
        let routes = transacted(&root, Arc::clone(&catalog), &trail);

        let (status, created) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 201, "{created}");
        let created: serde_json::Value = serde_json::from_str(&created).expect("JSON");
        assert_eq!(created["revision"], 1);
        assert!(created.get("operation").is_none(), "{created}");
        let id = created["id"].as_str().expect("an id").to_owned();
        let stored = catalog
            .get_zone(&permguard_core::Selector::Id(id.clone()))
            .expect("stored");
        assert_eq!(stored.operation.as_deref().map(str::len), Some(32));

        let rename = r#"{"name":"delivery-eu","request_id":"r-rename","expected_revision":1}"#;
        let (status, renamed) = send(&routes, "PATCH", "/v1/zones/delivery", Some(rename)).await;
        assert_eq!(status, 200, "{renamed}");
        assert!(renamed.contains(r#""revision":2"#), "{renamed}");
        let (status, deleted) = send(
            &routes,
            "DELETE",
            &format!("/v1/zones/{id}?request_id=r-delete&expected_revision=2"),
            None,
        )
        .await;
        assert_eq!(status, 200, "{deleted}");

        let zone = format!("zone/{id}");
        let expected: Vec<(String, &str, Option<String>)> = [
            ("catalog.zone.created", "intent", "zone-new"),
            ("catalog.zone.created", "applied", zone.as_str()),
            ("catalog.zone.renamed", "intent", zone.as_str()),
            ("catalog.zone.renamed", "applied", zone.as_str()),
            ("catalog.zone.deleted", "intent", zone.as_str()),
            ("catalog.zone.deleted", "applied", zone.as_str()),
        ]
        .into_iter()
        .map(|(action, phase, target)| (action.to_owned(), phase, Some(target.to_owned())))
        .collect();
        assert_eq!(*trail.records.lock().expect("lock"), expected);

        // A name the rules refuse is refused before any intent: nothing reaches the trail.
        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("Bad Name"))).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains(r#""code":"invalid_name""#), "{body}");
        assert_eq!(trail.records.lock().expect("lock").len(), 6, "no intent");
    }

    /// WP-7.3a, after the review: a retry of a rename or a delete learns the first answer,
    /// although that answer renamed or deleted what the request names.
    #[tokio::test]
    async fn a_retry_of_a_rename_or_a_delete_learns_the_first_answer() {
        let root = scratch("retry");
        let trail = Arc::new(Trail::default());
        let routes = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );
        send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        send(
            &routes,
            "POST",
            "/v1/zones/delivery/ledgers",
            Some(&named("policies")),
        )
        .await;
        send(
            &routes,
            "POST",
            "/v1/zones/delivery/ledgers",
            Some(&named("rules")),
        )
        .await;

        let twice = |method: &'static str, uri: &'static str, body: Option<&'static str>| {
            let routes = routes.clone();
            async move {
                let first = send(&routes, method, uri, body).await;
                let again = send(&routes, method, uri, body).await;
                assert_eq!(first.0, 200, "{uri}: {}", first.1);
                assert_eq!(first, again, "{uri}: the first answer");
            }
        };
        twice(
            "PATCH",
            "/v1/zones/delivery/ledgers/policies",
            Some(r#"{"name":"policies-v2","request_id":"r-ledger-rename","expected_revision":1}"#),
        )
        .await;
        twice(
            "DELETE",
            "/v1/zones/delivery/ledgers/rules?request_id=r-ledger-delete&expected_revision=1",
            None,
        )
        .await;
        twice(
            "DELETE",
            "/v1/zones/delivery/ledgers/policies-v2?request_id=r-ledger-delete-2&expected_revision=2",
            None,
        )
        .await;
        twice(
            "PATCH",
            "/v1/zones/delivery",
            Some(r#"{"name":"delivery-eu","request_id":"r-zone-rename","expected_revision":1}"#),
        )
        .await;
        twice(
            "DELETE",
            "/v1/zones/delivery-eu?request_id=r-zone-delete&expected_revision=2",
            None,
        )
        .await;
        // One operation each: an intent and an applied record, nothing applied twice.
        let applied = trail
            .records
            .lock()
            .expect("lock")
            .iter()
            .filter(|(_, phase, _)| *phase == "applied")
            .count();
        assert_eq!(applied, 3 + 5);
    }

    /// WP-7.3b, owner decision of 2026-10-21: a ledger is archived and restored by its own verbs,
    /// each an operation of the transaction, held to the revision expected and answered again to
    /// a retry; the body is closed.
    #[tokio::test]
    async fn a_ledger_is_archived_and_restored_through_the_transaction() {
        let root = scratch("archive");
        let trail = Arc::new(Trail::default());
        let routes = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );
        send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        send(
            &routes,
            "POST",
            "/v1/zones/delivery/ledgers",
            Some(&named("policies")),
        )
        .await;
        let base = "/v1/zones/delivery/ledgers/policies";

        let (status, archived) = send(
            &routes,
            "POST",
            &format!("{base}/archive"),
            Some(r#"{"request_id":"r-archive","expected_revision":1}"#),
        )
        .await;
        assert_eq!(status, 200, "{archived}");
        let read: serde_json::Value = serde_json::from_str(&archived).expect("JSON");
        assert_eq!(
            (read["state"].as_str(), read["revision"].as_u64()),
            (Some("archived"), Some(2))
        );
        let (_, again) = send(
            &routes,
            "POST",
            &format!("{base}/archive"),
            Some(r#"{"request_id":"r-archive","expected_revision":1}"#),
        )
        .await;
        assert_eq!(again, archived, "a retry learns the first answer");
        let (_, got) = send(&routes, "GET", base, None).await;
        assert!(got.contains(r#""state":"archived""#), "{got}");

        for (body, code) in [
            (r#"{"request_id":"r-stale","expected_revision":1}"#, 409),
            (r#"{"request_id":"r-zero","expected_revision":0}"#, 400),
            (r#"{"request_id":"r-open"}"#, 400),
            (
                r#"{"request_id":"r-more","expected_revision":2,"state":"active"}"#,
                400,
            ),
        ] {
            let (status, answer) =
                send(&routes, "POST", &format!("{base}/restore"), Some(body)).await;
            assert_eq!(status, code, "{body}: {answer}");
        }
        let (status, restored) = send(
            &routes,
            "POST",
            &format!("{base}/restore"),
            Some(r#"{"request_id":"r-restore","expected_revision":2}"#),
        )
        .await;
        assert_eq!(status, 200, "{restored}");
        assert!(restored.contains(r#""state":"active""#), "{restored}");
        assert!(restored.contains(r#""revision":3"#), "{restored}");

        let phases: Vec<(String, &str)> = trail
            .records
            .lock()
            .expect("lock")
            .iter()
            .filter(|(action, _, _)| {
                action.starts_with("catalog.ledger.a") || action.starts_with("catalog.ledger.r")
            })
            .map(|(action, phase, _)| (action.clone(), *phase))
            .collect();
        assert_eq!(
            phases,
            vec![
                ("catalog.ledger.archived".to_owned(), "intent"),
                ("catalog.ledger.archived".to_owned(), "applied"),
                ("catalog.ledger.restored".to_owned(), "intent"),
                ("catalog.ledger.restored".to_owned(), "failed"),
                ("catalog.ledger.restored".to_owned(), "intent"),
                ("catalog.ledger.restored".to_owned(), "applied"),
            ],
            "the stale restore is an operation that failed; the malformed ones never began"
        );
    }

    /// WP-7.3a: a Host that composes no mutation transaction refuses every change `503`
    /// `unavailable`, and still answers reads.
    #[tokio::test]
    async fn without_the_transaction_every_change_is_unavailable() {
        let root = scratch("untransacted");
        let routes = routes(CatalogFacade {
            host: None,
            authorization: Arc::new(permguard_host::composition::Authorization::permissive()),
            mutations: None,
            catalog: Arc::new(FileCatalog::new(root.join("catalog"))),
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::metrics::Metrics::none(),
        });
        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 503, "{body}");
        assert!(body.contains(r#""code":"unavailable""#), "{body}");
        let (status, body) = send(
            &routes,
            "DELETE",
            "/v1/zones/delivery?request_id=r-1&expected_revision=1",
            None,
        )
        .await;
        assert_eq!(status, 503, "{body}");
        let (status, body) = send(&routes, "GET", "/v1/zones", None).await;
        assert_eq!((status, body.as_str()), (200, "[]"));
    }

    /// WP-7.3a: a retry of a create with the same request id learns the first answer, applying
    /// nothing twice.
    #[tokio::test]
    async fn a_retry_with_the_same_request_id_learns_the_first_answer() {
        let root = scratch("replay");
        let trail = Arc::new(Trail::default());
        let routes = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );

        let body = r#"{"name":"delivery","request_id":"r-once"}"#;
        let (first_status, first) = send(&routes, "POST", "/v1/zones", Some(body)).await;
        let (again_status, again) = send(&routes, "POST", "/v1/zones", Some(body)).await;
        assert_eq!((first_status, again_status), (201, 201), "{again}");
        assert_eq!(first, again, "the first answer, not a second zone");
        let (_, listed) = send(&routes, "GET", "/v1/zones", None).await;
        assert_eq!(
            listed.matches(r#""name":"delivery""#).count(),
            1,
            "{listed}"
        );
        assert_eq!(
            trail.records.lock().expect("lock").len(),
            2,
            "one operation"
        );
    }

    /// WP-7.3a: the same request id for another body is `409 request_id_reused`, nothing applied.
    #[tokio::test]
    async fn a_request_id_reused_for_another_body_is_refused() {
        let root = scratch("reused");
        let trail = Arc::new(Trail::default());
        let routes = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );

        let (status, _) = send(
            &routes,
            "POST",
            "/v1/zones",
            Some(r#"{"name":"alpha","request_id":"r-same"}"#),
        )
        .await;
        assert_eq!(status, 201);
        let (status, body) = send(
            &routes,
            "POST",
            "/v1/zones",
            Some(r#"{"name":"beta","request_id":"r-same"}"#),
        )
        .await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""code":"request_id_reused""#), "{body}");
        let (status, _) = send(&routes, "GET", "/v1/zones/beta", None).await;
        assert_eq!(status, 404, "nothing applied");
    }

    /// WP-7.3a, owner decision of 2026-10-20: a rename or a delete against another revision than
    /// the record's is `409 revision_conflict` and changes nothing; a rename without one is
    /// refused.
    #[tokio::test]
    async fn a_stale_revision_over_rest_is_a_conflict_and_changes_nothing() {
        let root = scratch("revision");
        let trail = Arc::new(Trail::default());
        let routes = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );
        send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        send(
            &routes,
            "POST",
            "/v1/zones/delivery/ledgers",
            Some(&named("policies")),
        )
        .await;

        let rename = |name: &str, revision: u64, id: &str| {
            format!(r#"{{"name":"{name}","request_id":"{id}","expected_revision":{revision}}}"#)
        };
        let (status, body) = send(
            &routes,
            "PATCH",
            "/v1/zones/delivery",
            Some(&rename("other", 2, "r-1")),
        )
        .await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""class":"conflict""#), "{body}");
        assert!(body.contains(r#""code":"revision_conflict""#), "{body}");
        let (status, body) = send(
            &routes,
            "PATCH",
            "/v1/zones/delivery",
            Some(r#"{"name":"other","request_id":"r-2"}"#),
        )
        .await;
        assert_eq!(status, 400, "a rename names its revision: {body}");
        let (status, body) = send(
            &routes,
            "PATCH",
            "/v1/zones/delivery/ledgers/policies",
            Some(&rename("rules", 3, "r-3")),
        )
        .await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""code":"revision_conflict""#), "{body}");
        let (status, body) = send(
            &routes,
            "DELETE",
            "/v1/zones/delivery/ledgers/policies?request_id=r-4&expected_revision=2",
            None,
        )
        .await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains(r#""code":"revision_conflict""#), "{body}");

        let (_, zone) = send(&routes, "GET", "/v1/zones/delivery", None).await;
        assert!(zone.contains(r#""revision":1"#), "unchanged: {zone}");
        let (status, ledger) =
            send(&routes, "GET", "/v1/zones/delivery/ledgers/policies", None).await;
        assert_eq!(status, 200, "still there: {ledger}");
        assert!(ledger.contains(r#""revision":1"#), "unchanged: {ledger}");

        let (status, body) = send(
            &routes,
            "PATCH",
            "/v1/zones/delivery/ledgers/policies",
            Some(&rename("rules", 1, "r-5")),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains(r#""revision":2"#), "{body}");
    }

    /// WP-7.3 step 3: a listing's and a delete's query parameters are strict, unique and typed; a
    /// delete names its request id and revision.
    #[tokio::test]
    async fn an_unknown_duplicated_or_malformed_parameter_is_refused() {
        let routes = testing_routes(Disclosure::Minimal);
        send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;

        for uri in [
            "/v1/zones?pages=1",
            "/v1/zones?page=1&page=2",
            "/v1/zones?page=x",
            "/v1/zones?size=-1",
            "/v1/zones/delivery/ledgers?limit=1",
        ] {
            let (status, body) = send(&routes, "GET", uri, None).await;
            assert_eq!(status, 400, "{uri}: {body}");
            assert!(
                body.contains(r#""code":"invalid_argument""#),
                "{uri}: {body}"
            );
        }
        for uri in [
            "/v1/zones/delivery",
            "/v1/zones/delivery?request_id=r-1",
            "/v1/zones/delivery?expected_revision=1",
            "/v1/zones/delivery?request_id=r-1&expected_revision=x",
            "/v1/zones/delivery?request_id=r-1&expected_revision=0",
            "/v1/zones/delivery?request_id=r-1&request_id=r-2&expected_revision=1",
            "/v1/zones/delivery?request_id=r-1&expected_revision=1&force=true",
        ] {
            let (status, body) = send(&routes, "DELETE", uri, None).await;
            assert_eq!(status, 400, "{uri}: {body}");
            assert!(
                body.contains(r#""code":"invalid_argument""#),
                "{uri}: {body}"
            );
        }
        let (status, _) = send(&routes, "GET", "/v1/zones/delivery", None).await;
        assert_eq!(status, 200, "nothing deleted");
        let (status, body) = send(&routes, "GET", "/v1/zones?page=0&size=1", None).await;
        assert_eq!(status, 200, "{body}");
    }

    /// A catalog that writes, then reports a failure for a create or a delete: an answer lost
    /// after the write landed.
    struct LosingAnswers(FileCatalog);

    use permguard_core::catalog::CatalogError;

    impl permguard_core::Catalog for LosingAnswers {
        fn name(&self) -> &'static str {
            "losing-answers"
        }
        fn create_zone_with(
            &self,
            name: &str,
            write: &permguard_core::catalog::Write<'_>,
        ) -> Result<permguard_core::Zone, CatalogError> {
            self.0.create_zone_with(name, write)?;
            Err(CatalogError::backend("the answer was lost"))
        }
        fn list_zones(&self) -> Result<Vec<permguard_core::Zone>, CatalogError> {
            self.0.list_zones()
        }
        fn get_zone(
            &self,
            zone: &permguard_core::Selector,
        ) -> Result<permguard_core::Zone, CatalogError> {
            self.0.get_zone(zone)
        }
        fn rename_zone_with(
            &self,
            zone: &permguard_core::Selector,
            name: &str,
            write: &permguard_core::catalog::Write<'_>,
        ) -> Result<permguard_core::Zone, CatalogError> {
            self.0.rename_zone_with(zone, name, write)
        }
        fn delete_zone_with(
            &self,
            zone: &permguard_core::Selector,
            write: &permguard_core::catalog::Write<'_>,
        ) -> Result<permguard_core::Zone, CatalogError> {
            self.0.delete_zone_with(zone, write)?;
            Err(CatalogError::backend("the answer was lost"))
        }
        fn create_ledger_with(
            &self,
            zone: &permguard_core::Selector,
            name: &str,
            write: &permguard_core::catalog::Write<'_>,
        ) -> Result<permguard_core::Ledger, CatalogError> {
            self.0.create_ledger_with(zone, name, write)
        }
        fn list_ledgers(
            &self,
            zone: &permguard_core::Selector,
        ) -> Result<Vec<permguard_core::Ledger>, CatalogError> {
            self.0.list_ledgers(zone)
        }
        fn get_ledger(
            &self,
            zone: &permguard_core::Selector,
            ledger: &permguard_core::Selector,
        ) -> Result<permguard_core::Ledger, CatalogError> {
            self.0.get_ledger(zone, ledger)
        }
        fn rename_ledger_with(
            &self,
            zone: &permguard_core::Selector,
            ledger: &permguard_core::Selector,
            name: &str,
            write: &permguard_core::catalog::Write<'_>,
        ) -> Result<permguard_core::Ledger, CatalogError> {
            self.0.rename_ledger_with(zone, ledger, name, write)
        }
        fn delete_ledger_with(
            &self,
            zone: &permguard_core::Selector,
            ledger: &permguard_core::Selector,
            write: &permguard_core::catalog::Write<'_>,
        ) -> Result<permguard_core::Ledger, CatalogError> {
            self.0.delete_ledger_with(zone, ledger, write)
        }
        fn set_ledger_state_with(
            &self,
            zone: &permguard_core::Selector,
            ledger: &permguard_core::Selector,
            state: permguard_core::LedgerState,
            write: &permguard_core::catalog::Write<'_>,
        ) -> Result<permguard_core::Ledger, CatalogError> {
            self.0.set_ledger_state_with(zone, ledger, state, write)
        }
        fn zone_tombstone(
            &self,
            zone_id: &str,
        ) -> Result<Option<permguard_core::Tombstone>, CatalogError> {
            self.0.zone_tombstone(zone_id)
        }
        fn ledger_tombstone(
            &self,
            zone_id: &str,
            ledger_id: &str,
        ) -> Result<Option<permguard_core::Tombstone>, CatalogError> {
            self.0.ledger_tombstone(zone_id, ledger_id)
        }
    }

    /// WP-7.3a, owner decision of 2026-10-20: a create whose answer was lost after the write is
    /// left open, `mutation_unrecorded`; the next start finds the record carrying the operation and
    /// commits it, and the retry with the same request id learns the zone, not a second one.
    #[tokio::test]
    async fn an_operation_a_crash_left_open_is_resolved_at_start() {
        let root = scratch("recovery");
        let trail = Arc::new(Trail::default());
        let body = r#"{"name":"delivery","request_id":"r-lost"}"#;
        {
            let losing = transacted(
                &root,
                Arc::new(LosingAnswers(FileCatalog::new(root.join("catalog")))),
                &trail,
            );
            let (status, answer) = send(&losing, "POST", "/v1/zones", Some(body)).await;
            assert_eq!(status, 500, "{answer}");
            assert!(
                answer.contains(r#""code":"mutation_unrecorded""#),
                "{answer}"
            );
        }

        let restarted = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );
        assert!(
            trail
                .records
                .lock()
                .expect("lock")
                .iter()
                .any(
                    |(action, phase, _)| action == "catalog.zone.created" && *phase == "reconciled"
                ),
            "{:?}",
            trail.records.lock().expect("lock")
        );
        let (status, answer) = send(&restarted, "POST", "/v1/zones", Some(body)).await;
        assert_eq!(status, 201, "{answer}");
        let (_, got) = send(&restarted, "GET", "/v1/zones/delivery", None).await;
        let id = |json: &str| {
            serde_json::from_str::<serde_json::Value>(json).expect("JSON")["id"].clone()
        };
        assert_eq!(id(&answer), id(&got), "the zone the lost answer named");
        let (_, listed) = send(&restarted, "GET", "/v1/zones", None).await;
        assert_eq!(
            listed.matches(r#""name":"delivery""#).count(),
            1,
            "{listed}"
        );
        drop(restarted);

        // A delete whose answer was lost is reconciled at the next start from its tombstone, which
        // names the operation (WP-7.3b); its retry is answered as the zone being gone, the record
        // the first answer carried no longer existing.
        let id = id(&got);
        let id = id.as_str().expect("an id");
        let delete = format!("/v1/zones/{id}?request_id=r-gone&expected_revision=1");
        {
            let losing = transacted(
                &root,
                Arc::new(LosingAnswers(FileCatalog::new(root.join("catalog")))),
                &trail,
            );
            let (status, answer) = send(&losing, "DELETE", &delete, None).await;
            assert_eq!(status, 500, "{answer}");
        }
        let restarted = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );
        assert!(
            trail
                .records
                .lock()
                .expect("lock")
                .iter()
                .any(
                    |(action, phase, _)| action == "catalog.zone.deleted" && *phase == "reconciled"
                ),
            "{:?}",
            trail.records.lock().expect("lock")
        );
        let (status, answer) = send(&restarted, "DELETE", &delete, None).await;
        assert_eq!(status, 404, "{answer}");
    }

    /// WP-3.6 through WP-7.3a: an intent whose audit record fails changes nothing and answers
    /// `audit_unavailable`; a change whose applied record fails stands and answers
    /// `mutation_unrecorded`, never success; a refusal stays the refusal.
    #[tokio::test]
    async fn test_a_change_whose_record_fails_is_unrecorded_and_stands() {
        let root = scratch("unrecorded");
        let trail = Arc::new(Trail::default());
        let routes = transacted(
            &root,
            Arc::new(FileCatalog::new(root.join("catalog"))),
            &trail,
        );

        *trail.refuse.lock().expect("lock") = Some("intent");
        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 503, "{body}");
        assert!(body.contains(r#""code":"audit_unavailable""#), "{body}");
        let (status, _) = send(&routes, "GET", "/v1/zones/delivery", None).await;
        assert_eq!(status, 404, "nothing was made");

        *trail.refuse.lock().expect("lock") = Some("applied");
        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 500, "{body}");
        assert!(body.contains(r#""code":"mutation_unrecorded""#), "{body}");
        let (status, body) = send(&routes, "GET", "/v1/zones/delivery", None).await;
        assert_eq!(status, 200, "the zone stands: {body}");

        *trail.refuse.lock().expect("lock") = None;
        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 409, "a refusal stays a refusal: {body}");
    }

    /// Off — the default — the trail carries mutations only, exactly as before the switch existed.
    #[tokio::test]
    async fn test_refusals_stay_off_the_trail_by_default() {
        // The default-off facade the other tests use records nothing for refusals; this is the
        // regression guard on the default itself.
        let routes = testing_routes(Disclosure::Minimal);

        let (status, _) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 201);

        let (status, body) = send(&routes, "POST", "/v1/zones", Some(&named("delivery"))).await;
        assert_eq!(status, 409, "{body}");
        // No recorder is attached in testing_routes, so the assertion above is that the refusal
        // path with audit_refusals=false neither panics nor changes the answer.
    }

    /// A zone is reachable by its name and by the id the create answered with, identically.
    #[tokio::test]
    async fn test_name_and_id_answer_the_same_zone() {
        let routes = testing_routes(Disclosure::Minimal);

        let (_, created) = send(&routes, "POST", "/v1/zones", Some(&named("dual"))).await;
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

    /// `contracts/openapi/catalog.json`: every schema of the document, from the real types.
    ///
    /// `NameBody` is private to this module and only deserialises, so it is built by parsing the
    /// JSON a client sends and checked as that same JSON; `Zone` and `Ledger` are the public
    /// types, built through the catalog itself. The one `assert_covered` of the document lives
    /// here because this is the only place that sees all three.
    /// A member serving a ledger, with every optional member when `full`.
    fn serving_member(full: bool) -> super::super::serving::ServingMember {
        use permguard_host::api::members::{
            AssuranceView, ClaimView, ServingMemberView, ServingProgressView,
        };
        ServingMemberView {
            host_id: "01a3185c-5000-7111-9111-111111111111".to_owned(),
            membership_id: "01a3185c-5000-7444-8444-444444444444".to_owned(),
            task_id: "mirror".to_owned(),
            declared_assurance: "production".to_owned(),
            assurance_binding_status: full.then(|| AssuranceView {
                verdict: "accepted".to_owned(),
                current: true,
                policy_revision: "sha256:00".to_owned(),
                task_ids: vec!["mirror".to_owned()],
                claims: vec![ClaimView {
                    control: "custody.hsm".to_owned(),
                    class: "attested".to_owned(),
                    by: "tpm-quote".to_owned(),
                }],
                appraised_by: "spiffe://acme/operators/root".to_owned(),
                issued_at: "2027-01-15T00:00:00Z".to_owned(),
                expires_at: "2027-02-14T00:00:00Z".to_owned(),
                binding_digest: "sha256:11".to_owned(),
            }),
            lease_state: if full { "live" } else { "none" }.to_owned(),
            last_session_at: full.then(|| "2027-01-15T00:00:20Z".to_owned()),
            progress: full.then(|| ServingProgressView {
                report_seq: 7,
                reported_at: "2027-01-15T00:00:40Z".to_owned(),
                received_at: "2027-01-15T00:00:41Z".to_owned(),
                state: Some("serving".to_owned()),
                checkpoint_digest: Some("sha256:22".to_owned()),
                stale: false,
            }),
        }
        .into()
    }

    #[test]
    fn test_the_catalog_wire_types_match_openapi_catalog() {
        use permguard_conformance::schema::Document;
        use permguard_core::{Catalog, Selector};

        let doc = Document::load("catalog.json");

        let sent = serde_json::json!({"name": "delivery", "request_id": "r-1"});
        let body: NameBody = serde_json::from_value(sent.clone()).expect("a name body parses");
        assert_eq!(body.name, "delivery");
        doc.check_json("NameBody", &sent);
        // The schema and the type refuse the same bodies: an unknown member, a missing name.
        doc.check_json(
            "NameBody",
            &serde_json::json!({"name": "delivery", "request_id": "r-2", "expected_revision": 1}),
        );
        for refused in [
            serde_json::json!({"name": "x", "request_id": "r-1", "extra": 1}),
            serde_json::json!({"request_id": "r-1"}),
            serde_json::json!({"name": "x"}),
            serde_json::json!({}),
        ] {
            assert!(!doc.accepts_json("NameBody", &refused), "{refused}");
            assert!(
                serde_json::from_value::<NameBody>(refused.clone()).is_err(),
                "{refused}"
            );
        }

        // An archive's or a restore's body, closed as a name's (WP-7.3b).
        let sent = serde_json::json!({"request_id": "r-1", "expected_revision": 2});
        let body: StateBody = serde_json::from_value(sent.clone()).expect("a state body parses");
        assert_eq!(
            (body.request_id.as_str(), body.expected_revision),
            ("r-1", 2)
        );
        doc.check_json("StateBody", &sent);
        for refused in [
            serde_json::json!({"request_id": "r-1"}),
            serde_json::json!({"expected_revision": 1}),
            serde_json::json!({"request_id": "r-1", "expected_revision": 1, "state": "archived"}),
        ] {
            assert!(!doc.accepts_json("StateBody", &refused), "{refused}");
            assert!(
                serde_json::from_value::<StateBody>(refused.clone()).is_err(),
                "{refused}"
            );
        }

        let root =
            std::env::temp_dir().join(format!("permguard-catalog-openapi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let catalog = FileCatalog::new(root);
        let zone = catalog.create_zone("delivery").expect("a zone is created");
        let ledger = catalog
            .create_ledger(&Selector::parse("delivery"), "policies")
            .expect("a ledger is created");

        doc.check("Zone", &zone);
        doc.check("Ledger", &ledger);
        // `GetLedger`'s answer: the ledger with a member serving it, every optional member
        // present, then one with none (WP-4.4).
        let served = super::super::serving::LedgerServed {
            ledger: ledger.clone(),
            serving_members: vec![serving_member(true), serving_member(false)],
        };
        doc.check("Ledger", &served);

        doc.assert_covered();
    }

    /// WP-4.4: `GET …/ledgers/{ledger}` answers the members the Host's composition names for the
    /// ledger's resource, the same rows a gRPC `GetLedger` carries; a list or a create carries
    /// none, and a plane that does not provide `policy.mirror` is handed none.
    #[tokio::test]
    async fn get_ledger_lists_the_members_serving_it_with_their_reported_progress() {
        use permguard_host::composition::{Declaration, Host, ServingMembers};
        use permguard_host::membership::record::TaskType;

        /// Names one member for exactly the resource it was told about.
        struct Named(std::sync::Mutex<Option<permguard_core::authz::Resource>>);

        impl ServingMembers for Named {
            fn serving_members(
                &self,
                resource: &permguard_core::authz::Resource,
            ) -> Vec<permguard_host::api::members::ServingMemberView> {
                *self.0.lock().expect("lock") = Some(resource.clone());
                vec![permguard_host::api::members::ServingMemberView {
                    host_id: "member".to_owned(),
                    membership_id: "membership".to_owned(),
                    task_id: "mirror".to_owned(),
                    declared_assurance: "production".to_owned(),
                    assurance_binding_status: None,
                    lease_state: "live".to_owned(),
                    last_session_at: Some("2027-01-15T00:00:20Z".to_owned()),
                    progress: None,
                }]
            }
        }

        let named = Arc::new(Named(std::sync::Mutex::new(None)));
        let host = Host::builder()
            .memberships(Arc::clone(&named) as Arc<dyn ServingMembers>)
            .build();
        let provider = host
            .register(Declaration::new("control").handles_task(TaskType::PolicyMirror, 1))
            .expect("registered");
        let other = host
            .register(Declaration::new("data").uses_task(TaskType::PolicyMirror, 1))
            .expect("registered");
        assert!(
            other
                .serving_members(
                    &permguard_core::authz::Resource::parse("plane/data").expect("a resource")
                )
                .is_empty(),
            "a plane that does not provide the mirror is handed nobody"
        );

        let root =
            std::env::temp_dir().join(format!("permguard-catalog-serving-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let routes = routes(CatalogFacade {
            host: Some(Arc::new(provider)),
            authorization: Arc::new(permguard_host::composition::Authorization::permissive()),
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
            catalog: Arc::new(FileCatalog::new(root)),
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::metrics::Metrics::none(),
        });
        let (_, created) = send(
            &routes,
            "POST",
            "/v1/zones",
            Some(&super::tests::named("delivery")),
        )
        .await;
        let zone: serde_json::Value = serde_json::from_str(&created).expect("json");
        let (_, created) = send(
            &routes,
            "POST",
            "/v1/zones/delivery/ledgers",
            Some(&super::tests::named("policies")),
        )
        .await;
        let ledger: serde_json::Value = serde_json::from_str(&created).expect("json");
        assert!(
            ledger.get("serving_members").is_none(),
            "a create carries none"
        );

        let (status, body) =
            send(&routes, "GET", "/v1/zones/delivery/ledgers/policies", None).await;
        assert_eq!(status, 200, "{body}");
        let got: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(got["id"], ledger["id"]);
        assert_eq!(got["serving_members"][0]["task_id"], "mirror");
        assert_eq!(got["serving_members"][0]["lease_state"], "live");
        assert_eq!(
            named.0.lock().expect("lock").clone(),
            Some(super::super::ledger_resource(
                zone["id"].as_str().expect("an id"),
                ledger["id"].as_str().expect("an id")
            )),
            "asked about the ledger's own resource"
        );
    }
}
