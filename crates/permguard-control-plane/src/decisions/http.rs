// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision log's HTTP shape: one route to ship, and scoped routes to read.
//!
//! ```text
//! POST /decisions/v1/batches                                     ship
//! GET  /decisions/v1/records                                     read, deployment-wide
//! GET  /zones/{zone}/ledgers/{ledger}/decisions/v1/records       read, one tenant
//! ```
//!
//! The deployment-wide route exists because somebody has to be able to verify a
//! whole producer stream. It is the most powerful read in the system — every
//! tenant's decisions, which is *who accessed what* — and it is the one place
//! the two dimensions meet. When tokens arrive it must not be reachable by the
//! grant that reads one zone.

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use permguard_core::{ApiError, Disclosure, ErrorClass, Jwk, KeyManager, Metrics};
use permguard_decisions::envelope::Batch;
use serde::Serialize;

use super::store::{DecisionStore, Scope};
use super::{Accepted, Refused, ingest, measure, read};
use crate::wire;

/// Everything the routes need, resolved once.
#[derive(Clone)]
pub struct DecisionFacade {
    /// Where records are kept.
    pub store: Arc<DecisionStore>,
    /// The ring of a producer that shares this process — the all-in-one shape.
    ///
    /// A batch is signed by the plane that decided, never by this one, so this
    /// is a *producer's* ring that happens to be here rather than this plane's
    /// own. A control plane with no such neighbour has none.
    pub local: Option<Arc<dyn KeyManager>>,
    /// The published key sets of the producers this plane accepts, from the
    /// file. Never fetched: ingestion must not depend on reaching the planes
    /// that are shipping to it.
    ///
    /// Re-read when a batch cannot be attributed, so a producer that rotates
    /// its ring is a file to update rather than a plane to restart. Behind a
    /// lock because that re-read happens on a request.
    pub producers: std::sync::Arc<std::sync::RwLock<Vec<Jwk>>>,
    /// Where those sets are read from.
    pub producer_files: Vec<std::path::PathBuf>,
    /// How much a refusal says about the inside.
    pub disclosure: Disclosure,
    /// What to count.
    pub metrics: Metrics,
}

impl DecisionFacade {
    /// Every key a producer's batch may legitimately be signed by.
    ///
    /// The union of what the file declares and what a producer sharing this
    /// process publishes. Never this plane's own signing ring: a control plane
    /// that verified against itself would accept anything it could have
    /// written, which is the opposite of what the signature is for.
    pub(crate) fn accepted_keys(&self) -> anyhow::Result<Vec<Jwk>> {
        let mut keys = self
            .producers
            .read()
            .map(|held| held.clone())
            .unwrap_or_default();
        if let Some(local) = &self.local {
            keys.extend(local.public_keys()?);
        }

        Ok(keys)
    }

    /// Re-reads the producers' key sets from disk.
    ///
    /// Called when, and only when, a batch could not be attributed: a producer
    /// that rotated its ring publishes a new key, and a control plane that
    /// only read the file at startup would refuse everything it signs until
    /// somebody restarts the plane. Doing it on the failure rather than on a
    /// timer keeps the cost where the need is — a plane whose producers are
    /// stable never reads the files again.
    ///
    /// A forged batch cannot use this to make a plane re-read the world in a
    /// loop: an unattributable batch is refused either way, and the re-read is
    /// a handful of small local files.
    /// Where this producer stream now stands, for the gauge both surfaces feed.
    pub(crate) fn publish_acked(&self, batch: &permguard_decisions::envelope::Batch, acked: u64) {
        if let Ok(envelope) = batch.signature.envelope() {
            self.metrics.set(
                &measure::ACKED,
                &[
                    ("pdp", envelope.stream.id.as_str()),
                    ("instance", envelope.stream.instance.as_str()),
                ],
                acked as f64,
            );
        }
    }

    pub(crate) fn reload_producers(&self) -> Vec<Jwk> {
        let mut keys = Vec::new();
        for path in &self.producer_files {
            let parsed = std::fs::read_to_string(path)
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
            let Some(parsed) = parsed else {
                continue;
            };
            let set = parsed.get("keys").cloned().unwrap_or(parsed);
            if let Ok(found) = serde_json::from_value::<Vec<Jwk>>(set) {
                keys.extend(found);
            }
        }
        if let Ok(mut held) = self.producers.write() {
            held.clone_from(&keys);
        }
        if let Some(local) = &self.local
            && let Ok(published) = local.public_keys()
        {
            keys.extend(published);
        }

        keys
    }
}

/// The routes the control plane answers about decisions.
pub(crate) fn routes(facade: DecisionFacade) -> Router {
    Router::new()
        .route("/decisions/v1/batches", post(ship))
        .route("/decisions/v1/records", get(records))
        .route(
            "/zones/{zone}/ledgers/{ledger}/decisions/v1/records",
            get(tenant_records),
        )
        .with_state(facade)
}

/// What a producer is told about its batch.
#[derive(Debug, Serialize)]
struct Acknowledgement {
    /// The highest contiguous durable sequence. The producer truncates by this.
    acked: u64,
    /// How many records this call added.
    stored: u64,
}

/// What a producer that ran ahead is told.
#[derive(Debug, Serialize)]
struct OutOfOrder {
    /// The class of the answer, so a client need not match on prose.
    status: &'static str,
    /// Where to resume from.
    expected_seq: u64,
}

async fn ship(State(facade): State<DecisionFacade>, body: axum::body::Bytes) -> Response {
    let started = std::time::Instant::now();
    let batch: Batch = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(error) => {
            facade
                .metrics
                .count(&measure::REFUSALS, &[("reason", "malformed")]);
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Validation,
                    "malformed_batch",
                    format!("this is not a decision batch: {error}"),
                ),
            );
        }
    };

    let keys = match facade.accepted_keys() {
        Ok(keys) => keys,
        Err(error) => {
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Unavailable,
                    "keys_unavailable",
                    format!("this plane cannot verify signatures right now: {error}"),
                ),
            );
        }
    };

    // Off the runtime's threads: accepting a batch is appends and fsyncs
    // across several files, and a reactor thread that waits on a disk is a
    // reactor thread every other request is waiting on.
    let outcome = {
        let (facade, batch) = (facade.clone(), batch.clone());
        tokio::task::spawn_blocking(move || {
            match ingest::accept(&facade.store, &batch, &keys) {
                // A key this plane has not seen is the one refusal worth a
                // second look: a producer that rotated its ring publishes a
                // new one, and the file on this plane may already say so.
                Err(Refused::Unattributable(_)) => {
                    ingest::accept(&facade.store, &batch, &facade.reload_producers())
                }
                other => other,
            }
        })
        .await
        .unwrap_or_else(|error| Err(Refused::Unavailable(error.to_string())))
    };
    facade.metrics.observe(
        &measure::INGEST_SECONDS,
        &[],
        started.elapsed().as_secs_f64(),
    );

    match outcome {
        Ok(Accepted::Ok { acked, stored }) => {
            facade.metrics.count(
                &measure::BATCHES,
                &[("outcome", if stored == 0 { "replay" } else { "ok" })],
            );
            for record in &batch.records {
                if let Some((zone, ledger)) = super::store::tenancy(record) {
                    facade.metrics.count(
                        &measure::RECORDS,
                        &[("zone", zone.as_str()), ("ledger", ledger.as_str())],
                    );
                }
            }
            facade.publish_acked(&batch, acked);

            (StatusCode::OK, Json(Acknowledgement { acked, stored })).into_response()
        }
        Ok(Accepted::OutOfOrder { expected_seq }) => {
            facade
                .metrics
                .count(&measure::BATCHES, &[("outcome", "out_of_order")]);

            // Deliberately a `409`, not a `4xx` the shipper might treat as
            // fatal: nothing is wrong with the batch, the store simply needs
            // an earlier one first.
            (
                StatusCode::CONFLICT,
                Json(OutOfOrder {
                    status: "out_of_order",
                    expected_seq,
                }),
            )
                .into_response()
        }
        Err(refused) => {
            facade
                .metrics
                .count(&measure::REFUSALS, &[("reason", reason_of(&refused))]);
            if matches!(refused, Refused::Conflict { .. }) {
                facade.metrics.count(&measure::CLOSED, &[]);
            }

            refuse(&facade, api_error(&refused))
        }
    }
}

/// How far a reader wants to go, and from where.
#[derive(Debug, Default)]
struct Window {
    from: Option<String>,
    limit: Option<usize>,
    proof: bool,
}

/// Reads the query string this API defines, and nothing else.
///
/// Hand-parsed rather than deserialised, for two reasons that both matter
/// here: an offset is opaque and must survive percent-encoding untouched, and
/// a parameter nobody declared should be ignored rather than become a
/// deserialisation failure a caller cannot act on.
fn window_of(query: Option<&str>) -> (Window, Vec<(String, String)>) {
    let mut window = Window::default();
    let mut pairs = Vec::new();
    for pair in query.unwrap_or_default().split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        let value = percent_decode(value);
        match name {
            "from" => window.from = Some(value.clone()),
            "limit" => window.limit = value.parse().ok(),
            "proof" => window.proof = matches!(value.as_str(), "true" | "1" | "yes"),
            _ => {}
        }
        pairs.push((name.to_owned(), value));
    }

    (window, pairs)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default();
            if let Ok(byte) = u8::from_str_radix(pair, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

async fn records(State(facade): State<DecisionFacade>, RawQuery(query): RawQuery) -> Response {
    let (window, pairs) = window_of(query.as_deref());
    let named = |wanted: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.clone())
    };
    let (Some(pdp_id), Some(instance)) = (named("pdp"), named("instance")) else {
        return refuse(
            &facade,
            ApiError::new(
                ErrorClass::Validation,
                "stream_required",
                "a deployment-wide read names one producer stream: `?pdp=<id>&instance=<id>`",
            ),
        );
    };
    let scope = Scope::Stream { pdp_id, instance };

    serve(facade, scope, window, "stream").await
}

async fn tenant_records(
    State(facade): State<DecisionFacade>,
    Path((zone, ledger)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let scope = Scope::Tenant { zone, ledger };
    let (window, _) = window_of(query.as_deref());

    serve(facade, scope, window, "tenant").await
}

/// The bound on one page, whatever a caller asks for.
///
/// A reader that asks for a million records is either confused or hostile, and
/// either way the answer is a page rather than a stalled worker holding the
/// whole store in memory.
const MAX_PAGE: usize = 1_000;

async fn serve(
    facade: DecisionFacade,
    scope: Scope,
    window: Window,
    kind: &'static str,
) -> Response {
    let limit = window.limit.unwrap_or(100).clamp(1, MAX_PAGE);
    // Off the runtime's threads: a page is segment files read back, and a bulk
    // export must not stall the reactor the shippers are landing batches on.
    let page = {
        let (store, scope) = (facade.store.clone(), scope.clone());
        tokio::task::spawn_blocking(move || {
            read::page_with(&store, &scope, window.from.as_deref(), limit, window.proof)
        })
        .await
        .unwrap_or_else(|error| Err(read::ReadError::Unavailable(error.to_string())))
    };
    match page {
        Ok(page) => {
            facade
                .metrics
                .count(&measure::READS, &[("scope", kind), ("outcome", "ok")]);

            (StatusCode::OK, Json(page)).into_response()
        }
        Err(read::ReadError::Expired { oldest }) => {
            facade
                .metrics
                .count(&measure::READS, &[("scope", kind), ("outcome", "expired")]);

            (
                StatusCode::GONE,
                Json(serde_json::json!({
                    "class": "not_found",
                    "code": "offset_expired",
                    "message": "this offset is older than what this scope still holds",
                    "oldest": oldest,
                })),
            )
                .into_response()
        }
        Err(error) => {
            facade
                .metrics
                .count(&measure::READS, &[("scope", kind), ("outcome", "refused")]);

            refuse(
                &facade,
                ApiError::new(ErrorClass::Validation, "offset_invalid", error.to_string()),
            )
        }
    }
}

fn refuse(facade: &DecisionFacade, error: ApiError) -> Response {
    wire::http_error(&error, facade.disclosure)
}

fn reason_of(refused: &Refused) -> &'static str {
    match refused {
        Refused::Unattributable(_) => "unattributable",
        Refused::Unverifiable(_) => "unverifiable",
        Refused::Conflict { .. } => "conflict",
        Refused::Closed(_) => "closed",
        Refused::Unavailable(_) => "unavailable",
    }
}

fn api_error(refused: &Refused) -> ApiError {
    match refused {
        // A signature that does not verify and a chain that does not hold are
        // both "the request is malformed": the producer must not retry either.
        Refused::Unattributable(detail) => ApiError::new(
            ErrorClass::Validation,
            "batch_unattributable",
            detail.clone(),
        ),
        Refused::Unverifiable(detail) => {
            ApiError::new(ErrorClass::Validation, "batch_unverifiable", detail.clone())
        }
        Refused::Conflict { .. } => {
            ApiError::new(ErrorClass::Conflict, "stream_conflict", refused.to_string())
        }
        Refused::Closed(_) => {
            ApiError::new(ErrorClass::Conflict, "stream_closed", refused.to_string())
        }
        // The one a shipper must treat as *retry*, never as *drop*.
        Refused::Unavailable(detail) => {
            ApiError::new(ErrorClass::Unavailable, "store_unavailable", detail.clone())
        }
    }
}
