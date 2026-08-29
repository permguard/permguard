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
use permguard_stream::Window;
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
    /// The secret read offsets are signed with.
    ///
    /// The server keeps no per-consumer cursor, so the only thing between a consumer and a
    /// position it was never given is this signature. Held here rather than read per request: it
    /// is the store's, it is stable across restarts, and reading a key file on the hot path would
    /// be a disk read per page.
    pub cursor_key: permguard_stream::CursorKey,
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
struct Asked {
    from: Option<String>,
    until: Option<String>,
    limit_records: Option<usize>,
    limit_bytes: Option<u64>,
    proof: bool,
}

impl Asked {
    /// The read this asks for, in the shared contract's terms.
    ///
    /// An `until` this build did not issue is dropped rather than refused, and the read becomes a
    /// tail: the cursor carries the export bound inside its own signature, so a caller that
    /// garbled the parameter is caught there, by the binding, with a message about the offset
    /// rather than about a query string.
    fn window(&self) -> Window {
        Window {
            from: self.from.clone(),
            until: self
                .until
                .as_deref()
                .and_then(permguard_stream::Frontier::decode),
            limit_records: self.limit_records.unwrap_or_default(),
            limit_bytes: self.limit_bytes.unwrap_or_default(),
            proof: self.proof,
        }
    }
}

/// Reads the query string this API defines, and nothing else.
///
/// Hand-parsed rather than deserialised, for two reasons that both matter
/// here: an offset is opaque and must survive percent-encoding untouched, and
/// a parameter nobody declared should be ignored rather than become a
/// deserialisation failure a caller cannot act on.
fn window_of(query: Option<&str>) -> (Asked, Vec<(String, String)>) {
    let mut window = Asked::default();
    let mut pairs = Vec::new();
    for pair in query.unwrap_or_default().split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        let value = percent_decode(value);
        match name {
            "from" => window.from = Some(value.clone()),
            "until" => window.until = Some(value.clone()),
            // `limit` is the name this API shipped with and still answers to. `limit_records` is
            // the shared contract's name, and it wins where both are given: a caller writing to
            // the current contract should not be quietly overridden by a compatibility alias.
            "limit" => window.limit_records = window.limit_records.or_else(|| value.parse().ok()),
            "limit_records" => window.limit_records = value.parse().ok(),
            "limit_bytes" => window.limit_bytes = value.parse().ok(),
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

async fn serve(facade: DecisionFacade, scope: Scope, asked: Asked, kind: &'static str) -> Response {
    let window = asked.window();
    // Off the runtime's threads: a page is segment files read back, and a bulk
    // export must not stall the reactor the shippers are landing batches on.
    let page = {
        let (store, scope, key) = (
            facade.store.clone(),
            scope.clone(),
            facade.cursor_key.clone(),
        );
        tokio::task::spawn_blocking(move || read::read(&store, &scope, &key, &window))
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
        Err(
            ref expired @ read::ReadError::Expired {
                ref oldest,
                oldest_sequence,
                requested_sequence,
            },
        ) => {
            facade
                .metrics
                .count(&measure::READS, &[("scope", kind), ("outcome", "expired")]);

            // Expected retention behaviour rather than corruption, and the answer says so — with
            // where to resume and how large the gap is, so a consumer records a gap instead of
            // reporting a clean run it did not have.
            (
                StatusCode::GONE,
                Json(serde_json::json!({
                    "class": "not_found",
                    "code": "offset_expired",
                    "message": expired.to_string(),
                    "oldest_available": oldest,
                    "oldest_sequence": oldest_sequence,
                    "requested_sequence": requested_sequence,
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
