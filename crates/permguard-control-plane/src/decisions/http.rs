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
use permguard_core::metrics::labels;
use permguard_core::{ApiError, Disclosure, ErrorClass, Jwk, Metrics};
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
    pub local: Option<Arc<dyn permguard_core::keys::PublicSet>>,
    /// The producers this plane accepts, each key bound to the one `pdp_id` it may sign for.
    /// From the file, never fetched: ingestion must not depend on reaching the planes that are
    /// shipping to it.
    ///
    /// Re-read when a batch cannot be attributed, so a producer that rotates
    /// its ring is a file to update rather than a plane to restart. Behind a
    /// lock because that re-read happens on a request.
    pub producers: std::sync::Arc<std::sync::RwLock<Vec<ingest::ProducerTrust>>>,
    /// Where those sets are read from, each path bound to the producer it speaks for.
    pub producer_files: Vec<ProducerFile>,
    /// The producer identity of the ring sharing this process, when one does — the all-in-one.
    pub local_pdp: String,
    /// The secret read offsets are signed with.
    ///
    /// The server keeps no per-consumer cursor, so the only thing between a consumer and a
    /// position it was never given is this signature. Held here rather than read per request: it
    /// is the store's, it is stable across restarts, and reading a key file on the hot path would
    /// be a disk read per page.
    pub cursor_key: crate::decisions::cursorkey::CursorKeys,
    /// How much a refusal says about the inside.
    pub disclosure: Disclosure,
    /// What to count.
    pub metrics: Metrics,
}

/// One producer stream's signer history, with the receiver's durable frontier.
#[derive(Debug, Clone, Serialize)]
pub struct StreamSignersView {
    /// Everything through this sequence is durable here.
    pub acked: u64,
    pub spans: Vec<permguard_stream::SignerSpan>,
}

impl DecisionFacade {
    /// Which key signed which stretch of one producer stream — the answer both transports serve,
    /// so REST and gRPC cannot drift apart about who signed what.
    ///
    /// `until_seq` of zero means "from `from_seq` onward"; both zero means the whole history.
    pub fn signers_of(
        &self,
        pdp_id: &str,
        instance: &str,
        from_seq: u64,
        until_seq: u64,
    ) -> Result<StreamSignersView, ApiError> {
        if !permguard_stream::is_portable_name(pdp_id)
            || !permguard_stream::is_portable_name(instance)
        {
            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::stream::STREAM_MALFORMED,
                "`pdp` and `instance` are unchanged portable names",
            ));
        }
        // A stream this store never held is a `404`, not an empty manifest: an empty answer
        // reads as "held, nothing signed yet", and a typo in a producer name must not read as
        // that.
        let exists = self
            .store
            .stream_exists(pdp_id, instance)
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::STORE_UNAVAILABLE,
                    error.to_string(),
                )
            })?;
        if !exists {
            return Err(ApiError::new(
                ErrorClass::NotFound,
                permguard_core::codes::stream::STREAM_UNKNOWN,
                format!("this store holds no stream for `{pdp_id}/{instance}`"),
            ));
        }

        let until = if until_seq == 0 { u64::MAX } else { until_seq };
        let state = self.store.stream_state(pdp_id, instance).map_err(|error| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error.to_string(),
            )
        })?;
        let signers = self.store.signers(pdp_id, instance).map_err(|error| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error.to_string(),
            )
        })?;

        let spans = signers.covering(from_seq, until);
        if spans.len() > permguard_stream::MAX_SIGNER_SPANS {
            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::stream::SIGNER_RANGE_TOO_WIDE,
                format!(
                    "this range crosses more than {} signing-key spans; narrow `from_seq` and \
                     `until_seq`",
                    permguard_stream::MAX_SIGNER_SPANS
                ),
            ));
        }

        Ok(StreamSignersView {
            acked: state.acked,
            spans: spans.to_vec(),
        })
    }

    /// Every producer binding a batch may legitimately verify under.
    ///
    /// The union of what the file declares and what a producer sharing this
    /// process publishes — the latter bound to that producer's own `pdp_id`,
    /// never floating free. Never this plane's own signing ring: a control
    /// plane that verified against itself would accept anything it could have
    /// written, which is the opposite of what the signature is for.
    pub(crate) fn accepted_producers(&self) -> anyhow::Result<Vec<ingest::ProducerTrust>> {
        let mut producers = self
            .producers
            .read()
            .map(|held| held.clone())
            .unwrap_or_default();
        if let Some(local) = &self.local {
            producers.extend(
                local
                    .public_keys()?
                    .into_iter()
                    .map(|key| ingest::ProducerTrust {
                        key,
                        pdp: self.local_pdp.clone(),
                    }),
            );
        }

        Ok(producers)
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
    pub(crate) fn reload_producers(&self) -> Vec<ingest::ProducerTrust> {
        let mut producers = Vec::new();
        for file in &self.producer_files {
            let parsed = std::fs::read_to_string(&file.path)
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
            let Some(parsed) = parsed else {
                continue;
            };
            let set = parsed.get("keys").cloned().unwrap_or(parsed);
            if let Ok(found) = serde_json::from_value::<Vec<Jwk>>(set) {
                producers.extend(found.into_iter().map(|key| ingest::ProducerTrust {
                    key,
                    pdp: file.pdp.clone(),
                }));
            }
        }
        if let Ok(mut held) = self.producers.write() {
            held.clone_from(&producers);
        }
        if let Some(local) = &self.local
            && let Ok(published) = local.public_keys()
        {
            producers.extend(published.into_iter().map(|key| ingest::ProducerTrust {
                key,
                pdp: self.local_pdp.clone(),
            }));
        }

        producers
    }
}

/// One producer's published key set on disk, and the identity it signs for.
#[derive(Debug, Clone)]
pub struct ProducerFile {
    pub path: std::path::PathBuf,
    pub pdp: String,
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
        .route("/decisions/v1/signers", get(signers))
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
    let batch: Batch = match Batch::decode(&body) {
        Ok(batch) => batch,
        Err(error) => {
            facade
                .metrics
                .count(&measure::REFUSALS, &[(labels::REASON, "malformed")]);
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::stream::MALFORMED_BATCH,
                    format!("this is not a decision batch: {error}"),
                ),
            );
        }
    };

    let keys = match facade.accepted_producers() {
        Ok(keys) => keys,
        Err(error) => {
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::KEYS_UNAVAILABLE,
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
                &[(labels::OUTCOME, if stored == 0 { "replay" } else { "ok" })],
            );
            for record in &batch.records {
                if super::store::tenancy(record).is_some() {
                    facade.metrics.count(&measure::RECORDS, &[]);
                }
            }

            (StatusCode::OK, Json(Acknowledgement { acked, stored })).into_response()
        }
        Ok(Accepted::OutOfOrder { expected_seq }) => {
            facade
                .metrics
                .count(&measure::BATCHES, &[(labels::OUTCOME, "out_of_order")]);

            // Deliberately a `409`, not a `4xx` the shipper might treat as
            // fatal: nothing is wrong with the batch, the store simply needs
            // an earlier one first.
            (
                StatusCode::CONFLICT,
                Json(OutOfOrder {
                    status: permguard_core::codes::stream::OUT_OF_ORDER,
                    expected_seq,
                }),
            )
                .into_response()
        }
        Err(refused) => {
            facade
                .metrics
                .count(&measure::REFUSALS, &[(labels::REASON, reason_of(&refused))]);
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
                permguard_core::codes::stream::STREAM_REQUIRED,
                "a deployment-wide read names one producer stream: `?pdp=<id>&instance=<id>`",
            ),
        );
    };
    let scope = Scope::Stream { pdp_id, instance };

    serve(facade, scope, window, "stream").await
}

/// Which key signed which stretch of one producer stream, public keys included.
async fn signers(State(facade): State<DecisionFacade>, RawQuery(query): RawQuery) -> Response {
    let (_, pairs) = window_of(query.as_deref());
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
                permguard_core::codes::stream::STREAM_REQUIRED,
                "a signer manifest belongs to one producer stream: `?pdp=<id>&instance=<id>`",
            ),
        );
    };
    let bound = |name: &str| -> Result<u64, String> {
        match named(name) {
            None => Ok(0),
            Some(held) => held.parse().map_err(|_| name.to_owned()),
        }
    };
    let (from_seq, until_seq) = match (bound("from_seq"), bound("until_seq")) {
        (Ok(from_seq), Ok(until_seq)) => (from_seq, until_seq),
        (Err(name), _) | (_, Err(name)) => {
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::stream::BOUND_MALFORMED,
                    format!("`{name}` is a sequence number"),
                ),
            );
        }
    };

    let answered = {
        let facade = facade.clone();
        tokio::task::spawn_blocking(move || {
            facade.signers_of(&pdp_id, &instance, from_seq, until_seq)
        })
        .await
        .unwrap_or_else(|error| {
            Err(ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error.to_string(),
            ))
        })
    };
    match answered {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(error) => refuse(&facade, error),
    }
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
            facade.metrics.count(
                &measure::READS,
                &[(labels::SCOPE, kind), (labels::OUTCOME, "ok")],
            );

            (StatusCode::OK, Json(page)).into_response()
        }
        Err(
            ref expired @ read::ReadError::Expired {
                ref oldest,
                oldest_sequence,
                requested_sequence,
            },
        ) => {
            facade.metrics.count(
                &measure::READS,
                &[(labels::SCOPE, kind), (labels::OUTCOME, "expired")],
            );

            // Expected retention behaviour rather than corruption, and the answer says so — with
            // where to resume and how large the gap is, so a consumer records a gap instead of
            // reporting a clean run it did not have.
            (
                StatusCode::GONE,
                Json(serde_json::json!({
                    "class": "not_found",
                    "code": permguard_core::codes::stream::OFFSET_EXPIRED,
                    "message": expired.to_string(),
                    "oldest_available": oldest,
                    "oldest_sequence": oldest_sequence,
                    "requested_sequence": requested_sequence,
                })),
            )
                .into_response()
        }
        Err(error) => {
            facade.metrics.count(
                &measure::READS,
                &[(labels::SCOPE, kind), (labels::OUTCOME, "refused")],
            );

            refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::stream::OFFSET_INVALID,
                    error.to_string(),
                ),
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
            permguard_core::codes::stream::BATCH_UNATTRIBUTABLE,
            detail.clone(),
        ),
        Refused::Unverifiable(detail) => ApiError::new(
            ErrorClass::Validation,
            permguard_core::codes::stream::BATCH_UNVERIFIABLE,
            detail.clone(),
        ),
        Refused::Conflict { .. } => ApiError::new(
            ErrorClass::Conflict,
            permguard_core::codes::stream::STREAM_CONFLICT,
            refused.to_string(),
        ),
        Refused::Closed(_) => ApiError::new(
            ErrorClass::Conflict,
            permguard_core::codes::stream::STREAM_CLOSED,
            refused.to_string(),
        ),
        // The one a shipper must treat as *retry*, never as *drop*.
        Refused::Unavailable(detail) => ApiError::new(
            ErrorClass::Unavailable,
            permguard_core::codes::stream::STORE_UNAVAILABLE,
            detail.clone(),
        ),
    }
}

#[cfg(test)]
mod openapi {
    //! `contracts/openapi/evidence-decisions.json` and `stream-common.json`, checked against the
    //! types that put those documents' bodies on the wire.
    //!
    //! The two documents are checked here, in the crate that sees both the public record and
    //! stream types and the private bodies of this module, so each document's one
    //! `assert_covered` runs in a process that has seen all of its schemas.

    #![allow(clippy::expect_used)]

    use permguard_core::keys::PublicSet as _;

    use std::collections::BTreeMap;
    use std::time::Duration;

    use permguard_conformance::schema::Document;
    use permguard_core::KeyManager;
    use permguard_decisions::envelope::{Batch, Envelope, Signed};
    use permguard_decisions::merkle;
    use permguard_decisions::record::{
        ActionRef, Body, Build, Commitments, DecisionBody, DiscontinuityBody, EventRef, GENESIS,
        Inputs, Lost, MarkerBody, Outcome, Party, Predecessor, Reason, Record, Sampling, StoreRef,
        Stream, Trace, VERSION,
    };
    use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
    use permguard_stream::{Block, Coverage, Cursor, Frontier, Position, SignerSpan, Signers};
    use serde_json::{Value, json};

    use super::*;
    use crate::decisions::read::Inclusion;

    fn ring() -> DirectoryKeyManager {
        let root = std::env::temp_dir().join(format!(
            "permguard-decisions-openapi-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let keys = DirectoryKeyManager::new(
            root,
            KeyPolicy {
                publish_ahead: Duration::from_secs(0),
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(3600),
                verify_retain: Duration::from_secs(7200),
            },
        );
        keys.maintain().expect("the ring produces a key");

        keys
    }

    fn build(full: bool) -> Build {
        Build {
            version: "0.1.0".to_owned(),
            build: full.then(|| "sha256:b1".to_owned()),
            engines: full.then(|| BTreeMap::from([("cedar".to_owned(), "4.2.0".to_owned())])),
        }
    }

    fn party(kind: &str, id: &str, properties: bool) -> Party {
        Party {
            kind: kind.to_owned(),
            id: id.to_owned(),
            properties: properties
                .then(|| json!({"tier": "gold"}).as_object().cloned())
                .flatten(),
        }
    }

    fn store() -> StoreRef {
        StoreRef {
            zone: "acme".to_owned(),
            ledger: "main-ledger".to_owned(),
            commit: "sha256:ec1773bf".to_owned(),
            counter: 3,
            profile: "default".to_owned(),
        }
    }

    /// A marker, two decisions, a marker and a discontinuity: every kind, every optional member
    /// present in one record and absent in another.
    fn records() -> Vec<Record> {
        let marker_full = Body::Marker(Box::new(MarkerBody {
            predecessor: Some(Predecessor {
                instance: "inst-1".to_owned(),
                last_seq: Some(9),
                reason: "spool_full".to_owned(),
            }),
            pdp: build(true),
            sampling: Sampling {
                permits: "1.0".to_owned(),
            },
            commitments: Commitments {
                alg: "HMAC-SHA256".to_owned(),
                key_version: "v1".to_owned(),
            },
        }));
        let decision_full = Body::Decision(Box::new(DecisionBody {
            id: "id-2".to_owned(),
            pdp: build(false),
            store: store(),
            subject: party("User", "pseudo:v1:9f2c", true),
            resource: party("Document", "budget", false),
            action: ActionRef {
                name: "read".to_owned(),
            },
            principal: Some(party("User", "pseudo:v1:77aa", true)),
            inputs: Inputs {
                context: Some("hmac:c1".to_owned()),
                partition_inputs: Some("hmac:p1".to_owned()),
                absent: vec!["governance".to_owned()],
                external: vec![json!({"source": "pip"})],
            },
            decision: false,
            outcome: Some(Outcome::Indeterminate),
            causes: Some(vec!["evaluation_failed".to_owned()]),
            policies: vec![],
            reason: Reason {
                code: "evaluation_indeterminate".to_owned(),
            },
            trace: Some(Trace {
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
                span_id: "00f067aa0ba902b7".to_owned(),
            }),
            request_id: Some("req-1".to_owned()),
            context: json!({"region": "eu"}).as_object().cloned(),
            latency_us: 143,
            event: Some(EventRef {
                event_id: "evt-9".to_owned(),
                event_type: "permguard.dogwood.event.v1".to_owned(),
                instance: "inst-2".to_owned(),
                sequence: 41,
                history: Some("sha256:h1".to_owned()),
                consistency: Some("shared-bounded".to_owned()),
                watermark: Some("w1".to_owned()),
            }),
        }));
        let decision_minimal = Body::Decision(Box::new(DecisionBody {
            id: "id-3".to_owned(),
            pdp: build(false),
            store: store(),
            subject: party("User", "pseudo:v1:9f2c", false),
            resource: party("Document", "budget", false),
            action: ActionRef {
                name: "read".to_owned(),
            },
            principal: None,
            inputs: Inputs::default(),
            decision: true,
            outcome: None,
            causes: None,
            policies: vec!["af4c4260".to_owned()],
            reason: Reason {
                code: "200".to_owned(),
            },
            trace: None,
            request_id: None,
            context: None,
            latency_us: 12,
            event: None,
        }));
        let marker_minimal = Body::Marker(Box::new(MarkerBody {
            predecessor: Some(Predecessor {
                instance: "inst-1".to_owned(),
                last_seq: None,
                reason: "age_expiry".to_owned(),
            }),
            pdp: build(false),
            sampling: Sampling {
                permits: "0.5".to_owned(),
            },
            commitments: Commitments {
                alg: "HMAC-SHA256".to_owned(),
                key_version: "v2".to_owned(),
            },
        }));
        let discontinuity = Body::Discontinuity(Box::new(DiscontinuityBody {
            reason: "spool_full".to_owned(),
            lost: Lost {
                from_seq: 10,
                count_estimate: 4,
            },
            successor: "inst-3".to_owned(),
        }));

        let mut prev = GENESIS.to_owned();
        let mut chained = Vec::new();
        for (index, body) in [
            marker_full,
            decision_full,
            decision_minimal,
            marker_minimal,
            discontinuity,
        ]
        .into_iter()
        .enumerate()
        {
            let record = Record {
                v: VERSION,
                stream: Stream::new("plane", "inst-2"),
                seq: index as u64 + 1,
                prev: prev.clone(),
                at: "2026-08-24T10:00:00Z".to_owned(),
                body,
            };
            prev = record.digest().expect("it digests");
            chained.push(record);
        }

        chained
    }

    #[test]
    fn test_the_decision_wire_types_match_openapi_evidence_decisions() {
        let doc = Document::load("evidence-decisions.json");
        let held = records();
        let values: Vec<Value> = held
            .iter()
            .map(|record| record.to_value().expect("a record renders"))
            .collect();

        // Every kind, switched on `kind`; the oneOf takes exactly one branch.
        for value in &values {
            doc.check_json("Record", value);
        }
        for outcome in [
            Outcome::Permit,
            Outcome::Deny,
            Outcome::DenyByDefault,
            Outcome::Indeterminate,
        ] {
            doc.check("Outcome", &outcome);
        }

        // The signed envelope, built by the crate's own signer over this very chain.
        let leaves: Vec<String> = held
            .iter()
            .map(|record| record.digest().expect("it digests"))
            .collect();
        let envelope = Envelope {
            stream: Stream::new("plane", "inst-2"),
            first_seq: 1,
            last_seq: held.len() as u64,
            count: held.len() as u64,
            previous_head: GENESIS.to_owned(),
            head: leaves.last().expect("a head").clone(),
            merkle_root: merkle::root(&leaves).expect("a root"),
            sampling: Sampling {
                permits: "1.0".to_owned(),
            },
            at: "2026-08-24T10:00:01Z".to_owned(),
        };
        let keys = ring();
        let signed = Signed::create(&envelope, &keys).expect("it signs");
        doc.check("Envelope", &envelope);
        doc.check("Signed", &signed);
        // What the base64url members hold, which is what a verifier decodes.
        doc.check(
            "Protected",
            &signed.protected().expect("the header decodes"),
        );
        doc.check("Envelope", &signed.envelope().expect("the payload decodes"));

        let batch = Batch {
            signature: signed.clone(),
            records: values.clone(),
        };
        doc.check("Batch", &batch);
        let sent = serde_json::to_value(&batch).expect("a batch serialises");
        assert!(Batch::decode(sent.to_string().as_bytes()).is_ok());

        // Closed envelopes: a member the contract does not name is refused.
        let mut extra = sent.clone();
        extra["unexpected"] = json!(1);
        assert!(!doc.accepts_json("Batch", &extra));
        let mut extra_signature = sent.clone();
        extra_signature["signature"]["typ"] = json!("permguard.decision.batch.v1");
        assert!(!doc.accepts_json("Batch", &extra_signature));
        let mut no_records = sent.clone();
        no_records["records"] = json!([]);
        assert!(!doc.accepts_json("Batch", &no_records));
        let mut extra_envelope = serde_json::to_value(&envelope).expect("an envelope serialises");
        extra_envelope["event_types"] = json!(["x"]);
        assert!(!doc.accepts_json("Envelope", &extra_envelope));
        assert!(!doc.accepts_json("Protected", &json!({"alg": "HS256", "kid": "k"})));
        assert!(!doc.accepts_json("Record", &json!({"kind": "loss"})));
        let mut headless = values[2].clone();
        headless.as_object_mut().expect("an object").remove("id");
        assert!(!doc.accepts_json("Record", &headless));
        assert!(!doc.accepts_json("Outcome", &json!("maybe")));
        // Records are open: a newer producer's member is kept, not refused.
        let mut newer = values[2].clone();
        newer["added_later"] = json!(true);
        assert!(doc.accepts_json("Record", &newer));

        // The answers of the ship route.
        doc.check(
            "Acknowledgement",
            &Acknowledgement {
                acked: 5,
                stored: 5,
            },
        );
        doc.check(
            "OutOfOrder",
            &OutOfOrder {
                status: permguard_core::codes::stream::OUT_OF_ORDER,
                expected_seq: 6,
            },
        );
        assert!(!doc.accepts_json(
            "OutOfOrder",
            &json!({"status": "out_of_order", "expected_seq": 6, "class": "conflict"})
        ));

        // A page with proof, and one without: `proof` and `inclusion` are absent when empty.
        let path = merkle::path(&leaves, 1).expect("a path");
        let inclusion = Inclusion {
            seq: 2,
            leaf: leaves[1].clone(),
            root: envelope.merkle_root.clone(),
            path,
        };
        let page = Block {
            records: values.clone(),
            next: "AAAA".to_owned(),
            oldest_available: "BBBB".to_owned(),
            high_watermark: "CCCC".to_owned(),
            more: true,
            proof: vec![serde_json::to_value(&signed).expect("a signature serialises")],
            inclusion: vec![serde_json::to_value(&inclusion).expect("a path serialises")],
            coverage: Coverage {
                contiguous: false,
                examined: 5,
                scan_bounded: true,
            },
        };
        doc.check("DecisionBlock", &page);
        let bare = Block {
            proof: Vec::new(),
            inclusion: Vec::new(),
            ..page.clone()
        };
        doc.check("DecisionBlock", &bare);
        let mut no_next = serde_json::to_value(&bare).expect("a page serialises");
        no_next.as_object_mut().expect("an object").remove("next");
        assert!(!doc.accepts_json("DecisionBlock", &no_next));

        // The signer manifest, from the ring that signed.
        let jwk = keys.public_keys().expect("the ring publishes").remove(0);
        let view = StreamSignersView {
            acked: 5,
            spans: vec![SignerSpan {
                from: 1,
                kid: jwk.kid.clone(),
                jwk: serde_json::to_value(&jwk).expect("a key serialises"),
            }],
        };
        doc.check("StreamSignersView", &view);

        doc.assert_covered();
    }

    #[test]
    fn test_the_stream_wire_types_match_openapi_stream_common() {
        let doc = Document::load("stream-common.json");

        let coverage = Coverage {
            contiguous: true,
            examined: 3,
            scan_bounded: false,
        };
        doc.check("Coverage", &coverage);
        assert!(!doc.accepts_json(
            "Coverage",
            &json!({"contiguous": true, "examined": 1, "scan_bounded": false, "x": 1})
        ));

        let leaves = vec![
            "sha256:aa".to_owned(),
            "sha256:bb".to_owned(),
            "sha256:cc".to_owned(),
        ];
        let path = merkle::path(&leaves, 2).expect("a path");
        assert!(!path.is_empty());
        for step in &path {
            doc.check("Step", step);
        }
        let inclusion = Inclusion {
            seq: 3,
            leaf: leaves[2].clone(),
            root: merkle::root(&leaves).expect("a root"),
            path,
        };
        doc.check("Inclusion", &inclusion);

        let jwk = serde_json::to_value(permguard_core::keys::Jwk::okp(
            "k1", "Ed25519", "EdDSA", "AAAA",
        ))
        .expect("a public key serialises");
        let span = SignerSpan {
            from: 1,
            kid: "k1".to_owned(),
            jwk: jwk.clone(),
        };
        doc.check("SignerSpan", &span);
        let mut signers = Signers::empty();
        assert!(signers.observe(1, "k1", &jwk).expect("the first key"));
        doc.check("Signers", &signers);

        let mut frontier = Frontier::of("plane/inst-2", 4);
        frontier.cover("plane/inst-1", 9);
        doc.check("Frontier", &frontier);
        doc.check(
            "Position",
            &Position {
                segment: 1,
                offset: 3,
            },
        );
        doc.check(
            "Cursor",
            &Cursor {
                v: 1,
                api: "decisions".to_owned(),
                scope: "stream:plane/inst-2".to_owned(),
                filters: "sha256:f".to_owned(),
                until: Some(frontier.clone()),
                positions: BTreeMap::from([(
                    "plane/inst-2".to_owned(),
                    Position {
                        segment: 1,
                        offset: 3,
                    },
                )]),
                frontier: frontier.clone(),
            },
        );
        doc.check(
            "Cursor",
            &Cursor {
                v: 1,
                api: "decisions".to_owned(),
                scope: "stream:plane/inst-2".to_owned(),
                filters: "sha256:f".to_owned(),
                until: None,
                positions: BTreeMap::new(),
                frontier,
            },
        );

        let block: Block<Value> = Block {
            records: vec![json!({"seq": 3})],
            next: "AAAA".to_owned(),
            oldest_available: "BBBB".to_owned(),
            high_watermark: "CCCC".to_owned(),
            more: false,
            proof: vec![json!({"payload": "x"})],
            inclusion: vec![serde_json::to_value(&inclusion).expect("a path serialises")],
            coverage,
        };
        doc.check("Block", &block);
        let mut no_coverage = serde_json::to_value(&block).expect("a block serialises");
        no_coverage
            .as_object_mut()
            .expect("an object")
            .remove("coverage");
        assert!(!doc.accepts_json("Block", &no_coverage));

        // The 410 body is built by hand in `serve` above; this is the same object, with the
        // message the real refusal renders.
        let expired = read::ReadError::Expired {
            oldest: "BBBB".to_owned(),
            oldest_sequence: 40,
            requested_sequence: 12,
        };
        let body = json!({
            "class": "not_found",
            "code": permguard_core::codes::stream::OFFSET_EXPIRED,
            "message": expired.to_string(),
            "oldest_available": "BBBB",
            "oldest_sequence": 40,
            "requested_sequence": 12,
        });
        doc.check_json("OffsetExpired", &body);
        let mut wrong = body.clone();
        wrong["class"] = json!("validation");
        assert!(!doc.accepts_json("OffsetExpired", &wrong));

        doc.assert_covered();
    }
}
