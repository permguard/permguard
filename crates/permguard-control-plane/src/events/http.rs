// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event store's HTTP surface.
//!
//! # One facade, two transports
//!
//! Everything a request means lives in [`EventFacade`], and both this and [`super::grpc`] call it.
//! Not because it is tidy: an API whose two transports each carry a copy of the validation has two
//! APIs, and the second one is the one that is wrong — it accepts a batch the other refuses, or
//! bounds a page the other does not.
//!
//! # Routes
//!
//! ```text
//! POST /events/v1alpha1/batches                                  a producer ships
//! GET  /events/v1alpha1/records                                  the administrative read
//! GET  /events/v1alpha1/records/{event-id}                       one occurrence
//! GET  /v1/zones/{zone}/ledgers/{ledger}/events/v1alpha1/records one tenant's
//! ```
//!
//! The global read is administrative and names a producer stream outright. The tenant read is
//! physically isolated: it is served from that tenant's own view directory, so a bug would have to
//! be a bug in `open` to cross the boundary.
//!
//! # Status codes
//!
//! | Situation | Answer |
//! | --- | --- |
//! | a batch stored, or already held | `200` with the acknowledgement |
//! | the shipper ran ahead | `409` with the sequence to resend from |
//! | the batch cannot be attributed or verified | `400` |
//! | the stream has forked, or is closed | `409` |
//! | an offset older than what is held | `410`, with where to resume |
//! | the store cannot answer right now | `503` |

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use permguard_core::{ApiError, Disclosure, ErrorClass, Jwk, Metrics};
use permguard_stream::{CursorKey, Window};

use super::ingest::{self, Accepted, Batch, ProducerTrust, Refused};
use super::measure;
use super::read::{self, Filters};
use super::store::{EventStore, Scope};
use crate::wire;

/// Where a producer ships a signed batch.
pub const BATCHES_PATH: &str = "/events/v1alpha1/batches";
/// The administrative read.
pub const RECORDS_PATH: &str = "/events/v1alpha1/records";
/// One occurrence, by the identifier its caller stated.
pub const RECORD_PATH: &str = "/events/v1alpha1/records/{event_id}";
/// One tenant's read.
pub const TENANT_RECORDS_PATH: &str = "/v1/zones/{zone}/ledgers/{ledger}/events/v1alpha1/records";
/// Which key signed which stretch of each producer stream of one ledger.
pub const SIGNERS_PATH: &str = "/v1/zones/{zone}/ledgers/{ledger}/events/v1alpha1/signers";

/// Everything a request means, shared by both transports.
#[derive(Clone)]
pub struct EventFacade {
    /// Where events are kept.
    pub store: Arc<EventStore>,
    /// The published key sets of the producers this plane accepts.
    ///
    /// Never fetched: ingestion must not depend on reaching the planes that are shipping to it.
    pub producers: Arc<std::sync::RwLock<Vec<ProducerTrust>>>,
    /// Where those sets are read from, for the re-read when a batch cannot be attributed.
    pub producer_files: Vec<ProducerFile>,
    /// The secret read offsets are signed with.
    pub cursor_key: CursorKey,
    /// The catalog, for turning the scope a reader named into the one records are keyed by.
    ///
    /// Optional because the contract makes it optional: a build that composes no catalog has no
    /// names to resolve, and a reader there addresses records by identity or not at all.
    pub catalog: Option<Arc<dyn permguard_core::catalog::Catalog>>,
    /// How much a refusal says about the inside.
    pub disclosure: Disclosure,
    /// What to count.
    pub metrics: Metrics,
    /// The base URL this plane is reached at, for the configuration document.
    ///
    /// The document's endpoints are absolute, because the producer that reads it is configured with
    /// one URL and has to arrive at four. A relative path would leave it joining strings.
    pub base_url: String,
}

#[derive(Clone)]
pub struct ProducerFile {
    pub path: std::path::PathBuf,
    pub producer: String,
    pub zone: String,
    pub ledger: String,
}

impl EventFacade {
    /// The keys a **new** batch may be signed under: what the producers publish today, and nothing
    /// else.
    ///
    /// # Why the archive is not in here
    ///
    /// It used to be, and that made rotation meaningless. Verifying stored evidence and admitting
    /// new evidence are different questions that happen to use the same operation: a batch signed
    /// last year must still verify after the key that signed it has been rotated out, or history
    /// stops being checkable the first time somebody rotates — but a key that has been *retired*
    /// must not be able to sign anything new, or retiring it achieved nothing. A compromised key
    /// withdrawn from a producer's published set would have gone on being accepted for as long as
    /// the archive kept it, which is for ever.
    ///
    /// So ingest asks this, and a reader checking what is already stored asks
    /// [`EventFacade::verification_keys`].
    pub fn accepted_producers(&self) -> Vec<ProducerTrust> {
        self.producers
            .read()
            .map(|held| held.clone())
            .unwrap_or_default()
    }

    /// Every key that may verify evidence this store already holds.
    ///
    /// The published sets plus the archive. Read-only by construction: nothing that reaches this
    /// admits a record, it only re-checks records admitted earlier under keys that were current
    /// then.
    pub fn verification_keys(&self) -> Vec<Jwk> {
        let mut keys: Vec<Jwk> = self
            .accepted_producers()
            .into_iter()
            .map(|held| held.key)
            .collect();
        if let Ok(archived) = self.store.archived_keys() {
            for key in archived {
                // A key id is scoped to its producer. Two producers may legitimately publish
                // different material under the same label, and a verifier must try both.
                if !keys.iter().any(|held| held == &key) {
                    keys.push(key);
                }
            }
        }

        keys
    }

    /// Re-reads the producers' published sets, for a batch nothing could attribute.
    ///
    /// A producer that rotates its ring should be a file to update rather than a plane to restart.
    pub(crate) fn reload_producers(&self) -> Result<(), String> {
        let mut keys = Vec::new();
        for source in &self.producer_files {
            let text = std::fs::read_to_string(&source.path)
                .map_err(|error| format!("reading {}: {error}", source.path.display()))?;
            let parsed = serde_json::from_str::<serde_json::Value>(&text)
                .map_err(|error| format!("parsing {}: {error}", source.path.display()))?;
            let set = parsed.get("keys").cloned().unwrap_or(parsed);
            let found: Vec<Jwk> = serde_json::from_value(set)
                .map_err(|error| format!("{} is not a JWKS: {error}", source.path.display()))?;
            if found.is_empty() {
                return Err(format!("{} publishes no keys", source.path.display()));
            }
            keys.extend(found.into_iter().map(|key| ProducerTrust {
                key,
                producer: source.producer.clone(),
                zone: source.zone.clone(),
                ledger: source.ledger.clone(),
            }));
        }
        if keys.is_empty() {
            return Err("no event producer trust sources are configured".to_owned());
        }
        if let Ok(mut held) = self.producers.write() {
            *held = keys;
        } else {
            return Err("the event producer trust lock is poisoned".to_owned());
        }

        Ok(())
    }

    /// The event types this store accepts.
    ///
    /// Read off the language registry rather than configured: a type is accepted exactly when this
    /// build carries something that can validate it, and a list an operator could widen would be a
    /// way to store records nothing here understands.
    pub fn accepted_types(&self) -> Vec<&'static str> {
        vec![permguard_languages::event::EVENT_TYPE]
    }

    /// Accepts one batch.
    /// Which key signed which stretch of each producer stream of one ledger — the answer both
    /// transports serve, so REST and gRPC cannot drift apart about who signed what.
    ///
    /// `until_seq` of zero means "from `from_seq` onward"; both zero means the whole history.
    pub fn signers_of(
        &self,
        zone: &str,
        ledger: &str,
        from_seq: u64,
        until_seq: u64,
    ) -> Result<Vec<StreamSignersView>, ApiError> {
        let scope = super::read::canonical(
            self.catalog.as_ref(),
            Scope::Tenant {
                zone: zone.to_owned(),
                ledger: ledger.to_owned(),
            },
        )
        .map_err(|error| match error {
            super::read::ReadError::Unknown(detail) => {
                ApiError::new(ErrorClass::NotFound, "scope_unknown", detail)
            }
            other => ApiError::new(
                ErrorClass::Unavailable,
                "store_unavailable",
                other.to_string(),
            ),
        })?;
        let Scope::Tenant { zone, ledger } = scope else {
            return Err(ApiError::new(
                ErrorClass::Internal,
                "scope_mismatch",
                "a tenant scope resolved to something else",
            ));
        };
        let until = if until_seq == 0 { u64::MAX } else { until_seq };

        let streams = self
            .store
            .producer_streams(&zone, &ledger)
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    "store_unavailable",
                    error.to_string(),
                )
            })?;
        let mut answered = Vec::with_capacity(streams.len());
        for stream in streams {
            let state = self.store.stream_state(&stream).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    "store_unavailable",
                    error.to_string(),
                )
            })?;
            let signers = self.store.signers(&stream).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    "store_unavailable",
                    error.to_string(),
                )
            })?;

            answered.push(StreamSignersView {
                producer_class: stream.producer.class,
                producer: stream.producer.id,
                instance: stream.producer.instance,
                acked: state.acked,
                spans: signers.covering(from_seq, until).to_vec(),
            });
        }

        Ok(answered)
    }

    pub fn ingest(&self, batch: &Batch) -> Result<Accepted, Refused> {
        let started = std::time::Instant::now();
        let types = self.accepted_types();
        let mut answered = ingest::accept(&self.store, batch, &self.accepted_producers(), &types);
        if matches!(answered, Err(Refused::Unattributable(_))) {
            // One re-read, then one retry: a producer that rotated is the ordinary reason a
            // signature stops being attributable, and it should not need an operator.
            if let Err(error) = self.reload_producers() {
                tracing::warn!(
                    event.name = "events.producer_keys_reload_failed",
                    error = error.as_str(),
                    "the event producer trust set could not be reloaded; keeping the last complete set"
                );
            }
            answered = ingest::accept(&self.store, batch, &self.accepted_producers(), &types);
        }
        self.metrics.observe(
            &measure::INGEST_SECONDS,
            &[],
            started.elapsed().as_secs_f64(),
        );
        match &answered {
            Ok(Accepted::Ok { stored, .. }) => {
                self.metrics.count(
                    &measure::BATCHES,
                    &[("outcome", if *stored > 0 { "accepted" } else { "replayed" })],
                );
                self.metrics.add(&measure::RECORDS, &[], *stored as f64);
            }
            Ok(Accepted::OutOfOrder { .. }) => {
                self.metrics
                    .count(&measure::BATCHES, &[("outcome", "out_of_order")]);
            }
            Err(refused) => {
                self.metrics
                    .count(&measure::BATCHES, &[("outcome", "refused")]);
                if matches!(refused, Refused::Fork { .. }) {
                    self.metrics.count(&measure::FORKS, &[]);
                }
            }
        }

        answered
    }

    /// Reads one bounded, filtered block.
    pub fn read(
        &self,
        scope: &Scope,
        filters: &Filters,
        window: &Window,
        kind: &'static str,
    ) -> Result<read::Page, read::ReadError> {
        let answered = read::read(&self.store, scope, filters, &self.cursor_key, window);
        match &answered {
            Ok(page) => {
                self.metrics
                    .count(&measure::READS, &[("scope", kind), ("outcome", "ok")]);
                self.metrics.add(
                    &measure::EXAMINED,
                    &[("scope", kind)],
                    page.coverage.examined as f64,
                );
                self.metrics.add(
                    &measure::RETURNED,
                    &[("scope", kind)],
                    page.records.len() as f64,
                );
            }
            Err(read::ReadError::Expired { .. }) => {
                self.metrics
                    .count(&measure::READS, &[("scope", kind), ("outcome", "expired")]);
            }
            Err(_) => {
                self.metrics
                    .count(&measure::READS, &[("scope", kind), ("outcome", "refused")]);
            }
        }

        answered
    }
}

/// The routes the event store answers.
pub fn routes(facade: EventFacade) -> Router {
    // Mounted from the interface's own constants, which is also what the configuration document
    // advertises — so the document cannot name a path this plane does not answer.
    Router::new()
        .route(BATCHES_PATH, post(batches))
        .route(RECORDS_PATH, get(records))
        .route(RECORD_PATH, get(record))
        .route(TENANT_RECORDS_PATH, get(tenant_records))
        .route(SIGNERS_PATH, get(signers))
        .route(super::configuration::CONFIGURATION_PATH, get(document))
        .with_state(facade)
}

/// One producer stream's signer history, with the receiver's durable frontier — what a verifier
/// needs to check a range of that stream without reaching the producer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamSignersView {
    pub producer_class: String,
    pub producer: String,
    pub instance: String,
    /// Everything through this sequence is durable here.
    pub acked: u64,
    pub spans: Vec<permguard_stream::SignerSpan>,
}

async fn signers(
    State(facade): State<EventFacade>,
    Path((zone, ledger)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let asked = asked_of(query.as_deref());
    let bound = |name: &str| -> Result<u64, String> {
        match asked.value(name) {
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
                    "bound_malformed",
                    format!("`{name}` is a sequence number"),
                ),
            );
        }
    };

    match facade.signers_of(&zone, &ledger, from_seq, until_seq) {
        Ok(streams) => (
            StatusCode::OK,
            Json(serde_json::json!({ "streams": streams })),
        )
            .into_response(),
        Err(error) => refuse(&facade, error),
    }
}

/// What this plane offers of the event-log interface.
///
/// Unauthenticated on purpose, like every other layer of the discovery chain: it says what the
/// shapes are, never what is inside them. Reading a record still takes a scope and an offset.
async fn document(State(facade): State<EventFacade>) -> Json<super::configuration::Document> {
    Json(super::configuration::document(
        &facade.base_url,
        &facade.base_url,
        &facade.accepted_types(),
    ))
}

async fn batches(
    State(facade): State<EventFacade>,
    body: Result<Json<Batch>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(batch) = match body {
        Ok(body) => body,
        Err(rejection) => {
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Validation,
                    "payload_malformed",
                    format!("the request body is not a signed batch: {rejection}"),
                ),
            );
        }
    };

    // Off the runtime's threads: verifying a batch is signature work and file writes, and a
    // shipper landing a large one must not stall the reactor the reads are answered on.
    let answered = {
        let facade = facade.clone();
        tokio::task::spawn_blocking(move || facade.ingest(&batch))
            .await
            .unwrap_or_else(|error| Err(Refused::Unavailable(error.to_string())))
    };

    match answered {
        Ok(Accepted::Ok { acked, stored }) => (
            StatusCode::OK,
            Json(serde_json::json!({"acked": acked, "stored": stored})),
        )
            .into_response(),
        Ok(Accepted::OutOfOrder { expected_seq }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "class": "conflict",
                "code": "out_of_order",
                "message": format!(
                    "this store holds through {} and this batch begins later: resend from {expected_seq}",
                    expected_seq.saturating_sub(1)
                ),
                "expected_seq": expected_seq,
            })),
        )
            .into_response(),
        Err(refused) => refuse(&facade, api_error(&refused)),
    }
}

/// The refusal, in the taxonomy every surface here shares.
fn api_error(refused: &Refused) -> ApiError {
    let class = match refused {
        Refused::Unattributable(_) | Refused::Unverifiable(_) | Refused::Unregistered(_) => {
            ErrorClass::Validation
        }
        Refused::Fork { .. } | Refused::Closed(_) => ErrorClass::Conflict,
        Refused::Unavailable(_) => ErrorClass::Unavailable,
    };

    ApiError::new(class, refused.code(), refused.to_string())
}

/// How far a reader wants to go, from where, and narrowed to what.
#[derive(Debug, Default)]
struct Asked {
    from: Option<String>,
    until: Option<String>,
    limit_records: Option<usize>,
    limit_bytes: Option<u64>,
    proof: bool,
    filters: Filters,
    named: Vec<(String, String)>,
}

impl Asked {
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

    fn value(&self, wanted: &str) -> Option<String> {
        self.named
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.clone())
    }
}

/// Reads the query string this API defines, and nothing else.
///
/// Hand-parsed rather than deserialised, for two reasons that both matter: an offset is opaque and
/// must survive percent-encoding untouched, and a parameter nobody declared should be ignored
/// rather than become a deserialisation failure a caller cannot act on.
fn asked_of(query: Option<&str>) -> Asked {
    let mut asked = Asked::default();
    for pair in query.unwrap_or_default().split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        let value = percent_decode(value);
        match name {
            "from" => asked.from = Some(value.clone()),
            "until" => asked.until = Some(value.clone()),
            "limit_records" | "limit" => asked.limit_records = value.parse().ok(),
            "limit_bytes" => asked.limit_bytes = value.parse().ok(),
            "proof" => asked.proof = matches!(value.as_str(), "true" | "1" | "yes"),
            // Repeated, because a reader asking for two types is asking for both rather than
            // whichever the query string happened to mention last.
            "event_type" => asked.filters.event_types.push(value.clone()),
            "producer" => asked.filters.producer = Some(value.clone()),
            "instance" => asked.filters.instance = Some(value.clone()),
            "profile" => asked.filters.profile = Some(value.clone()),
            "policy_partition" => asked.filters.policy_partition = Some(value.clone()),
            "kind" => asked.filters.kind = Some(value.clone()),
            "event_id" => asked.filters.event_id = Some(value.clone()),
            "since" => asked.filters.since = Some(value.clone()),
            "until_time" => asked.filters.until_time = Some(value.clone()),
            "history" => asked.filters.history = Some(value.clone()),
            _ => {}
        }
        asked.named.push((name.to_owned(), value));
    }

    asked
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

async fn records(State(facade): State<EventFacade>, RawQuery(query): RawQuery) -> Response {
    let asked = asked_of(query.as_deref());
    let named = |wanted: &str| asked.value(wanted);
    let (Some(zone), Some(ledger), Some(class), Some(producer), Some(instance)) = (
        named("zone"),
        named("ledger"),
        named("producer_class"),
        named("producer"),
        named("instance"),
    ) else {
        return refuse(
            &facade,
            ApiError::new(
                ErrorClass::Validation,
                "stream_required",
                "a deployment-wide read names one producer stream: \
                 `?zone=&ledger=&producer_class=&producer=&instance=`",
            ),
        );
    };

    serve(
        facade,
        Scope::Stream {
            zone,
            ledger,
            class,
            producer,
            instance,
        },
        asked,
        "stream",
    )
    .await
}

async fn tenant_records(
    State(facade): State<EventFacade>,
    Path((zone, ledger)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let asked = asked_of(query.as_deref());

    serve(facade, Scope::Tenant { zone, ledger }, asked, "tenant").await
}

async fn record(
    State(facade): State<EventFacade>,
    Path(event_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let asked = asked_of(query.as_deref());
    let (Some(zone), Some(ledger)) = (asked.value("zone"), asked.value("ledger")) else {
        return refuse(
            &facade,
            ApiError::new(
                ErrorClass::Validation,
                "store_required",
                "one occurrence is read inside one ledger: `?zone=&ledger=`",
            ),
        );
    };
    // Resolved like every other read, and like the gRPC `get` beside it. Without this the two
    // transports answered the same request differently: gRPC found the record by name, REST looked
    // for a directory named after it and reported the occurrence missing.
    let scope = match read::canonical(facade.catalog.as_ref(), Scope::Tenant { zone, ledger }) {
        Ok(scope) => scope,
        Err(error) => return read_refusal(&facade, error),
    };

    let found = {
        let (facade, scope) = (facade.clone(), scope.clone());
        tokio::task::spawn_blocking(move || {
            read::get(&facade.store, &scope, &event_id, &facade.cursor_key)
        })
        .await
        .unwrap_or_else(|error| Err(read::ReadError::Unavailable(error.to_string())))
    };

    match found {
        Ok(Some(record)) => (StatusCode::OK, Json(record)).into_response(),
        Ok(None) => refuse(
            &facade,
            ApiError::new(
                ErrorClass::NotFound,
                "event_not_found",
                "no event in this ledger carries that identifier",
            ),
        ),
        Err(error) => read_refusal(&facade, error),
    }
}

async fn serve(facade: EventFacade, scope: Scope, asked: Asked, kind: &'static str) -> Response {
    let scope = match read::canonical(facade.catalog.as_ref(), scope) {
        Ok(scope) => scope,
        Err(error) => return read_refusal(&facade, error),
    };
    let window = asked.window();
    let filters = asked.filters.clone();
    let page = {
        let (facade, scope) = (facade.clone(), scope.clone());
        tokio::task::spawn_blocking(move || facade.read(&scope, &filters, &window, kind))
            .await
            .unwrap_or_else(|error| Err(read::ReadError::Unavailable(error.to_string())))
    };

    match page {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(error) => read_refusal(&facade, error),
    }
}

fn read_refusal(facade: &EventFacade, error: read::ReadError) -> Response {
    match error {
        ref expired @ read::ReadError::Expired {
            ref oldest,
            oldest_sequence,
            requested_sequence,
        } => (
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
            .into_response(),
        read::ReadError::Offset(refused) => refuse(
            facade,
            ApiError::new(
                ErrorClass::Validation,
                "offset_invalid",
                refused.to_string(),
            ),
        ),
        // A scope nobody holds is a 404, never an empty page: the two are the same shape to a
        // script, and only one of them means the ledger is empty.
        read::ReadError::Unknown(detail) => refuse(
            facade,
            ApiError::new(ErrorClass::NotFound, "ledger_not_held", detail),
        ),
        read::ReadError::Unavailable(detail) => refuse(
            facade,
            ApiError::new(ErrorClass::Unavailable, "event_store_unavailable", detail),
        ),
        // Not a `404`: the search stopped at a bound this store chose, so whether the record is
        // here was never established. A `404` would be this store inventing an absence.
        ref exhausted @ read::ReadError::SearchExhausted { .. } => refuse(
            facade,
            ApiError::new(
                ErrorClass::Unavailable,
                "search_exhausted",
                exhausted.to_string(),
            ),
        ),
    }
}

fn refuse(facade: &EventFacade, error: ApiError) -> Response {
    wire::http_error(&error, facade.disclosure)
}
