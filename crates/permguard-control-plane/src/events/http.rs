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

use permguard_core::metrics::labels;
use permguard_core::{ApiError, Disclosure, ErrorClass, Jwk, Metrics};
use permguard_stream::Window;

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
    /// The Host's consumer of the event stream, which the public reads answer from beside the
    /// store (WP-6.2b); `None` when no engine consumes it.
    pub host: Option<permguard_host::composition::StreamConsumer>,
    /// Producers bound by whoever composes the facade: empty in a served deployment, where the
    /// in-process ring is the only trust (WP-6.2b); what a test or an embedding names directly.
    pub producers: Arc<std::sync::RwLock<Vec<ProducerTrust>>>,
    /// The ring of the data plane sharing this process, bound to the legacy journals it may
    /// still ship (WP-6.2b): no key file is read.
    pub local: Option<LocalTrust>,
    /// The secret read offsets are signed with.
    pub cursor_key: crate::decisions::cursorkey::CursorKeys,
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

/// The `data.attest` ring of the data plane sharing this process, and the legacy journals beside
/// it that its old shipper may still send here (WP-6.2b, owner decision of 2026-10-18).
#[derive(Clone)]
pub struct LocalTrust {
    /// The ring; `None` when this process composes no `data.attest` ring, which leaves the
    /// journals' batches refused and the store degraded rather than silently waiting.
    pub keys: Option<Arc<dyn permguard_core::keys::PublicSet>>,
    /// `(producer, zone, ledger)` of each legacy journal.
    pub bindings: Vec<(String, String, String)>,
}

impl EventFacade {
    /// Where its reads find their events: the store, and the Host's consumer (WP-6.2b).
    pub(crate) fn sources(&self) -> read::Sources<'_> {
        read::Sources {
            store: &self.store,
            host: self.host.as_ref(),
        }
    }

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
        let mut producers = self
            .producers
            .read()
            .map(|held| held.clone())
            .unwrap_or_default();
        // Read on every batch, so the ring's rotation needs no reload: what it publishes now.
        if let Some(local) = &self.local
            && let Some(keys) = &local.keys
        {
            match keys.public_keys() {
                Ok(keys) => {
                    for key in keys {
                        for (producer, zone, ledger) in &local.bindings {
                            producers.push(ProducerTrust {
                                key: key.clone(),
                                producer: producer.clone(),
                                zone: zone.clone(),
                                ledger: ledger.clone(),
                            });
                        }
                    }
                }
                Err(error) => tracing::warn!(
                    event.name = "events.local_keys_unreadable",
                    error = %error,
                    "the ring of the data plane in this process cannot publish its keys: batches \
                     of its legacy journals are refused until it can"
                ),
            }
        }
        producers
    }

    /// Whether this store waits for batches over its ingest route: a bound producer, or a
    /// legacy journal beside it (WP-6.2b). A plane in this process records on the Host's stream,
    /// and a store expecting nothing is not degraded.
    pub fn expects_batches(&self) -> bool {
        self.local
            .as_ref()
            .is_some_and(|local| !local.bindings.is_empty())
            || self
                .producers
                .read()
                .map(|held| !held.is_empty())
                .unwrap_or(true)
    }

    /// Whether this store expects batches it can accept from nobody: a legacy journal or a bound
    /// producer waits, and no key is trusted. Health reports the store degraded then.
    pub fn awaits_trust(&self) -> bool {
        self.expects_batches() && self.accepted_producers().is_empty()
    }

    /// Every key that may verify evidence this store already holds.
    ///
    /// The published sets plus the archive. Read-only by construction: nothing that reaches this
    /// admits a record, it only re-checks records admitted earlier under keys that were current
    /// then.
    pub fn verification_keys(&self) -> Result<Vec<Jwk>, String> {
        let mut keys: Vec<Jwk> = self
            .accepted_producers()
            .into_iter()
            .map(|held| held.key)
            .collect();
        let archived = self
            .store
            .archived_keys()
            .map_err(|error| error.to_string())?;
        for key in archived {
            // A key id is scoped to its producer. Two producers may legitimately publish
            // different material under the same label, and a verifier must try both.
            if !keys.iter().any(|held| held == &key) {
                keys.push(key);
            }
        }

        Ok(keys)
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
    /// The filters narrow to one producer class, producer or incarnation; the answer is one
    /// bounded page of [`SIGNERS_STREAM_CEILING`] streams, walked and cut at the directory —
    /// never collected whole and trimmed — and a truncated page carries `next`, the cursor the
    /// following ask passes back as `after`.
    pub fn signers_of(
        &self,
        zone: &str,
        ledger: &str,
        from_seq: u64,
        until_seq: u64,
        ask: &StreamsAsked,
    ) -> Result<SignersDocument, ApiError> {
        let scope = super::read::canonical(
            self.catalog.as_ref(),
            Scope::Tenant {
                zone: zone.to_owned(),
                ledger: ledger.to_owned(),
            },
        )
        .map_err(|error| match error {
            super::read::ReadError::Unknown(detail) => ApiError::new(
                ErrorClass::NotFound,
                permguard_core::codes::stream::SCOPE_UNKNOWN,
                detail,
            ),
            other => ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                other.to_string(),
            ),
        })?;
        let Scope::Tenant { zone, ledger } = scope else {
            return Err(ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::stream::SCOPE_MISMATCH,
                "a tenant scope resolved to something else",
            ));
        };
        let until = if until_seq == 0 { u64::MAX } else { until_seq };

        let page = self
            .store
            .producer_streams_page(
                &zone,
                &ledger,
                ask.producer_class.as_deref(),
                ask.producer.as_deref(),
                ask.instance.as_deref(),
                ask.after
                    .as_ref()
                    .map(permguard_stream::StreamPosition::as_tuple),
                SIGNERS_STREAM_CEILING,
            )
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::STORE_UNAVAILABLE,
                    error.to_string(),
                )
            })?;
        let mut truncated = page.truncated;
        let mut answered = Vec::with_capacity(page.streams.len());
        for stream in page.streams {
            let state = self.store.stream_state(&stream).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::STORE_UNAVAILABLE,
                    error.to_string(),
                )
            })?;
            let signers = self.store.signers(&stream).map_err(|error| {
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
            answered.push(StreamSignersView {
                producer_class: stream.producer.class,
                producer: stream.producer.id,
                instance: stream.producer.instance,
                acked: state.acked,
                spans: spans.to_vec(),
            });
        }

        // The Host consumer's runs of the ledger beside the legacy streams (WP-6.2b), in the same
        // `(class, producer, instance)` order: past `after`, and no further than the last legacy
        // stream of a truncated page, so the next page skips none of the streams in between.
        if let Some(host) = &self.host {
            let tuple = |view: &StreamSignersView| {
                (
                    view.producer_class.clone(),
                    view.producer.clone(),
                    view.instance.clone(),
                )
            };
            let after = ask
                .after
                .as_ref()
                .map(|after| permguard_stream::StreamPosition::clone(after).into_tuple());
            let reached = truncated.then(|| answered.last().map(tuple)).flatten();
            let unavailable = |error: String| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::STORE_UNAVAILABLE,
                    error,
                )
            };
            let resource = permguard_core::authz::Resource::ledger("data", &zone, &ledger);
            for run in host.signers(&resource).map_err(unavailable)? {
                let view = StreamSignersView {
                    producer_class: permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned(),
                    producer: crate::decisions::read::hex(&run.producer),
                    instance: crate::decisions::read::hex(&run.run),
                    acked: run.acked,
                    spans: Vec::new(),
                };
                let asked = |filter: &Option<String>, held: &str| {
                    filter.as_deref().is_none_or(|filter| filter == held)
                };
                if !asked(&ask.producer_class, &view.producer_class)
                    || !asked(&ask.producer, &view.producer)
                    || !asked(&ask.instance, &view.instance)
                    || after.as_ref().is_some_and(|after| tuple(&view) <= *after)
                    || reached
                        .as_ref()
                        .is_some_and(|reached| tuple(&view) > *reached)
                {
                    continue;
                }
                let mut signers = permguard_stream::Signers::empty();
                for (from, kid, jwk) in &run.spans {
                    let jwk: serde_json::Value = serde_json::from_str(jwk).map_err(|error| {
                        unavailable(format!("a signer of the Host's stream: {error}"))
                    })?;
                    signers
                        .observe(*from, kid, &jwk)
                        .map_err(|error| unavailable(format!("{error:?}")))?;
                }
                let spans = signers.covering(from_seq, until);
                if spans.len() > permguard_stream::MAX_SIGNER_SPANS {
                    return Err(ApiError::new(
                        ErrorClass::Validation,
                        permguard_core::codes::stream::SIGNER_RANGE_TOO_WIDE,
                        format!(
                            "this range crosses more than {} signing-key spans; narrow \
                             `from_seq` and `until_seq`",
                            permguard_stream::MAX_SIGNER_SPANS
                        ),
                    ));
                }
                answered.push(StreamSignersView {
                    spans: spans.to_vec(),
                    ..view
                });
            }
            answered.sort_by_key(tuple);
            if answered.len() > SIGNERS_STREAM_CEILING {
                answered.truncate(SIGNERS_STREAM_CEILING);
                truncated = true;
            }
        }

        // The cursor is the last stream of a truncated page: the next ask passes it back as
        // `after` and the walk resumes strictly past it.
        let next = truncated
            .then(|| answered.last())
            .flatten()
            .map(|held| StreamCursor {
                producer_class: held.producer_class.clone(),
                producer: held.producer.clone(),
                instance: held.instance.clone(),
            });

        Ok(SignersDocument {
            streams: answered,
            truncated,
            next,
        })
    }

    pub fn ingest(&self, batch: &Batch) -> Result<Accepted, Refused> {
        let started = std::time::Instant::now();
        let types = self.accepted_types();
        let answered = ingest::accept(&self.store, batch, &self.accepted_producers(), &types);
        self.metrics.observe(
            &measure::INGEST_SECONDS,
            &[],
            started.elapsed().as_secs_f64(),
        );
        match &answered {
            Ok(Accepted::Ok { stored, .. }) => {
                self.metrics.count(
                    &measure::BATCHES,
                    &[(
                        labels::OUTCOME,
                        if *stored > 0 { "accepted" } else { "replayed" },
                    )],
                );
                self.metrics.add(&measure::RECORDS, &[], *stored as f64);
            }
            Ok(Accepted::OutOfOrder { .. }) => {
                self.metrics
                    .count(&measure::BATCHES, &[(labels::OUTCOME, "out_of_order")]);
            }
            Err(refused) => {
                self.metrics
                    .count(&measure::BATCHES, &[(labels::OUTCOME, "refused")]);
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
        let answered = read::read_with(&self.sources(), scope, filters, &self.cursor_key, window);
        match &answered {
            Ok(page) => {
                self.metrics.count(
                    &measure::READS,
                    &[(labels::SCOPE, kind), (labels::OUTCOME, "ok")],
                );
                self.metrics.add(
                    &measure::EXAMINED,
                    &[(labels::SCOPE, kind)],
                    page.coverage.examined as f64,
                );
                self.metrics.add(
                    &measure::RETURNED,
                    &[(labels::SCOPE, kind)],
                    page.records.len() as f64,
                );
            }
            Err(read::ReadError::Expired { .. }) => {
                self.metrics.count(
                    &measure::READS,
                    &[(labels::SCOPE, kind), (labels::OUTCOME, "expired")],
                );
            }
            Err(_) => {
                self.metrics.count(
                    &measure::READS,
                    &[(labels::SCOPE, kind), (labels::OUTCOME, "refused")],
                );
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

/// The most producer streams one signers answer carries.
///
/// A ledger's incarnation count grows without bound over its lifetime; an answer must not. Past
/// the ceiling the response says `truncated`, and `producer`/`instance` narrow the next ask.
pub const SIGNERS_STREAM_CEILING: usize = 256;

/// The signers answer: one page of streams, and where the next page starts when there is one.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignersDocument {
    pub streams: Vec<StreamSignersView>,
    /// True when more streams matched than one page carries. Never a failure: `next` is the
    /// cursor, and the filters narrow the ask.
    pub truncated: bool,
    /// The position to resume from — passed back as `after`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<StreamCursor>,
}

/// A position in the `(class, producer, instance)` order of one ledger's streams.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamCursor {
    pub producer_class: String,
    pub producer: String,
    pub instance: String,
}

/// What narrows a stream listing: filters, and the cursor of the previous page.
#[derive(Debug, Clone, Default)]
pub struct StreamsAsked {
    pub producer_class: Option<String>,
    pub producer: Option<String>,
    pub instance: Option<String>,
    /// Resume strictly after this `(class, producer, instance)`.
    pub after: Option<permguard_stream::StreamPosition>,
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
    let asked = match asked_of(
        query.as_deref(),
        &[
            "from_seq",
            "until_seq",
            "after_class",
            "after_producer",
            "after_instance",
            "producer_class",
            "producer",
            "instance",
        ],
    ) {
        Ok(asked) => asked,
        Err(error) => return refuse(&facade, error),
    };
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
                    permguard_core::codes::stream::BOUND_MALFORMED,
                    format!("`{name}` is a sequence number"),
                ),
            );
        }
    };

    // The cursor is all-or-nothing: two thirds of a position is not a position.
    let after = match (
        asked.value("after_class"),
        asked.value("after_producer"),
        asked.value("after_instance"),
    ) {
        (None, None, None) => None,
        (Some(class), Some(producer), Some(instance)) => {
            match permguard_stream::StreamPosition::new(class, producer, instance) {
                Ok(position) => Some(position),
                Err(error) => {
                    return refuse(
                        &facade,
                        ApiError::new(
                            ErrorClass::Validation,
                            permguard_core::codes::stream::CURSOR_MALFORMED,
                            error.to_string(),
                        ),
                    );
                }
            }
        }
        _ => {
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::stream::CURSOR_MALFORMED,
                    "a stream cursor names all of `after_class`, `after_producer` and \
                     `after_instance`, or none of them",
                ),
            );
        }
    };
    let wanted = StreamsAsked {
        producer_class: asked.value("producer_class"),
        producer: asked.value("producer"),
        instance: asked.value("instance"),
        after,
    };

    let answered = {
        let facade = facade.clone();
        tokio::task::spawn_blocking(move || {
            facade.signers_of(&zone, &ledger, from_seq, until_seq, &wanted)
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
        Ok(document) => (StatusCode::OK, Json(document)).into_response(),
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

async fn batches(State(facade): State<EventFacade>, body: axum::body::Bytes) -> Response {
    let batch = match Batch::decode(&body) {
        Ok(batch) => batch,
        Err(rejection) => {
            return refuse(
                &facade,
                ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::notp::PAYLOAD_MALFORMED,
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
                "code": permguard_core::codes::stream::OUT_OF_ORDER,
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
    until: Option<permguard_stream::Frontier>,
    limit_records: Option<usize>,
    limit_bytes: Option<u64>,
    proof: bool,
    filters: Filters,
    query: crate::query::Query,
}

impl Asked {
    fn window(&self) -> Window {
        Window {
            from: self.from.clone(),
            until: self.until.clone(),
            limit_records: self.limit_records.unwrap_or_default(),
            limit_bytes: self.limit_bytes.unwrap_or_default(),
            proof: self.proof,
        }
    }

    fn value(&self, wanted: &str) -> Option<String> {
        self.query.value(wanted)
    }
}

/// The filters a read of events narrows by.
const FILTERS: [&str; 10] = [
    "event_type",
    "producer",
    "instance",
    "profile",
    "policy_partition",
    "kind",
    "event_id",
    "since",
    "until_time",
    "history",
];

/// Reads the query string of a read taking `names`, strictly (WP-5.5): a parameter it does not
/// name, one given twice (but `event_type`, which a reader repeats to ask for several), or a value
/// that does not parse is refused.
fn asked_of(query: Option<&str>, names: &[&str]) -> Result<Asked, ApiError> {
    let query = crate::query::parse(query, names, &["event_type"])?;
    let mut asked = Asked::default();
    if names.contains(&"from") {
        asked.from = query.value("from");
        asked.until = query.frontier("until")?;
        asked.limit_records = query.limit_records()?;
        asked.limit_bytes = query.number("limit_bytes")?;
        asked.proof = query.flag("proof")?;
    }
    asked.filters.event_types = query.values("event_type");
    asked.filters.producer = query.value("producer");
    asked.filters.instance = query.value("instance");
    asked.filters.profile = query.value("profile");
    asked.filters.policy_partition = query.value("policy_partition");
    asked.filters.kind = query.value("kind");
    asked.filters.event_id = query.value("event_id");
    asked.filters.since = query.value("since");
    asked.filters.until_time = query.value("until_time");
    asked.filters.history = query.value("history");
    asked.query = query;
    Ok(asked)
}

/// The names a bounded read of events takes: the window, the filters and `extra`.
fn reading(extra: &[&'static str]) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = crate::query::WINDOW.to_vec();
    names.extend_from_slice(&FILTERS);
    names.extend_from_slice(extra);
    names
}

async fn records(State(facade): State<EventFacade>, RawQuery(query): RawQuery) -> Response {
    let asked = match asked_of(
        query.as_deref(),
        &reading(&["zone", "ledger", "producer_class"]),
    ) {
        Ok(asked) => asked,
        Err(error) => return refuse(&facade, error),
    };
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
                permguard_core::codes::stream::STREAM_REQUIRED,
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
    let asked = match asked_of(query.as_deref(), &reading(&[])) {
        Ok(asked) => asked,
        Err(error) => return refuse(&facade, error),
    };

    serve(facade, Scope::Tenant { zone, ledger }, asked, "tenant").await
}

async fn record(
    State(facade): State<EventFacade>,
    Path(event_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let asked = match asked_of(query.as_deref(), &["zone", "ledger"]) {
        Ok(asked) => asked,
        Err(error) => return refuse(&facade, error),
    };
    let (Some(zone), Some(ledger)) = (asked.value("zone"), asked.value("ledger")) else {
        return refuse(
            &facade,
            ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::STORE_REQUIRED,
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
            read::get(&facade.sources(), &scope, &event_id, &facade.cursor_key)
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
                permguard_core::codes::stream::EVENT_NOT_FOUND,
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
                "code": permguard_core::codes::stream::OFFSET_EXPIRED,
                "message": expired.to_string(),
                "oldest_available": oldest,
                "oldest_sequence": oldest_sequence,
                "requested_sequence": requested_sequence,
            })),
        )
            .into_response(),
        read::ReadError::Offset(refused) => refuse(
            facade,
            ApiError::new(ErrorClass::Validation, refused.code(), refused.to_string()),
        ),
        // A scope nobody holds is a 404, never an empty page: the two are the same shape to a
        // script, and only one of them means the ledger is empty.
        read::ReadError::Unknown(detail) => refuse(
            facade,
            ApiError::new(
                ErrorClass::NotFound,
                permguard_core::codes::stream::LEDGER_NOT_HELD,
                detail,
            ),
        ),
        read::ReadError::Unavailable(detail) => refuse(
            facade,
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::EVENT_STORE_UNAVAILABLE,
                detail,
            ),
        ),
        // Not a `404`: the search stopped at a bound this store chose, so whether the record is
        // here was never established. A `404` would be this store inventing an absence.
        ref exhausted @ read::ReadError::SearchExhausted { .. } => refuse(
            facade,
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::SEARCH_EXHAUSTED,
                exhausted.to_string(),
            ),
        ),
    }
}

fn refuse(facade: &EventFacade, error: ApiError) -> Response {
    wire::http_error(&error, facade.disclosure)
}

#[cfg(test)]
mod openapi {
    //! `contracts/openapi/evidence-events-v1alpha1.json`, checked against the types that put its
    //! bodies on the wire.
    //!
    //! Here rather than beside the public event types because the signer views, the signers
    //! document and the configuration document are private to this plane, and the document's one
    //! `assert_covered` has to run in a process that has seen all of its schemas.

    #![allow(clippy::expect_used)]

    use permguard_core::keys::PublicSet as _;

    use std::time::Duration;

    use permguard_conformance::schema::Document;
    use permguard_core::KeyManager;
    use permguard_events::envelope::{Batch, Envelope, Signed};
    use permguard_events::record::{
        GENESIS, HistoryKey, PRODUCER_CLASS_DATA_PLANE, Producer, RECORD_TYPE, Record, Stream,
        VERSION, digest_of, occurrence_digest_of,
    };
    use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
    use serde_json::{Value, json};

    use super::*;

    fn ring() -> DirectoryKeyManager {
        let root = std::env::temp_dir().join(format!(
            "permguard-events-openapi-{}-{:?}",
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

    fn stream() -> Stream {
        Stream::new(
            Producer::data_plane("plane-a", "inst-1"),
            "acme",
            "agent-governance",
        )
    }

    /// Two records: one with a history key, one with global history.
    fn records() -> Vec<Value> {
        let mut prev = GENESIS.to_owned();
        let mut built = Vec::new();
        for seq in 1..=2_u64 {
            let event = json!({
                "event_id": format!("evt-{seq}"),
                "kind": "request",
                "action": "Drupe::Action::Login",
                "occurred_at": "2026-08-28T10:15:30Z",
            });
            let record = Record {
                v: VERSION,
                record_type: RECORD_TYPE.to_owned(),
                stream: stream(),
                seq,
                prev: prev.clone(),
                event_type: permguard_languages::event::EVENT_TYPE.to_owned(),
                event_id: format!("evt-{seq}"),
                source: None,
                occurrence_digest: occurrence_digest_of(&event).expect("the occurrence digests"),
                kind: "request".to_owned(),
                profile: "temporal".to_owned(),
                policy_partitions: vec!["governance".to_owned()],
                commit: "sha256:commit".to_owned(),
                history_key: (seq == 1).then(|| HistoryKey {
                    pins: vec!["user".to_owned()],
                    values: vec!["alice".to_owned()],
                    digest: "sha256:hk".to_owned(),
                }),
                occurred_at: "2026-08-28T10:15:30Z".to_owned(),
                observed_at: "2026-08-28T10:15:31Z".to_owned(),
                event,
            };
            let value = record.to_value().expect("a record renders");
            prev = digest_of(&value).expect("it digests");
            built.push(value);
        }

        built
    }

    #[test]
    fn test_the_event_wire_types_match_openapi_evidence_events() {
        let doc = Document::load("evidence-events-v1alpha1.json");
        let values = records();
        for value in &values {
            doc.check_json("Record", value);
        }
        // The producer and stream identities, as a typed value serialises them.
        doc.check("Stream", &stream());
        doc.check("Producer", &stream().producer);
        assert_eq!(stream().producer.class, PRODUCER_CLASS_DATA_PLANE);

        let leaves: Vec<String> = values
            .iter()
            .map(|value| digest_of(value).expect("it digests"))
            .collect();
        let envelope = Envelope {
            stream: stream(),
            first_seq: 1,
            last_seq: 2,
            count: 2,
            previous_head: GENESIS.to_owned(),
            head: leaves[1].clone(),
            merkle_root: permguard_stream::merkle::root(&leaves).expect("a root"),
            event_types: vec![permguard_languages::event::EVENT_TYPE.to_owned()],
            record_version: 1,
            at: "2026-08-28T10:15:32Z".to_owned(),
        };
        let keys = ring();
        let signed = Signed::create(&envelope, &keys).expect("it signs");
        doc.check("Envelope", &envelope);
        doc.check("Signed", &signed);
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

        // Closed envelopes refuse a member the contract does not name.
        let mut extra = sent.clone();
        extra["unexpected"] = json!(1);
        assert!(!doc.accepts_json("Batch", &extra));
        let mut extra_header = sent.clone();
        extra_header["signature"]["kid"] = json!("k");
        assert!(!doc.accepts_json("Batch", &extra_header));
        let mut empty = sent.clone();
        empty["records"] = json!([]);
        assert!(!doc.accepts_json("Batch", &empty));
        assert!(!doc.accepts_json(
            "Protected",
            &json!({"alg": "EdDSA", "typ": "permguard.decision.batch.v1", "kid": "k"})
        ));
        let mut extra_stream = serde_json::to_value(stream()).expect("a stream serialises");
        extra_stream["host"] = json!("h");
        assert!(!doc.accepts_json("Stream", &extra_stream));
        let mut nameless = values[1].clone();
        nameless
            .as_object_mut()
            .expect("an object")
            .remove("event_id");
        assert!(!doc.accepts_json("Record", &nameless));
        // Records are open: a newer producer's member is kept, not refused.
        let mut newer = values[1].clone();
        newer["added_later"] = json!(true);
        assert!(doc.accepts_json("Record", &newer));

        // The 200 and 409 answers are built inline in `batches`; these are the same objects.
        doc.check_json("Acknowledgement", &json!({"acked": 2, "stored": 2}));
        let expected_seq = 3_u64;
        doc.check_json(
            "OutOfOrder",
            &json!({
                "class": "conflict",
                "code": permguard_core::codes::stream::OUT_OF_ORDER,
                "message": format!(
                    "this store holds through {} and this batch begins later: resend from {expected_seq}",
                    expected_seq.saturating_sub(1)
                ),
                "expected_seq": expected_seq,
            }),
        );
        assert!(!doc.accepts_json(
            "OutOfOrder",
            &json!({"class": "conflict", "code": "out_of_order", "message": "m"})
        ));

        // A page with proof, and one without.
        let path = permguard_stream::merkle::path(&leaves, 0).expect("a path");
        let page = permguard_stream::Block {
            records: values.clone(),
            next: "AAAA".to_owned(),
            oldest_available: "BBBB".to_owned(),
            high_watermark: "CCCC".to_owned(),
            more: false,
            // Each entry names its format (WP-6.2b): the legacy JWS, and a Host batch's.
            proof: vec![
                {
                    let mut legacy = serde_json::to_value(&signed).expect("a signature serialises");
                    legacy["format"] = json!(crate::decisions::read::LEGACY_FORMAT);
                    legacy
                },
                json!({
                    "format": crate::decisions::read::HOST_FORMAT,
                    "signature": serde_json::to_value(&signed).expect("a signature serialises"),
                }),
            ],
            inclusion: vec![json!({
                "seq": 1,
                "leaf": leaves[0],
                "root": envelope.merkle_root,
                "path": path,
            })],
            coverage: permguard_stream::Coverage {
                contiguous: true,
                examined: 2,
                scan_bounded: false,
            },
        };
        doc.check("EventBlock", &page);
        // A proof entry naming no format, or the other format's members, is not one.
        let mut unnamed = serde_json::to_value(&page).expect("a page serialises");
        unnamed["proof"][0]
            .as_object_mut()
            .expect("an object")
            .remove("format");
        assert!(!doc.accepts_json("EventBlock", &unnamed));
        let mut crossed = serde_json::to_value(&page).expect("a page serialises");
        crossed["proof"][1]["format"] = json!(crate::decisions::read::LEGACY_FORMAT);
        assert!(!doc.accepts_json("EventBlock", &crossed));
        let bare = permguard_stream::Block {
            proof: Vec::new(),
            inclusion: Vec::new(),
            ..page.clone()
        };
        doc.check("EventBlock", &bare);

        // The signers answer: a truncated page with its cursor, and a complete one without.
        let jwk = keys.public_keys().expect("the ring publishes").remove(0);
        let view = StreamSignersView {
            producer_class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
            producer: "plane-a".to_owned(),
            instance: "inst-1".to_owned(),
            acked: 2,
            spans: vec![permguard_stream::SignerSpan {
                from: 1,
                kid: jwk.kid.clone(),
                jwk: serde_json::to_value(&jwk).expect("a key serialises"),
            }],
        };
        doc.check("StreamSignersView", &view);
        doc.check(
            "SignersDocument",
            &SignersDocument {
                streams: vec![view.clone()],
                truncated: true,
                next: Some(StreamCursor {
                    producer_class: view.producer_class.clone(),
                    producer: view.producer.clone(),
                    instance: view.instance.clone(),
                }),
            },
        );
        doc.check(
            "SignersDocument",
            &SignersDocument {
                streams: vec![view],
                truncated: false,
                next: None,
            },
        );

        // The discovery document, built by the function the route serves.
        let configuration = super::super::configuration::document(
            "http://plane.example",
            "plane.example",
            &[permguard_languages::event::EVENT_TYPE],
        );
        doc.check("Document", &configuration);
        let mut unlimited = serde_json::to_value(&configuration).expect("it serialises");
        unlimited
            .as_object_mut()
            .expect("an object")
            .remove("limits");
        assert!(!doc.accepts_json("Document", &unlimited));
        doc.check("Limits", &configuration.limits);
        doc.check("Endpoints", &configuration.endpoints);
        doc.check("Offsets", &configuration.offsets);

        doc.assert_covered();
    }

    /// WP-5.5: a read of events takes its window, its filters and its own names, each once but
    /// `event_type`, with values that parse; anything else is a validation refusal.
    #[test]
    fn a_read_of_events_takes_only_its_parameters() {
        let names = reading(&["zone"]);
        let asked = asked_of(
            Some("zone=acme&event_type=a&event_type=b&limit_records=3&proof=true&history=all"),
            &names,
        )
        .expect("it parses");
        assert_eq!(asked.filters.event_types, vec!["a", "b"]);
        assert_eq!(asked.limit_records, Some(3));
        assert!(asked.proof);
        assert_eq!(asked.filters.history.as_deref(), Some("all"));
        assert_eq!(asked.value("zone").as_deref(), Some("acme"));

        for query in [
            "color=red",
            "producer=a&producer=b",
            "limit=1&limit_records=2",
            "limit_bytes=many",
            "proof=yes",
            "until=nothing",
            "kind",
        ] {
            let error = asked_of(Some(query), &names).expect_err(query);
            assert_eq!(
                error.code(),
                permguard_core::codes::common::INVALID_ARGUMENT,
                "{query}"
            );
        }
        // A read without a window refuses one.
        assert!(asked_of(Some("from=a"), &FILTERS).is_err());
    }

    /// WP-5.5: over REST, an offset of another read is `forged` and a malformed one
    /// `offset_invalid`, both `400`.
    #[tokio::test]
    async fn an_offset_of_another_read_is_forged_over_rest() {
        use http_body_util::BodyExt as _;
        use permguard_stream::cursor::CursorError;

        let root =
            std::env::temp_dir().join(format!("permguard-events-refusal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let facade = EventFacade {
            host: None,
            catalog: None,
            store: std::sync::Arc::new(crate::events::EventStore::open(&root).expect("it opens")),
            producers: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            local: None,
            cursor_key: crate::decisions::cursorkey::CursorKeys::from_root(
                b"a-test-cursor-key-of-32-bytes!!!!",
                [1; 16],
                "events",
            )
            .expect("a cursor key"),
            disclosure: permguard_core::Disclosure::default(),
            metrics: permguard_core::metrics::Metrics::default(),
            base_url: String::new(),
        };
        for (error, code) in [
            (CursorError::Forged, "forged"),
            (CursorError::WrongApi, "forged"),
            (CursorError::Malformed, "offset_invalid"),
        ] {
            let response = read_refusal(&facade, read::ReadError::Offset(error));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{code}");
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("the body reads")
                .to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON body");
            assert_eq!(body["code"], code, "{body}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
