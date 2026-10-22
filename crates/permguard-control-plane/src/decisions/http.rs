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
    /// The Host's consumer of the decision stream: what the public reads answer from besides the
    /// legacy store (WP-6.1b). `None` when the Host composes none.
    pub host: Option<permguard_host::composition::StreamConsumer>,
    /// The catalog, turning a tenant route's names into the ids the consumer's streams are keyed
    /// by (owner decision of 2026-10-18).
    pub catalog: Option<Arc<dyn permguard_core::catalog::Catalog>>,
    /// Where this plane is reached, what its discovery document's endpoints are built on.
    pub base_url: String,
    /// Who serves the interface, its build and its phase: the discovery document's common header
    /// (WP-7.4a).
    pub describer: permguard_core::stages::Describer,
    /// The Host's authorization, every evidence read decides with before it looks anything up
    /// (WP-6.3c).
    pub authorization: Arc<permguard_host::composition::Authorization>,
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
        // A Host run named by its `host_id` and run, as the read names it (WP-6.3b): answered from
        // the consumer's signer observations of the run's resource.
        if let Some(view) = self.host_signers(pdp_id, instance, from_seq, until_seq)? {
            return Ok(view);
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

    /// The signers of the Host run `pdp_id`/`instance` names in hex, when the consumer holds it
    /// (WP-6.3b); `None` for a pair naming no run it holds, which the legacy store then answers.
    fn host_signers(
        &self,
        pdp_id: &str,
        instance: &str,
        from_seq: u64,
        until_seq: u64,
    ) -> Result<Option<StreamSignersView>, ApiError> {
        let (Some(host), Some(producer), Some(run)) = (
            self.host.as_ref(),
            read::unhex16(pdp_id),
            read::unhex16(instance),
        ) else {
            return Ok(None);
        };
        let unavailable = |error: String| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error,
            )
        };
        let Some(resource) = host.locate(&producer, &run).map_err(unavailable)? else {
            return Ok(None);
        };
        let Some(held) = host
            .signers(&resource)
            .map_err(unavailable)?
            .into_iter()
            .find(|held| held.producer == producer && held.run == run)
        else {
            return Ok(None);
        };
        let mut signers = permguard_stream::Signers::empty();
        for (from, kid, jwk) in &held.spans {
            let jwk: serde_json::Value = serde_json::from_str(jwk)
                .map_err(|error| unavailable(format!("a signer of the Host's stream: {error}")))?;
            signers
                .observe(*from, kid, &jwk)
                .map_err(|error| unavailable(format!("{error:?}")))?;
        }
        let until = if until_seq == 0 { u64::MAX } else { until_seq };
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
        Ok(Some(StreamSignersView {
            acked: held.acked,
            spans: spans.to_vec(),
        }))
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

    /// Reads one bounded block of `scope` from the legacy store and the Host's consumer
    /// (WP-6.1b): what both transports answer.
    pub(crate) fn read(
        &self,
        scope: &Scope,
        window: &Window,
    ) -> Result<read::Page, read::ReadError> {
        read::read_with(
            &read::Sources {
                store: &self.store,
                host: self.host.as_ref(),
                catalog: self.catalog.as_ref(),
            },
            scope,
            &self.cursor_key,
            window,
        )
    }

    /// The scope `actor` may read under `evidence.read`, resolved to ids (WP-6.3c): refused before
    /// any lookup when nothing is granted under the plane; an unknown scope `not_found` only
    /// under a whole-plane grant; a tenant on its ledger; a stream on the ledger of the Host run
    /// it names, or on the whole plane for a legacy stream mixing tenants.
    pub(crate) fn gate(
        &self,
        actor: &permguard_core::authz::Actor,
        scope: Scope,
    ) -> Result<Scope, crate::evidence::Gated<read::ReadError>> {
        use crate::evidence::{self, Gated};

        evidence::admitted(&self.authorization, actor).map_err(Gated::Denied)?;
        let sources = read::Sources {
            store: &self.store,
            host: self.host.as_ref(),
            catalog: self.catalog.as_ref(),
        };
        let scope = match read::canonical(&sources, scope) {
            Ok(scope) => scope,
            Err(error @ read::ReadError::Unknown(_)) => {
                evidence::unknown(&self.authorization, actor).map_err(Gated::Denied)?;
                return Err(Gated::Refused(error));
            }
            Err(error) => return Err(Gated::Refused(error)),
        };
        let allowed = match &scope {
            Scope::Tenant { zone, ledger } => {
                evidence::on_ledger(&self.authorization, actor, zone, ledger)
            }
            Scope::Stream { pdp_id, instance } => {
                match self.run_ledger(pdp_id, instance).map_err(Gated::Refused)? {
                    Some((zone_id, ledger_id)) => {
                        evidence::on_ledger(&self.authorization, actor, &zone_id, &ledger_id)
                    }
                    None => evidence::on_plane(&self.authorization, actor),
                }
            }
        };
        allowed.map_err(Gated::Denied)?;
        Ok(scope)
    }

    /// The ledger of the Host run `pdp_id`/`instance` names in hex, when the consumer holds it.
    fn run_ledger(
        &self,
        pdp_id: &str,
        instance: &str,
    ) -> Result<Option<(String, String)>, read::ReadError> {
        let (Some(host), Some(producer), Some(run)) = (
            self.host.as_ref(),
            read::unhex16(pdp_id),
            read::unhex16(instance),
        ) else {
            return Ok(None);
        };
        Ok(
            match host
                .locate(&producer, &run)
                .map_err(read::ReadError::Unavailable)?
            {
                Some(permguard_core::authz::Resource::Ledger {
                    zone_id, ledger_id, ..
                }) => Some((zone_id, ledger_id)),
                _ => None,
            },
        )
    }

    /// Reads one bounded block of `scope` as `actor`, through the `evidence.read` gate (WP-6.3c):
    /// what both transports answer.
    pub(crate) fn read_as(
        &self,
        actor: &permguard_core::authz::Actor,
        scope: Scope,
        window: &Window,
    ) -> Result<read::Page, crate::evidence::Gated<read::ReadError>> {
        let scope = self.gate(actor, scope)?;
        self.read(&scope, window)
            .map_err(crate::evidence::Gated::Refused)
    }

    /// Whether this store waits for batches over its ingest route: a producer key set is
    /// configured, or a legacy spool beside it names its producer. Since WP-6.1 a plane in the
    /// same process records on the Host's stream, and a store expecting nothing is not degraded.
    pub(crate) fn expects_batches(&self) -> bool {
        !self.producer_files.is_empty() || !self.local_pdp.is_empty()
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

/// Where a legacy producer delivers a batch.
pub const BATCHES_PATH: &str = "/decisions/v1/batches";
/// One producer stream's records.
pub const RECORDS_PATH: &str = "/decisions/v1/records";
/// One tenant's records.
pub const TENANT_RECORDS_PATH: &str = "/zones/{zone}/ledgers/{ledger}/decisions/v1/records";
/// One producer stream's signing-key spans.
pub const SIGNERS_PATH: &str = "/decisions/v1/signers";

/// The routes the control plane answers about decisions.
pub(crate) fn routes(facade: DecisionFacade) -> Router {
    Router::new()
        .route(BATCHES_PATH, post(ship))
        .route(RECORDS_PATH, get(records))
        .route(TENANT_RECORDS_PATH, get(tenant_records))
        .route(SIGNERS_PATH, get(signers))
        .route(super::configuration::CONFIGURATION_PATH, get(document))
        .with_state(facade)
}

/// What this plane offers of the decision log interface (WP-6.3b). Unauthenticated, like every
/// layer of the discovery chain: it says what the shapes are, never what is inside them.
async fn document(State(facade): State<DecisionFacade>) -> Response {
    match facade
        .describer
        .header(permguard_core::domains::interface::DECISIONS_NATIVE_V1)
    {
        Ok(header) => Json(super::configuration::document(
            &facade.base_url,
            &facade.base_url,
            header,
        ))
        .into_response(),
        Err(refused) => crate::wire::http_error(&refused, facade.disclosure),
    }
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
    until: Option<permguard_stream::Frontier>,
    limit_records: Option<usize>,
    limit_bytes: Option<u64>,
    proof: bool,
}

impl Asked {
    /// The read this asks for, in the shared contract's terms.
    fn window(&self) -> Window {
        Window {
            from: self.from.clone(),
            until: self.until.clone(),
            limit_records: self.limit_records.unwrap_or_default(),
            limit_bytes: self.limit_bytes.unwrap_or_default(),
            proof: self.proof,
        }
    }
}

/// Reads the query string of a bounded read taking `names` beside the window, strictly
/// (WP-5.5): a parameter it does not name, one given twice, or a value that does not parse is
/// refused, an `until` this build did not issue included.
fn window_of(
    query: Option<&str>,
    names: &[&str],
) -> Result<(Asked, crate::query::Query), ApiError> {
    let mut allowed: Vec<&str> = crate::query::WINDOW.to_vec();
    allowed.extend_from_slice(names);
    let query = crate::query::parse(query, &allowed, &[])?;
    let asked = Asked {
        from: query.value("from"),
        until: query.frontier("until")?,
        limit_records: query.limit_records()?,
        limit_bytes: query.number("limit_bytes")?,
        proof: query.flag("proof")?,
    };
    Ok((asked, query))
}

async fn records(
    State(facade): State<DecisionFacade>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let (window, query) = match window_of(query.as_deref(), &["pdp", "instance"]) {
        Ok(parsed) => parsed,
        Err(error) => return refuse(&facade, error),
    };
    let named = |wanted: &str| query.value(wanted);
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

    serve(facade, actor, scope, window, "stream").await
}

/// Which key signed which stretch of one producer stream, public keys included.
async fn signers(State(facade): State<DecisionFacade>, RawQuery(query): RawQuery) -> Response {
    let query = match crate::query::parse(
        query.as_deref(),
        &["pdp", "instance", "from_seq", "until_seq"],
        &[],
    ) {
        Ok(query) => query,
        Err(error) => return refuse(&facade, error),
    };
    let named = |wanted: &str| query.value(wanted);
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
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let scope = Scope::Tenant { zone, ledger };
    let (window, _) = match window_of(query.as_deref(), &[]) {
        Ok(parsed) => parsed,
        Err(error) => return refuse(&facade, error),
    };

    serve(facade, actor, scope, window, "tenant").await
}

async fn serve(
    facade: DecisionFacade,
    actor: Arc<permguard_core::authz::Actor>,
    scope: Scope,
    asked: Asked,
    kind: &'static str,
) -> Response {
    let window = asked.window();
    // Off the runtime's threads: a page is segment files read back, and a bulk
    // export must not stall the reactor the shippers are landing batches on.
    let page = {
        let reader = facade.clone();
        tokio::task::spawn_blocking(move || reader.read_as(&actor, scope, &window))
            .await
            .unwrap_or_else(|error| {
                Err(crate::evidence::Gated::Refused(
                    read::ReadError::Unavailable(error.to_string()),
                ))
            })
    };
    let page = match page {
        Ok(page) => Ok(page),
        // Before anything else: a denial says nothing the caller may not learn (WP-6.3c).
        Err(crate::evidence::Gated::Denied(denial)) => {
            facade.metrics.count(
                &measure::READS,
                &[(labels::SCOPE, kind), (labels::OUTCOME, "denied")],
            );
            return crate::wire::http_denial(&denial);
        }
        Err(crate::evidence::Gated::Refused(error)) => Err(error),
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

            let (class, code) = crate::decisions::read::refusal(&error);
            refuse(&facade, ApiError::new(class, code, error.to_string()))
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
                // What the decision cited (WP-6.4a), every member.
                frontier: vec![permguard_core::frontier::FrontierRun {
                    origin: "0a".repeat(16),
                    run: "0b".repeat(16),
                    covered_through: 9,
                    low_watermark: 2,
                    gaps: vec![permguard_core::frontier::FrontierGap {
                        from: 4,
                        through: Some(5),
                    }],
                }],
                origin_set_revision: Some("0c".repeat(32)),
                max_staleness_seconds: Some(10),
                degraded: vec!["0a".repeat(16)],
                time: Some("occurred_at".to_owned()),
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
        // A deprecated interface's header, every member present (WP-7.4a).
        doc.check(
            "ConfigurationDocument",
            &super::super::configuration::document(
                "http://host",
                "store",
                permguard_core::stages::Header::of(
                    &permguard_core::stages::Registered {
                        id: permguard_core::domains::interface::DECISIONS_NATIVE_V1,
                        stage: permguard_core::stages::Stage::Deprecated {
                            sunset: "2027-06-30T00:00:00Z",
                        },
                    },
                    "control-plane",
                    "0.1.0",
                    permguard_core::lifecycle::Phase::Serving,
                ),
            ),
        );
        // The discovery document (WP-6.3b).
        doc.check(
            "ConfigurationDocument",
            &super::super::configuration::document(
                "http://host",
                "store",
                permguard_core::stages::Describer::detached("control-plane")
                    .header(permguard_core::domains::interface::DECISIONS_NATIVE_V1)
                    .expect("served"),
            ),
        );
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
            // Each entry names its format (WP-6.1b): the legacy JWS, and a Host batch's.
            proof: vec![
                {
                    let mut legacy = serde_json::to_value(&signed).expect("a signature serialises");
                    legacy["format"] = json!(read::LEGACY_FORMAT);
                    legacy
                },
                json!({
                    "format": read::HOST_FORMAT,
                    "signature": serde_json::to_value(&signed).expect("a signature serialises"),
                }),
            ],
            inclusion: vec![serde_json::to_value(&inclusion).expect("a path serialises")],
            coverage: Coverage {
                contiguous: false,
                examined: 5,
                scan_bounded: true,
            },
        };
        doc.check("DecisionBlock", &page);
        // A proof entry naming no format, or the other format's members, is not one.
        let mut unnamed = serde_json::to_value(&page).expect("a page serialises");
        unnamed["proof"][0]
            .as_object_mut()
            .expect("an object")
            .remove("format");
        assert!(!doc.accepts_json("DecisionBlock", &unnamed));
        let mut crossed = serde_json::to_value(&page).expect("a page serialises");
        crossed["proof"][1]["format"] = json!(read::LEGACY_FORMAT);
        assert!(!doc.accepts_json("DecisionBlock", &crossed));
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

#[cfg(test)]
mod strict {
    //! WP-5.5 over the REST binding: the strict query and the cursor refusals.

    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    const ROOT: &[u8] = b"a-test-cursor-key-of-32-bytes!!!!";

    /// The Host's consumer of one run, `a1…`/`01…` over `acme/main`, signed by `k1` from 1 and
    /// `k2` from 5, acknowledged through 7.
    struct Signing;

    impl permguard_host::composition::StreamConsumerReads for Signing {
        fn runs(
            &self,
            _: &permguard_core::authz::Resource,
        ) -> Result<Vec<permguard_host::composition::ConsumedRun>, String> {
            Ok(Vec::new())
        }

        fn locate(
            &self,
            producer: &[u8; 16],
            run: &[u8; 16],
        ) -> Result<Option<permguard_core::authz::Resource>, String> {
            Ok((*producer == [0xa1; 16] && *run == [0x01; 16])
                .then(|| permguard_core::authz::Resource::ledger("data", "acme", "main")))
        }

        fn records(
            &self,
            _: &permguard_core::authz::Resource,
            _: &[u8; 16],
            _: &[u8; 16],
            _: u64,
            _: usize,
        ) -> Result<permguard_host::composition::ConsumedPage, String> {
            Ok(permguard_host::composition::ConsumedPage::default())
        }

        fn batch(
            &self,
            _: &permguard_core::authz::Resource,
            _: &[u8; 16],
            _: &[u8; 16],
            _: u64,
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }

        fn signers(
            &self,
            _: &permguard_core::authz::Resource,
        ) -> Result<Vec<permguard_host::composition::ConsumedSigners>, String> {
            let jwk = |kid: &str| {
                serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": kid, "kid": kid})
                    .to_string()
            };
            Ok(vec![
                permguard_host::composition::ConsumedSigners {
                    producer: [0xb2; 16],
                    run: [0x01; 16],
                    acked: 3,
                    spans: vec![(1, "other".to_owned(), jwk("other"))],
                },
                permguard_host::composition::ConsumedSigners {
                    producer: [0xa1; 16],
                    run: [0x01; 16],
                    acked: 7,
                    spans: vec![
                        (1, "k1".to_owned(), jwk("k1")),
                        (5, "k2".to_owned(), jwk("k2")),
                    ],
                },
            ])
        }
    }

    fn signing(tag: &str) -> DecisionFacade {
        DecisionFacade {
            host: Some(permguard_host::composition::StreamConsumer::over(Arc::new(
                Signing,
            ))),
            ..facade(tag)
        }
    }

    /// WP-6.3b: `pdp` and `instance` naming a Host run in hex answer its signers from the
    /// consumer, the run's own and no other's, cut to the range asked.
    #[tokio::test]
    async fn the_signers_of_a_host_run_come_from_the_consumer() {
        let router = routes(signing("host-signers"));
        let (pdp, instance) = (read::hex(&[0xa1; 16]), read::hex(&[0x01; 16]));
        let (status, body) = get(
            &router,
            &format!("/decisions/v1/signers?pdp={pdp}&instance={instance}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["acked"], 7);
        let kids: Vec<&str> = body["spans"]
            .as_array()
            .expect("spans")
            .iter()
            .filter_map(|span| span["kid"].as_str())
            .collect();
        assert_eq!(kids, ["k1", "k2"]);
        let (_, later) = get(
            &router,
            &format!("/decisions/v1/signers?pdp={pdp}&instance={instance}&from_seq=6"),
        )
        .await;
        assert_eq!(later["spans"][0]["kid"], "k2");
        assert_eq!(later["spans"].as_array().map(Vec::len), Some(1));
    }

    /// WP-6.3b: the decision log's discovery document is served beside its routes, on the base
    /// the plane is reached at.
    #[tokio::test]
    async fn the_decision_document_is_served_beside_the_routes() {
        let router = routes(DecisionFacade {
            base_url: "http://plane:6443".to_owned(),
            ..facade("document")
        });
        let (status, body) = get(&router, super::super::configuration::CONFIGURATION_PATH).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["endpoints"]["signers"],
            format!("http://plane:6443{SIGNERS_PATH}")
        );
        assert_eq!(body["interface"], read::API);
    }

    /// WP-6.3b: a pair naming no run the consumer holds and no legacy stream is `404`, never an
    /// empty manifest.
    #[tokio::test]
    async fn the_signers_of_a_run_nobody_holds_are_not_found() {
        let router = routes(signing("host-signers-none"));
        let (status, body) = get(
            &router,
            &format!(
                "/decisions/v1/signers?pdp={}&instance={}",
                read::hex(&[0xa1; 16]),
                read::hex(&[0x09; 16])
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], permguard_core::codes::stream::STREAM_UNKNOWN);
    }

    /// WP-6.3b: `GetSigners` answers the same manifest of a Host run.
    #[tokio::test]
    async fn get_signers_answers_a_host_run_over_grpc() {
        use crate::v1::decision_log_server::DecisionLog as _;

        let answered = signing("host-signers-grpc")
            .get_signers(tonic::Request::new(crate::v1::GetDecisionSignersRequest {
                pdp: read::hex(&[0xa1; 16]),
                instance: read::hex(&[0x01; 16]),
                from_seq: 0,
                until_seq: 0,
            }))
            .await
            .expect("answered")
            .into_inner();
        assert_eq!(answered.acked, 7);
        assert_eq!(
            answered
                .spans
                .iter()
                .map(|span| span.kid.as_str())
                .collect::<Vec<_>>(),
            ["k1", "k2"]
        );
    }

    /// WP-6.1: a store beside a plane recording on the Host's stream expects no batch unless a
    /// producer key set is configured or a legacy spool names its producer.
    #[test]
    fn a_store_expects_batches_only_from_a_named_producer() {
        let mut held = facade("expects");
        assert!(!held.expects_batches(), "nothing names a producer");
        held.local_pdp = "data-plane-local".to_owned();
        assert!(held.expects_batches(), "a legacy spool names one");
        held.local_pdp.clear();
        held.producer_files.push(ProducerFile {
            path: std::path::PathBuf::from("keys.json"),
            pdp: "plane-a".to_owned(),
        });
        assert!(held.expects_batches(), "a configured key set");
    }

    fn facade(tag: &str) -> DecisionFacade {
        let root = std::env::temp_dir().join(format!(
            "permguard-decisions-strict-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        DecisionFacade {
            store: Arc::new(DecisionStore::open(root).expect("it opens")),
            local: None,
            local_pdp: String::new(),
            cursor_key: crate::decisions::cursorkey::CursorKeys::from_root(
                ROOT,
                [1; 16],
                "decisions",
            )
            .expect("a cursor key"),
            producers: Arc::new(std::sync::RwLock::new(Vec::new())),
            producer_files: Vec::new(),
            disclosure: permguard_core::Disclosure::Full,
            metrics: permguard_core::Metrics::none(),
            host: None,
            catalog: None,
            base_url: String::new(),
            describer: permguard_core::stages::Describer::detached("control-plane"),
            authorization: std::sync::Arc::new(
                permguard_host::composition::Authorization::permissive(),
            ),
        }
    }

    /// The auditor every gate test reads as.
    fn auditor() -> Arc<permguard_core::authz::Actor> {
        Arc::new(permguard_core::authz::Actor::Authenticated(
            permguard_core::authz::ActorContext::new(
                permguard_core::authz::Principal::new("spiffe://acme/auditor")
                    .expect("a principal"),
                permguard_core::authz::Credential::SanUri,
                None,
            ),
        ))
    }

    /// Everybody granted `evidence.read` on `selector`, and nothing else.
    fn granted(selector: &str) -> Arc<permguard_host::composition::Authorization> {
        Arc::new(permguard_host::composition::Authorization::public_only(&[
            permguard_host::authz::PublicGrant::new(
                &[permguard_core::authz::operations::EVIDENCE_READ],
                permguard_core::authz::Selector::parse(selector).expect("a selector"),
            ),
        ]))
    }

    /// The routes of `facade` as `actor` reads them.
    fn as_actor(facade: DecisionFacade, actor: Arc<permguard_core::authz::Actor>) -> Router {
        routes(facade).layer(axum::Extension(actor))
    }

    /// WP-6.3c, owner decision of 2026-10-20: a tenant read takes `evidence.read` on its ledger in
    /// this plane's tree and on nothing else; a caller no boundary decided is `401`.
    #[tokio::test]
    async fn a_tenant_read_takes_evidence_read_on_its_ledger_and_nothing_else() {
        let held = DecisionFacade {
            authorization: granted("plane/control/zone/acme/ledger/main"),
            ..facade("gate-tenant")
        };
        let router = as_actor(held.clone(), auditor());
        let (status, body) = get(&router, "/zones/acme/ledgers/main/decisions/v1/records").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = get(&router, "/zones/acme/ledgers/audit/decisions/v1/records").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body.get("class").is_none(),
            "the closed denial body: {body}"
        );
        let (status, _) = get(
            &routes(held),
            "/zones/acme/ledgers/main/decisions/v1/records",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// WP-6.3c: a ledger nobody holds is refused as a foreign one, unless the caller's grants
    /// cover the whole plane, which learns it is `not_found`.
    #[tokio::test]
    async fn an_unknown_and_a_foreign_ledger_are_refused_alike() {
        use permguard_core::catalog::{Catalog as _, Selector};

        let root = std::env::temp_dir().join(format!(
            "permguard-decisions-gate-catalog-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let catalog = permguard_std::catalog::FileCatalog::new(root.join("catalog"));
        let zone = catalog.create_zone("acme").expect("a zone");
        let main = catalog
            .create_ledger(&Selector::Id(zone.id.clone()), "main")
            .expect("a ledger");
        catalog
            .create_ledger(&Selector::Id(zone.id.clone()), "audit")
            .expect("another");
        let catalog: Arc<dyn permguard_core::catalog::Catalog> = Arc::new(catalog);
        let on = |selector: &str| {
            as_actor(
                DecisionFacade {
                    authorization: granted(selector),
                    catalog: Some(Arc::clone(&catalog)),
                    ..facade("gate-unknown")
                },
                auditor(),
            )
        };
        let ledger = on(&format!(
            "plane/control/zone/{}/ledger/{}",
            zone.id, main.id
        ));
        let (status, _) = get(&ledger, "/zones/acme/ledgers/main/decisions/v1/records").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "granted by its ids, asked by its names"
        );
        let foreign = get(&ledger, "/zones/acme/ledgers/audit/decisions/v1/records").await;
        let unknown = get(&ledger, "/zones/acme/ledgers/nowhere/decisions/v1/records").await;
        assert_eq!(foreign.0, StatusCode::FORBIDDEN);
        assert_eq!(unknown, foreign, "indistinguishable");
        let plane = on("plane/control/*");
        let (status, body) = get(&plane, "/zones/acme/ledgers/nowhere/decisions/v1/records").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], permguard_core::codes::stream::SCOPE_UNKNOWN);
    }

    /// WP-6.3c: a stream read takes the grant of the ledger of the Host run it names; a legacy
    /// stream, mixing every tenant, a grant covering the whole plane.
    #[tokio::test]
    async fn a_decision_stream_read_takes_the_runs_ledger_or_the_whole_plane() {
        let host_run = format!(
            "/decisions/v1/records?pdp={}&instance={}",
            read::hex(&[0xa1; 16]),
            read::hex(&[0x01; 16])
        );
        let legacy = "/decisions/v1/records?pdp=plane-a&instance=i-1";
        let ledger = as_actor(
            DecisionFacade {
                authorization: granted("plane/control/zone/acme/ledger/main"),
                ..signing("gate-stream-ledger")
            },
            auditor(),
        );
        assert_eq!(get(&ledger, &host_run).await.0, StatusCode::OK);
        assert_eq!(get(&ledger, legacy).await.0, StatusCode::FORBIDDEN);
        let other = as_actor(
            DecisionFacade {
                authorization: granted("plane/control/zone/acme/ledger/audit"),
                ..signing("gate-stream-other")
            },
            auditor(),
        );
        assert_eq!(get(&other, &host_run).await.0, StatusCode::FORBIDDEN);
        let plane = as_actor(
            DecisionFacade {
                authorization: granted("plane/control/*"),
                ..signing("gate-stream-plane")
            },
            auditor(),
        );
        // Admitted, and told the legacy stream it names was never held.
        let (status, body) = get(&plane, legacy).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], permguard_core::codes::stream::STREAM_UNKNOWN);
    }

    /// WP-6.3c, after the review: a caller granted nothing under the plane is refused before the
    /// catalog is consulted at all, and the refusal is counted.
    #[tokio::test]
    async fn nothing_granted_under_the_plane_is_refused_before_any_lookup() {
        use permguard_core::Recorder as _;

        let registry = Arc::new(permguard_std::metrics::Registry::new());
        let held = DecisionFacade {
            authorization: granted("plane/data/*"),
            catalog: Some(Arc::new(crate::evidence::Untouchable)),
            metrics: permguard_core::Metrics::new(
                Arc::clone(&registry) as Arc<dyn permguard_core::Recorder>
            ),
            ..facade("gate-before")
        };
        let path = "/zones/acme/ledgers/main/decisions/v1/records";
        let (status, _) = get(&routes(held.clone()), path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "nobody");
        let (status, _) = get(&as_actor(held, auditor()), path).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "nothing granted here");
        let denied: f64 = registry
            .snapshot()
            .into_iter()
            .filter(|sample| {
                sample.metric.name() == measure::READS.name()
                    && sample
                        .labels
                        .iter()
                        .any(|(name, value)| name == "outcome" && value == "denied")
            })
            .map(|sample| match sample.reading {
                permguard_core::metrics::Reading::Value(value) => value,
                permguard_core::metrics::Reading::Distribution { count, .. } => count as f64,
            })
            .sum();
        assert_eq!(denied, 2.0);
    }

    /// WP-6.3c: the signers and the discovery document are not evidence reads, and answer a
    /// caller with no grant at all.
    #[tokio::test]
    async fn the_signers_and_the_documents_stay_open() {
        let router = routes(DecisionFacade {
            authorization: Arc::new(permguard_host::composition::Authorization::closed()),
            ..signing("gate-open")
        });
        let (status, body) = get(
            &router,
            &format!(
                "/decisions/v1/signers?pdp={}&instance={}",
                read::hex(&[0xa1; 16]),
                read::hex(&[0x01; 16])
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _) = get(&router, super::super::configuration::CONFIGURATION_PATH).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = get(&router, "/zones/acme/ledgers/main/decisions/v1/records").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the records are");
    }

    /// WP-6.3c: `Read` over gRPC is gated as the REST reads: `PERMISSION_DENIED` without the
    /// grant, `UNAUTHENTICATED` for a caller no boundary decided.
    #[tokio::test]
    async fn the_grpc_reads_are_gated_as_the_rest_reads() {
        use crate::v1::decision_log_server::DecisionLog;

        let held = DecisionFacade {
            authorization: granted("plane/control/zone/acme/ledger/main"),
            ..facade("gate-grpc")
        };
        let ask = |ledger: &str, actor: Option<Arc<permguard_core::authz::Actor>>| {
            let mut request = tonic::Request::new(crate::v1::ReadRequest {
                zone: "acme".to_owned(),
                ledger: ledger.to_owned(),
                ..Default::default()
            });
            if let Some(actor) = actor {
                request.extensions_mut().insert(actor);
            }
            request
        };
        assert!(
            DecisionLog::read(&held, ask("main", Some(auditor())))
                .await
                .is_ok()
        );
        let refused = DecisionLog::read(&held, ask("audit", Some(auditor())))
            .await
            .expect_err("another ledger");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
        let refused = DecisionLog::read(&held, ask("main", None))
            .await
            .expect_err("nobody");
        assert_eq!(refused.code(), tonic::Code::Unauthenticated);
    }

    /// `router` as the authentication boundary leaves an anonymous caller (WP-6.3c): what the
    /// test facades' public grants admit.
    fn anonymous(router: Router) -> Router {
        router.layer(axum::Extension(Arc::new(
            permguard_core::authz::Actor::Anonymous,
        )))
    }

    async fn get(router: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("answered");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body reads")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// WP-5.5: a read refuses a parameter it does not name, one given twice, a number or a flag
    /// that does not parse and an `until` it did not issue, as validation; a cursor of another
    /// API, resource or filter set is `forged`; a malformed one `offset_invalid`.
    #[tokio::test]
    async fn a_read_takes_only_its_parameters_and_only_its_own_cursors() {
        let facade = facade("query");
        let keys = facade.cursor_key.clone();
        let router = anonymous(routes(facade));
        let path = "/zones/acme/ledgers/main/decisions/v1/records";
        for query in [
            "color=red",
            "from=a&from=b",
            "limit=1&limit_records=2",
            "limit=many",
            "limit_bytes=-1",
            "proof=yes",
            "until=nothing",
            "proof",
        ] {
            let (status, body) = get(&router, &format!("{path}?{query}")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
            assert_eq!(body["code"], "invalid_argument", "{query}: {body}");
        }
        let (status, body) = get(&router, &format!("{path}?pdp=a")).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a stream's name on a tenant read: {body}"
        );
        assert_eq!(body["code"], "invalid_argument", "{body}");

        // A cursor this server issued for another read.
        let key = keys.for_resource("tenant:acme/main").expect("a key");
        let foreign = permguard_stream::Cursor::beginning("events", "tenant:acme/main", "f", None)
            .seal_v2(&key, keys.now(), keys.lifetime())
            .expect("sealed");
        let (status, body) = get(&router, &format!("{path}?from={foreign}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "forged", "{body}");
        let (status, body) = get(&router, &format!("{path}?from=v2.abc")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "offset_invalid", "{body}");
    }
}
