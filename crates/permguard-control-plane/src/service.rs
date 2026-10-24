// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context as _;
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tonic::service::RoutesBuilder;

use permguard_core::{PlaneContext, PlaneHealth};
use permguard_server::plane::PlaneModule;

use crate::api::PlaneApi;
use crate::catalog::CatalogFacade;
use crate::v1::control_plane_server::ControlPlaneServer;
use crate::v1::zone_catalog_server::ZoneCatalogServer;

pub(crate) const COMPONENT: &str = "control-plane";
pub(crate) const PLANE: &str = "control";

#[derive(Clone)]
struct PlaneState {
    plane: &'static str,
    product: String,
    version: String,
    commit: String,
    health: PlaneHealth,
    /// The event ingestion capability, when this deployment serves it.
    ///
    /// Carried so `/health` can say *which* part of the plane is not ready. A plane whose event
    /// trust set is empty accepts no batch, and reporting that as process-wide not-ready would take
    /// its decisions and its catalog out of rotation over a capability neither of them uses.
    events: Option<std::sync::Arc<std::sync::Mutex<Option<crate::events::http::EventFacade>>>>,
    /// The decision capability actually composed for this process, when configured.
    decisions:
        Option<std::sync::Arc<std::sync::Mutex<Option<crate::decisions::http::DecisionFacade>>>>,
}

#[derive(Serialize)]
struct InfoBody {
    plane: &'static str,
    product: String,
    version: String,
    commit: String,
}

/// `GET /health`: the two booleans every reader knows, then the lifecycle (P2) — this plane's
/// phase, what it serves without, and every component the process hosts, a plane not yet Ready
/// listed with its phase rather than omitted.
///
/// `degraded` was added rather than folded into `ready`: a reader that only knows the two booleans
/// keeps reading them and gets the same answer it always did, and a reader that wants to know *why*
/// a plane is accepting nothing no longer has to infer it from refusals. It carries what the
/// lifecycle recorded and what this plane's facades say about themselves at the moment asked.
#[derive(Serialize)]
struct HealthBody {
    live: bool,
    ready: bool,
    #[serde(flatten)]
    lifecycle: permguard_core::lifecycle::Report,
}

/// One capability that is served and cannot currently do its work.
type Degraded = permguard_core::lifecycle::Degraded;

/// One of this plane's degraded capabilities, in the terms an operator would fix it in.
fn degraded(capability: &str, reason: &str) -> Degraded {
    Degraded {
        capability: capability.to_owned(),
        reason: reason.to_owned(),
    }
}

/// A facade composed once per store directory, for every surface that serves it.
///
/// Successful composition is cached so every transport shares one set of write gates. A failed
/// attempt is not: HTTP and gRPC are assembled one after the other, and a transient filesystem
/// failure during the first must not permanently suppress the second. Disabled capabilities never
/// call this helper in the first place.
type Composed<T> = std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Option<T>>>;

/// The control plane, and the stores it composed.
///
/// # Why the stores live here and not in `routes()`
///
/// [`PlaneModule::http_routes`] and [`PlaneModule::grpc_routes`] are both called for the same
/// plane — always, in the shipped single-port shape, where the two surfaces share one address.
/// Building a store inside each meant *two* [`crate::events::EventStore`] values over one
/// directory, and a store is not a stateless handle: it carries the per-stream write gate that
/// makes ingest's read-check-append atomic. Two gate maps are two locks that do not see each
/// other, so an HTTP batch and a gRPC batch for the same producer stream could interleave the
/// sequence the gate exists to serialise — a corruption reachable from the default configuration
/// and invisible to a test that exercises one transport at a time.
///
/// So the composition root is here: resolved once, keyed by the directory it opened, and handed to
/// both surfaces.
#[derive(Default)]
pub struct ControlPlaneModule {
    events: Composed<crate::events::http::EventFacade>,
    event_store:
        std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::events::EventStore>>>>,
    /// The composed facade, shared with the service that re-reads the producers' published keys.
    /// The trust set lives behind an `Arc` inside it, so what that service reloads is what
    /// ingestion admits under.
    event_trust: std::sync::Arc<std::sync::Mutex<Option<crate::events::http::EventFacade>>>,
    decisions: Composed<crate::decisions::http::DecisionFacade>,
    decision_state:
        std::sync::Arc<std::sync::Mutex<Option<crate::decisions::http::DecisionFacade>>>,
    /// The NOTP facade, composed once: REST, gRPC and the `policy.mirror` task share its stores,
    /// so one gate serializes a ledger's compare-and-swap and its transfer sessions (WP-7.12).
    notp: Composed<crate::notp::NotpFacade>,
    /// Whether the `events.import` handler was offered to the Host, once (WP-6.2c1).
    import: std::sync::OnceLock<()>,
}

pub fn module() -> Box<dyn PlaneModule> {
    Box::new(ControlPlaneModule::default())
}

/// Reads a composed facade, or builds and remembers it.
fn composed<T: Clone>(
    held: &Composed<T>,
    directory: std::path::PathBuf,
    build: impl FnOnce() -> Option<T>,
) -> Option<T> {
    let mut held = match held.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(Some(known)) = held.get(&directory) {
        return Some(known.clone());
    }
    let built = build();
    match &built {
        Some(built) => {
            held.insert(directory, Some(built.clone()));
        }
        None => {
            held.remove(&directory);
        }
    }

    built
}

impl ControlPlaneModule {
    /// Serves `events.import` from the Host's event consumer, once, when the Host routes task
    /// sessions, consumes the event stream and composes this plane's signing ring (WP-6.2c1).
    fn serve_import(&self, context: &PlaneContext<'_>) {
        self.import.get_or_init(|| {
            let (Some(registration), Some(consumer), Some(signer), Some(coordinator)) = (
                crate::handles::registration(context),
                crate::handles::event_consumer(context),
                crate::handles::import_signer(context),
                crate::handles::host_id(context),
            ) else {
                tracing::warn!(
                    event.name = "events.import_unserved",
                    component = COMPONENT,
                    "the events.import task is not served: this Host routes no task sessions, \
                     consumes no event stream or composes no control.attest ring"
                );
                return;
            };
            let origins = std::sync::Arc::clone(&registration);
            let import = std::sync::Arc::new(crate::events::import::Import {
                consumer,
                origins: std::sync::Arc::new(move |resource| {
                    origins
                        .import_origins(resource)
                        .unwrap_or_else(|| Ok(Default::default()))
                }),
                signer,
                coordinator,
            });
            if let Err(error) = registration.serve_task(
                permguard_host::membership::record::TaskType::EventsImport,
                crate::events::import::VERSION,
                import,
            ) {
                tracing::error!(
                    event.name = "events.import_unserved",
                    component = COMPONENT,
                    error = %error,
                    "the events.import task is not served by this plane"
                );
            }
        });
    }

    /// The event store's facade, composed once and shared by both surfaces.
    fn event_facade(&self, context: &PlaneContext<'_>) -> Option<crate::events::http::EventFacade> {
        let config = context.config();
        if !events_served(config) {
            return None;
        }
        let directory = config.event_store_directory();

        composed(&self.events, directory.clone(), || {
            build_event_facade(context, &directory, &self.event_store, &self.event_trust)
        })
    }

    /// The NOTP facade, composed once; its first composition serves the `policy.mirror` task.
    fn notp_facade(&self, context: &PlaneContext<'_>) -> Option<crate::notp::NotpFacade> {
        let directory = context.config().zones_directory();
        composed(&self.notp, directory, || {
            let facade = notp_facade(context)?;
            if let Some(registration) = crate::handles::registration(context) {
                let mirror = std::sync::Arc::new(crate::notp::mirror::Mirror {
                    facade: std::sync::Arc::new(facade.clone()),
                });
                if let Err(error) = registration.serve_task(
                    permguard_host::membership::record::TaskType::PolicyMirror,
                    crate::notp::mirror::VERSION,
                    mirror,
                ) {
                    tracing::error!(
                        event.name = "notp.mirror_unserved",
                        component = COMPONENT,
                        error = %error,
                        "the policy.mirror task is not served by this plane"
                    );
                }
            }
            Some(facade)
        })
    }

    /// The decision log's facade, composed the same way and for the same reason.
    fn decision_facade(
        &self,
        context: &PlaneContext<'_>,
    ) -> Option<crate::decisions::http::DecisionFacade> {
        let config = context.config();
        if !config.decision_store_enabled() {
            return None;
        }
        let directory = config.working_dir().join(config.decision_store_directory());

        composed(&self.decisions, directory.clone(), || {
            build_decision_facade(context, &directory, &self.decision_state)
        })
    }
}

impl PlaneModule for ControlPlaneModule {
    fn id(&self) -> &'static str {
        PLANE
    }

    fn component(&self) -> &'static str {
        COMPONENT
    }

    fn description(&self) -> &'static str {
        "control plane"
    }

    /// Background work this plane runs beside its listeners: measuring what
    /// it holds, so "how much disk is this deployment using" is a number and
    /// not an ssh session.
    fn declaration(
        &self,
        _config: &permguard_core::Config,
    ) -> permguard_host::composition::Declaration {
        crate::handles::declaration()
    }

    fn verified_trees(&self) -> Vec<permguard_server::VerifiedTree> {
        // `Config::zones_directory`, relative to the volume root: every ledger's objects.
        vec![(
            std::path::Path::new("data").join("zones"),
            std::sync::Arc::new(crate::store::object_check),
        )]
    }

    fn services(&self) -> Vec<Box<dyn permguard_core::PlaneTask>> {
        vec![
            Box::new(crate::inventory::InventoryService::new()),
            // What startup does not read: a sample of the objects, checked in the background.
            Box::new(crate::verify::VerifyService::new()),
            Box::new(crate::gc::GcService::new()),
            Box::new(crate::decisions::retention::RetentionService::new()),
            // The event store's own sweep. Registered beside the decision store's rather than
            // relying on it: they are two stores with two windows, and the event one held a
            // `sweep` nothing ever called.
            Box::new(
                crate::events::retention::EventRetentionService::new()
                    .with_store(std::sync::Arc::clone(&self.event_store)),
            ),
        ]
    }

    fn streams(&self, config: &permguard_core::Config) -> Vec<permguard_stream::StreamDescriptor> {
        let mut streams = Vec::new();

        // Declared whether or not the deployment turned them on: "not here" and "here, turned
        // off" are different answers, and discovery serves the second one too. Only enabled
        // streams own their directories.

        // The decision store: what the data planes ship, kept and served. The directory predates
        // the versioned layout and stays where recorded evidence already is.
        if let Ok(identity) = permguard_stream::StreamIdentity::new("control-plane", "decisions") {
            streams.push(permguard_stream::StreamDescriptor {
                identity,
                role: permguard_stream::Role::Consumer,
                record_type: permguard_core::domains::record::DECISION_V1.to_owned(),
                directory: config.working_dir().join(config.decision_store_directory()),
                legacy: true,
                enabled: config.decision_store_enabled(),
            });
        }

        // The event store, likewise. Its default directory nests under the root the data plane
        // journals in — the exact fragility the registry names at startup on an all-in-one.
        if let Ok(identity) = permguard_stream::StreamIdentity::new("control-plane", "events") {
            streams.push(permguard_stream::StreamDescriptor {
                identity,
                role: permguard_stream::Role::Consumer,
                record_type: permguard_events::RECORD_TYPE.to_owned(),
                directory: config.event_store_directory(),
                legacy: true,
                enabled: events_served(config),
            });
        }

        streams
    }

    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        // The languages this binary carries, before anything is ingested against them (LANG-12).
        permguard_languages::registry::check_registry().map_err(|collision| {
            anyhow::anyhow!("this build's language catalogue is inconsistent: {collision}")
        })?;
        events_startup_check(config)?;
        decisions_startup_check(config)
    }

    fn http_routes(&self, context: &PlaneContext<'_>) -> Router {
        self.serve_import(context);
        let state = plane_state(context)
            .serving_events(&self.event_trust, context.config())
            .serving_decisions(&self.decision_state, context.config());

        let routes = Router::new()
            .route("/", get(info))
            .route("/health", get(health))
            .route("/version", get(info))
            .with_state(state)
            .merge(permguard_server::plane::streams_route(
                self.streams(context.config()),
            ));

        // The catalog is optional in the contract and composed by every shipped binary; a build
        // that leaves it out simply has no zone routes, rather than routes that answer 500.
        let routes = match context.catalog() {
            Some(catalog) => {
                let facade = CatalogFacade {
                    catalog: std::sync::Arc::clone(catalog),
                    recorder: crate::handles::audit(context),
                    disclosure: context.config().error_detail(),
                    audit_refusals: context.config().audit_refusals(),
                    metrics: context.metrics().clone(),
                    authorization: crate::handles::authorization(context),
                    host: crate::handles::registration(context),
                    mutations: catalog_mutations(context, catalog),
                    exports: exports_of(context),
                };
                // The holdings gauges start truthful, not at zero.
                facade.refresh_holdings();
                routes.merge(crate::catalog::http::routes(facade))
            }
            None => routes,
        };

        // NOTP needs both the catalog (to resolve ledgers) and the git-like
        // signing ring (every served head is attested). Fail-closed: a build
        // missing either simply has no ledger-content routes.
        let routes = match self.notp_facade(context) {
            Some(facade) => routes.merge(crate::notp::http::routes(facade)),
            None => routes,
        };

        // The decision log, when this deployment keeps one. Fail-closed like
        // everything else here: a plane with no signing ring cannot verify a
        // producer's batches, so it simply has no decision routes rather than
        // routes that accept what nobody checked.
        let routes = match self.decision_facade(context) {
            Some(facade) => routes.merge(crate::decisions::http::routes(facade)),
            None => routes,
        };
        // The event store, when this deployment receives one. Merged rather than always mounted:
        // a plane that keeps no events must answer `404` for a submission route, not accept one
        // and then fail — a `404` says "not here" and a broken route says "here, and broken".
        let routes = match self.event_facade(context) {
            Some(facade) => routes.merge(crate::events::http::routes(facade)),
            None => routes,
        };

        routes.merge(discovery_routes(
            context,
            self.event_facade(context).is_some(),
            self.decision_facade(context).is_some(),
        ))
    }

    fn grpc_routes(&self, context: &PlaneContext<'_>) -> Router {
        self.serve_import(context);
        let state = plane_state(context)
            .serving_events(&self.event_trust, context.config())
            .serving_decisions(&self.decision_state, context.config());
        let mut grpc = RoutesBuilder::default();
        grpc.add_service(ControlPlaneServer::new(PlaneApi {
            plane: state.plane,
            product: state.product,
            version: state.version,
            commit: state.commit,
            health: state.health,
            rest: control_configuration_document(
                context,
                self.event_facade(context).is_some(),
                self.decision_facade(context).is_some(),
            ),
        }));

        if let Some(catalog) = context.catalog() {
            grpc.add_service(ZoneCatalogServer::new(CatalogFacade {
                catalog: std::sync::Arc::clone(catalog),
                recorder: crate::handles::audit(context),
                disclosure: context.config().error_detail(),
                audit_refusals: context.config().audit_refusals(),
                metrics: context.metrics().clone(),
                authorization: crate::handles::authorization(context),
                host: crate::handles::registration(context),
                mutations: catalog_mutations(context, catalog),
                exports: exports_of(context),
            }));
        }

        // The codec ceiling matches what this plane's own protocols advertise:
        // tonic's 4 MiB default sits *below* the negotiated NOTP batch size,
        // and a limit nobody chose would refuse messages the negotiation
        // invited. The transport's body limit (see [`Self::limits`]) is raised
        // to the same line, so the three layers agree instead of the lowest
        // one silently winning.
        let message_ceiling = grpc_message_ceiling(context.config());
        if let Some(facade) = self.notp_facade(context) {
            grpc.add_service(
                crate::v1::git_like_store_server::GitLikeStoreServer::new(facade)
                    .max_decoding_message_size(message_ceiling),
            );
        }

        // The decision log, on the other transport: the same contract, the
        // same code behind it, so neither surface can drift from the other.
        if let Some(facade) = self.decision_facade(context) {
            grpc.add_service(
                crate::v1::decision_log_server::DecisionLogServer::new(facade)
                    .max_decoding_message_size(message_ceiling),
            );
        }
        // The same contract as the HTTP surface, over the same facade.
        if let Some(facade) = self.event_facade(context) {
            grpc.add_service(
                crate::v1::event_log_server::EventLogServer::new(facade)
                    .max_decoding_message_size(message_ceiling),
            );
        }

        grpc.routes().into_axum_router()
    }

    /// The generic limits, with the body ceiling raised to what this plane's
    /// own protocols advertise.
    ///
    /// NOTP negotiates batches of `notp.max_batch_bytes` and the shipper of a
    /// data plane sends decision batches sized by *its* configuration: a body
    /// limit below either turns a negotiated size into a refusal the client
    /// cannot explain. The generic default still stands wherever it is the
    /// larger number, and the ceiling is still a ceiling — only its value now
    /// comes from the protocol instead of from a constant that never heard of
    /// it.
    fn limits(&self, config: &permguard_core::Config) -> permguard_core::Limits {
        let limits = config.limits().clone();
        let floor = body_floor(config);
        if limits.body_bytes() >= floor {
            return limits;
        }

        limits.with_body_bytes(floor)
    }
}

/// The smallest body ceiling under which every negotiated NOTP batch fits,
/// with headroom for the request's own framing.
fn body_floor(config: &permguard_core::Config) -> usize {
    let batch = usize::try_from(config.notp_max_batch_bytes()).unwrap_or(usize::MAX);

    batch.saturating_add(64 * 1024)
}

/// The gRPC codec ceiling: the same line the body limit holds.
fn grpc_message_ceiling(config: &permguard_core::Config) -> usize {
    body_floor(config).max(config.limits().body_bytes())
}

/// The service-config pattern on this plane's own port: the well-known
/// document describes **this plane and nothing else** — its `jwks_uri` at
/// `/control-plane/keys` (the plane's signing ring, published as JWKS). The
/// cross-plane registry is the process's business and lives on the telemetry
/// surface, so nothing ever collapses two planes onto one public port.
fn discovery_routes(
    context: &PlaneContext<'_>,
    events_composed: bool,
    decisions_composed: bool,
) -> Router {
    #[derive(Clone)]
    struct Discovery {
        /// Everything after `plane` and `state`: the document as composed at start.
        rest: String,
        keys: Option<std::sync::Arc<dyn permguard_core::keys::PublicSet>>,
        health: permguard_core::PlaneHealth,
    }

    async fn configuration(State(state): State<Discovery>) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        let document = plane_document(&state.rest, state.health.phase());
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            document,
        )
            .into_response()
    }

    /// Three states, three answers. A composed ring that reads is the JWKS with the cache header
    /// every verifier's refresh is tuned to; a plane with no ring is the empty set, because that
    /// is the truth about what it publishes; and a ring that cannot be read is a `503` — never
    /// `{"keys":[]}`, which reads as a legitimate state of a young ring and would send a verifier
    /// away satisfied while an operator should be looking at the volume.
    async fn keys(State(state): State<Discovery>) -> axum::response::Response {
        use axum::http::{StatusCode, header};
        use axum::response::IntoResponse as _;

        // No composed ring answers the empty set: the plane's document advertises this route
        // unconditionally, and "nothing is published" is the truthful state of a plane that
        // signs nothing. Only a ring that exists and cannot be read is an error.
        let Some(keys) = state.keys.as_ref() else {
            return Json(permguard_core::keys::JwkSet::new(Vec::new())).into_response();
        };

        match keys.public_keys() {
            Ok(published) => (
                [(
                    header::CACHE_CONTROL,
                    format!(
                        "max-age={}",
                        permguard_core::keys::KEY_SET_MAX_AGE.as_secs()
                    ),
                )],
                Json(permguard_core::keys::JwkSet::new(published)),
            )
                .into_response(),
            Err(error) => {
                tracing::warn!(
                    event.name = "plane.keys.unreadable",
                    component = COMPONENT,
                    error = %error,
                    "the plane signing ring could not be read"
                );

                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the signing ring could not be read\n",
                )
                    .into_response()
            }
        }
    }

    let state = Discovery {
        rest: control_configuration_document(context, events_composed, decisions_composed),
        keys: crate::handles::own_public_keys(context),
        health: context.health(),
    };

    Router::new()
        .route("/.well-known/server-configuration", get(configuration))
        .route("/control-plane/keys", get(keys))
        .with_state(state)
}

/// The plane document as answered: `plane`, then `state`, the phase as it is now rather than as
/// it was when the rest was composed (WP-7.4a), then the rest. A phase is one of eight fixed
/// words, never anything to escape.
pub(crate) fn plane_document(rest: &str, phase: permguard_core::lifecycle::Phase) -> String {
    format!(
        "{{\"plane\":\"control-plane\",\"state\":\"{}\",{rest}",
        phase.as_str()
    )
}

/// This plane's configuration document, OIDC-discovery style: flat
/// `*_endpoint` names, absolute URLs, RFC 6570 templates for the segments a
/// caller fills in (`{zone}`, `{ledger}`, `{ref}`). It describes this plane
/// and nothing else; the base URL is resolved from the same configuration
/// the listener binds with. Answered without its first two members, `plane` and `state`, which
/// the route writes in front of it when it answers (WP-7.4a).
fn control_configuration_document(
    context: &PlaneContext<'_>,
    events_composed: bool,
    decisions_composed: bool,
) -> String {
    let base = permguard_server::plane::plane_http_base(
        context.config(),
        permguard_server::plane::PlaneId::Control,
    )
    .unwrap_or_default();
    let ledger = format!("{base}/v1/zones/{{zone}}/ledgers/{{ledger}}");

    // Hand-ordered on purpose: `serde_json` maps sort alphabetically, and a
    // discovery document reads top-down — who I am, my keys, my protocols,
    // then the plain APIs.
    format!(
        concat!(
            "\"transports\":{{\"http\":{http},\"grpc\":{grpc}}},",
            "\"jwks_uri\":\"{base}/control-plane/keys\",",
            "\"notp\":{{",
            "\"media_type\":\"{media}\",",
            "\"compression\":\"{compression}\",",
            "\"ref_endpoint\":\"{ledger}/refs/{{ref}}\",",
            "\"push_negotiation_endpoint\":\"{ledger}/notp/push/negotiate\",",
            "\"push_commit_endpoint\":\"{ledger}/notp/push/commit\",",
            "\"pull_negotiation_endpoint\":\"{ledger}/notp/pull/negotiate\",",
            "\"object_upload_endpoint\":\"{ledger}/notp/objects\",",
            "\"object_fetch_endpoint\":\"{ledger}/notp/objects/fetch\"",
            "}},",
            "\"zones_endpoint\":\"{base}/v1/zones\",",
            "\"ledgers_endpoint\":\"{base}/v1/zones/{{zone}}/ledgers\",",
            "\"streams_endpoint\":\"{base}/v1/streams\"",
            "{interfaces}",
            "}}"
        ),
        base = base,
        ledger = ledger,
        interfaces = interfaces(events_composed, decisions_composed, &base),
        http = transport_enabled(
            context,
            permguard_server::plane::SETTING_CONTROL_HTTP_ENABLED
        ),
        grpc = transport_enabled(
            context,
            permguard_server::plane::SETTING_CONTROL_GRPC_ENABLED
        ),
        media = permguard_notp::MEDIA_TYPE,
        compression = if context.config().notp_compression() {
            permguard_objects::compress::DEFLATE
        } else {
            "none"
        },
    )
}

/// The catalog's mutation transaction (WP-7.3a), the operations a crash left open resolved
/// before the catalog takes a change: `None`, and every change refused `unavailable`, when the
/// Host composes none or the recovery fails.
fn catalog_mutations(
    context: &PlaneContext<'_>,
    catalog: &std::sync::Arc<dyn permguard_core::catalog::Catalog>,
) -> Option<permguard_host::composition::MutationHandle> {
    crate::catalog::recovered(crate::handles::catalog_mutations(context)?, catalog)
}

/// The interfaces this plane serves, as the second layer of the discovery chain.
///
/// Listed only when they are actually served. A discovery document is a promise about what answers
/// here, and naming an interface a caller then cannot reach is exactly the failure the three-layer
/// chain exists to prevent — so the entry and the route are decided by one predicate.
///
/// Rendered as a trailing fragment rather than a field, because this document is written in source
/// order on purpose: who I am, my keys, my protocols, the plain APIs, and only then the interfaces
/// that hang off them.
fn interfaces(events_composed: bool, decisions_composed: bool, base: &str) -> String {
    // Whether the interface *was composed*, not whether it was configured.
    //
    // A store that would not open, or read offsets that could not be signed, leave the routes
    // uninstalled — deliberately, because serving them badly is worse than not serving them. The
    // document used to be written from the configuration instead, so exactly that deployment
    // advertised an endpoint which answered 404: a client would read the interface as present,
    // call it, and get a refusal that names nothing.
    let mut served = Vec::new();
    // The decision log beside the events' (WP-6.3b).
    if decisions_composed {
        served.push((
            crate::decisions::read::API,
            crate::decisions::configuration::CONFIGURATION_PATH,
        ));
    }
    if events_composed {
        served.push((
            crate::events::read::API,
            crate::events::configuration::CONFIGURATION_PATH,
        ));
    }
    if served.is_empty() {
        return String::new();
    }
    // Each with its stage (WP-7.4a); an id the registry does not serve is not listed.
    let entries: Vec<String> = served
        .into_iter()
        .filter_map(|(api, path)| {
            let link = permguard_server::plane::InterfaceLink::of(api, format!("{base}{path}"))?;
            Some(format!("\"{api}\":{}", serde_json::to_string(&link).ok()?))
        })
        .collect();

    format!(",\"interfaces\":{{{}}}", entries.join(","))
}

/// Whether one of this plane's transports is on: absent means on — a plane
/// section that never mentioned a listener still serves it.
fn transport_enabled(context: &PlaneContext<'_>, setting: &str) -> bool {
    context
        .config()
        .setting(setting)
        .map(|value| matches!(value.trim(), "true" | "yes" | "on" | "1"))
        .unwrap_or(true)
}

/// Assembles the NOTP facade, when this build composes everything it needs:
/// the catalog to resolve ledgers, and the git-like signing ring — never the
/// audit ring — to attest every served head.
/// The decision-log routes, when the deployment keeps a decision log.
/// Whether this deployment serves the event store at all.
///
/// # Two switches, not one
///
/// `controlPlane.events.enabled` is the operator's: *this plane receives and keeps other planes'
/// event history*. `experimental.dogwood.enabled` is a different statement: *this deployment
/// accepts a contract whose shape is not yet stable*. The records this store holds and the API
/// family that reads them are that contract, so it is served only where both have been said —
/// matching the data plane's own gate, so a deployment cannot have a producer that ships and a
/// receiver that does not, or the reverse, from one switch.
fn events_served(config: &permguard_core::Config) -> bool {
    config.event_store_enabled() && config.experimental_dogwood()
}

/// What this plane requires before it binds anything.
///
/// Said one of the two things and not the other is refused rather than quietly served as nothing:
/// an operator who turned on an event store and finds nothing answering has a plane that looks
/// configured and is not, and nothing in its logs to say which switch it is missing.
fn events_startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    // Every `experimental.<name>` this deployment wrote down must name a runtime this build
    // actually gates, or the operator has enabled nothing while believing otherwise.
    permguard_languages::registry::check_opted_in(config.experimental_named())
        .map_err(|error| anyhow::anyhow!(error))?;

    if config.event_store_enabled() && !config.experimental_dogwood() {
        anyhow::bail!(
            "`controlPlane.events.enabled` is true and `experimental.dogwood.enabled` is not. The \
             event store holds records whose shape is not yet stable, and is served only where a \
             deployment has accepted that: set `experimental.dogwood.enabled: true` to serve it, \
             or `controlPlane.events.enabled: false` if this plane should not receive events"
        );
    }
    // Retired (WP-6.2b, owner decision of 2026-10-18): events arrive over the Host's
    // `events.ship`, and the ingest route trusts only the ring of the plane sharing this process
    // for its legacy journals. A configuration still naming key files is refused, so no
    // deployment believes they are in force.
    if config.event_producer_keys_declared() {
        anyhow::bail!(
            "`controlPlane.events.producer_keys` is retired: events arrive over the Host's \
             `events.ship`, and the event store trusts only the signing ring of a data plane in \
             this process for what its legacy journals still ship. Remove it"
        );
    }

    Ok(())
}

/// A configured decision store is a startup requirement, not an optional
/// route that may disappear behind a ready health endpoint.
fn decisions_startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    if !config.decision_store_enabled() {
        return Ok(());
    }
    if config.decision_producer_keys().is_empty() && !local_plane_logs(config) {
        anyhow::bail!(
            "the decision store is enabled and this process has neither \
             `controlPlane.decisions.producer_keys` nor a data plane in the same process with \
             its decision log on (`dataPlane.decisions.log.enabled`). It would serve no decision \
             routes because no batch could be verified"
        );
    }

    let directory = config.working_dir().join(config.decision_store_directory());
    // Open and drop as a preflight. The facade composed after startup owns the
    // actual per-stream gates; this pass establishes that the configured path
    // and its durable cursor key are usable before any listener reports ready.
    crate::decisions::DecisionStore::open(&directory).with_context(|| {
        format!(
            "opening the configured decision store at {}",
            directory.display()
        )
    })?;
    crate::decisions::cursorkey::load_root(&directory).with_context(|| {
        format!(
            "loading the decision store cursor key at {}",
            directory.display()
        )
    })?;

    Ok(())
}

/// The event store's facade, when this deployment receives events.
///
/// Built the same way the decision store's is, and for the same reasons: the producers' published
/// keys come from files rather than from dialling back, the offset key lives beside the store it
/// issues positions into, and a store that cannot be opened means the surface is not served rather
/// than served badly.
fn build_event_facade(
    context: &PlaneContext<'_>,
    directory: &std::path::Path,
    shared: &std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::events::EventStore>>>>,
    facades: &std::sync::Arc<std::sync::Mutex<Option<crate::events::http::EventFacade>>>,
) -> Option<crate::events::http::EventFacade> {
    let config = context.config();
    let store = match crate::events::EventStore::open(directory) {
        Ok(store) => std::sync::Arc::new(store),
        Err(error) => {
            tracing::error!(
                event.name = "events.unavailable",
                component = COMPONENT,
                error = %error,
                "the event store is configured and could not be opened"
            );
            return None;
        }
    };
    let cursor_key = match crate::handles::host_id(context)
        .ok_or_else(|| {
            anyhow::anyhow!("no Host identity is composed: read offsets are keyed per Host")
        })
        .and_then(|host_id| crate::decisions::cursorkey::load(directory, host_id, "events"))
        .map(|keys| keys.with_lifetime(context.config().stream_cursor_ttl()))
    {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(
                event.name = "events.unavailable",
                component = COMPONENT,
                error = %error,
                "the event store is configured and its read offsets cannot be signed: refusing to \
                 serve offsets a consumer could edit"
            );
            return None;
        }
    };

    // The ring of the data plane sharing this process, bound to the producer, zone and ledger of
    // each legacy journal it may still ship (WP-6.2b): nothing else is trusted on this route.
    let bindings = legacy_event_producers(config);
    let local = (!bindings.is_empty()).then(|| {
        let keys = crate::handles::data_public_keys(context);
        if keys.is_none() {
            tracing::warn!(
                event.name = "events.legacy_untrusted",
                component = COMPONENT,
                "a legacy event journal beside this store waits to ship and this process composes \
                 no data signing ring: its batches are refused"
            );
        }
        crate::events::http::LocalTrust { keys, bindings }
    });

    let facade = crate::events::http::EventFacade {
        catalog: context.catalog().map(std::sync::Arc::clone),
        store,
        host: crate::handles::event_consumer(context),
        producers: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        local,
        cursor_key,
        disclosure: config.error_detail(),
        metrics: context.metrics().clone(),
        base_url: permguard_server::plane::plane_http_base(
            config,
            permguard_server::plane::PlaneId::Control,
        )
        .unwrap_or_default(),
        describer: permguard_core::stages::Describer::of_plane(context, "control-plane"),
        authorization: crate::handles::authorization(context),
    };
    if let Ok(mut held) = shared.lock() {
        *held = Some(std::sync::Arc::clone(&facade.store));
    }
    if let Ok(mut held) = facades.lock() {
        *held = Some(facade.clone());
    }

    Some(facade)
}

/// Whether this process contains a data plane keeping a decision log, with the ring that signs
/// for it.
fn local_plane_logs(config: &permguard_core::Config) -> bool {
    config.data_signing_keys_enabled() && config.log_enabled()
}

/// The producer this process contains whose batches arrive here: a data plane with the decision
/// log on, the ring that signs for it, and a version 1 spool still naming it (WP-6.1).
///
/// Since WP-6.1 a plane records on the Host's stream, and this store receives only what an
/// upgraded plane's legacy spool still ships, under the name its records carry. The signing ring
/// alone is not it: a control-plane-only process composes a data signing ring whenever the key
/// lifecycle is on, and trusting that ring would bind keys to a producer nothing can ever
/// legitimately claim, dressed as a working fallback.
fn local_producer(config: &permguard_core::Config) -> Option<String> {
    if !local_plane_logs(config) {
        return None;
    }
    let spool = config.working_dir().join(config.log_spool_directory());
    match permguard_decisions::spool::producer_of(&spool) {
        Ok(producer) => producer.filter(|name| !name.trim().is_empty()),
        Err(error) => {
            tracing::warn!(
                event.name = "decisions.legacy_unreadable",
                component = COMPONENT,
                error = %error,
                "the legacy decision spool beside this store cannot be read: its producer is not \
                 trusted here"
            );
            None
        }
    }
}

fn build_decision_facade(
    context: &PlaneContext<'_>,
    directory: &std::path::Path,
    shared: &std::sync::Arc<std::sync::Mutex<Option<crate::decisions::http::DecisionFacade>>>,
) -> Option<crate::decisions::http::DecisionFacade> {
    let config = context.config();
    // Whose signatures this plane accepts. Its own ring is deliberately not
    // among them: a batch is signed by the plane that decided.
    let producers = load_producer_keys(config);
    // The ring sharing this process is trusted only when a local producer actually exists to
    // bind it to — see `local_producer`.
    let local_pdp = local_producer(config);
    let local = local_pdp
        .is_some()
        .then(|| crate::handles::data_public_keys(context))
        .flatten();
    if producers.is_empty() && local.is_none() {
        if config.decision_producer_keys().is_empty() && !local_plane_logs(config) {
            // The startup check reports this before listeners are built. Keep
            // the composition root fail-closed if it was bypassed in a test or
            // an embedding application.
            tracing::error!(
                event.name = "decisions.disabled",
                component = COMPONENT,
                "the decision log is on and this plane has no producer trust source"
            );
            return None;
        }
        // A configured producer may not have published its first JWKS yet.
        // Mount the routes with an empty trust set: every batch is refused,
        // `reload_producers` retries the files, and health names the degraded
        // capability. Omitting the routes here would make that recoverable
        // state permanent until restart. A plane in this process records on the
        // Host's stream (WP-6.1), and expects nothing here.
        if !config.decision_producer_keys().is_empty() {
            tracing::warn!(
                event.name = "decisions.no_producers",
                component = COMPONENT,
                "the decision store is ready but no configured producer key set has loaded; \
                 batches are refused until one is published"
            );
        }
    }
    let store = match crate::decisions::DecisionStore::open(directory) {
        Ok(store) => std::sync::Arc::new(store),
        Err(error) => {
            tracing::error!(
                event.name = "decisions.unavailable",
                component = COMPONENT,
                error = %error,
                "the decision log is configured but its store could not be opened"
            );
            return None;
        }
    };

    // The offset signing key lives beside the store it issues positions into, and is created on
    // first use. A store that cannot hold one cannot issue a resumable offset, so the decision log
    // is not served at all rather than served with offsets a consumer could edit.
    let cursor_key = match crate::handles::host_id(context)
        .ok_or_else(|| {
            anyhow::anyhow!("no Host identity is composed: read offsets are keyed per Host")
        })
        .and_then(|host_id| crate::decisions::cursorkey::load(directory, host_id, "decisions"))
        .map(|keys| keys.with_lifetime(context.config().stream_cursor_ttl()))
    {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(
                event.name = "decisions.unavailable",
                component = COMPONENT,
                error = %error,
                "the decision log is configured and its read offsets cannot be signed: refusing to \
                 serve offsets a consumer could edit"
            );
            return None;
        }
    };

    let facade = crate::decisions::http::DecisionFacade {
        store,
        local,
        // The ring sharing this process signs as the data plane it belongs to: bound to that
        // plane's own producer identity, never floating free of one.
        local_pdp: local_pdp.unwrap_or_default(),
        cursor_key,
        producers: std::sync::Arc::new(std::sync::RwLock::new(producers)),
        producer_files: config
            .decision_producer_keys()
            .iter()
            .map(|source| crate::decisions::http::ProducerFile {
                path: config.working_dir().join(&source.path),
                pdp: source.pdp.clone(),
            })
            .collect(),
        disclosure: config.error_detail(),
        metrics: context.metrics().clone(),
        host: crate::handles::decision_consumer(context),
        catalog: context.catalog().map(std::sync::Arc::clone),
        base_url: permguard_server::plane::plane_http_base(
            config,
            permguard_server::plane::PlaneId::Control,
        )
        .unwrap_or_default(),
        describer: permguard_core::stages::Describer::of_plane(context, "control-plane"),
        authorization: crate::handles::authorization(context),
    };
    if let Ok(mut held) = shared.lock() {
        *held = Some(facade.clone());
    }

    Some(facade)
}

/// Reads the producers' published key sets from the paths the file names, each bound to the
/// producer its entry declares.
///
/// A path that cannot be read is reported and skipped rather than fatal: a
/// deployment with three producers and one unreadable file should keep
/// accepting the other two, and hear about the third.
fn load_producer_keys(
    config: &permguard_core::Config,
) -> Vec<crate::decisions::ingest::ProducerTrust> {
    let mut trusted = Vec::new();
    for source in config.decision_producer_keys() {
        for key in load_keys_from(config, std::slice::from_ref(&source.path)) {
            trusted.push(crate::decisions::ingest::ProducerTrust {
                key,
                pdp: source.pdp.clone(),
            });
        }
    }

    trusted
}

/// The `(producer, zone, ledger)` each legacy event journal of the data plane in this process names
/// (WP-6.2b): what its old shipper may still send here, under the ring it shares with this plane.
/// None without a data plane keeping events and its signing ring.
fn legacy_event_producers(config: &permguard_core::Config) -> Vec<(String, String, String)> {
    if !config.events_enabled() || !config.data_signing_keys_enabled() {
        return Vec::new();
    }
    let root = config.events_directory();
    let mut found = Vec::new();
    let Ok(zones) = std::fs::read_dir(&root) else {
        return found;
    };
    for zone in zones.flatten() {
        let Ok(ledgers) = std::fs::read_dir(zone.path()) else {
            continue;
        };
        for ledger in ledgers.flatten() {
            let directory = ledger.path();
            if !directory
                .join(permguard_events::journal::STATE_FILE)
                .exists()
            {
                continue;
            }
            match permguard_events::journal::stream_of(&directory) {
                Ok(stream) => found.push((stream.producer.id, stream.zone, stream.ledger)),
                Err(error) => tracing::warn!(
                    event.name = "events.legacy_unreadable",
                    component = COMPONENT,
                    error = %error,
                    "a legacy event journal beside this store cannot be read: its producer is not \
                     trusted here"
                ),
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn load_keys_from(config: &permguard_core::Config, paths: &[String]) -> Vec<permguard_core::Jwk> {
    let mut keys = Vec::new();
    for path in paths {
        let resolved = config.working_dir().join(path);
        let parsed = std::fs::read_to_string(&resolved)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
        let Some(parsed) = parsed else {
            tracing::error!(
                event.name = "decisions.producer_keys_unreadable",
                component = COMPONENT,
                path = %resolved.display(),
                "a producer's key set could not be read: its batches will not be accepted"
            );
            continue;
        };
        let set = parsed.get("keys").cloned().unwrap_or(parsed);
        match serde_json::from_value::<Vec<permguard_core::Jwk>>(set) {
            Ok(found) => keys.extend(found),
            Err(error) => tracing::error!(
                event.name = "decisions.producer_keys_unreadable",
                component = COMPONENT,
                path = %resolved.display(),
                error = %error,
                "a producer's key set is not a JWKS"
            ),
        }
    }

    keys
}

/// What exports a zone or a ledger (WP-7.10): `None` without the Host's `host.operations` signer
/// or a Host identity to name as the source authority.
fn exports_of(
    context: &PlaneContext<'_>,
) -> Option<std::sync::Arc<crate::catalog::exports::Exports>> {
    let signer = crate::handles::export_signer(context)?;
    let authority = crate::handles::host_id(context)?;
    let config = context.config();
    // The archive travels base64url in a JSON body and as bytes in a gRPC message: three quarters
    // of the ceiling both share.
    let max_bytes = grpc_message_ceiling(config) / 4 * 3;
    Some(std::sync::Arc::new(crate::catalog::exports::Exports::new(
        config.zones_directory(),
        signer,
        authority,
        max_bytes,
    )))
}

fn notp_facade(context: &PlaneContext<'_>) -> Option<crate::notp::NotpFacade> {
    let catalog = context.catalog()?;
    let Some(keys) = crate::handles::head_signer(context) else {
        tracing::warn!(
            event.name = "notp.disabled",
            component = COMPONENT,
            "the git-like store is not served: no signing ring is composed (controlPlane.keys)"
        );
        return None;
    };
    // Every head statement names the Host that signs it (WP-7.1): without a `host_id` there is
    // no authority to name, and the store is not served.
    let Some(authority) = crate::handles::host_id(context) else {
        tracing::warn!(
            event.name = "notp.disabled",
            component = COMPONENT,
            "the git-like store is not served: no Host identity names the signing authority"
        );
        return None;
    };
    let config = context.config();
    // Every ref update runs in the Host's mutation transaction (WP-3.6): without one the store is
    // not served, and the operations a crash left open are resolved before it is.
    let Some(mutations) = crate::handles::ref_mutations(context) else {
        tracing::warn!(
            event.name = "notp.disabled",
            component = COMPONENT,
            "the git-like store is not served: the Host composes no mutation transaction"
        );
        return None;
    };
    let domain = crate::store::RefDomain {
        zones_root: config.zones_directory(),
    };
    if let Err(error) = mutations.recover(&domain) {
        tracing::error!(
            event.name = "notp.disabled",
            component = COMPONENT,
            error = %error,
            "the git-like store is not served: the ref updates a crash left open could not be \
             resolved"
        );
        return None;
    }

    Some(crate::notp::NotpFacade::new(
        std::sync::Arc::clone(catalog),
        config.zones_directory(),
        keys,
        authority,
        crate::engine::EngineLimits {
            max_batch_bytes: config.notp_max_batch_bytes(),
            max_batch_objects: config.notp_max_batch_objects(),
            max_push_objects: config.notp_max_push_objects(),
            max_push_bytes: config.notp_max_push_bytes(),
            ledger_quota_bytes: config.notp_ledger_quota_bytes(),
        },
        crate::engine::TransferPolicy {
            ttl: config.notp_transfer_ttl(),
            grace: config.gc_grace(),
        },
        mutations,
        crate::handles::registration(context).and_then(|registration| registration.hints()),
        // The ingest gate reads the deployment's opt-ins, not the build's: a plane that has not
        // enabled a provisional runtime refuses the push rather than storing a ledger it would
        // then refuse to serve.
        permguard_languages::registry::Enabled::from_names(config.experimental_enabled_names()),
        config.notp_compression(),
        crate::handles::audit(context),
        config.error_detail(),
        config.audit_refusals(),
        context.metrics().clone(),
        crate::handles::authorization(context),
    ))
}

/// What every answer about this plane is built from.
///
/// The build details follow `public.disclose_build`: a deployment that turned it off answers with
/// the plane and product — enough for `permguard inspect` to identify what it reached — and nothing
/// a fingerprinting pass can match an exploit against.
fn plane_state(context: &PlaneContext<'_>) -> PlaneState {
    let disclose = context.config().disclose_build();

    PlaneState {
        plane: PLANE,
        product: context.identity().product_name().to_owned(),
        version: if disclose {
            context.config().version().to_owned()
        } else {
            String::new()
        },
        commit: if disclose {
            context.config().commit().to_owned()
        } else {
            String::new()
        },
        health: context.health(),
        events: None,
        decisions: None,
    }
}

impl PlaneState {
    /// Reports the event capability's state alongside the process's, when this plane serves it.
    fn serving_events(
        mut self,
        events: &std::sync::Arc<std::sync::Mutex<Option<crate::events::http::EventFacade>>>,
        config: &permguard_core::Config,
    ) -> Self {
        if events_served(config) {
            self.events = Some(std::sync::Arc::clone(events));
        }

        self
    }

    /// Carries the facade that was actually composed, rather than inferring
    /// decision-log availability from the configuration that requested it.
    fn serving_decisions(
        mut self,
        decisions: &std::sync::Arc<
            std::sync::Mutex<Option<crate::decisions::http::DecisionFacade>>,
        >,
        config: &permguard_core::Config,
    ) -> Self {
        if config.decision_store_enabled() {
            self.decisions = Some(std::sync::Arc::clone(decisions));
        }

        self
    }
}

async fn info(State(state): State<PlaneState>) -> Json<InfoBody> {
    Json(InfoBody {
        plane: state.plane,
        product: state.product,
        version: state.version,
        commit: state.commit,
    })
}

async fn health(State(state): State<PlaneState>) -> Json<HealthBody> {
    let mut found = Vec::new();
    // Served and holding nobody's keys: every batch is refused as unattributable, which from the
    // outside looks like the producers are at fault. Said here instead.
    if let Some(events) = &state.events {
        // Two different failures, and they were being reported as one. A facade that was never
        // composed — a store that would not open, read offsets that could not be signed — is not a
        // plane waiting for somebody to publish keys, and saying so would send an operator to fix
        // the wrong thing while the store's own refusal sits in the log above.
        let composed = events.lock().ok().and_then(|held| {
            held.as_ref()
                .map(crate::events::http::EventFacade::awaits_trust)
        });
        match composed {
            None => found.push(degraded(
                "events",
                "the event store did not compose: this plane serves no event routes at \
                         all, and the reason it could not open them was recorded at startup",
            )),
            Some(true) => found.push(degraded(
                "events",
                "a legacy event journal beside this store waits to ship and the ring of \
                         its data plane publishes no key: its batches are refused as \
                         unattributable until it does",
            )),
            Some(false) => {}
        }
    }
    if let Some(decisions) = &state.decisions {
        let composed = decisions.lock().ok().and_then(|held| {
            held.as_ref().map(|facade| {
                facade
                    .accepted_producers()
                    .map(|keys| keys.len().max(usize::from(!facade.expects_batches())))
            })
        });
        match composed {
            None => found.push(degraded(
                "decisions",
                "the decision store did not compose: this plane serves no decision routes \
                         and its startup preflight must be corrected before it can become ready",
            )),
            Some(Err(_)) => found.push(degraded(
                "decisions",
                "the decision store composed but its local producer keys cannot currently \
                         be published: batches are refused until the signing ring recovers",
            )),
            Some(Ok(0)) => found.push(degraded(
                "decisions",
                "no decision producer key is available: batches are refused as \
                         unattributable until a configured key set is published",
            )),
            Some(Ok(_)) => {}
        }
    }

    let mut lifecycle = state.health.report();
    // What the lifecycle recorded first, then what the facades say now: one list, no duplicates.
    for item in found {
        lifecycle
            .degraded
            .retain(|held| held.capability != item.capability);
        lifecycle.degraded.push(item);
    }

    Json(HealthBody {
        live: state.health.is_live(),
        ready: state.health.is_ready(),
        lifecycle,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use permguard_core::ProductIdentity;
    use permguard_core::config::{
        SETTING_EVENT_STORE_DIRECTORY, SETTING_EVENT_STORE_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD,
        SETTING_WORKING_DIR,
    };
    use permguard_std::audit::RecordingAuditSink;
    use permguard_std::storage::MemoryStorage;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-control-composition-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch directory is created");

        path
    }

    fn identity() -> ProductIdentity {
        ProductIdentity::new(
            "permguard-control-plane",
            "Permguard",
            "tagline",
            "about",
            "",
        )
    }

    /// A deployment that receives events into a store it can actually open.
    fn receiving(tag: &str) -> permguard_core::Config {
        let root = scratch(tag);
        let file: Vec<(String, String)> = vec![
            (
                permguard_server::plane::SETTING_CONTROL_HTTP_ADDR.to_owned(),
                "127.0.0.1:6443".to_owned(),
            ),
            (SETTING_WORKING_DIR.to_owned(), root.display().to_string()),
            (SETTING_EVENT_STORE_ENABLED.to_owned(), "true".to_owned()),
            (SETTING_EXPERIMENTAL_DOGWOOD.to_owned(), "true".to_owned()),
            (
                SETTING_EVENT_STORE_DIRECTORY.to_owned(),
                "events".to_owned(),
            ),
        ];

        permguard_core::Config::from_layers(
            permguard_server::plane::build_settings("0.0.0-test"),
            vec![
                permguard_server::plane::SETTING_RUNTIME_PLANES,
                permguard_server::plane::SETTING_CONTROL_HTTP_ADDR,
            ],
            permguard_core::config::Layers {
                file,
                ..Default::default()
            },
        )
        .expect("the test configuration builds")
    }

    mod legacy_events;

    /// `server` with this plane registered on a Host that knows its `host_id`: the salt of the
    /// stores' cursor keys (WP-3.3).
    fn registered<'a>(
        server: permguard_core::ServerContext<'a>,
        _config: &permguard_core::Config,
    ) -> permguard_core::ServerContext<'a> {
        let registration = permguard_host::composition::Host::builder()
            .host_id([1; 16])
            .build()
            .register(crate::handles::declaration())
            .expect("the control plane registers");
        server.with_plane_handles(PLANE, std::sync::Arc::new(registration))
    }

    fn stream() -> permguard_events::Stream {
        permguard_events::Stream::new(
            permguard_events::Producer::data_plane("plane-a", "instance-1"),
            "zone-1",
            "ledger-1",
        )
    }

    /// One store per directory, however many surfaces ask for it.
    ///
    /// The failure this pins down is not "two objects exist": it is that the per-stream write gate
    /// lives *inside* the store, so a second store is a second lock, and the HTTP and gRPC surfaces
    /// of one plane would serialise ingest against different mutexes — which is not serialising it.
    #[test]
    fn both_surfaces_share_one_event_store_and_therefore_one_write_gate() {
        let config = receiving("event-store");
        let storage = MemoryStorage::new();
        let audit = RecordingAuditSink::new();
        let server = registered(
            permguard_core::ServerContext::new(identity(), &config, &storage, &audit),
            &config,
        );
        let context = PlaneContext::new(&server, PLANE);
        let module = ControlPlaneModule::default();

        let http = module.event_facade(&context).expect("the store opens");
        let grpc = module.event_facade(&context).expect("the store opens");

        assert!(
            std::sync::Arc::ptr_eq(&http.store, &grpc.store),
            "the two surfaces composed two stores over one directory"
        );
        assert!(
            std::sync::Arc::ptr_eq(&http.store.gate(&stream()), &grpc.store.gate(&stream())),
            "one stream's write gate is not shared, so the two surfaces do not exclude each other"
        );
    }

    /// The decision log is composed the same way, and was broken the same way.
    #[test]
    fn both_surfaces_share_one_decision_store() {
        let config = receiving("decision-store");
        let storage = MemoryStorage::new();
        let audit = RecordingAuditSink::new();
        let server = registered(
            permguard_core::ServerContext::new(identity(), &config, &storage, &audit),
            &config,
        );
        let context = PlaneContext::new(&server, PLANE);
        let module = ControlPlaneModule::default();

        match (
            module.decision_facade(&context),
            module.decision_facade(&context),
        ) {
            (Some(http), Some(grpc)) => assert!(
                std::sync::Arc::ptr_eq(&http.store, &grpc.store),
                "the two surfaces composed two decision stores over one directory"
            ),
            (None, None) => {
                // This deployment does not serve the decision log; the refusal is shared too.
            }
            _ => panic!("the same configuration composed differently on two calls"),
        }
    }

    #[tokio::test]
    async fn health_names_a_decision_store_that_did_not_compose() {
        let health_state = permguard_core::Health::new();
        health_state.set_ready(true);
        let state = PlaneState {
            plane: PLANE,
            product: "Permguard".to_owned(),
            version: String::new(),
            commit: String::new(),
            health: PlaneHealth::new(health_state, PLANE),
            events: None,
            decisions: Some(std::sync::Arc::new(std::sync::Mutex::new(None))),
        };

        let body = health(State(state)).await.0;
        assert!(
            body.lifecycle
                .degraded
                .iter()
                .any(|held| held.capability == "decisions"),
            "an enabled capability cannot disappear behind a clean health answer"
        );
    }

    /// `contracts/openapi/discovery.json`: every schema of the document, from the real writers.
    ///
    /// The control plane's document is written by `control_configuration_document`, the one
    /// hand-built `format!`; the data plane's, the registry's and the streams' types are public in
    /// `permguard-server` and `permguard-stream`, so this is the one place that sees all five
    /// schemas and holds the document's one `assert_covered`.
    #[test]
    fn test_the_discovery_documents_match_openapi_discovery() {
        use permguard_conformance::schema::Document;
        use permguard_server::plane::discovery::{PlaneLink, ServerConfiguration};
        use permguard_server::plane::{InterfaceLink, PlaneConfiguration};
        use permguard_stream::{Role, StreamDescriptor, StreamIdentity};

        let doc = Document::load("discovery.json");
        let config = receiving("openapi-discovery");
        let storage = MemoryStorage::new();
        let audit = RecordingAuditSink::new();
        let server = permguard_core::ServerContext::new(identity(), &config, &storage, &audit);
        let context = PlaneContext::new(&server, PLANE);

        // With and without the optional `interfaces` member.
        for (events_composed, decisions_composed) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let text = plane_document(
                &control_configuration_document(&context, events_composed, decisions_composed),
                permguard_core::lifecycle::Phase::Serving,
            );
            let json: serde_json::Value =
                serde_json::from_str(&text).expect("the control plane's document is JSON");
            // WP-7.4a: its phase, and every interface with its stage.
            assert_eq!(json["state"], "serving");
            if decisions_composed {
                assert_eq!(
                    json["interfaces"][crate::decisions::read::API]["stage"],
                    "v1"
                );
            }
            if events_composed {
                assert_eq!(
                    json["interfaces"][crate::events::read::API]["stage"],
                    "v1alpha1"
                );
            }
            assert_eq!(
                json.get("interfaces").is_some(),
                events_composed || decisions_composed
            );
            // WP-6.3b: the decision log is listed exactly when its routes are served.
            assert_eq!(
                json.pointer(&format!(
                    "/interfaces/{}",
                    crate::decisions::read::API.replace('/', "~1")
                ))
                .and_then(|entry| entry["configuration"].as_str())
                .map(|link| link.ends_with(crate::decisions::configuration::CONFIGURATION_PATH)),
                decisions_composed.then_some(true)
            );
            assert_eq!(
                json.pointer(&format!("/interfaces/{}", crate::events::read::API))
                    .is_some(),
                events_composed
            );
            doc.check_json("ControlPlaneConfiguration", &json);
        }

        let mut data = PlaneConfiguration {
            plane: "data-plane".to_owned(),
            state: "serving".to_owned(),
            jwks_uri: "http://127.0.0.1:7443/data-plane/keys".to_owned(),
            streams_endpoint: None,
            interfaces: std::collections::BTreeMap::new(),
        };
        doc.check("DataPlaneConfiguration", &data);
        data.streams_endpoint = Some("http://127.0.0.1:7443/v1/streams".to_owned());
        data.interfaces.insert(
            "permguard.api.pdp.native.v1".to_owned(),
            InterfaceLink {
                configuration: "http://127.0.0.1:7443/.well-known/x-configuration".to_owned(),
                // Every member present: a deprecated interface carries its sunset (WP-7.4a).
                stage: "deprecated".to_owned(),
                sunset: Some("2027-06-30T00:00:00Z".to_owned()),
            },
        );
        doc.check("DataPlaneConfiguration", &data);
        doc.check(
            "InterfaceLink",
            &data.interfaces["permguard.api.pdp.native.v1"],
        );
        assert!(!doc.accepts_json(
            "DataPlaneConfiguration",
            &serde_json::json!({"plane": "data-plane", "jwks_uri": "u", "extra": 1})
        ));

        // The registry the telemetry listener serves: an HTTP plane, a gRPC-only plane, and the
        // Host's keys; and the real writer's own text.
        let mut planes = std::collections::BTreeMap::new();
        planes.insert(
            "control-plane".to_owned(),
            PlaneLink {
                state: "serving".to_owned(),
                server_configuration: Some("http://a/.well-known/server-configuration".to_owned()),
                grpc_endpoint: None,
            },
        );
        planes.insert(
            "data-plane".to_owned(),
            PlaneLink {
                state: "load".to_owned(),
                server_configuration: None,
                grpc_endpoint: Some("127.0.0.1:7444".to_owned()),
            },
        );
        doc.check(
            "ServerConfiguration",
            &ServerConfiguration {
                host_id: Some("01a00000-0000-7000-8000-000000000001".to_owned()),
                state: "serving".to_owned(),
                planes,
                jwks_uri: Some("http://a/server-host/keys".to_owned()),
                // Every member of the block filled: a higher control added and a relaxation.
                assurance: permguard_core::assurance::Assurance::new(
                    permguard_core::assurance::AssuranceProfile::Development,
                    [permguard_core::assurance::Control::Tls13Only],
                )
                .report(&[permguard_core::assurance::Relaxation::CustodyPlaintext]),
                // Served with a limit: both members present.
                peer_sessions: permguard_core::PeerSessionsReport {
                    served: true,
                    reason: Some(permguard_core::PeerSessionsReport::TLS_1_2_REFUSED),
                },
                // Every class and authentication, a TLS minimum present and absent (WP-2.11).
                listeners: vec![
                    permguard_core::ListenerReport::of(
                        "control-http-grpc",
                        permguard_core::ListenerClass::PlanePublic,
                        None,
                        true,
                        false,
                    ),
                    permguard_core::ListenerReport::of(
                        "data-http",
                        permguard_core::ListenerClass::PlanePublic,
                        Some(&permguard_core::TlsSettings::new("c", "k")),
                        false,
                        false,
                    ),
                    permguard_core::ListenerReport::of(
                        "host-api",
                        permguard_core::ListenerClass::Host,
                        Some(&permguard_core::TlsSettings::new("c", "k").with_client_ca("ca")),
                        false,
                        true,
                    ),
                    permguard_core::ListenerReport::of(
                        "telemetry",
                        permguard_core::ListenerClass::Telemetry,
                        None,
                        false,
                        false,
                    ),
                ],
            },
        );
        let written: serde_json::Value =
            serde_json::from_str(&permguard_server::plane::server_configuration_document(
                &config,
                &permguard_core::lifecycle::Lifecycle::new(),
            ))
            .expect("the registry is JSON");
        doc.check_json("ServerConfiguration", &written);
        doc.check(
            "ServerConfiguration",
            &ServerConfiguration {
                host_id: None,
                state: "bootstrap".to_owned(),
                planes: std::collections::BTreeMap::new(),
                jwks_uri: None,
                assurance: permguard_core::assurance::Assurance::new(
                    permguard_core::assurance::AssuranceProfile::Regulated,
                    [],
                )
                .report(&[]),
                peer_sessions: permguard_core::PeerSessionsReport {
                    served: true,
                    reason: None,
                },
                listeners: Vec::new(),
            },
        );

        // `streams_route` (permguard-server discovery.rs) wraps `public_view` in `{"streams": []}`.
        let streams: Vec<serde_json::Value> = [
            ("data-plane", "decisions", Role::Producer, true),
            ("control-plane", "events", Role::Consumer, false),
        ]
        .into_iter()
        .map(|(plane, stream_type, role, enabled)| {
            let descriptor = StreamDescriptor {
                identity: StreamIdentity::new(plane, stream_type).expect("a stream name"),
                role,
                record_type: "permguard.event.record.v1".to_owned(),
                directory: std::path::PathBuf::from("streams/never-published"),
                legacy: false,
                enabled,
            };
            let view = descriptor.public_view();
            doc.check_json("StreamView", &view);
            view
        })
        .collect();
        doc.check_json(
            "StreamsDocument",
            &serde_json::json!({ "streams": streams }),
        );
        doc.check_json("StreamsDocument", &serde_json::json!({ "streams": [] }));

        doc.assert_covered();
    }

    /// `contracts/openapi/health.json`: every schema of the document.
    ///
    /// The control plane's `InfoBody`, `HealthBody` and `Degraded` are private to this file and are
    /// built here. The data plane's two bodies (`permguard-data-plane` service.rs) and the telemetry
    /// listener's `VersionBody` (`permguard-telemetry` host.rs) are private to crates that cannot
    /// reach this document's coverage, so they are the same JSON built by hand here, and the data
    /// plane's own tests check its real types against the same schemas. This is the document's one
    /// `assert_covered`.
    #[test]
    fn test_the_health_bodies_match_openapi_health() {
        use permguard_conformance::schema::Document;

        let doc = Document::load("health.json");

        doc.check(
            "InfoBody",
            &InfoBody {
                plane: PLANE,
                product: "Permguard".to_owned(),
                version: "1.2.3".to_owned(),
                commit: "abc1234".to_owned(),
            },
        );
        // Builds are not disclosed: empty strings, never absent members.
        doc.check(
            "InfoBody",
            &InfoBody {
                plane: PLANE,
                product: "Permguard".to_owned(),
                version: String::new(),
                commit: String::new(),
            },
        );
        // Serving, nothing degraded: the lifecycle members beside the two booleans.
        let health = permguard_core::Health::new();
        health.lifecycle().enter(
            PLANE,
            permguard_core::lifecycle::Kind::Plane,
            true,
            permguard_core::lifecycle::Phase::Load,
        );
        health.lifecycle().settle(PLANE);
        health.set_ready(true);
        let plane = PlaneHealth::new(health.clone(), PLANE);
        doc.check(
            "ControlHealthBody",
            &HealthBody {
                live: true,
                ready: true,
                lifecycle: plane.report(),
            },
        );
        let found = vec![
            degraded("events", "no producer key set has loaded"),
            degraded("decisions", "the decision store did not compose"),
        ];
        doc.check("Degraded", &found[0]);
        let mut lifecycle = plane.report();
        lifecycle.degraded = found;
        doc.check(
            "ControlHealthBody",
            &HealthBody {
                live: true,
                ready: false,
                lifecycle,
            },
        );
        // A component with every optional member: a stalled plane and a service in backoff.
        let since = std::time::SystemTime::now();
        health.lifecycle().enter(
            "data",
            permguard_core::lifecycle::Kind::Plane,
            false,
            permguard_core::lifecycle::Phase::Load,
        );
        health
            .lifecycle()
            .wait("data", "mirrors", "the server did not answer", since);
        health.lifecycle().service(
            "sync",
            permguard_core::lifecycle::ServiceState::Backoff,
            Some(since),
            Some(since),
            Some("retrying".to_owned()),
        );
        let report = plane.report();
        for component in &report.components {
            doc.check("Component", component);
        }
        doc.check(
            "ControlHealthBody",
            &HealthBody {
                live: true,
                ready: true,
                lifecycle: report,
            },
        );

        // permguard-data-plane service.rs `HealthBody`: the same members, checked from its real
        // types in its own crate.
        doc.check_json(
            "DataHealthBody",
            &serde_json::json!({
                "live": true,
                "ready": false,
                "state": "load",
                "components": [
                    {"component": "host", "kind": "host", "state": "serving", "required": true},
                    {"component": "data", "kind": "plane", "state": "load", "required": true,
                     "stalled_since": "2026-10-05T00:00:00Z", "reason": "the server did not answer"}
                ]
            }),
        );
        doc.check_json(
            "DataHealthBody",
            &serde_json::json!({
                "live": true,
                "ready": true,
                "state": "serving",
                "degraded": [{"capability": "mirrors:https://control.example", "reason": "older than `mirrors.expire_after`"}],
                "components": [
                    {"component": "host", "kind": "host", "state": "serving", "required": true},
                    {"component": "data", "kind": "plane", "state": "serving", "required": true}
                ]
            }),
        );
        // permguard-telemetry host.rs `VersionBody`: `component` where a plane says `plane`.
        doc.check_json(
            "VersionBody",
            &serde_json::json!({
                "component": "server-host",
                "product": "Permguard",
                "version": "1.2.3",
                "commit": "abc1234",
            }),
        );

        assert!(
            !doc.accepts_json(
                "DataHealthBody",
                &serde_json::json!({"live": true, "ready": true})
            ),
            "the phase and the components are not optional"
        );
        assert!(
            !doc.accepts_json(
                "Component",
                &serde_json::json!({"component": "host", "kind": "host", "state": "serving"})
            ),
            "`required` is not optional"
        );
        assert!(!doc.accepts_json(
            "InfoBody",
            &serde_json::json!({"plane": "control-plane", "product": "p", "version": "", "commit": ""})
        ));

        doc.assert_covered();
    }
}
