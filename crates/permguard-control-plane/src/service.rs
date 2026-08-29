// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context as _;
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tonic::service::RoutesBuilder;

use permguard_core::{Health, ServerContext};
use permguard_server::plane::PlaneModule;

use crate::api::PlaneApi;
use crate::catalog::CatalogFacade;
use crate::v1::control_plane_server::ControlPlaneServer;
use crate::v1::zone_catalog_server::ZoneCatalogServer;

const COMPONENT: &str = "control-plane";
const PLANE: &str = "control";

#[derive(Clone)]
struct PlaneState {
    plane: &'static str,
    product: String,
    version: String,
    commit: String,
    health: Health,
}

#[derive(Serialize)]
struct InfoBody {
    plane: &'static str,
    product: String,
    version: String,
    commit: String,
}

#[derive(Serialize)]
struct HealthBody {
    live: bool,
    ready: bool,
}

/// A facade composed once per store directory, for every surface that serves it.
///
/// `None` is cached as deliberately as `Some`: "this deployment does not serve events" is a
/// decision, and re-deciding it per surface would log the same refusal once per transport.
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
    decisions: Composed<crate::decisions::http::DecisionFacade>,
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
    if let Some(known) = held.get(&directory) {
        return known.clone();
    }
    let built = build();
    held.insert(directory, built.clone());

    built
}

impl ControlPlaneModule {
    /// The event store's facade, composed once and shared by both surfaces.
    fn event_facade(
        &self,
        context: &ServerContext<'_>,
    ) -> Option<crate::events::http::EventFacade> {
        let config = context.config();
        if !events_served(config) {
            return None;
        }
        let directory = config.event_store_directory();

        composed(&self.events, directory.clone(), || {
            build_event_facade(context, &directory, &self.event_store)
        })
    }

    /// The decision log's facade, composed the same way and for the same reason.
    fn decision_facade(
        &self,
        context: &ServerContext<'_>,
    ) -> Option<crate::decisions::http::DecisionFacade> {
        let config = context.config();
        if !config.decision_store_enabled() {
            return None;
        }
        let directory = config.working_dir().join(config.decision_store_directory());

        composed(&self.decisions, directory.clone(), || {
            build_decision_facade(context, &directory)
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
    fn services(&self) -> Vec<Box<dyn permguard_core::Service>> {
        vec![
            Box::new(crate::inventory::InventoryService::new()),
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

    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        events_startup_check(config)
    }

    fn http_routes(&self, context: &ServerContext<'_>) -> Router {
        let state = plane_state(context);

        let routes = Router::new()
            .route("/", get(info))
            .route("/health", get(health))
            .route("/version", get(info))
            .with_state(state);

        // The catalog is optional in the contract and composed by every shipped binary; a build
        // that leaves it out simply has no zone routes, rather than routes that answer 500.
        let routes = match context.catalog() {
            Some(catalog) => {
                let facade = CatalogFacade {
                    catalog: std::sync::Arc::clone(catalog),
                    recorder: context.recorder().cloned(),
                    disclosure: context.config().error_detail(),
                    audit_refusals: context.config().audit_refusals(),
                    metrics: context.metrics().clone(),
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
        let routes = match notp_facade(context) {
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

        routes.merge(discovery_routes(context))
    }

    fn grpc_routes(&self, context: &ServerContext<'_>) -> Router {
        let state = plane_state(context);
        let mut grpc = RoutesBuilder::default();
        grpc.add_service(ControlPlaneServer::new(PlaneApi {
            plane: state.plane,
            product: state.product,
            version: state.version,
            commit: state.commit,
            health: state.health,
            configuration: control_configuration_document(context),
        }));

        if let Some(catalog) = context.catalog() {
            grpc.add_service(ZoneCatalogServer::new(CatalogFacade {
                catalog: std::sync::Arc::clone(catalog),
                recorder: context.recorder().cloned(),
                disclosure: context.config().error_detail(),
                audit_refusals: context.config().audit_refusals(),
                metrics: context.metrics().clone(),
            }));
        }

        // The codec ceiling matches what this plane's own protocols advertise:
        // tonic's 4 MiB default sits *below* the negotiated NOTP batch size,
        // and a limit nobody chose would refuse messages the negotiation
        // invited. The transport's body limit (see [`Self::limits`]) is raised
        // to the same line, so the three layers agree instead of the lowest
        // one silently winning.
        let message_ceiling = grpc_message_ceiling(context.config());
        if let Some(facade) = notp_facade(context) {
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
fn discovery_routes(context: &ServerContext<'_>) -> Router {
    #[derive(Clone)]
    struct Discovery {
        document: String,
        keys: Option<std::sync::Arc<dyn permguard_core::keys::KeyManager>>,
    }

    async fn configuration(State(state): State<Discovery>) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            state.document,
        )
            .into_response()
    }

    async fn keys(State(state): State<Discovery>) -> Json<permguard_core::keys::JwkSet> {
        let published = state
            .keys
            .as_ref()
            .and_then(|keys| keys.public_keys().ok())
            .unwrap_or_default();
        Json(permguard_core::keys::JwkSet::new(published))
    }

    let state = Discovery {
        document: control_configuration_document(context),
        keys: context.control_signing_keys().cloned(),
    };

    Router::new()
        .route("/.well-known/server-configuration", get(configuration))
        .route("/control-plane/keys", get(keys))
        .with_state(state)
}

/// This plane's configuration document, OIDC-discovery style: flat
/// `*_endpoint` names, absolute URLs, RFC 6570 templates for the segments a
/// caller fills in (`{zone}`, `{ledger}`, `{ref}`). It describes this plane
/// and nothing else; the base URL is resolved from the same configuration
/// the listener binds with.
fn control_configuration_document(context: &ServerContext<'_>) -> String {
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
            "{{",
            "\"plane\":\"control-plane\",",
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
            "\"ledgers_endpoint\":\"{base}/v1/zones/{{zone}}/ledgers\"",
            "{interfaces}",
            "}}"
        ),
        base = base,
        ledger = ledger,
        interfaces = interfaces(context, &base),
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

/// The interfaces this plane serves, as the second layer of the discovery chain.
///
/// Listed only when they are actually served. A discovery document is a promise about what answers
/// here, and naming an interface a caller then cannot reach is exactly the failure the three-layer
/// chain exists to prevent — so the entry and the route are decided by one predicate.
///
/// Rendered as a trailing fragment rather than a field, because this document is written in source
/// order on purpose: who I am, my keys, my protocols, the plain APIs, and only then the interfaces
/// that hang off them.
fn interfaces(context: &ServerContext<'_>, base: &str) -> String {
    if !events_served(context.config()) {
        return String::new();
    }

    format!(
        ",\"interfaces\":{{\"{api}\":{{\"configuration\":\"{base}{path}\"}}}}",
        api = crate::events::read::API,
        base = base,
        path = crate::events::configuration::CONFIGURATION_PATH,
    )
}

/// Whether one of this plane's transports is on: absent means on — a plane
/// section that never mentioned a listener still serves it.
fn transport_enabled(context: &ServerContext<'_>, setting: &str) -> bool {
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
    if events_served(config) && config.event_producer_keys().is_empty() {
        anyhow::bail!(
            "the event store is enabled and `controlPlane.events.producer_keys` is empty. Event \
             keys must be bound explicitly to a producer and its allowed zone/ledger scope; the \
             unbound decision-producer list is not an event-ingestion trust policy"
        );
    }
    for source in config.event_producer_keys() {
        if source.path.trim().is_empty()
            || source.producer.trim().is_empty()
            || source.zone.trim().is_empty()
            || source.ledger.trim().is_empty()
            || source.producer == "*"
        {
            anyhow::bail!(
                "every event producer key names a non-empty `path`, exact `producer`, and \
                `zone`/`ledger` (which may be `*`)"
            );
        }
        let keys = read_key_set(config, &source.path).map_err(|error| {
            anyhow::anyhow!(
                "reading event producer `{}` from `{}`: {error:#}",
                source.producer,
                source.path
            )
        })?;
        if keys.is_empty() {
            anyhow::bail!(
                "event producer `{}` publishes no keys in `{}`: an empty trust source would \
                 make every batch from that producer unattributable",
                source.producer,
                source.path
            );
        }
    }

    Ok(())
}

/// The event store's facade, when this deployment receives events.
///
/// Built the same way the decision store's is, and for the same reasons: the producers' published
/// keys come from files rather than from dialling back, the offset key lives beside the store it
/// issues positions into, and a store that cannot be opened means the surface is not served rather
/// than served badly.
fn build_event_facade(
    context: &ServerContext<'_>,
    directory: &std::path::Path,
    shared: &std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::events::EventStore>>>>,
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
    let cursor_key = match crate::decisions::cursorkey::load(directory) {
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

    // The explicitly bound event producers this plane accepts. Decision-log keys are not enough:
    // an event key is authority for one producer and an allowed zone/ledger scope, and accepting
    // an unbound key would let its holder claim another producer or tenant in the signed payload.
    let producers = load_event_producer_keys(config);
    if producers.is_empty() {
        tracing::warn!(
            event.name = "events.no_producers",
            component = COMPONENT,
            "the event store is on and this plane knows no producer's keys: name bound sources \
             under `controlPlane.events.producer_keys`. Batches will be refused as unattributable \
             rather than accepted unchecked"
        );
    }

    let facade = crate::events::http::EventFacade {
        store,
        producers: std::sync::Arc::new(std::sync::RwLock::new(producers)),
        producer_files: config
            .event_producer_keys()
            .iter()
            .map(|source| crate::events::http::ProducerFile {
                path: config.working_dir().join(&source.path),
                producer: source.producer.clone(),
                zone: source.zone.clone(),
                ledger: source.ledger.clone(),
            })
            .collect(),
        cursor_key,
        disclosure: config.error_detail(),
        metrics: context.metrics().clone(),
        base_url: permguard_server::plane::plane_http_base(
            config,
            permguard_server::plane::PlaneId::Control,
        )
        .unwrap_or_default(),
    };
    if let Ok(mut held) = shared.lock() {
        *held = Some(std::sync::Arc::clone(&facade.store));
    }

    Some(facade)
}

fn build_decision_facade(
    context: &ServerContext<'_>,
    directory: &std::path::Path,
) -> Option<crate::decisions::http::DecisionFacade> {
    let config = context.config();
    // Whose signatures this plane accepts. Its own ring is deliberately not
    // among them: a batch is signed by the plane that decided.
    let producers = load_producer_keys(config);
    let local = context.data_signing_keys().map(std::sync::Arc::clone);
    if producers.is_empty() && local.is_none() {
        tracing::warn!(
            event.name = "decisions.disabled",
            component = COMPONENT,
            "the decision log is on and this plane knows no producer's keys: name them under \
             `controlPlane.decisions.producer_keys`, or run a data plane in this process. Nothing \
             is served rather than accepting what nobody checked"
        );
        return None;
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
    let cursor_key = match crate::decisions::cursorkey::load(directory) {
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

    Some(crate::decisions::http::DecisionFacade {
        store,
        local,
        cursor_key,
        producers: std::sync::Arc::new(std::sync::RwLock::new(producers)),
        producer_files: config
            .decision_producer_keys()
            .iter()
            .map(|path| config.working_dir().join(path))
            .collect(),
        disclosure: config.error_detail(),
        metrics: context.metrics().clone(),
    })
}

/// Reads the producers' published key sets from the paths the file names.
///
/// A path that cannot be read is reported and skipped rather than fatal: a
/// deployment with three producers and one unreadable file should keep
/// accepting the other two, and hear about the third.
fn load_producer_keys(config: &permguard_core::Config) -> Vec<permguard_core::Jwk> {
    load_keys_from(config, config.decision_producer_keys())
}

/// The event producers' published sets, from wherever this deployment named them.
fn load_event_producer_keys(
    config: &permguard_core::Config,
) -> Vec<crate::events::ingest::ProducerTrust> {
    let mut trusted = Vec::new();
    for source in config.event_producer_keys() {
        for key in load_keys_from(config, std::slice::from_ref(&source.path)) {
            trusted.push(crate::events::ingest::ProducerTrust {
                key,
                producer: source.producer.clone(),
                zone: source.zone.clone(),
                ledger: source.ledger.clone(),
            });
        }
    }

    trusted
}

fn read_key_set(
    config: &permguard_core::Config,
    path: &str,
) -> anyhow::Result<Vec<permguard_core::Jwk>> {
    let resolved = config.working_dir().join(path);
    let text = std::fs::read_to_string(&resolved)
        .with_context(|| format!("reading {}", resolved.display()))?;
    let parsed: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", resolved.display()))?;
    let set = parsed.get("keys").cloned().unwrap_or(parsed);

    serde_json::from_value(set).with_context(|| format!("{} is not a JWKS", resolved.display()))
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

fn notp_facade(context: &ServerContext<'_>) -> Option<crate::notp::NotpFacade> {
    let catalog = context.catalog()?;
    let Some(keys) = context.control_signing_keys() else {
        tracing::warn!(
            event.name = "notp.disabled",
            component = COMPONENT,
            "the git-like store is not served: no signing ring is composed (controlPlane.keys)"
        );
        return None;
    };
    let config = context.config();

    Some(crate::notp::NotpFacade::new(
        std::sync::Arc::clone(catalog),
        config.zones_directory(),
        std::sync::Arc::clone(keys),
        crate::engine::EngineLimits {
            max_batch_bytes: config.notp_max_batch_bytes(),
            max_batch_objects: config.notp_max_batch_objects(),
            max_push_objects: config.notp_max_push_objects(),
            max_push_bytes: config.notp_max_push_bytes(),
            ledger_quota_bytes: config.notp_ledger_quota_bytes(),
        },
        // The ingest gate reads the deployment's opt-ins, not the build's: a plane that has not
        // enabled a provisional runtime refuses the push rather than storing a ledger it would
        // then refuse to serve.
        permguard_languages::registry::Enabled::from_names(config.experimental_enabled_names()),
        config.notp_compression(),
        context.recorder().cloned(),
        config.error_detail(),
        config.audit_refusals(),
        context.metrics().clone(),
    ))
}

/// What every answer about this plane is built from.
///
/// The build details follow `public.disclose_build`: a deployment that turned it off answers with
/// the plane and product — enough for `permguard inspect` to identify what it reached — and nothing
/// a fingerprinting pass can match an exploit against.
fn plane_state(context: &ServerContext<'_>) -> PlaneState {
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
        health: context.health().clone(),
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
    Json(HealthBody {
        live: state.health.is_live(),
        ready: state.health.is_ready(),
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
                "127.0.0.1:7556".to_owned(),
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
        let context = ServerContext::new(identity(), &config, &storage, &audit);
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
        let context = ServerContext::new(identity(), &config, &storage, &audit);
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
}
