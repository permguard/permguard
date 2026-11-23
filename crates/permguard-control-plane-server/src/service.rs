// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tonic::service::RoutesBuilder;

use permguard_core::{PlaneContext, PlaneHealth};
use permguard_server::plane::PlaneModule;

use crate::{COMPONENT, PLANE};
use permguard_control_plane::plane::events_served;

use crate::api::PlaneApi;
use crate::v1::control_plane_server::ControlPlaneServer;
use crate::v1::zone_catalog_server::ZoneCatalogServer;

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
    events: Option<std::sync::Arc<std::sync::Mutex<Option<crate::events::facade::EventFacade>>>>,
    /// The decision capability actually composed for this process, when configured.
    decisions:
        Option<std::sync::Arc<std::sync::Mutex<Option<crate::decisions::facade::DecisionFacade>>>>,
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

/// The control plane, served over the stores its domain composed.
#[derive(Default)]
pub struct ControlPlaneModule {
    composition: permguard_control_plane::plane::Composition,
}

pub fn module() -> Box<dyn PlaneModule> {
    Box::new(ControlPlaneModule::default())
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
        permguard_control_plane::plane::declaration()
    }

    fn verified_trees(&self) -> Vec<permguard_server::VerifiedTree> {
        permguard_control_plane::plane::verified_trees()
    }

    fn services(&self) -> Vec<Box<dyn permguard_core::PlaneTask>> {
        permguard_control_plane::plane::services(&self.composition)
    }

    fn streams(&self, config: &permguard_core::Config) -> Vec<permguard_stream::StreamDescriptor> {
        permguard_control_plane::plane::streams(config)
    }

    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        permguard_control_plane::plane::startup_check(config)
    }

    fn http_routes(&self, context: &PlaneContext<'_>) -> Router {
        self.composition.serve_import(context);
        let state = plane_state(context)
            .serving_events(self.composition.event_trust(), context.config())
            .serving_decisions(self.composition.decision_state(), context.config());

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
        let routes =
            match permguard_control_plane::plane::catalog_facade(&self.composition, context) {
                Some(facade) => {
                    // The holdings gauges start truthful, not at zero.
                    facade.refresh_holdings();
                    routes.merge(crate::catalog::http::routes(facade))
                }
                None => routes,
            };

        // NOTP needs both the catalog (to resolve ledgers) and the git-like
        // signing ring (every served head is attested). Fail-closed: a build
        // missing either simply has no ledger-content routes.
        let routes = match self.composition.notp_facade(context) {
            Some(facade) => routes.merge(crate::notp::http::routes(facade)),
            None => routes,
        };

        // The decision log, when this deployment keeps one. Fail-closed like
        // everything else here: a plane with no signing ring cannot verify a
        // producer's batches, so it simply has no decision routes rather than
        // routes that accept what nobody checked.
        let routes = match self.composition.decision_facade(context) {
            Some(facade) => routes.merge(crate::decisions::http::routes(facade)),
            None => routes,
        };
        // The event store, when this deployment receives one. Merged rather than always mounted:
        // a plane that keeps no events must answer `404` for a submission route, not accept one
        // and then fail — a `404` says "not here" and a broken route says "here, and broken".
        let routes = match self.composition.event_facade(context) {
            Some(facade) => routes.merge(crate::events::http::routes(facade)),
            None => routes,
        };

        routes.merge(discovery_routes(
            context,
            self.composition.event_facade(context).is_some(),
            self.composition.decision_facade(context).is_some(),
        ))
    }

    fn grpc_routes(&self, context: &PlaneContext<'_>) -> Router {
        self.composition.serve_import(context);
        let state = plane_state(context)
            .serving_events(self.composition.event_trust(), context.config())
            .serving_decisions(self.composition.decision_state(), context.config());
        let mut grpc = RoutesBuilder::default();
        // The gRPC Health Checking Protocol, beside the plane's own services.
        grpc.add_service(permguard_server::plane::health::service(context));
        grpc.add_service(ControlPlaneServer::new(PlaneApi {
            plane: state.plane,
            product: state.product,
            version: state.version,
            commit: state.commit,
            health: state.health,
            rest: control_configuration_document(
                context,
                self.composition.event_facade(context).is_some(),
                self.composition.decision_facade(context).is_some(),
            ),
            streams: permguard_server::plane::streams_document(&self.streams(context.config())),
        }));

        if let Some(facade) =
            permguard_control_plane::plane::catalog_facade(&self.composition, context)
        {
            grpc.add_service(ZoneCatalogServer::new(crate::served::Served(facade)));
        }

        // The codec ceiling matches what this plane's own protocols advertise:
        // tonic's 4 MiB default sits *below* the negotiated NOTP batch size,
        // and a limit nobody chose would refuse messages the negotiation
        // invited. The transport's body limit (see [`Self::limits`]) is raised
        // to the same line, so the three layers agree instead of the lowest
        // one silently winning.
        let message_ceiling =
            permguard_control_plane::plane::grpc_message_ceiling(context.config());
        if let Some(facade) = self.composition.notp_facade(context) {
            grpc.add_service(
                crate::v1::git_like_store_server::GitLikeStoreServer::new(crate::served::Served(
                    facade,
                ))
                .max_decoding_message_size(message_ceiling),
            );
        }

        // The decision log, on the other transport: the same contract, the
        // same code behind it, so neither surface can drift from the other.
        if let Some(facade) = self.composition.decision_facade(context) {
            grpc.add_service(
                crate::v1::decision_log_server::DecisionLogServer::new(crate::served::Served(
                    facade,
                ))
                .max_decoding_message_size(message_ceiling),
            );
        }
        // The same contract as the HTTP surface, over the same facade.
        if let Some(facade) = self.composition.event_facade(context) {
            grpc.add_service(
                crate::v1::event_log_server::EventLogServer::new(crate::served::Served(facade))
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
        let floor = permguard_control_plane::plane::body_floor(config);
        if limits.body_bytes() >= floor {
            return limits;
        }

        limits.with_body_bytes(floor)
    }
}

/// The service-config pattern on this plane's own port: the well-known
/// document describes **this plane and nothing else** — its `jwks_uri` at
/// `/control-plane/v1/keys` (the plane's signing ring, published as JWKS). The
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
        .route("/control-plane/v1/keys", get(keys))
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
    let ledger = format!("{base}/notp/v1/zones/{{zone}}/ledgers/{{ledger}}");

    // Hand-ordered on purpose: `serde_json` maps sort alphabetically, and a
    // discovery document reads top-down — who I am, my keys, my protocols,
    // then the plain APIs.
    format!(
        concat!(
            "\"transports\":{{\"http\":{http},\"grpc\":{grpc}}},",
            "\"jwks_uri\":\"{base}/control-plane/v1/keys\",",
            "\"notp\":{{",
            "\"media_type\":\"{media}\",",
            "\"compression\":\"{compression}\",",
            "\"ref_endpoint\":\"{ledger}/refs/{{ref}}\",",
            "\"push_negotiation_endpoint\":\"{ledger}/push/negotiate\",",
            "\"push_commit_endpoint\":\"{ledger}/push/commit\",",
            "\"pull_negotiation_endpoint\":\"{ledger}/pull/negotiate\",",
            "\"object_upload_endpoint\":\"{ledger}/objects\",",
            "\"object_fetch_endpoint\":\"{ledger}/objects/fetch\"",
            "}},",
            "\"zones_endpoint\":\"{base}/catalog/v1/zones\",",
            "\"ledgers_endpoint\":\"{base}/catalog/v1/zones/{{zone}}/ledgers\",",
            "\"streams_endpoint\":\"{base}/streams/v1\"",
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
        events: &std::sync::Arc<std::sync::Mutex<Option<crate::events::facade::EventFacade>>>,
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
            std::sync::Mutex<Option<crate::decisions::facade::DecisionFacade>>,
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
    // A facade that was never composed — a store that would not open, read offsets that could not
    // be signed — serves no routes; said here so the cause recorded at startup is looked for.
    if let Some(events) = &state.events
        && events.lock().ok().is_none_or(|held| held.is_none())
    {
        found.push(degraded(
            "events",
            "the event store did not compose: this plane serves no event routes at all, and \
             the reason it could not open them was recorded at startup",
        ));
    }
    if let Some(decisions) = &state.decisions
        && decisions.lock().ok().is_none_or(|held| held.is_none())
    {
        found.push(degraded(
            "decisions",
            "the decision store did not compose: this plane serves no decision routes and its \
             startup preflight must be corrected before it can become ready",
        ));
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

        let http = module
            .composition
            .event_facade(&context)
            .expect("the store opens");
        let grpc = module
            .composition
            .event_facade(&context)
            .expect("the store opens");

        let (http, grpc) = (
            http.store.expect("a legacy store on files"),
            grpc.store.expect("a legacy store on files"),
        );
        assert!(
            std::sync::Arc::ptr_eq(&http, &grpc),
            "the two surfaces composed two stores over one directory"
        );
        assert!(
            std::sync::Arc::ptr_eq(&http.gate(&stream()), &grpc.gate(&stream())),
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
            module.composition.decision_facade(&context),
            module.composition.decision_facade(&context),
        ) {
            (Some(http), Some(grpc)) => assert!(
                std::sync::Arc::ptr_eq(
                    &http.store.expect("a legacy store on files"),
                    &grpc.store.expect("a legacy store on files")
                ),
                "the two surfaces composed two decision stores over one directory"
            ),
            (None, None) => {
                // This deployment does not serve the decision log; the refusal is shared too.
            }
            _ => panic!("the same configuration composed differently on two calls"),
        }
    }

    /// The store is composed with the ceiling the configuration declares
    /// (`controlPlane.decisions.accept`), and with none where it declares none.
    #[test]
    fn the_decision_store_is_composed_with_its_ceiling() {
        // A store that receives from one named producer, whose key set is not published yet: the
        // routes are mounted all the same, as a deployment waiting for its first JWKS has them.
        let storing = |tag: &str| {
            let file = vec![
                (
                    permguard_server::plane::SETTING_CONTROL_HTTP_ADDR.to_owned(),
                    "127.0.0.1:6443".to_owned(),
                ),
                (
                    SETTING_WORKING_DIR.to_owned(),
                    scratch(tag).display().to_string(),
                ),
                (
                    permguard_core::config::SETTING_DECISION_STORE_ENABLED.to_owned(),
                    "true".to_owned(),
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
            .with_decision_producer_keys([
                permguard_core::decisions::DecisionProducerSource {
                    path: "trust/plane-a.jwks".to_owned(),
                    pdp: "plane-a".to_owned(),
                },
            ])
        };
        let composed = |config: &permguard_core::Config| {
            let storage = MemoryStorage::new();
            let audit = RecordingAuditSink::new();
            let server = registered(
                permguard_core::ServerContext::new(identity(), config, &storage, &audit),
                config,
            );
            let context = PlaneContext::new(&server, PLANE);
            ControlPlaneModule::default()
                .composition
                .decision_facade(&context)
                .expect("the decision store composes")
                .ceiling
        };
        let accept = permguard_core::decisions::IncludeSection {
            context: vec!["mfa".to_owned()],
            ..permguard_core::decisions::IncludeSection::default()
        };
        let declared = storing("decision-ceiling")
            .with_decision_accept(Some(accept.clone()))
            .expect("a well-formed ceiling");
        assert_eq!(composed(&declared), Some(accept));
        assert_eq!(
            composed(&storing("decision-no-ceiling")),
            None,
            "production with no ceiling: the producers' inclusion is the rule"
        );
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
            jwks_uri: "http://127.0.0.1:7443/data-plane/v1/keys".to_owned(),
            streams_endpoint: None,
            interfaces: std::collections::BTreeMap::new(),
            languages: Vec::new(),
        };
        doc.check("DataPlaneConfiguration", &data);
        // Each runtime with its gate (TL-6): every member present.
        data.languages.push(serde_json::json!({
            "name": "cedar",
            "descriptor_digest": "sha256:00",
            "experimental": false,
            "served": true,
            "conformance": {
                "gate": "permguard.language.conformance.v1",
                "production_ready": false,
                "open": ["golden_vectors"]
            }
        }));
        doc.check("DataPlaneConfiguration", &data);
        doc.check_json("LanguageListing", &data.languages[0]);
        doc.check_json("ConformanceGate", &data.languages[0]["conformance"]);
        assert!(!doc.accepts_json(
            "LanguageListing",
            &serde_json::json!({"name": "cedar", "descriptor_digest": "d", "experimental": false,
                "served": true, "conformance": {"gate": "permguard.language.conformance.v1",
                "production_ready": true, "open": []}, "extra": 1})
        ));
        data.streams_endpoint = Some("http://127.0.0.1:7443/streams/v1".to_owned());
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
                jwks_uri: Some("http://a/server-host/v1/keys".to_owned()),
                storage: None,
                objectives: None,
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
                storage: Some(permguard_core::volume::StorageReport {
                    qualification: "qualified".to_owned(),
                    evidence: Some("QUAL-2026-01".to_owned()),
                }),
                objectives: Some(
                    permguard_core::objectives::Objectives {
                        data_loss: Some(std::time::Duration::ZERO),
                        recovery_time: Some(std::time::Duration::from_secs(3_600)),
                        max_volume_size: Some(100 << 30),
                        membership_offline_grace: Some(std::time::Duration::from_secs(86_400)),
                        mirror_staleness: Some(std::time::Duration::from_secs(300)),
                        evidence_shipping_lag: Some(std::time::Duration::from_secs(900)),
                        spool_headroom: Some(20),
                        checkpoint_export_lag: Some(std::time::Duration::from_secs(3_600)),
                        backup_interval: Some(std::time::Duration::from_secs(86_400)),
                        restore_test_interval: Some(std::time::Duration::from_secs(2_592_000)),
                        key_recovery_owner: Some("security-team".to_owned()),
                    }
                    .report("validated"),
                ),
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
