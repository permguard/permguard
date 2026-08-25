// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

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

pub struct ControlPlaneModule;

pub fn module() -> Box<dyn PlaneModule> {
    Box::new(ControlPlaneModule)
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
        ]
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
        let routes = match decision_facade(context) {
            Some(facade) => routes.merge(crate::decisions::http::routes(facade)),
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
        if let Some(facade) = decision_facade(context) {
            grpc.add_service(
                crate::v1::decision_log_server::DecisionLogServer::new(facade)
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
    let base =
        permguard_server::plane::plane_http_base(context.config(), PLANE).unwrap_or_default();
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
            "}}"
        ),
        base = base,
        ledger = ledger,
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
fn decision_facade(context: &ServerContext<'_>) -> Option<crate::decisions::http::DecisionFacade> {
    let config = context.config();
    if !config.decision_store_enabled() {
        return None;
    }
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
    let directory = config.working_dir().join(config.decision_store_directory());
    let store = match crate::decisions::DecisionStore::open(&directory) {
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

    Some(crate::decisions::http::DecisionFacade {
        store,
        local,
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
    let mut keys = Vec::new();
    for path in config.decision_producer_keys() {
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
