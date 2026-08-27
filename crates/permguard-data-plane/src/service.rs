// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tonic::service::RoutesBuilder;

use permguard_core::{Health, ServerContext};
use permguard_server::plane::PlaneModule;

use crate::api::PlaneApi;
use crate::authz;
use crate::v1::data_plane_server::DataPlaneServer;
use crate::v1::policy_decision_point_server::PolicyDecisionPointServer;

const COMPONENT: &str = "data-plane";
const PLANE: &str = "data";

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

/// The service-config pattern, same shape on every plane: the well-known
/// document names what this process hosts; `/data-plane/keys` is this plane's
/// `jwks_uri` — the data plane's own signing ring (`dataPlane.keys`), which
/// will sign the decision responses it returns. Until that ring is enabled
/// the key set is published empty: the endpoint exists from day one so the
/// pattern is uniform, and keys appear here the day this plane signs.
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
        document: data_plane_configuration_document(context),
        keys: context.data_signing_keys().cloned(),
    };

    Router::new()
        .route("/.well-known/server-configuration", get(configuration))
        .route("/data-plane/keys", get(keys))
        .with_state(state)
}

/// This plane's own discovery document: who it is, what it signs with, and **which interfaces it
/// exposes** — each with the address of its own configuration.
///
/// The link is the point. Discovery is layered — the process names its planes, a plane names its
/// interfaces, an interface describes itself — so a caller given one URL reaches the rest without
/// ever having a path compiled into it. A client that knew `/.well-known/permguard-pdp-v1-configuration`
/// in advance would be a client that breaks the day the interface gains a version.
fn data_plane_configuration_document(context: &ServerContext<'_>) -> String {
    let base =
        permguard_server::plane::plane_http_base(context.config(), PLANE).unwrap_or_default();
    let generic = permguard_server::plane::plane_configuration_document(context.config(), PLANE);
    let Some(head) = generic.strip_suffix('}') else {
        return generic;
    };

    format!(
        "{head},\"interfaces\":{{\"{interface}\":{{\"configuration\":\"{base}{path}\"}}}}}}",
        interface = permguard_languages::request::INTERFACE,
        path = permguard_languages::request::CONFIGURATION_PATH,
    )
}

pub struct DataPlaneModule;

pub fn module() -> Box<dyn PlaneModule> {
    Box::new(DataPlaneModule)
}

impl PlaneModule for DataPlaneModule {
    fn id(&self) -> &'static str {
        PLANE
    }

    fn component(&self) -> &'static str {
        COMPONENT
    }

    fn description(&self) -> &'static str {
        "data plane"
    }

    fn http_routes(&self, context: &ServerContext<'_>) -> Router {
        let state = plane_state(context);

        Router::new()
            .route("/", get(info))
            .route("/health", get(health))
            .route("/version", get(info))
            .with_state(state)
            .merge(discovery_routes(context))
            // The reason this plane exists: decisions, over HTTP.
            .merge(authz::http::routes(authz::http::Surface {
                decider: authz::decider(context),
                disclosure: context.config().error_detail(),
                base_url: authz::base_url(context),
            }))
    }

    /// Two loops, both off by default and both about the volume rather than
    /// the request: the mirroring loop keeps the policies current, and the
    /// decision-log loop drains what this plane decided. A plane fed by other
    /// means, or one that records nothing, is a legitimate deployment.
    fn services(&self) -> Vec<Box<dyn permguard_core::Service>> {
        vec![
            Box::new(crate::mirrors::MirrorService::new()),
            Box::new(crate::decisions::DecisionService::new()),
            Box::new(crate::authz::audit::DecisionAuditService::new()),
        ]
    }

    fn grpc_routes(&self, context: &ServerContext<'_>) -> Router {
        let state = plane_state(context);
        let mut grpc = RoutesBuilder::default();
        grpc.add_service(DataPlaneServer::new(PlaneApi {
            plane: state.plane,
            product: state.product,
            version: state.version,
            commit: state.commit,
            health: state.health,
        }));
        // The same contract as the HTTP surface, field for field: a deployment
        // picks a transport, not a set of semantics.
        grpc.add_service(PolicyDecisionPointServer::new(authz::grpc::PdpApi {
            decider: authz::decider(context),
            disclosure: context.config().error_detail(),
            base_url: authz::base_url(context),
        }));

        grpc.routes().into_axum_router()
    }
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
