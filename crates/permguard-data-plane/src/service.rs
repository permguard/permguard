// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tonic::service::RoutesBuilder;

use permguard_core::{Health, ServerContext};
use permguard_server::plane::PlaneModule;

use crate::api::PlaneApi;
use crate::authz;
use crate::temporal;
use crate::v1::data_plane_server::DataPlaneServer;
use crate::v1::policy_decision_point_server::PolicyDecisionPointServer;
use crate::v1::temporal_policy_decision_point_server::TemporalPolicyDecisionPointServer;

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
        document: permguard_server::plane::PlaneConfiguration,
        keys: Option<std::sync::Arc<dyn permguard_core::keys::KeyManager>>,
    }

    /// Serialized by the response type, not by hand. A document that could not be rendered is a
    /// server error and says so — never an empty object that reads as a plane offering nothing.
    async fn configuration(
        State(state): State<Discovery>,
    ) -> Json<permguard_server::plane::PlaneConfiguration> {
        Json(state.document)
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
        document: data_plane_configuration(context),
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
/// interfaces, an interface describes itself — so a client holding only a plane's address can
/// reach the rest by following it.
///
/// That is for callers who need it: something generic, written against no particular version of
/// the interface, or an operator with an address and a question. Permguard's own client does not
/// walk this chain — it is a versioned client for `permguard.api.pdp.native.v1` and links against that
/// interface's constants directly, which is the same place these links are built from.
///
/// Composed as a value and serialized by the response type, never assembled as text: this used to
/// slice the closing brace off the generic document and concatenate, with a fallback that returned
/// the *unextended* document when the surgery did not find what it expected. A caller following a
/// link that silently was not there concludes the plane offers nothing.
fn data_plane_configuration(
    context: &ServerContext<'_>,
) -> permguard_server::plane::PlaneConfiguration {
    // The same string the PDP's own document publishes, from the same function: a plane whose two
    // documents named different addresses would send a client following the link somewhere the
    // interface does not answer.
    let base = authz::base_url(context);
    let mut configuration = permguard_server::plane::plane_configuration(
        context.config(),
        permguard_server::plane::PlaneId::Data,
    );
    configuration.interfaces.insert(
        permguard_languages::request::INTERFACE.to_owned(),
        permguard_server::plane::InterfaceLink {
            configuration: format!("{base}{}", permguard_languages::request::CONFIGURATION_PATH),
        },
    );
    // The second interface is listed only when it is served. A plane's discovery document is a
    // promise about what answers here, and listing an interface a caller then cannot reach is
    // exactly the failure the three-layer chain exists to prevent.
    if temporal::served(context.config()) {
        configuration.interfaces.insert(
            permguard_languages::temporal::INTERFACE.to_owned(),
            permguard_server::plane::InterfaceLink {
                configuration: format!("{base}{}", temporal::configuration::CONFIGURATION_PATH),
            },
        );
    }

    configuration
}

/// The temporal interface's routes, when this deployment serves it.
fn temporal_routes(context: &ServerContext<'_>) -> Router {
    let Some(submitter) = temporal::submitter(context) else {
        return Router::new();
    };
    let base_url = authz::base_url(context);

    temporal::http::routes(temporal::http::Surface {
        submitter,
        disclosure: context.config().error_detail(),
        pdp: base_url.clone(),
        base_url,
    })
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
            // The temporal interface, when this deployment serves one. Merged rather than always
            // mounted: a plane that keeps no history must not answer a submission route at all,
            // because a `404` says "not here" and a route that accepted and refused would say
            // "here, and broken".
            .merge(temporal_routes(context))
    }

    /// What this plane requires before it binds anything.
    fn streams(&self, config: &permguard_core::Config) -> Vec<permguard_stream::StreamDescriptor> {
        let mut streams = Vec::new();

        // The decision log: this plane produces it into a local spool and ships it. The spool
        // directory predates the versioned layout and stays where recorded evidence already is.
        if config.log_enabled()
            && let Ok(identity) = permguard_stream::StreamIdentity::new("data-plane", "decisions")
        {
            streams.push(permguard_stream::StreamDescriptor {
                identity,
                role: permguard_stream::Role::Producer,
                record_type: "permguard.decision.v1".to_owned(),
                directory: config.working_dir().join(config.log_spool_directory()),
                legacy: true,
            });
        }

        // The temporal events: journals per ledger under the events root, produced and shipped.
        if crate::temporal::served(config)
            && let Ok(identity) = permguard_stream::StreamIdentity::new("data-plane", "events")
        {
            streams.push(permguard_stream::StreamDescriptor {
                identity,
                role: permguard_stream::Role::Producer,
                record_type: permguard_events::RECORD_TYPE.to_owned(),
                directory: config.events_directory(),
                legacy: true,
            });
        }

        streams
    }

    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        temporal::startup_check(config)
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
            // The third loop, off unless this plane serves the temporal interface: it drains the
            // event journals and evicts what neither the control plane nor a loaded policy still
            // needs.
            Box::new(crate::temporal::service::EventService::new()),
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
        // And the temporal interface, on the same terms and only when it is served.
        if let Some(submitter) = temporal::submitter(context) {
            grpc.add_service(TemporalPolicyDecisionPointServer::new(
                temporal::grpc::TemporalPdpApi {
                    submitter,
                    disclosure: context.config().error_detail(),
                    base_url: authz::base_url(context),
                    pdp: authz::base_url(context),
                },
            ));
        }

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
