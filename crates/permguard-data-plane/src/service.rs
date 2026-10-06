// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tonic::service::RoutesBuilder;

use permguard_core::{PlaneContext, PlaneHealth};
use permguard_server::plane::PlaneModule;

use crate::api::PlaneApi;
use crate::authz;
use crate::temporal;
use crate::v1::data_plane_server::DataPlaneServer;
use crate::v1::policy_decision_point_server::PolicyDecisionPointServer;
use crate::v1::temporal_policy_decision_point_server::TemporalPolicyDecisionPointServer;

const COMPONENT: &str = "data-plane";
pub(crate) const PLANE: &str = "data";

#[derive(Clone)]
struct PlaneState {
    plane: &'static str,
    product: String,
    version: String,
    commit: String,
    health: PlaneHealth,
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
#[derive(Serialize)]
struct HealthBody {
    live: bool,
    ready: bool,
    #[serde(flatten)]
    lifecycle: permguard_core::lifecycle::Report,
}

/// The service-config pattern, same shape on every plane: the well-known
/// document names what this process hosts; `/data-plane/keys` is this plane's
/// `jwks_uri` — the data plane's own signing ring (`dataPlane.keys`), which
/// will sign the decision responses it returns. Until that ring is enabled
/// the key set is published empty: the endpoint exists from day one so the
/// pattern is uniform, and keys appear here the day this plane signs.
fn discovery_routes(context: &PlaneContext<'_>) -> Router {
    #[derive(Clone)]
    struct Discovery {
        document: permguard_server::plane::PlaneConfiguration,
        keys: Option<std::sync::Arc<dyn permguard_core::keys::PublicSet>>,
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
        keys: crate::handles::public_keys(context),
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
    context: &PlaneContext<'_>,
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
fn temporal_routes(context: &PlaneContext<'_>) -> Router {
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

    fn declaration(
        &self,
        config: &permguard_core::Config,
    ) -> permguard_host::composition::Declaration {
        crate::handles::declaration(config)
    }

    fn component(&self) -> &'static str {
        COMPONENT
    }

    fn description(&self) -> &'static str {
        "data plane"
    }

    fn http_routes(&self, context: &PlaneContext<'_>) -> Router {
        let state = plane_state(context);

        Router::new()
            .route("/", get(info))
            .route("/health", get(health))
            .route("/version", get(info))
            .with_state(state)
            .merge(permguard_server::plane::streams_route(
                self.streams(context.config()),
            ))
            .merge(discovery_routes(context))
            // The reason this plane exists: decisions, over HTTP.
            .merge(authz::http::routes(authz::http::Surface {
                decider: authz::decider(context),
                disclosure: context.config().error_detail(),
                base_url: authz::base_url(context),
                authorization: crate::handles::authorization(context),
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

        // Declared whether or not the deployment turned them on: "not here" and "here, turned
        // off" are different answers, and discovery serves the second one too. Only enabled
        // streams own their directories.

        // The decision log: this plane produces it into a local spool and ships it. The spool
        // directory predates the versioned layout and stays where recorded evidence already is.
        if let Ok(identity) = permguard_stream::StreamIdentity::new("data-plane", "decisions") {
            streams.push(permguard_stream::StreamDescriptor {
                identity,
                role: permguard_stream::Role::Producer,
                record_type: permguard_core::domains::record::DECISION_V1.to_owned(),
                directory: config.working_dir().join(config.log_spool_directory()),
                legacy: true,
                enabled: config.log_enabled(),
            });
        }

        // The temporal events: journals per ledger under the events root, produced and shipped.
        if let Ok(identity) = permguard_stream::StreamIdentity::new("data-plane", "events") {
            streams.push(permguard_stream::StreamDescriptor {
                identity,
                role: permguard_stream::Role::Producer,
                record_type: permguard_events::RECORD_TYPE.to_owned(),
                directory: config.events_directory(),
                legacy: true,
                enabled: crate::temporal::served(config),
            });
        }

        streams
    }

    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        // The languages this binary carries, before any ledger is loaded against them (LANG-12).
        permguard_languages::registry::check_registry().map_err(|collision| {
            anyhow::anyhow!("this build's language catalogue is inconsistent: {collision}")
        })?;
        temporal::startup_check(config)
    }

    /// Two loops, both off by default and both about the volume rather than
    /// the request: the mirroring loop keeps the policies current, and the
    /// decision-log loop drains what this plane decided. A plane fed by other
    /// means, or one that records nothing, is a legitimate deployment.
    fn services(&self) -> Vec<Box<dyn permguard_core::PlaneTask>> {
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

    fn grpc_routes(&self, context: &PlaneContext<'_>) -> Router {
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
            authorization: crate::handles::authorization(context),
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
        lifecycle: state.health.report(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data plane's bodies against `contracts/openapi/health.json`, from the real types.
    ///
    /// Coverage of the document is asserted once, in the control plane's test, which sees every
    /// schema; this checks that nothing the data plane serializes falls outside it.
    #[test]
    fn test_the_data_plane_bodies_match_openapi_health() {
        let doc = permguard_conformance::schema::Document::load("health.json");

        doc.check(
            "InfoBody",
            &InfoBody {
                plane: PLANE,
                product: "Permguard".to_owned(),
                version: "1.2.3".to_owned(),
                commit: "abc1234".to_owned(),
            },
        );
        let health = permguard_core::Health::new();
        let lifecycle = health.lifecycle();
        lifecycle.enter(
            PLANE,
            permguard_core::lifecycle::Kind::Plane,
            true,
            permguard_core::lifecycle::Phase::Load,
        );
        let plane = PlaneHealth::new(health.clone(), PLANE);
        // In Load, stalled on a remote: the phase, the stall and the reason all travel.
        plane.wait(
            "mirrors:https://control.example",
            "the server did not answer",
            std::time::SystemTime::now(),
        );
        lifecycle.service(
            "sync",
            permguard_core::lifecycle::ServiceState::Backoff,
            None,
            Some(std::time::SystemTime::now()),
            Some("retrying".to_owned()),
        );
        doc.check(
            "DataHealthBody",
            &HealthBody {
                live: plane.is_live(),
                ready: plane.is_ready(),
                lifecycle: plane.report(),
            },
        );
        // Serving with a capability degraded.
        plane.satisfy("mirrors:https://control.example");
        lifecycle.settle(PLANE);
        health.set_ready(true);
        plane.wait(
            "mirrors:https://control.example",
            "older than `mirrors.expire_after`",
            std::time::SystemTime::now(),
        );
        let body = HealthBody {
            live: plane.is_live(),
            ready: plane.is_ready(),
            lifecycle: plane.report(),
        };
        assert!(body.ready);
        assert_eq!(body.lifecycle.state, "serving");
        assert_eq!(body.lifecycle.degraded.len(), 1);
        doc.check("DataHealthBody", &body);
    }
}
