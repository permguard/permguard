// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane served: its module for the composition, the documents that describe it,
//! and its routes on both transports, over the facade the domain package composes.

use std::sync::{Arc, OnceLock};

use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use tonic::service::RoutesBuilder;

use permguard_authority_plane::authority::Authority;
use permguard_authority_plane::plane::{self as domain, Composition};
use permguard_core::{PlaneContext, PlaneTask};
use permguard_host::composition::Declaration;
use permguard_server::PlaneModule;

/// What every answer about this plane is built from.
pub(crate) struct PlaneInfo {
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) health: permguard_core::PlaneHealth,
    /// The discovery document, without its first two members.
    rest: String,
}

impl PlaneInfo {
    fn of(context: &PlaneContext<'_>, issuer: &str) -> Self {
        let disclose = context.config().disclose_build();
        let rest = serde_json::json!({
            "edition": permguard_authority_plane::authority::EDITION,
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/authority/v1/keys"),
            "token_endpoint": format!("{issuer}/authority/v1/token"),
            "status_lists_endpoint": format!("{issuer}/authority/v1/status-lists"),
            "service_accounts_endpoint": format!("{issuer}/authority/v1/service-accounts"),
            "authorization_server_metadata": format!("{issuer}/.well-known/oauth-authorization-server"),
            "capabilities": ["service_accounts", "access_keys", "tokens", "status_lists"],
            "transports": {"http": true, "grpc": true},
        })
        .to_string();
        Self {
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
            rest: rest.trim_start_matches('{').to_owned(),
        }
    }

    /// The discovery document: who the plane is and its phase, then what it serves.
    pub(crate) fn document(&self) -> String {
        format!(
            "{{\"plane\":\"authority-plane\",\"state\":\"{}\",{}",
            self.health.phase().as_str(),
            self.rest
        )
    }
}

/// The Authority Plane module.
#[derive(Default)]
pub struct AuthorityPlaneModule {
    composition: Arc<Composition>,
    served: OnceLock<Option<(Arc<Authority>, Arc<PlaneInfo>)>>,
}

/// The module every binary that runs the Authority Plane registers.
pub fn module() -> Box<dyn PlaneModule> {
    Box::new(AuthorityPlaneModule::default())
}

impl AuthorityPlaneModule {
    fn authority(&self, context: &PlaneContext<'_>) -> Option<(Arc<Authority>, Arc<PlaneInfo>)> {
        self.served
            .get_or_init(|| {
                let authority = self.composition.authority(context)?;
                let plane = Arc::new(PlaneInfo::of(context, authority.issuer()));
                Some((authority, plane))
            })
            .clone()
    }
}

async fn info(State(plane): State<Arc<PlaneInfo>>) -> Response {
    Json(serde_json::json!({
        "plane": crate::PLANE,
        "product": plane.product,
        "version": plane.version,
        "commit": plane.commit,
        "edition": permguard_authority_plane::authority::EDITION,
    }))
    .into_response()
}

async fn health(State(plane): State<Arc<PlaneInfo>>) -> Response {
    let mut body = serde_json::to_value(plane.health.report()).unwrap_or_default();
    if let Some(object) = body.as_object_mut() {
        object.insert("live".to_owned(), plane.health.is_live().into());
        object.insert("ready".to_owned(), plane.health.is_ready().into());
    }
    Json(body).into_response()
}

async fn configuration(State(plane): State<Arc<PlaneInfo>>) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        plane.document(),
    )
        .into_response()
}

impl PlaneModule for AuthorityPlaneModule {
    fn id(&self) -> &'static str {
        crate::PLANE
    }

    fn component(&self) -> &'static str {
        crate::COMPONENT
    }

    fn description(&self) -> &'static str {
        "authority plane"
    }

    fn declaration(&self, config: &permguard_core::Config) -> Declaration {
        domain::declaration(config)
    }

    fn dormant(&self, config: &permguard_core::Config) -> bool {
        domain::dormant(config)
    }

    fn client_authentication_paths(&self) -> Vec<String> {
        vec![crate::http::TOKEN_PATH.to_owned()]
    }

    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        domain::startup_check(config)
    }

    fn services(&self) -> Vec<Box<dyn PlaneTask>> {
        domain::services(&self.composition)
    }

    fn http_routes(&self, context: &PlaneContext<'_>) -> Router {
        let Some((authority, plane)) = self.authority(context) else {
            return Router::new();
        };
        Router::new()
            .route("/", get(info))
            .route("/version", get(info))
            .route("/health", get(health))
            .route("/.well-known/server-configuration", get(configuration))
            .with_state(plane)
            .merge(crate::http::routes(crate::http::Served {
                authority,
                disclosure: context.config().error_detail(),
            }))
    }

    fn grpc_routes(&self, context: &PlaneContext<'_>) -> Router {
        let Some((authority, plane)) = self.authority(context) else {
            return Router::new();
        };
        let served = crate::grpc::Served {
            authority,
            disclosure: context.config().error_detail(),
            plane,
        };
        let mut grpc = RoutesBuilder::default();
        // The gRPC Health Checking Protocol, beside the plane's own services.
        grpc.add_service(permguard_server::plane::health::service(context));
        grpc.add_service(
            crate::v1::authority_plane_server::AuthorityPlaneServer::new(served.clone()),
        );
        grpc.add_service(crate::v1::token_service_server::TokenServiceServer::new(
            served.clone(),
        ));
        grpc.add_service(
            crate::v1::service_account_service_server::ServiceAccountServiceServer::new(served),
        );
        grpc.routes().into_axum_router()
    }
}
