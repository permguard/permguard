// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Who may ask a route at all, decided before the request is read.
//!
//! The [`ActorLayer`](crate::ActorLayer) settles who the caller is; the handler settles whether
//! it may do what it asks, on the resource it resolves. Between the two, every closed route of a
//! surface had its body decoded and its names looked up for a caller that holds nothing: nobody
//! was told `400` or `404` where `401` was the only answer owed, and a parser ran on input of
//! someone the surface does not know. This layer closes that gap with the routes as the
//! contracts state them: each named route carries the operation it requires and the scope it
//! applies to, and a caller holding that operation nowhere under the scope is refused here, in
//! the caller's own protocol, before anything else runs. The handler still decides precisely:
//! this is the first stage of the same authorization, not another one.
//!
//! A route the table does not name passes through untouched: the router answers it as it would,
//! `404` or `405` for a path nothing serves, and a served route authorizes in its handler as every
//! route does. Completeness is the contracts' to prove, and they are checked against the code.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Method, Request, Response};
use tower_service::Service;

use permguard_core::authz::{Admission, Resource};

/// What asking a route requires of a caller's operations, each held anywhere under one of the
/// route's scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    /// Every one of these operations: `catalog.write + policy.push`.
    All(Vec<String>),
    /// Any one of these operations: `keys.admin | membership.admin`.
    Any(Vec<String>),
}

impl Requirement {
    /// The requirement a contract's `operation` states: operations joined by `+` are all
    /// required, by `|` any one.
    pub fn of(text: &str) -> Self {
        let names = |separator: char| -> Vec<String> {
            text.split(separator)
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect()
        };
        if text.contains('|') {
            Self::Any(names('|'))
        } else {
            Self::All(names('+'))
        }
    }

    /// The operations named, for the log.
    fn describe(&self) -> String {
        match self {
            Self::All(names) => names.join(" + "),
            Self::Any(names) => names.join(" | "),
        }
    }
}

/// One route of a surface and what asking it requires: its operations, and the scopes they may
/// be held under, any one of them enough to be asked at all.
#[derive(Debug, Clone)]
pub struct AdmittedRoute {
    /// The HTTP method, or `None` for a gRPC method, whose path is the whole route.
    pub method: Option<Method>,
    /// The path template, `{name}` standing for one segment; for gRPC, `/package.Service/Method`.
    pub path: String,
    pub requires: Requirement,
    pub scopes: Vec<Resource>,
}

impl AdmittedRoute {
    /// Whether this route is the one `method` and `path` ask, the query left aside.
    fn matches(&self, method: &Method, path: &str) -> bool {
        if self.method.as_ref().is_some_and(|wanted| wanted != method) {
            return false;
        }
        let mut held = path.split('/');
        let mut wanted = self.path.split('/');
        loop {
            match (held.next(), wanted.next()) {
                (None, None) => return true,
                (Some(segment), Some(template))
                    if template.starts_with('{') && template.ends_with('}') =>
                {
                    if segment.is_empty() {
                        return false;
                    }
                }
                (Some(segment), Some(literal)) if segment == literal => {}
                _ => return false,
            }
        }
    }
}

/// Refuses, before the handler, a caller that holds a route's operation nowhere under its scope.
#[derive(Clone)]
pub struct AdmissionLayer {
    admission: Arc<dyn Admission>,
    routes: Arc<[AdmittedRoute]>,
}

impl AdmissionLayer {
    /// A layer deciding with `admission` over `routes`.
    pub fn new(admission: Arc<dyn Admission>, routes: Vec<AdmittedRoute>) -> Self {
        Self {
            admission,
            routes: routes.into(),
        }
    }
}

impl<S> tower_layer::Layer<S> for AdmissionLayer {
    type Service = Admitted<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Admitted {
            inner,
            admission: Arc::clone(&self.admission),
            routes: Arc::clone(&self.routes),
        }
    }
}

/// A service whose closed routes are asked only by a caller with standing under them.
#[derive(Clone)]
pub struct Admitted<S> {
    inner: S,
    admission: Arc<dyn Admission>,
    routes: Arc<[AdmittedRoute]>,
}

impl<S> Service<Request<Body>> for Admitted<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let grpc = crate::gate::speaks_grpc(&request);
        let path = request.uri().path();
        let route = self.routes.iter().find(|route| {
            if grpc {
                route.method.is_none() && route.path == path
            } else {
                route.method.is_some() && route.matches(request.method(), path)
            }
        });
        if let Some(route) = route {
            let actor = crate::actor::actor_of(request.extensions());
            // An operation is held when it is held anywhere under any one of the scopes.
            let held = |operation: &str| -> Result<(), permguard_core::AccessDenial> {
                let mut refused = None;
                for scope in &route.scopes {
                    match self.admission.may_act_under(&actor, operation, scope) {
                        Ok(()) => return Ok(()),
                        Err(denial) => refused = Some(denial),
                    }
                }
                Err(refused.unwrap_or_else(|| {
                    permguard_core::AccessDenial::forbidden("the route names no scope")
                }))
            };
            let decided = match &route.requires {
                Requirement::All(names) => names.iter().try_for_each(|name| held(name)),
                Requirement::Any(names) => names
                    .iter()
                    .map(|name| held(name))
                    .reduce(|first, next| first.or(next))
                    .unwrap_or_else(|| {
                        Err(permguard_core::AccessDenial::forbidden(
                            "the route names no operation",
                        ))
                    }),
            };
            if let Err(denial) = decided {
                tracing::info!(
                    event.name = "transport.route_refused",
                    component = "transport",
                    operation = route.requires.describe(),
                    error.code = denial.code(),
                    "refused a route to a caller holding nothing under its scope"
                );
                let body = request.into_body();
                return Box::pin(async move {
                    Ok(crate::gate::drained(body, crate::gate::refused(denial, grpc)).await)
                });
            }
        }
        Box::pin(self.inner.call(request))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use axum::Router;
    use axum::routing::{get, post};
    use permguard_core::AccessDenial;
    use permguard_core::authz::{Actor, ActorContext, Credential, Principal, TokenGrant};
    use tower::ServiceExt as _;

    /// Admits a token bearing the operation under the scope's plane, nobody else.
    struct ByToken;

    impl Admission for ByToken {
        fn may_act_under(
            &self,
            actor: &Actor,
            operation: &str,
            scope: &Resource,
        ) -> Result<(), AccessDenial> {
            let Actor::Authenticated(context) = actor else {
                return Err(AccessDenial::unauthenticated("nobody"));
            };
            let Some(grant) = context.token() else {
                return Err(AccessDenial::forbidden("no token"));
            };
            if grant.permits_anywhere_under(operation, scope) {
                Ok(())
            } else {
                Err(AccessDenial::forbidden("not there"))
            }
        }
    }

    fn bearer(operation: &str, selector: &str) -> Actor {
        Actor::Authenticated(ActorContext::of_token(
            Principal::new("sa:billing").expect("a principal"),
            TokenGrant {
                scopes: vec![permguard_core::authz::TokenScope {
                    operations: [operation.to_owned()].into_iter().collect(),
                    selector: permguard_core::authz::Selector::parse(selector).expect("a selector"),
                }],
                jti: "j".to_owned(),
                list_uri: String::new(),
                list_iat: 0,
                list_digest: [0; 32],
            },
        ))
    }

    fn router(routes: Vec<AdmittedRoute>) -> Router {
        Router::new()
            .route("/catalog/v1/zones/{zone}", get(|| async { "read" }))
            .route("/catalog/v1/zones", post(|| async { "made" }))
            .route("/health", get(|| async { "fine" }))
            .route(
                "/permguard.control.v1.Catalog/CreateZone",
                post(|| async { "made" }),
            )
            .route_layer(AdmissionLayer::new(Arc::new(ByToken), routes))
    }

    fn routes() -> Vec<AdmittedRoute> {
        vec![
            AdmittedRoute {
                method: Some(Method::GET),
                path: "/catalog/v1/zones/{zone}".to_owned(),
                requires: Requirement::of("catalog.read"),
                scopes: vec![Resource::plane("control")],
            },
            AdmittedRoute {
                method: Some(Method::POST),
                path: "/catalog/v1/zones".to_owned(),
                requires: Requirement::of("catalog.write + policy.push"),
                scopes: vec![Resource::host(), Resource::plane("control")],
            },
            AdmittedRoute {
                method: None,
                path: "/permguard.control.v1.Catalog/CreateZone".to_owned(),
                requires: Requirement::of("catalog.write | keys.admin"),
                scopes: vec![Resource::plane("control")],
            },
        ]
    }

    async fn ask(
        router: &Router,
        method: Method,
        path: &str,
        actor: Option<Actor>,
        grpc: bool,
    ) -> u16 {
        let mut request = Request::builder().method(method).uri(path);
        if grpc {
            request = request.header("content-type", "application/grpc");
        }
        let mut request = request.body(Body::from("{")).expect("a request");
        if let Some(actor) = actor {
            request.extensions_mut().insert(Arc::new(actor));
        }
        router
            .clone()
            .oneshot(request)
            .await
            .expect("an answer")
            .status()
            .as_u16()
    }

    /// Nobody is refused `401` and a token holding the operation elsewhere `403`, before the
    /// handler and whatever the body holds; a token holding it anywhere under the scope passes
    /// to the handler, as does a route the table does not name.
    #[tokio::test]
    async fn a_closed_route_is_asked_only_with_standing_under_its_scope() {
        let router = router(routes());
        assert_eq!(
            ask(&router, Method::GET, "/catalog/v1/zones/z?x=1", None, false).await,
            401
        );
        assert_eq!(
            ask(
                &router,
                Method::GET,
                "/catalog/v1/zones/z",
                Some(bearer("catalog.read", "plane/data/*")),
                false
            )
            .await,
            403
        );
        assert_eq!(
            ask(
                &router,
                Method::GET,
                "/catalog/v1/zones/z",
                Some(bearer("catalog.read", "plane/control/zone/other")),
                false
            )
            .await,
            200,
            "held somewhere under the plane: the handler decides which zone"
        );
        assert_eq!(
            ask(&router, Method::GET, "/catalog/v1/zones", None, false).await,
            405,
            "a method the route does not take is the router's answer"
        );
        assert_eq!(ask(&router, Method::GET, "/health", None, false).await, 200);
        assert_eq!(
            ask(
                &router,
                Method::POST,
                "/permguard.control.v1.Catalog/CreateZone",
                None,
                true
            )
            .await,
            200,
            "a gRPC refusal is a 200 with a grpc-status"
        );
    }

    /// A gRPC refusal carries its status in the trailers' place, as the transport answers every
    /// denial on gRPC.
    #[tokio::test]
    async fn a_grpc_route_is_refused_in_grpc() {
        let router = router(routes());
        let request = Request::builder()
            .method(Method::POST)
            .uri("/permguard.control.v1.Catalog/CreateZone")
            .header("content-type", "application/grpc")
            .body(Body::empty())
            .expect("a request");
        let response = router.oneshot(request).await.expect("an answer");
        assert_eq!(
            response
                .headers()
                .get("grpc-status")
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "UNAUTHENTICATED"
        );
    }

    /// `+` requires every operation named, `|` any one of them.
    #[tokio::test]
    async fn a_requirement_is_all_of_or_any_of_its_operations() {
        let router = router(routes());
        let both = Actor::Authenticated(ActorContext::of_token(
            Principal::new("sa:ops").expect("a principal"),
            TokenGrant {
                scopes: vec![permguard_core::authz::TokenScope {
                    operations: ["catalog.write".to_owned(), "policy.push".to_owned()]
                        .into_iter()
                        .collect(),
                    selector: permguard_core::authz::Selector::parse("plane/control/*")
                        .expect("a selector"),
                }],
                jti: "j".to_owned(),
                list_uri: String::new(),
                list_iat: 0,
                list_digest: [0; 32],
            },
        ));
        assert_eq!(
            ask(
                &router,
                Method::POST,
                "/catalog/v1/zones",
                Some(both),
                false
            )
            .await,
            200
        );
        assert_eq!(
            ask(
                &router,
                Method::POST,
                "/catalog/v1/zones",
                Some(bearer("catalog.write", "plane/control/*")),
                false
            )
            .await,
            403,
            "one of two required operations"
        );
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/permguard.control.v1.Catalog/CreateZone")
            .header("content-type", "application/grpc")
            .body(Body::empty())
            .expect("a request");
        request
            .extensions_mut()
            .insert(Arc::new(bearer("keys.admin", "plane/control/*")));
        let response = router.clone().oneshot(request).await.expect("an answer");
        assert!(
            response.headers().get("grpc-status").is_none(),
            "one of two alternatives: the handler answered"
        );
        assert_eq!(
            Requirement::of("a + b"),
            Requirement::All(vec!["a".to_owned(), "b".to_owned()])
        );
        assert_eq!(
            Requirement::of("a | b"),
            Requirement::Any(vec!["a".to_owned(), "b".to_owned()])
        );
    }

    /// A template matches one segment per `{name}`, never an empty one, and the whole path.
    #[test]
    fn a_route_matches_its_template_segment_by_segment() {
        let route = &routes()[0];
        assert!(route.matches(&Method::GET, "/catalog/v1/zones/z"));
        assert!(!route.matches(&Method::GET, "/catalog/v1/zones/"));
        assert!(!route.matches(&Method::GET, "/catalog/v1/zones/z/ledgers"));
        assert!(!route.matches(&Method::POST, "/catalog/v1/zones/z"));
        let certificate = Actor::Authenticated(ActorContext::new(
            Principal::new("cert:sha256:ab").expect("a principal"),
            Credential::Certificate,
            None,
        ));
        assert!(
            ByToken
                .may_act_under(&certificate, "catalog.read", &Resource::plane("control"))
                .is_err()
        );
    }
}
