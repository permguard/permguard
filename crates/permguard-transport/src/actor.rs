// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Who a request acts as, decided once at the boundary and carried as an extension.
//!
//! The acceptor attached the peer's certificate identity to the connection; this layer asks the
//! Host's [`Authenticator`] what that identity, or the bearer token the request carries, maps to,
//! and attaches the [`Actor`] to the request. Nothing after it can change the answer: a handler
//! reads the actor, it does not build one. A credential that fails verification is answered here,
//! before any handler runs, in the caller's own protocol.
//!
//! A router without this layer has no actor on its requests, and [`actor_of`] reads that as a
//! credential nobody mapped: refused, never anonymous. Only this layer produces
//! [`Actor::Anonymous`], so a surface composed without an authentication boundary is closed, not
//! open to whatever the configuration declares public.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Request, Response};
use tower_service::Service;

use permguard_core::PeerIdentity;
use permguard_core::authz::{Actor, Authenticator};

/// Attaches the actor to every request, or refuses the request when its credential fails.
#[derive(Clone)]
pub struct ActorLayer {
    authenticator: Arc<dyn Authenticator>,
}

impl ActorLayer {
    /// Builds the layer over the Host's authenticator.
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self { authenticator }
    }
}

impl<S> tower_layer::Layer<S> for ActorLayer {
    type Service = Actored<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Actored {
            inner,
            authenticator: Arc::clone(&self.authenticator),
        }
    }
}

/// A service whose requests carry their actor.
#[derive(Clone)]
pub struct Actored<S> {
    inner: S,
    authenticator: Arc<dyn Authenticator>,
}

impl<S> Service<Request<Body>> for Actored<S>
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

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let peer = request
            .extensions()
            .get::<Arc<PeerIdentity>>()
            .map(Arc::clone);
        let grpc = crate::gate::speaks_grpc(&request);
        // Credentials the server does not understand are refused, not ignored (RFC 7235): an
        // `Authorization` header is a claim to be somebody, and only `Bearer` is a claim this
        // boundary can read.
        let bearer = match request.headers().get(http::header::AUTHORIZATION) {
            None => None,
            Some(value) => match value
                .to_str()
                .ok()
                .and_then(|value| value.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            {
                Some((_, token)) => Some(token.trim().to_owned()),
                None => {
                    return Box::pin(async move {
                        Ok(crate::gate::refused(
                            permguard_core::AccessDenial::unauthenticated(
                                "the Authorization header carries a scheme this surface does not read; use Bearer",
                            ),
                            grpc,
                        ))
                    });
                }
            },
        };
        match self
            .authenticator
            .authenticate(peer.as_deref(), bearer.as_deref())
        {
            Ok(actor) => {
                request.extensions_mut().insert(Arc::new(actor));
                Box::pin(self.inner.call(request))
            }
            Err(denial) => {
                tracing::warn!(
                    event.name = "transport.credential_refused",
                    component = "transport",
                    error.code = denial.code(),
                    "refused a credential that did not verify"
                );
                Box::pin(async move { Ok(crate::gate::refused(denial, grpc)) })
            }
        }
    }
}

/// The actor a request carries: what the layer attached. A request no layer decided is refused
/// as unmapped: without an authentication boundary nobody is anonymous, so a surface composed
/// without the layer is closed rather than open to the public grants.
pub fn actor_of(extensions: &http::Extensions) -> Arc<Actor> {
    extensions.get::<Arc<Actor>>().map_or_else(
        || {
            Arc::new(Actor::Unmapped {
                reason: "no authentication boundary decided this request".to_owned(),
            })
        },
        Arc::clone,
    )
}

/// The axum extractor of the request's actor: never fails, so a handler cannot forget to ask.
#[derive(Debug, Clone)]
pub struct ActorOf(pub Arc<Actor>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ActorOf {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(actor_of(&parts.extensions)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use axum::Router;
    use axum::routing::get;
    use permguard_core::AccessDenial;
    use permguard_core::authz::{ActorContext, Credential, Principal};
    use tower::ServiceExt as _;

    struct Rules;

    impl Authenticator for Rules {
        fn authenticate(
            &self,
            peer: Option<&PeerIdentity>,
            bearer: Option<&str>,
        ) -> Result<Actor, AccessDenial> {
            match (peer, bearer) {
                (Some(peer), _) if peer.fingerprint() == "aa" => {
                    Ok(Actor::Authenticated(ActorContext::new(
                        Principal::new("spiffe://acme/billing").expect("p"),
                        Credential::SanUri,
                        None,
                    )))
                }
                (Some(_), _) => Ok(Actor::Unmapped {
                    reason: "stranger".to_owned(),
                }),
                (None, Some("good")) => Ok(Actor::Authenticated(ActorContext::new(
                    Principal::new("oidc:x#alice").expect("p"),
                    Credential::Oidc,
                    None,
                ))),
                (None, Some(_)) => Err(AccessDenial::unauthenticated("bad token")),
                (None, None) => Ok(Actor::Anonymous),
            }
        }
    }

    fn router() -> Router {
        Router::new()
            .route(
                "/who",
                get(|ActorOf(actor): ActorOf| async move { actor.label() }),
            )
            .layer(ActorLayer::new(Arc::new(Rules)))
    }

    async fn ask(peer: Option<&str>, bearer: Option<&str>) -> (http::StatusCode, String) {
        let mut request = Request::get("/who");
        if let Some(bearer) = bearer {
            request = request.header(http::header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let mut request = request.body(Body::empty()).expect("a request");
        if let Some(fingerprint) = peer {
            request.extensions_mut().insert(Arc::new(PeerIdentity::new(
                "CN=x",
                None,
                fingerprint,
                "01",
            )));
        }
        let response = router().oneshot(request).await.expect("answered");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body reads");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn the_actor_is_decided_once_and_a_failing_credential_is_answered_before_the_handler() {
        assert_eq!(
            ask(None, None).await,
            (http::StatusCode::OK, "anonymous".to_owned())
        );
        assert_eq!(
            ask(Some("aa"), None).await,
            (http::StatusCode::OK, "spiffe://acme/billing".to_owned())
        );
        assert_eq!(
            ask(Some("bb"), None).await,
            (http::StatusCode::OK, "unmapped: stranger".to_owned())
        );
        assert_eq!(
            ask(None, Some("good")).await,
            (http::StatusCode::OK, "oidc:x#alice".to_owned())
        );
        let (status, body) = ask(None, Some("bad")).await;
        assert_eq!(status, http::StatusCode::UNAUTHORIZED);
        assert!(body.contains("unauthenticated"), "{body}");
    }

    #[tokio::test]
    async fn a_credential_scheme_the_boundary_does_not_read_is_refused_not_ignored() {
        let request = Request::get("/who")
            .header(http::header::AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0")
            .body(Body::empty())
            .expect("a request");
        let response = router().oneshot(request).await.expect("answered");
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_request_without_the_layer_is_refused_never_anonymous() {
        assert!(matches!(
            *actor_of(&http::Extensions::new()),
            Actor::Unmapped { .. }
        ));
    }
}
