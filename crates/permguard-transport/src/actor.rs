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
    clear_bearer_refused: bool,
    client_authentication: Arc<[String]>,
}

impl ActorLayer {
    /// Builds the layer over the Host's authenticator.
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            authenticator,
            clear_bearer_refused: false,
            client_authentication: Arc::from(Vec::new()),
        }
    }

    /// Paths where `Authorization: Basic` is a client's credential the route reads itself, an
    /// OAuth token endpoint's `client_secret_basic` (RFC 6749 §2.3.1), not a claim to be somebody
    /// this boundary decides: there the header passes unread, and the request acts as its peer
    /// certificate maps, or as nobody. Every other path still refuses the scheme.
    pub fn client_authentication(mut self, paths: impl IntoIterator<Item = String>) -> Self {
        self.client_authentication = paths.into_iter().collect::<Vec<_>>().into();
        self
    }

    /// Refuses every bearer token, unread: the listener is in the clear, neither on a loopback
    /// address nor behind a declared TLS terminator, where a token would cross the network as
    /// plainly as a password (WP-8.1).
    pub fn refusing_clear_bearer(mut self, refused: bool) -> Self {
        self.clear_bearer_refused = refused;
        self
    }
}

impl<S> tower_layer::Layer<S> for ActorLayer {
    type Service = Actored<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Actored {
            inner,
            authenticator: Arc::clone(&self.authenticator),
            clear_bearer_refused: self.clear_bearer_refused,
            client_authentication: Arc::clone(&self.client_authentication),
        }
    }
}

/// A service whose requests carry their actor.
#[derive(Clone)]
pub struct Actored<S> {
    inner: S,
    authenticator: Arc<dyn Authenticator>,
    clear_bearer_refused: bool,
    client_authentication: Arc<[String]>,
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
        let client_authenticates = self
            .client_authentication
            .iter()
            .any(|path| path == request.uri().path());
        let bearer = match request.headers().get(http::header::AUTHORIZATION) {
            None => None,
            Some(value)
                if client_authenticates
                    && value
                        .to_str()
                        .ok()
                        .and_then(|value| value.split_once(' '))
                        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic")) =>
            {
                // A client's secret travels only over TLS, as a bearer token does.
                if self.clear_bearer_refused {
                    return Box::pin(async move {
                        Ok(bearer_refused(
                            permguard_core::AccessDenial::unauthenticated(
                                "a client secret travels only over TLS: this listener is in the clear",
                            ),
                            grpc,
                        ))
                    });
                }
                None
            }
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
        if bearer.is_some() && self.clear_bearer_refused {
            return Box::pin(async move {
                Ok(bearer_refused(
                    permguard_core::AccessDenial::unauthenticated(
                        "a bearer token travels only over TLS: this listener is in the clear, not on \
                         a loopback address and behind no declared TLS terminator",
                    ),
                    grpc,
                ))
            });
        }
        match self
            .authenticator
            .authenticate(peer.as_deref(), bearer.as_deref())
        {
            Ok(actor) => {
                let by_token =
                    matches!(&actor, Actor::Authenticated(context) if context.token().is_some());
                request.extensions_mut().insert(Arc::new(actor));
                let answer = self.inner.call(request);
                if !by_token || grpc {
                    return Box::pin(answer);
                }
                // A token caller refused for what it asked is told the token's scope or target is
                // what fell short (RFC 6750 `insufficient_scope`).
                Box::pin(async move {
                    let mut response = answer.await?;
                    if response.status() == http::StatusCode::FORBIDDEN {
                        response.headers_mut().append(
                            http::header::WWW_AUTHENTICATE,
                            http::HeaderValue::from_static(permguard_core::api::SCOPE_CHALLENGE),
                        );
                    }
                    Ok(response)
                })
            }
            Err(denial) => {
                tracing::warn!(
                    event.name = "transport.credential_refused",
                    component = "transport",
                    error.code = denial.code(),
                    "refused a credential that did not verify"
                );
                if bearer.is_some() {
                    Box::pin(async move { Ok(bearer_refused(denial, grpc)) })
                } else {
                    Box::pin(async move { Ok(crate::gate::refused(denial, grpc)) })
                }
            }
        }
    }
}

/// A refused bearer token, answered like any denial plus, on an HTTP `401`, the RFC 6750 `Bearer`
/// challenge, so a client knows the token is what to replace.
fn bearer_refused(denial: permguard_core::AccessDenial, grpc: bool) -> Response<Body> {
    let challenged = !grpc && denial.http_status() == 401;
    let mut response = crate::gate::refused(denial, grpc);
    if challenged {
        response.headers_mut().append(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static(permguard_core::api::BEARER_CHALLENGE),
        );
    }

    response
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
                        Principal::new("cert:sha256:aa").expect("p"),
                        Credential::Certificate,
                        None,
                    )))
                }
                (Some(_), _) => Ok(Actor::Unmapped {
                    reason: "stranger".to_owned(),
                }),
                // A caller that is not a token's: what a 403 without a challenge is answered to.
                (None, Some("good")) => Ok(Actor::Authenticated(ActorContext::new(
                    Principal::new("cert:sha256:good").expect("p"),
                    Credential::Certificate,
                    None,
                ))),
                (None, Some("scoped")) => Ok(Actor::Authenticated(ActorContext::of_token(
                    Principal::new("sa:billing").expect("p"),
                    permguard_core::authz::TokenGrant {
                        scopes: Vec::new(),
                        jti: "j".to_owned(),
                        list_uri: "u".to_owned(),
                        list_iat: 1,
                        list_digest: [0; 32],
                    },
                ))),
                (None, Some(_)) => Err(AccessDenial::unauthenticated("bad token")),
                (None, None) => Ok(Actor::Anonymous),
            }
        }
    }

    fn router() -> Router {
        clear_router(false)
    }

    fn clear_router(clear_bearer_refused: bool) -> Router {
        Router::new()
            .route(
                "/who",
                get(|ActorOf(actor): ActorOf| async move { actor.label() }),
            )
            .route("/forbidden", get(|| async { http::StatusCode::FORBIDDEN }))
            .layer(ActorLayer::new(Arc::new(Rules)).refusing_clear_bearer(clear_bearer_refused))
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
            (http::StatusCode::OK, "cert:sha256:aa".to_owned())
        );
        assert_eq!(
            ask(Some("bb"), None).await,
            (http::StatusCode::OK, "unmapped: stranger".to_owned())
        );
        assert_eq!(
            ask(None, Some("good")).await,
            (http::StatusCode::OK, "cert:sha256:good".to_owned())
        );
        let (status, body) = ask(None, Some("bad")).await;
        assert_eq!(status, http::StatusCode::UNAUTHORIZED);
        assert!(body.contains("unauthenticated"), "{body}");
    }

    /// An OAuth token endpoint reads `client_secret_basic` itself (`2-security/8` Token endpoint): on the
    /// paths a listener declares, `Basic` passes unread and the request acts as its peer or as
    /// nobody; on every other path it is still refused.
    #[tokio::test]
    async fn basic_passes_unread_only_where_a_route_authenticates_its_clients() {
        let router = Router::new()
            .route(
                "/token",
                get(|ActorOf(actor): ActorOf| async move { actor.label() }),
            )
            .route(
                "/who",
                get(|ActorOf(actor): ActorOf| async move { actor.label() }),
            )
            .layer(ActorLayer::new(Arc::new(Rules)).client_authentication(["/token".to_owned()]));
        let basic = |path: &str| {
            Request::get(path)
                .header(http::header::AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0")
                .body(Body::empty())
                .expect("a request")
        };
        let answered = router
            .clone()
            .oneshot(basic("/token"))
            .await
            .expect("answered");
        assert_eq!(answered.status(), http::StatusCode::OK);
        let bytes = axum::body::to_bytes(answered.into_body(), 1 << 16)
            .await
            .expect("the body reads");
        assert_eq!(String::from_utf8_lossy(&bytes), "anonymous");
        let refused = router.oneshot(basic("/who")).await.expect("answered");
        assert_eq!(refused.status(), http::StatusCode::UNAUTHORIZED);
        // In the clear, a client's secret is refused unread there too, as a bearer token is.
        let clear = Router::new()
            .route(
                "/token",
                get(|ActorOf(actor): ActorOf| async move { actor.label() }),
            )
            .layer(
                ActorLayer::new(Arc::new(Rules))
                    .refusing_clear_bearer(true)
                    .client_authentication(["/token".to_owned()]),
            );
        let refused = clear.oneshot(basic("/token")).await.expect("answered");
        assert_eq!(refused.status(), http::StatusCode::UNAUTHORIZED);
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

    #[tokio::test]
    async fn a_refused_bearer_is_challenged_with_the_bearer_scheme() {
        let request = Request::get("/who")
            .header(http::header::AUTHORIZATION, "Bearer bad")
            .body(Body::empty())
            .expect("a request");
        let response = router().oneshot(request).await.expect("answered");
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        let challenges: Vec<_> = response
            .headers()
            .get_all(http::header::WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().expect("ascii").to_owned())
            .collect();
        assert!(
            challenges.contains(&permguard_core::api::BEARER_CHALLENGE.to_owned()),
            "{challenges:?}"
        );
    }

    #[tokio::test]
    async fn a_bearer_on_a_clear_listener_is_refused_unread_and_certificates_still_pass() {
        let request = Request::get("/who")
            .header(http::header::AUTHORIZATION, "Bearer good")
            .body(Body::empty())
            .expect("a request");
        let response = clear_router(true).oneshot(request).await.expect("answered");
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body reads");
        assert!(
            String::from_utf8_lossy(&bytes).contains("only over TLS"),
            "the refusal says why"
        );

        let request = Request::get("/who").body(Body::empty()).expect("a request");
        let response = clear_router(true).oneshot(request).await.expect("answered");
        assert_eq!(
            response.status(),
            http::StatusCode::OK,
            "no bearer, no refusal"
        );
    }

    #[test]
    fn a_request_without_the_layer_is_refused_never_anonymous() {
        assert!(matches!(
            *actor_of(&http::Extensions::new()),
            Actor::Unmapped { .. }
        ));
    }

    /// Step 7 of `2-security/8` Verifying a token: a token caller refused for what it asked is told
    /// `insufficient_scope`; any other caller's `403` carries no challenge.
    #[tokio::test]
    async fn a_token_callers_refusal_names_insufficient_scope() {
        let challenges = |response: &Response<Body>| -> Vec<String> {
            response
                .headers()
                .get_all(http::header::WWW_AUTHENTICATE)
                .iter()
                .map(|value| value.to_str().expect("ascii").to_owned())
                .collect()
        };
        for (bearer, expected) in [
            (
                "scoped",
                vec![permguard_core::api::SCOPE_CHALLENGE.to_owned()],
            ),
            ("good", Vec::new()),
        ] {
            let request = Request::get("/forbidden")
                .header(http::header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .expect("a request");
            let response = router().oneshot(request).await.expect("answered");
            assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
            assert_eq!(challenges(&response), expected, "{bearer}");
        }
        // A token caller answered `200` is not challenged.
        let request = Request::get("/who")
            .header(http::header::AUTHORIZATION, "Bearer scoped")
            .body(Body::empty())
            .expect("a request");
        let response = router().oneshot(request).await.expect("answered");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert!(challenges(&response).is_empty());
    }
}
