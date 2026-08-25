// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Deciding whether an authenticated peer is one this surface answers.
//!
//! The handshake settles *authenticity*: the certificate is genuine, signed by the configured
//! authority, not revoked. It cannot settle *authorisation*, because an authority signs every client
//! it was ever asked to — the SDK in another team's service, a batch job from last year, the
//! monitoring probe. Which of them this surface is for is a separate list, and this is the layer
//! that reads it.
//!
//! # Where it sits
//!
//! On the transport, outside the handlers, applied by [`Surface`](crate::Surface) whenever the
//! listener's settings carry an allow list — so it covers HTTP and gRPC alike, and no route can be
//! added that forgets to check. A refused request never reaches an application handler at all.
//!
//! # What a refusal says
//!
//! `403`, a stable body, and a log record naming the peer by its label and fingerprint. Not `401`:
//! the client authenticated perfectly well — that is how we know who to name in the record. What it
//! lacks is standing, and telling it so precisely is what lets the operator on the other end fix the
//! list instead of debugging their certificate.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Request, Response, StatusCode};
use tower_service::Service;

use permguard_core::{AllowedPeer, PeerIdentity};

/// The `component` every record of a refusal carries.
const COMPONENT: &str = "transport";

/// Admits only the peers an allow list names.
#[derive(Clone)]
pub struct PeerGateLayer {
    allow: Arc<Vec<AllowedPeer>>,
}

impl PeerGateLayer {
    /// Builds a gate over `allow`.
    ///
    /// An empty list refuses everybody, which is never what a configuration means — the caller
    /// applies this layer only when the list has entries, and validation refuses the configurations
    /// where an empty list would be dangerous rather than redundant.
    pub fn new(allow: Vec<AllowedPeer>) -> Self {
        Self {
            allow: Arc::new(allow),
        }
    }
}

impl<S> tower_layer::Layer<S> for PeerGateLayer {
    type Service = PeerGated<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PeerGated {
            inner,
            allow: Arc::clone(&self.allow),
        }
    }
}

/// A service that answers only the peers on the list.
#[derive(Clone)]
pub struct PeerGated<S> {
    inner: S,
    allow: Arc<Vec<AllowedPeer>>,
}

impl<S> Service<Request<Body>> for PeerGated<S>
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
        // The identity the acceptor attached when the handshake demanded a certificate. Its absence
        // here means the request arrived over a connection that never authenticated — which, on a
        // surface carrying an allow list, is a refusal and not an oversight: a gate that waves
        // through whoever forgot to show identification is a decoration.
        let identity = request
            .extensions()
            .get::<Arc<PeerIdentity>>()
            .map(Arc::clone);

        match identity {
            Some(peer) if peer.is_allowed_by(&self.allow) => Box::pin(self.inner.call(request)),
            Some(peer) => {
                tracing::warn!(
                    event.name = "transport.peer_refused",
                    component = COMPONENT,
                    peer.label = %peer.label(),
                    peer.fingerprint = %peer.fingerprint(),
                    "refused an authenticated peer the allow list does not name"
                );

                Box::pin(async { Ok(refused()) })
            }
            None => {
                tracing::warn!(
                    event.name = "transport.peer_refused",
                    component = COMPONENT,
                    "refused a request that arrived with no peer identity on a surface with an allow list"
                );

                Box::pin(async { Ok(refused()) })
            }
        }
    }
}

/// What a peer that authenticated and lacks standing is told.
fn refused() -> Response<Body> {
    let mut response = Response::new(Body::from("this surface does not answer this peer\n"));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    response
}
