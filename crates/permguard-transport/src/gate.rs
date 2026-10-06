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
//! Two refusals, never interchangeable. A peer that authenticated and is not on the list is told
//! `403` with the `forbidden` body, and the log names it by label and fingerprint: what it lacks is
//! standing, and telling it so precisely lets the operator on the other end fix the list instead of
//! debugging a certificate. A request that arrived with no peer identity at all is told `401` with
//! the `unauthenticated` body: it never authenticated, so there is nobody to name and nothing to
//! grant. Neither answer says anything about what lives behind the gate.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Request, Response, StatusCode};
use tower_service::Service;

use permguard_core::{AccessDenial, AllowedPeer, PeerIdentity};

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
        let grpc = speaks_grpc(&request);

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

                Box::pin(async move {
                    Ok(refused(
                        AccessDenial::forbidden("this surface does not answer this peer"),
                        grpc,
                    ))
                })
            }
            None => {
                tracing::warn!(
                    event.name = "transport.peer_refused",
                    component = COMPONENT,
                    "refused a request that arrived with no peer identity on a surface with an allow list"
                );

                Box::pin(async move {
                    Ok(refused(
                        AccessDenial::unauthenticated(
                            "this surface answers only authenticated peers",
                        ),
                        grpc,
                    ))
                })
            }
        }
    }
}

/// The answer a denial renders as, in the caller's own protocol.
///
/// Over HTTP: the denial's status, the closed `{code, message}` body serialised — never spliced —
/// and, on a `401`, the `Mutual-TLS` challenge. Over gRPC: a trailers-only answer with the
/// denial's status and its code in `permguard-error-code`; an access denial has no class, so no
/// `permguard-error-class` is sent.
pub(crate) fn refused(denial: AccessDenial, grpc: bool) -> Response<Body> {
    if grpc {
        return refused_in_grpc(&denial);
    }

    let body = serde_json::to_vec(&denial.on_the_wire()).unwrap_or_default();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() =
        StatusCode::from_u16(denial.http_status()).unwrap_or(StatusCode::FORBIDDEN);
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    if let Some(challenge) = denial.challenge() {
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static(challenge),
        );
    }

    response
}

/// A gRPC trailers-only answer: HTTP `200`, and the status, message and code as headers.
fn refused_in_grpc(denial: &AccessDenial) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    if let Ok(status) = http::HeaderValue::from_str(&denial.grpc_code().number().to_string()) {
        headers.insert("grpc-status", status);
    }
    if let Ok(message) = http::HeaderValue::from_str(&grpc_message(denial.message())) {
        headers.insert("grpc-message", message);
    }
    headers.insert(
        permguard_core::GRPC_ERROR_CODE,
        http::HeaderValue::from_static(denial.code()),
    );

    response
}

/// Percent-encodes a `grpc-message` as the gRPC wire format requires: every byte outside printable
/// ASCII, and `%` itself.
fn grpc_message(message: &str) -> String {
    use std::fmt::Write as _;

    message.bytes().fold(String::new(), |mut out, byte| {
        if (0x20..=0x7e).contains(&byte) && byte != b'%' {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }

        out
    })
}

/// Whether a request speaks gRPC, by its content type.
pub(crate) fn speaks_grpc<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use http_body_util::BodyExt as _;
    use tower_layer::Layer as _;

    type Served = std::future::Ready<Result<Response<Body>, std::convert::Infallible>>;
    type Inner = tower::util::ServiceFn<fn(Request<Body>) -> Served>;

    fn served(_request: Request<Body>) -> Served {
        std::future::ready(Ok(Response::new(Body::from("served"))))
    }

    fn gate() -> PeerGated<Inner> {
        PeerGateLayer::new(vec!["cn:named".parse().expect("a valid allow entry")])
            .layer(tower::service_fn(served as fn(Request<Body>) -> Served))
    }

    async fn ask(content_type: &str, peer: Option<PeerIdentity>) -> Response<Body> {
        let mut request = Request::builder()
            .header(http::header::CONTENT_TYPE, content_type)
            .body(Body::empty())
            .expect("the request builds");
        if let Some(peer) = peer {
            request.extensions_mut().insert(Arc::new(peer));
        }

        gate().call(request).await.expect("the gate answers")
    }

    fn stranger() -> PeerIdentity {
        PeerIdentity::new("CN=stranger", Some("stranger".to_owned()), "ab12", "07")
    }

    async fn json(response: Response<Body>) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body reads")
            .to_bytes();

        serde_json::from_slice(&bytes).expect("the body is JSON")
    }

    #[tokio::test]
    async fn test_no_identity_is_401_with_the_mutual_tls_challenge_and_the_closed_body() {
        let answer = ask("application/json", None).await;

        assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            answer
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Mutual-TLS realm=\"permguard\""),
            "a 401 names how to authenticate"
        );
        let body = json(answer).await;
        assert_eq!(body["code"], "unauthenticated");
        assert_eq!(
            body.as_object().map(serde_json::Map::len),
            Some(2),
            "the body is closed: {body}"
        );
    }

    #[tokio::test]
    async fn test_an_unlisted_peer_is_403_without_a_challenge() {
        let answer = ask("application/json", Some(stranger())).await;

        assert_eq!(answer.status(), StatusCode::FORBIDDEN);
        assert!(
            answer
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .is_none(),
            "a known peer is not told to authenticate again"
        );
        let body = json(answer).await;
        assert_eq!(body["code"], "forbidden");
        assert!(body.get("class").is_none(), "an access denial has no class");
    }

    #[tokio::test]
    async fn test_a_grpc_caller_is_refused_in_grpc_with_the_same_code() {
        for (peer, status, code) in [
            (None, "16", "unauthenticated"),
            (Some(stranger()), "7", "forbidden"),
        ] {
            let answer = ask("application/grpc", peer).await;
            let header = |name: &str| {
                answer
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned)
            };

            assert_eq!(
                answer.status(),
                StatusCode::OK,
                "gRPC carries its status itself"
            );
            assert_eq!(header("grpc-status").as_deref(), Some(status));
            assert_eq!(header("permguard-error-code").as_deref(), Some(code));
            assert_eq!(
                header("permguard-error-class"),
                None,
                "an access denial has no class"
            );
            assert!(header("grpc-message").is_some());
        }
    }

    #[test]
    fn test_a_grpc_message_is_percent_encoded() {
        assert_eq!(grpc_message("plain words"), "plain words");
        assert_eq!(grpc_message("100% \n é"), "100%25 %0A %C3%A9");
    }

    #[tokio::test]
    async fn test_a_message_holding_json_syntax_cannot_break_the_body() {
        let hostile = "a \"quoted\" word,\n a \\ and a } that closes nothing";
        let body = json(refused(AccessDenial::forbidden(hostile), false)).await;

        assert_eq!(body["message"], hostile);
        assert_eq!(body["code"], "forbidden");
    }
}
