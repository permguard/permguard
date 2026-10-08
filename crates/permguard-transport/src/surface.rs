// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One listener: bound before it serves, and drained before it stops.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::error_handling::HandleErrorLayer;
use axum::extract::DefaultBodyLimit;
use axum_server::Handle;
use axum_server::accept::DefaultAcceptor;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use http::StatusCode;
use hyper_util::rt::TokioTimer;
use tokio::task::JoinHandle;
use tower::limit::ConcurrencyLimitLayer;
use tower::load_shed::LoadShedLayer;
use tower::{BoxError, ServiceBuilder};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use permguard_core::{Limits, Metrics, TlsSettings};

use crate::gate::PeerGateLayer;
use crate::guard::LimitedAcceptor;
use crate::identity::PeerAcceptor;
use crate::material::server_config;
use crate::measure;
use crate::reload;
use crate::request;

/// A listener that is up, and the things needed to take it down again.
pub struct Surface {
    address: SocketAddr,
    handle: Handle<SocketAddr>,
    task: JoinHandle<()>,
    /// Kept alive for as long as the surface is: the registry that SIGHUP walks holds only a weak
    /// reference, so dropping this is what takes the surface out of it.
    material: Option<Arc<reload::Reloadable>>,
    watcher: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Surface {
    /// Says what a listener is, which is the address it got. The rest is machinery.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Surface")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// A listener being described, before it is bound.
///
/// A builder rather than a widening argument list: what a listener needs has grown from an address
/// and a router to bounds, measurement and a name, and each of those arrived as one more positional
/// argument that every call site had to get in the right order. Named, they read at the call site and
/// the next one costs nothing.
pub struct Listener<'a> {
    surface: &'static str,
    address: &'a str,
    router: Router,
    tls: Option<&'a TlsSettings>,
    limits: Limits,
    metrics: Metrics,
    authenticator: Option<std::sync::Arc<dyn permguard_core::authz::Authenticator>>,
    streaming: Vec<String>,
}

impl<'a> Listener<'a> {
    /// Paths whose request body is a long-lived stream of bounded messages, the peer channel
    /// (WP-2.3): exempt from the cumulative body limit, which would end the stream after
    /// `limits.body_bytes()` in total. The service behind each bounds every message itself.
    pub fn streaming(mut self, paths: impl IntoIterator<Item = String>) -> Self {
        self.streaming = paths.into_iter().collect();

        self
    }

    /// Serves this listener over TLS as `tls` describes, or in the clear when it is `None`.
    pub fn tls(mut self, tls: Option<&'a TlsSettings>) -> Self {
        self.tls = tls;

        self
    }

    /// Bounds what this listener will spend. Defaults to [`Limits::default`].
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;

        self
    }

    /// Records what this listener does into `metrics`. Defaults to recording nothing.
    pub fn metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;

        self
    }

    /// The Host's credential mapper: every request this surface answers carries the actor it
    /// decided, before any handler runs. Without one, `NoRules` decides: nobody is anonymous,
    /// every credential is unmapped.
    pub fn authenticator(
        mut self,
        authenticator: Option<std::sync::Arc<dyn permguard_core::authz::Authenticator>>,
    ) -> Self {
        self.authenticator = authenticator;

        self
    }

    /// Binds the address and starts serving.
    ///
    /// Returns once the socket is bound and the server is running, so a caller that got a [`Surface`]
    /// back knows the port is genuinely theirs.
    pub async fn start(self) -> Result<Surface> {
        let Self {
            surface,
            address,
            router,
            tls,
            limits,
            metrics,
            authenticator,
            streaming,
        } = self;

        let parsed: SocketAddr = address
            .parse()
            .with_context(|| format!("reading the listen address `{address}`"))?;

        // Bound here, synchronously, so "the port is taken" is an error from `start`.
        let listener =
            std::net::TcpListener::bind(parsed).with_context(|| format!("binding {parsed}"))?;
        listener
            .set_nonblocking(true)
            .with_context(|| format!("preparing the listener on {parsed}"))?;
        let bound = listener
            .local_addr()
            .with_context(|| format!("reading back the address of {parsed}"))?;

        let secured = match tls {
            Some(settings) => Some((
                settings,
                RustlsConfig::from_config(server_config(settings)?),
            )),
            None => None,
        };

        // Who, of everybody the client authority signed, this surface answers. Carried out of the
        // settings here because the router layers are built inside the serving task.
        let allow = tls
            .map(|settings| settings.allow().to_vec())
            .unwrap_or_default();

        let handle = Handle::new();
        let serving = handle.clone();
        let accepting = secured.as_ref().map(|(_, config)| config.clone());

        let measuring = metrics.clone();
        let task = tokio::spawn(async move {
            // A ceiling on requests in flight, and a refusal rather than a queue once it is reached.
            // The two belong together: a concurrency limit on its own makes an overloaded surface
            // slow instead of full, which is worse — the client waits, the memory the wait costs is
            // still spent, and nobody is told anything. Shedding turns that into an answer.
            let overload = ServiceBuilder::new()
                .layer(HandleErrorLayer::new(overloaded))
                .layer(LoadShedLayer::new())
                .layer(ConcurrencyLimitLayer::new(
                    limits.concurrent_requests() as usize
                ));

            // Applied here rather than by each surface, so no surface can be added without them.
            // Innermost first: the body limit sits closest to the handler, the identity outermost so
            // even a request that is refused before reaching a handler is named in the log and in the
            // answer the client gets.
            // Who the request acts as, decided once for every request this surface answers: the
            // handlers read the actor and never build one (WP-2.4). Always installed: a surface
            // given no mapper decides with `NoRules`, which maps no credential, so a composition
            // that forgot its mapper is closed to credentials rather than open. Applied before
            // the gate below, which is therefore the outer layer: a peer the allow list refuses is
            // refused before any token of its is read.
            let authenticator = authenticator
                .unwrap_or_else(|| std::sync::Arc::new(permguard_core::authz::NoRules));
            let router = router.layer(crate::actor::ActorLayer::new(authenticator));
            // Between the handlers and everything else: nothing below this line runs for a peer the
            // list does not name. Applied conditionally because an empty list means the handshake is
            // the whole decision — configurations where that is dangerous are refused by validation,
            // not silently gated here.
            let router = if allow.is_empty() {
                router
            } else {
                router.layer(PeerGateLayer::new(allow))
            };

            let service = router
                // Innermost of all, so it is between the handlers and everything else: a panic there
                // becomes an answer rather than a connection that closes with nothing on it. Without
                // it the client sees a transport error, which sends whoever reports it to the
                // network — and the surface loses the one request that would have explained itself.
                .layer(CatchPanicLayer::custom(panicked))
                .layer(DefaultBodyLimit::max(limits.body_bytes()))
                .layer(StreamingExempt::new(
                    RequestBodyLimitLayer::new(limits.body_bytes()),
                    streaming,
                ))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    limits.request_timeout(),
                ))
                .layer(overload)
                .layer(measure::MeasureLayer::new(surface, measuring.clone()))
                .layer(request::IdentityLayer::new())
                .into_make_service();

            let served = match accepting {
                Some(config) => match axum_server::from_tcp(listener) {
                    Ok(mut server) => {
                        bound_connections(&mut server, &limits);

                        server
                            .acceptor(
                                LimitedAcceptor::new(
                                    PeerAcceptor::new(
                                        RustlsAcceptor::new(config)
                                            .handshake_timeout(limits.handshake_timeout()),
                                    ),
                                    limits.clone(),
                                )
                                .measured(surface, measuring.clone()),
                            )
                            .handle(serving)
                            .serve(service)
                            .await
                    }
                    Err(error) => Err(error),
                },
                None => match axum_server::from_tcp(listener) {
                    Ok(mut server) => {
                        bound_connections(&mut server, &limits);

                        server
                            .acceptor(
                                LimitedAcceptor::new(DefaultAcceptor::new(), limits.clone())
                                    .measured(surface, measuring.clone()),
                            )
                            .handle(serving)
                            .serve(service)
                            .await
                    }
                    Err(error) => Err(error),
                },
            };

            if let Err(error) = served {
                tracing::warn!(
                    event.name = "surface.failed",
                    address = %bound,
                    error = %error,
                    "the listener stopped on its own"
                );
            }
        });

        let (material, watcher) = match secured {
            Some((settings, config)) => {
                // Before anything is served, so a deployment that started with an expired certificate
                // says so in its first seconds rather than at the first handshake that fails.
                measure::record_certificate_expiry(surface, &metrics, settings);

                let material = Arc::new(
                    reload::Reloadable::new(bound, settings.clone(), config)
                        .measured(surface, metrics.clone()),
                );
                reload::register(&material);

                let watcher = settings.reload().map(|interval| {
                    let watched = Arc::downgrade(&material);

                    tokio::spawn(reload::watch(watched, interval))
                });

                (Some(material), watcher)
            }
            None => (None, None),
        };

        Ok(Surface {
            address: bound,
            handle,
            task,
            material,
            watcher,
        })
    }
}

impl Surface {
    /// Describes a listener called `surface`, on `address`, serving `router`.
    ///
    /// Nothing is bound until [`Listener::start`].
    pub fn listener<'a>(surface: &'static str, address: &'a str, router: Router) -> Listener<'a> {
        Listener {
            surface,
            address,
            router,
            tls: None,
            limits: Limits::default(),
            metrics: Metrics::none(),
            authenticator: None,
            streaming: Vec::new(),
        }
    }

    /// Returns the address actually bound, which is what to log.
    ///
    /// Not the address that was asked for: port zero is a real configuration, and reporting `:0` back
    /// to an operator would be useless.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stops accepting connections, at once, and lets the ones open finish what they carry:
    /// the first step of a drain (WP-2.7). Nothing waits here; [`Surface::finish`] waits.
    pub fn stop_intake(&self) {
        self.handle.graceful_shutdown(None);
    }

    /// Waits for the connections still open to finish their requests, until `deadline`; what is
    /// still open then is cut. Returns the address and whether everything finished: `false` means
    /// requests were cut at the deadline, which makes the drain incomplete. Stops the intake too,
    /// for a caller that did not.
    ///
    /// When the caller gives up on this future (its own deadline passed), the serving task is left
    /// to end on its own: the intake is already stopped and the process is about to exit.
    pub async fn finish(self, deadline: tokio::time::Instant) -> Result<(SocketAddr, bool)> {
        if let Some(watcher) = self.watcher {
            watcher.abort();
        }
        drop(self.material);

        self.handle.graceful_shutdown(None);
        let mut task = self.task;
        let complete = match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(joined) => {
                joined.with_context(|| {
                    format!("waiting for the listener on {} to finish", self.address)
                })?;
                true
            }
            Err(_) => {
                // The drain deadline passed with requests still open: they are cut, and the
                // caller reports the drain incomplete.
                self.handle.shutdown();
                task.await.with_context(|| {
                    format!("waiting for the listener on {} to stop", self.address)
                })?;
                false
            }
        };

        Ok((self.address, complete))
    }

    /// Stops accepting, lets what is in flight finish within `grace`, and waits for it to be over.
    ///
    /// Waiting is the point. Asking a server to stop and returning immediately reports a shutdown
    /// that has not happened, and the process exits underneath the requests it promised to finish.
    pub async fn stop(self, grace: Duration) -> Result<SocketAddr> {
        if let Some(watcher) = self.watcher {
            watcher.abort();
        }

        // Dropping the last strong reference is what removes this surface from the set SIGHUP walks.
        drop(self.material);

        self.handle.graceful_shutdown(Some(grace));
        self.task
            .await
            .with_context(|| format!("waiting for the listener on {} to finish", self.address))?;

        Ok(self.address)
    }
}

/// A body limit every path gets except the streaming ones.
#[derive(Clone)]
struct StreamingExempt<L> {
    limit: L,
    paths: Arc<[String]>,
}

impl<L> StreamingExempt<L> {
    fn new(limit: L, paths: Vec<String>) -> Self {
        Self {
            limit,
            paths: paths.into(),
        }
    }
}

impl<L, S> tower_layer::Layer<S> for StreamingExempt<L>
where
    L: tower_layer::Layer<S>,
    S: Clone,
{
    type Service = Exempting<L::Service, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Exempting {
            limited: self.limit.layer(inner.clone()),
            plain: inner,
            paths: Arc::clone(&self.paths),
        }
    }
}

/// The limited service, or the plain one for a streaming path.
#[derive(Clone)]
struct Exempting<Limited, Plain> {
    limited: Limited,
    plain: Plain,
    paths: Arc<[String]>,
}

impl<Limited, Plain, B, LB, PB> tower_service::Service<http::Request<B>>
    for Exempting<Limited, Plain>
where
    Limited: tower_service::Service<http::Request<B>, Response = http::Response<LB>>,
    Plain: tower_service::Service<
            http::Request<B>,
            Response = http::Response<PB>,
            Error = Limited::Error,
        >,
    Limited::Future: Send + 'static,
    Plain::Future: Send + 'static,
    LB: axum::body::HttpBody<Data = axum::body::Bytes> + Send + 'static,
    LB::Error: Into<BoxError>,
    PB: axum::body::HttpBody<Data = axum::body::Bytes> + Send + 'static,
    PB::Error: Into<BoxError>,
{
    type Response = http::Response<Body>;
    type Error = Limited::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.limited.poll_ready(context) {
            std::task::Poll::Ready(Ok(())) => self.plain.poll_ready(context),
            other => other,
        }
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        if self.paths.iter().any(|path| path == request.uri().path()) {
            let answer = self.plain.call(request);
            Box::pin(async move { answer.await.map(|response| response.map(Body::new)) })
        } else {
            let answer = self.limited.call(request);
            Box::pin(async move { answer.await.map(|response| response.map(Body::new)) })
        }
    }
}

/// How often an idle HTTP/2 connection is pinged to check the peer is still on the other end.
///
/// Not a configured limit: it is a livability detail, not a defence, and there is no deployment whose
/// correctness turns on whether a dead peer's streams are reclaimed in twenty seconds or forty. Thirty
/// seconds reclaims them promptly without a quiet connection generating a PING every few seconds for
/// as long as it stays open.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Bounds what a client may do to a connection before it becomes a request.
///
/// Everything a request goes through — the timeout, the body limit, the concurrency ceiling — starts
/// once the protocol has a request to hand over. A client that never finishes sending one is therefore
/// invisible to all of it, and the only thing bounding it is the connection limit. Spending a thousand
/// sockets is not an attack, it is an afternoon.
///
/// # The timer that has to be here
///
/// hyper carries a thirty-second default for the header read, and **discards it unless a timer is
/// installed** — it warns and serves without one. Nothing between this and hyper installs one, so
/// without these lines the default is a line in someone else's documentation and the surface has no
/// defence against a slow header at all. Setting it and forgetting the timer is worse: hyper panics.
fn bound_connections<A: axum_server::Address>(
    server: &mut axum_server::Server<A>,
    limits: &Limits,
) {
    server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout())
        // The head, bounded in bytes as well as in time: a client that sends fast can otherwise
        // make this buffer whatever hyper's default happens to be, per connection, repeatedly.
        .max_buf_size(limits.header_bytes());

    server
        .http_builder()
        .http2()
        .timer(TokioTimer::new())
        // One connection may not open more streams than the whole surface will serve requests. A
        // stream is cheaper than a connection and therefore a cheaper way to spend the same budget:
        // without this, one socket can hold as much of the surface as a thousand.
        .max_concurrent_streams(limits.concurrent_requests())
        // The same bound, in HTTP/2's vocabulary: what one request's header list may total.
        .max_header_list_size(limits.header_bytes() as u32)
        // A peer whose TCP connection died without a FIN — a pulled cable, a NAT that forgot it —
        // keeps its streams and their buffers until something notices. A PING notices in seconds
        // where the OS would take hours. The interval is its own thing on purpose: it is how often to
        // check a *quiet* connection is still there, which has nothing to do with how long a client
        // gets to send a request head, and it must be longer than the time allowed for the answer or
        // a peer with a slow link gets hung up on between the ping and its reply.
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .keep_alive_timeout(limits.header_timeout());
}

/// Turns a panic in a handler into an answer, and into a record somebody can find.
///
/// The process survives a panic either way — it unwinds into the connection's task and stops there.
/// What differs is what the client gets: without this, a connection that closes mid-answer, which is
/// indistinguishable from a network fault and gets investigated as one. With it, a 500 and a log
/// record naming the panic, on a connection that stays up for the next request.
///
/// It deliberately does not tell the client *what* panicked. A panic message names internals, and the
/// client is not the audience for those; the log is.
fn panicked(payload: Box<dyn std::any::Any + Send + 'static>) -> http::Response<Body> {
    // A panic carries a `&str` when it was `panic!("literal")` and a `String` when it was formatted.
    // Anything else is a payload nobody here can read, and saying so is better than saying nothing.
    let reported = payload
        .downcast_ref::<&'static str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic carrying something unprintable".to_owned());

    tracing::error!(
        event.name = "surface.panicked",
        component = "transport",
        panic.message = %reported,
        "a handler panicked; the connection was kept and the client told nothing about it"
    );

    let mut response = http::Response::new(Body::from("internal error\n"));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    response
}

/// What a client is told when the surface is already serving as much as it is allowed to.
///
/// 503 and not 500: the request was not wrong and nothing is broken. It is a "come back", and a
/// client that reads status codes will treat it as one — which is the difference between a load spike
/// that recovers and one that turns into a retry storm against an endpoint the client thinks is
/// faulty.
async fn overloaded(_error: BoxError) -> (StatusCode, &'static str) {
    tracing::warn!(
        event.name = "surface.shed",
        component = "transport",
        "refused a request: the surface is already serving as many as it is allowed to"
    );

    (
        StatusCode::SERVICE_UNAVAILABLE,
        "the surface is serving as many requests as it is allowed to",
    )
}
