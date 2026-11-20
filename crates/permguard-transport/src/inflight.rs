// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The request bytes a surface holds in flight (BUG-0056).
//!
//! `body_bytes` bounds one body and `concurrent_requests` how many are served at once, and nothing
//! bounds their product, while parsing a body costs many times its bytes. This budget does: every
//! request is charged the bytes of its body from the moment they are read until its answer is
//! given, and the surface holds at most `inflight_body_bytes` of them at once.
//!
//! | body                      | charged                               | past the budget                  |
//! | ------------------------- | ------------------------------------- | -------------------------------- |
//! | a declared length         | that length, before the body is read  | refused `overloaded` at once     |
//! | no declared length (gRPC) | each frame, as it is read             | the frame waits for room          |
//!
//! A body whose frames wait is still bounded by the header timeout between two of its frames, so
//! a surface full of partial bodies sheds them rather than holding them. The budget is never less
//! than one body, so a single request of `body_bytes` always fits. The probes and the streaming
//! routes, whose body is a conversation, are exempt, as they are from the request budget.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};

use axum::body::{Body, Bytes};
use axum::middleware::Next;
use axum::response::Response;
use http_body::Frame;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

/// The answer's message once the budget is spent.
pub(crate) const OVERLOADED_BODIES: &str =
    "the surface holds as many request bytes in flight as it is allowed to";

/// One surface's budget of request bytes in flight.
pub(crate) struct Budget {
    semaphore: Arc<Semaphore>,
    /// Every permit the budget holds: what one charge is clamped to.
    total: u32,
    /// The paths outside it: the probes and the streaming routes.
    exempt: Arc<[String]>,
}

impl Budget {
    /// A budget of `inflight` bytes, never less than one body of `body_bytes`.
    pub(crate) fn new(inflight: usize, body_bytes: usize, exempt: Vec<String>) -> Arc<Self> {
        let total = inflight
            .max(body_bytes)
            .clamp(1, Semaphore::MAX_PERMITS.min(u32::MAX as usize));
        let total = u32::try_from(total).unwrap_or(u32::MAX);
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(total as usize)),
            total,
            exempt: exempt.into(),
        })
    }

    fn weight(&self, bytes: u64) -> u32 {
        u32::try_from(bytes).unwrap_or(u32::MAX).min(self.total)
    }

    /// The bytes free now: what a test reads.
    #[cfg(test)]
    fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// The permits one request holds: shared by the request and its body, released when both went.
type Held = Arc<Mutex<Vec<OwnedSemaphorePermit>>>;

/// Charges `request` to `budget` until its answer is given.
pub(crate) async fn charge(
    budget: Arc<Budget>,
    request: http::Request<Body>,
    next: Next,
) -> Response {
    if budget
        .exempt
        .iter()
        .any(|path| path == request.uri().path())
    {
        return next.run(request).await;
    }
    let held: Held = Arc::default();
    let declared = request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let request = match declared {
        Some(0) => request,
        Some(length) => {
            match Arc::clone(&budget.semaphore).try_acquire_many_owned(budget.weight(length)) {
                Ok(permit) => held
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(permit),
                Err(_) => {
                    let grpc = request
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| value.starts_with("application/grpc"));
                    tracing::warn!(
                        event.name = "surface.shed",
                        component = "transport",
                        bytes = length,
                        "refused a request: the surface holds as many request bytes in flight as \
                         it is allowed to"
                    );
                    return crate::gate::unavailable(OVERLOADED_BODIES, grpc);
                }
            }
            request
        }
        // No declared length: each frame is charged as it is read.
        None => {
            let (parts, body) = request.into_parts();
            let charged = Charged {
                inner: body,
                budget: Arc::clone(&budget),
                held: Arc::clone(&held),
                waiting: None,
                frame: None,
            };
            http::Request::from_parts(parts, Body::new(charged))
        }
    };
    let response = next.run(request).await;
    drop(held);
    response
}

type Acquiring = Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

/// A body charged to its surface's budget frame by frame.
struct Charged {
    inner: Body,
    budget: Arc<Budget>,
    held: Held,
    /// The room a frame waits for, and the frame.
    waiting: Option<Acquiring>,
    frame: Option<Frame<Bytes>>,
}

impl http_body::Body for Charged {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        if let Some(waiting) = this.waiting.as_mut() {
            let acquired = ready!(waiting.as_mut().poll(context));
            this.waiting = None;
            if let Ok(permit) = acquired {
                this.held
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(permit);
            }
            return Poll::Ready(this.frame.take().map(Ok));
        }
        let frame = match ready!(Pin::new(&mut this.inner).poll_frame(context)) {
            Some(Ok(frame)) => frame,
            other => return Poll::Ready(other),
        };
        let bytes = frame.data_ref().map_or(0, Bytes::len) as u64;
        if bytes == 0 {
            return Poll::Ready(Some(Ok(frame)));
        }
        let weight = this.budget.weight(bytes);
        let semaphore = Arc::clone(&this.budget.semaphore);
        if let Ok(permit) = Arc::clone(&semaphore).try_acquire_many_owned(weight) {
            this.held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(permit);
            return Poll::Ready(Some(Ok(frame)));
        }
        this.frame = Some(frame);
        this.waiting = Some(Box::pin(semaphore.acquire_many_owned(weight)));
        // Polled once now, so its waker is registered.
        self.poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.waiting.is_none() && self.frame.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use axum::Router;
    use axum::routing::post;
    use http_body_util::BodyExt as _;
    use tower_service::Service as _;

    /// A surface whose one route holds its request until `release` is notified.
    fn surface(budget: Arc<Budget>, release: Arc<tokio::sync::Notify>) -> Router {
        Router::new()
            .route(
                "/decide",
                post(move |body: Bytes| {
                    let release = Arc::clone(&release);
                    async move {
                        release.notified().await;
                        body.len().to_string()
                    }
                }),
            )
            .route("/health", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |request, next| {
                charge(Arc::clone(&budget), request, next)
            }))
    }

    fn declared(path: &str, bytes: usize) -> http::Request<Body> {
        http::Request::post(path)
            .header(http::header::CONTENT_LENGTH, bytes)
            .body(Body::from(vec![b'x'; bytes]))
            .expect("a request")
    }

    /// BUG-0056: a request declaring its length is charged it before its body is read and until
    /// its answer; past the budget it is refused `overloaded` at once, and the probes are exempt.
    #[tokio::test]
    async fn a_declared_body_is_charged_until_its_answer_and_refused_past_the_budget() {
        let budget = Budget::new(1_000, 600, vec!["/health".to_owned()]);
        let release = Arc::new(tokio::sync::Notify::new());
        let mut router = surface(Arc::clone(&budget), Arc::clone(&release));

        let first = tokio::spawn(router.call(declared("/decide", 600)));
        while budget.available() == 1_000 {
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.available(), 400, "charged its declared length");

        let refused = router
            .call(declared("/decide", 500))
            .await
            .expect("an answer");
        assert_eq!(refused.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        let body = refused
            .into_body()
            .collect()
            .await
            .expect("read")
            .to_bytes();
        assert!(
            String::from_utf8_lossy(&body).contains(OVERLOADED_BODIES),
            "{}",
            String::from_utf8_lossy(&body)
        );
        let probe = router
            .call(declared("/health", 500))
            .await
            .expect("an answer");
        assert_eq!(probe.status(), http::StatusCode::OK, "the probe is exempt");

        release.notify_one();
        let answered = first.await.expect("joined").expect("an answer");
        assert_eq!(answered.status(), http::StatusCode::OK);
        assert_eq!(budget.available(), 1_000, "released with the answer");
    }

    /// BUG-0056: a body with no declared length is charged frame by frame, a frame past the
    /// budget waits for room, and everything is released with the answer.
    #[tokio::test]
    async fn an_undeclared_body_is_charged_frame_by_frame() {
        let budget = Budget::new(100, 80, Vec::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut router = surface(Arc::clone(&budget), Arc::clone(&release));
        let undeclared = |bytes: usize| {
            http::Request::post("/decide")
                .body(Body::new(OneFrame(Some(Bytes::from(vec![b'y'; bytes])))))
                .expect("a request")
        };

        let first = tokio::spawn(router.call(undeclared(80)));
        while budget.available() == 100 {
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.available(), 20);
        let second = tokio::spawn(router.call(undeclared(50)));
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(!second.is_finished(), "its frame waits for room");
        release.notify_one();
        assert_eq!(
            first.await.expect("joined").expect("an answer").status(),
            http::StatusCode::OK
        );
        release.notify_one();
        let answered = second.await.expect("joined").expect("an answer");
        let body = answered
            .into_body()
            .collect()
            .await
            .expect("read")
            .to_bytes();
        assert_eq!(&body[..], b"50", "the whole body was read");
        assert_eq!(budget.available(), 100, "released with the answers");
    }

    /// A body of one frame, with no declared length.
    struct OneFrame(Option<Bytes>);

    impl http_body::Body for OneFrame {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
        }
    }

    /// The budget is never less than one body.
    #[test]
    fn the_budget_holds_one_body_at_least() {
        assert_eq!(Budget::new(10, 600, Vec::new()).total, 600);
        assert_eq!(Budget::new(1_000, 600, Vec::new()).total, 1_000);
    }
}
