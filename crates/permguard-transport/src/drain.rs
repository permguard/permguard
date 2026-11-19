// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Ending the streaming answers when a surface drains (BUG-0222).
//!
//! A drain stops the intake and waits for the requests still open. A streaming path's answer, the
//! peer channel and the task watch it carries, is not a request that finishes: it lasts as long as
//! the peer keeps it, so a drain that waits for it waits for its whole budget and is then cut.
//! Here such an answer ends as soon as the drain starts, between two of its frames: over gRPC with
//! `UNAVAILABLE`, which a peer reads as "try again later", elsewhere as an ended body. What was
//! queued before is sent first; nothing is cut in the middle of a frame.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use http::{HeaderMap, HeaderValue};
use http_body::Frame;
use tokio::sync::watch;
use tower::BoxError;

/// What a gRPC peer is told when its stream ends on a drain: `UNAVAILABLE`, retried later.
const GRPC_UNAVAILABLE: &str = "14";

/// The message carried with it.
const DRAINING: &str = "the listener is draining: reconnect later";

/// Ends the answers of `paths` when `draining` turns true.
#[derive(Clone)]
pub(crate) struct EndOnDrainLayer {
    paths: Arc<[String]>,
    draining: watch::Receiver<bool>,
}

impl EndOnDrainLayer {
    pub(crate) fn new(paths: Vec<String>, draining: watch::Receiver<bool>) -> Self {
        Self {
            paths: paths.into(),
            draining,
        }
    }
}

impl<S> tower_layer::Layer<S> for EndOnDrainLayer {
    type Service = EndOnDrain<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EndOnDrain {
            inner,
            paths: Arc::clone(&self.paths),
            draining: self.draining.clone(),
        }
    }
}

/// The service [`EndOnDrainLayer`] makes.
#[derive(Clone)]
pub(crate) struct EndOnDrain<S> {
    inner: S,
    paths: Arc<[String]>,
    draining: watch::Receiver<bool>,
}

impl<S, B, RB> tower_service::Service<http::Request<B>> for EndOnDrain<S>
where
    S: tower_service::Service<http::Request<B>, Response = http::Response<RB>>,
    S::Future: Send + 'static,
    RB: http_body::Body<Data = Bytes> + Send + 'static,
    RB::Error: Into<BoxError>,
{
    type Response = http::Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let streaming = self.paths.iter().any(|path| path == request.uri().path());
        let draining = self.draining.clone();
        let answer = self.inner.call(request);

        Box::pin(async move {
            let response = answer.await?;
            if !streaming {
                return Ok(response.map(Body::new));
            }
            let grpc = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("application/grpc"));

            Ok(response.map(|body| Body::new(EndingBody::new(body, draining, grpc))))
        })
    }
}

/// A streaming body that ends when the drain starts.
struct EndingBody<B> {
    inner: Pin<Box<B>>,
    drained: Pin<Box<dyn Future<Output = ()> + Send>>,
    grpc: bool,
    ended: bool,
}

impl<B> EndingBody<B> {
    fn new(inner: B, mut draining: watch::Receiver<bool>, grpc: bool) -> Self {
        let drained = Box::pin(async move {
            // A surface dropped without a drain leaves its answers as they were.
            if draining.wait_for(|draining| *draining).await.is_err() {
                std::future::pending::<()>().await;
            }
        });

        Self {
            inner: Box::pin(inner),
            drained,
            grpc,
            ended: false,
        }
    }
}

impl<B> http_body::Body for EndingBody<B>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        // What the answer has ready goes first: the drain ends it between frames.
        if let Poll::Ready(frame) = self.inner.as_mut().poll_frame(context) {
            match &frame {
                Some(Ok(frame)) if frame.is_trailers() => self.ended = true,
                Some(Err(_)) | None => self.ended = true,
                Some(Ok(_)) => {}
            }

            return Poll::Ready(frame.map(|frame| frame.map_err(Into::into)));
        }
        if self.drained.as_mut().poll(context).is_ready() {
            self.ended = true;
            if !self.grpc {
                return Poll::Ready(None);
            }
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static(GRPC_UNAVAILABLE));
            trailers.insert("grpc-message", HeaderValue::from_static(DRAINING));

            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }

        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }
}
