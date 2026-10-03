// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Giving every request a name, so the lines it produced can be found together.
//!
//! Without one, a surface under investigation offers a pile of records that happened at about the
//! same time and no way to tell which belong to the same call. With one, every line a request caused
//! carries it — because the identity is a `tracing` span the whole handler runs inside, not a field
//! somebody has to remember to add — and the client is told it too, so a report can name the request
//! it is about.
//!
//! # Where it comes from
//!
//! Always from this process. The name in every log line and span is one this surface drew itself:
//! P10 admits only opaque ids in a log, and a name a client chose is not opaque — it could carry a
//! tenant's name, or anything else the client wanted written into every record of the request.
//!
//! What a client sent as `X-Request-Id` is still honoured on the wire: the answer carries it back
//! in `X-Request-Id`, as AuthZEN requires of a decision point, after it has been **bounded and
//! filtered** — a value that arrives from outside and is written out unexamined is how a header gets
//! split. A value that is not a short run of plain characters is replaced by the drawn name rather
//! than rejected; a malformed id is not worth failing a request over. The drawn name is always told
//! back too, in `X-Permguard-Request-Id`, so a report can name the log lines it is about.

use std::task::{Context, Poll};

use http::{HeaderName, HeaderValue, Request, Response};
use tower_service::Service;

/// The header this reads, and echoes on the answer.
pub const HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// The header naming the request as this surface's logs name it.
pub const LOG_HEADER: HeaderName = HeaderName::from_static("x-permguard-request-id");

/// The longest client-supplied identity that will be believed: the one rule every surface applies.
#[cfg(test)]
const MAXIMUM: usize = permguard_core::correlation::MAXIMUM;

/// What a request is called, for as long as it is being served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// Returns the name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reads what a client called this request, when what it sent can be used as a name.
    ///
    /// Plain ASCII letters, digits, `-` and `_`, and no longer than 64 of them. Everything else is
    /// treated as absent: an identity is a label, and a label that can contain anything is a way of
    /// writing anything into every record that mentions it.
    fn from_client(value: &HeaderValue) -> Option<Self> {
        let text = permguard_core::correlation::admitted(value.to_str().ok()?)?;

        Some(Self(text.to_owned()))
    }

    /// Draws a name nothing else in this process will draw.
    ///
    /// Not a UUID: the value has to be unique among the requests one deployment is serving and
    /// readable in a log line, which is a much smaller requirement than universal uniqueness and does
    /// not need a dependency to meet. Sixteen hex characters from the system's generator is far more
    /// than enough to make a collision uninteresting.
    fn generated() -> Self {
        use std::fmt::Write;

        let mut material = [0_u8; 8];
        // A failure here would mean the system has no randomness, which is not a reason to refuse a
        // request — it is a reason for this one request to be named less distinctly.
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut material).is_err()
        {
            return Self("unnamed".to_owned());
        }

        Self(material.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");

            out
        }))
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Names every request, and puts the name on everything it causes.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityLayer;

impl IdentityLayer {
    /// Builds the layer.
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower_layer::Layer<S> for IdentityLayer {
    type Service = Identified<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Identified { inner }
    }
}

/// A service that runs each request inside a span named after it.
#[derive(Debug, Clone)]
pub struct Identified<S> {
    inner: S,
}

impl<S, B, C> Service<Request<B>> for Identified<S>
where
    S: Service<Request<B>, Response = Response<C>>,
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

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        // Drawn here, whatever the client sent: this is the only name a log line carries.
        let identity = RequestId::generated();
        // What the client called it, kept only to be echoed on the answer.
        let echoed = request
            .headers()
            .get(HEADER)
            .and_then(RequestId::from_client)
            .unwrap_or_else(|| identity.clone());

        // On the request, so a handler that audits can name what it is serving; and in a span, so
        // every record the handler produces carries it without the handler doing anything.
        let span = tracing::info_span!("request", request.id = %identity);
        request.extensions_mut().insert(identity.clone());

        let called = {
            let _entered = span.enter();

            self.inner.call(request)
        };

        Box::pin(async move {
            use tracing::Instrument;

            let mut response = called.instrument(span).await?;

            // Told back to the client: its own name for the request, and the one the logs use, so a
            // report can name the request it is about.
            if let Ok(value) = HeaderValue::from_str(echoed.as_str()) {
                response.headers_mut().insert(HEADER, value);
            }
            if let Ok(value) = HeaderValue::from_str(identity.as_str()) {
                response.headers_mut().insert(LOG_HEADER, value);
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_a_client_may_name_its_own_request() {
        let sent = HeaderValue::from_static("trace-0123456789abcdef");

        assert_eq!(
            RequestId::from_client(&sent).map(|id| id.as_str().to_owned()),
            Some("trace-0123456789abcdef".to_owned())
        );
    }

    #[test]
    fn test_a_name_that_could_forge_a_log_line_is_not_believed() {
        // Every one of these ends up in a log record and a response header if it is taken at face
        // value: a newline forges a second record, a colon and CR split a header, and a very long one
        // pushes whatever follows it out of view.
        for attempt in [
            "has space",
            "has\nnewline",
            "has\rreturn",
            "has\"quote",
            "has=equals",
            "",
        ] {
            let Ok(header) = HeaderValue::from_str(attempt) else {
                // Rejected by the header type before it reaches us, which is also a refusal.
                continue;
            };

            assert!(
                RequestId::from_client(&header).is_none(),
                "`{attempt}` was accepted as a request name"
            );
        }

        let long = "a".repeat(MAXIMUM + 1);
        assert!(
            RequestId::from_client(&HeaderValue::from_str(&long).expect("ascii")).is_none(),
            "a name longer than the limit was accepted"
        );
    }

    /// What the log is given, and what the client is told, for a request it named itself.
    #[tokio::test(flavor = "current_thread")]
    async fn test_a_name_the_client_chose_is_echoed_and_never_logged() {
        use std::sync::{Arc, Mutex};
        use tower_layer::Layer as _;
        use tower_service::Service as _;

        #[derive(Clone, Default)]
        struct Captured(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("not poisoned")
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let logs = Captured::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut service =
            IdentityLayer::new().layer(tower::service_fn(|_request: Request<()>| async {
                tracing::info!("the handler ran");
                Ok::<_, std::convert::Infallible>(Response::new(()))
            }));
        let request = Request::builder()
            .header(HEADER, "tenant-acme-spy")
            .body(())
            .expect("the request builds");
        let response = service.call(request).await.expect("an answer");

        assert_eq!(
            response.headers().get(HEADER).map(HeaderValue::as_bytes),
            Some(&b"tenant-acme-spy"[..]),
            "the client's name is echoed"
        );
        let logged = response
            .headers()
            .get(LOG_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("the logs' name is told")
            .to_owned();
        let written =
            String::from_utf8(logs.0.lock().expect("not poisoned").clone()).expect("text");
        assert!(
            written.contains("the handler ran"),
            "the handler logged: {written}"
        );
        assert!(
            written.contains(&logged),
            "the record carries the drawn name: {written}"
        );
        assert!(
            !written.contains("tenant-acme-spy"),
            "the client's name reached the log: {written}"
        );
    }

    #[test]
    fn test_a_generated_name_is_distinct_and_readable() {
        let first = RequestId::generated();
        let second = RequestId::generated();

        assert_ne!(first, second);
        assert_eq!(first.as_str().len(), 16);
        assert!(first.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        // And it is a value the header type will take back out again.
        assert!(HeaderValue::from_str(first.as_str()).is_ok());
    }
}
