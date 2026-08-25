// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What every surface counts about itself.
//!
//! Declared and recorded here rather than by each surface, for the same reason the limits are applied
//! here: a surface that has to remember to instrument itself is a surface that will be added one day
//! without it, and the gap will be found during the incident it would have explained.
//!
//! # The label that could have been the attack
//!
//! A request method is a token the client writes. HTTP allows extension methods, so `method` is a
//! label whose values come from outside — and a label like that turns every request into a series
//! that lives until the process exits. [`method_of`] maps anything outside the standard set to
//! `other`, which bounds it at nine values whatever a client sends.
//!
//! The path is deliberately **not** a label. It is the most useful label there is and the most
//! dangerous: a router with a wildcard turns every distinct URL into a series, and a client that can
//! ask for `/a`, `/b`, `/c`… controls how much memory the registry holds.

use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::{Request, Response};
use rustls::pki_types::CertificateDer;
use tower_service::Service;
use x509_parser::prelude::{FromDer, X509Certificate};

use permguard_core::metrics::{Metric, SECONDS};
use permguard_core::{Metrics, TlsSettings};

/// How many requests each surface has answered, and how they ended.
pub const REQUESTS: Metric = Metric::counter(
    "permguard_surface_requests_total",
    "Requests answered, by surface, method and status.",
);

/// How long they took.
///
/// The one number that answers "is it slow" — and the one an average cannot give, because the mean of
/// a hundred fast requests and one that took a minute is a fast request.
pub const LATENCY: Metric = Metric::histogram(
    "permguard_surface_request_seconds",
    "How long requests took, by surface and method.",
    SECONDS,
);

/// How many connections a surface is holding right now.
///
/// Watch it against the configured ceiling: a surface sitting at its limit is refusing clients, and it
/// was doing so before anybody noticed.
pub const CONNECTIONS: Metric = Metric::gauge(
    "permguard_surface_connections",
    "Connections currently held, by surface.",
);

/// How many connections have been accepted.
pub const ACCEPTED: Metric = Metric::counter(
    "permguard_surface_connections_accepted_total",
    "Connections accepted, by surface.",
);

/// How many were turned away because the surface was already at its limit.
///
/// Any value above zero is worth an alert: it is the first thing that happens under a connection
/// flood, and it happens long before the process shows any other sign.
pub const REFUSED: Metric = Metric::counter(
    "permguard_surface_connections_refused_total",
    "Connections refused because the surface was at its limit, by surface.",
);

/// When the certificate a surface presents stops being valid, as a Unix timestamp.
///
/// A timestamp rather than "days remaining", and the reason is what this registry is: a value written
/// when the certificate was loaded and read whenever somebody scrapes. "Days remaining" would be
/// correct at the moment it was written and quietly wrong for every scrape after — a certificate with
/// two days left would still be reporting thirty a month later. A timestamp is true whenever it is
/// read, and the subtraction happens in the query:
///
/// ```promql
/// (permguard_tls_certificate_expiry_timestamp_seconds - time()) / 86400 < 30
/// ```
pub const CERTIFICATE_EXPIRY: Metric = Metric::gauge(
    "permguard_tls_certificate_expiry_timestamp_seconds",
    "When the certificate a surface presents stops being valid, in seconds since the epoch.",
);

/// When the revocation list a surface checks clients against stops being usable.
///
/// Expiry is enforced — an expired list refuses every mutual-TLS handshake — so this is the number
/// that turns that moment from a discovery into a prediction:
///
/// ```promql
/// (permguard_tls_crl_expiry_timestamp_seconds - time()) / 86400 < 7
/// ```
pub const CRL_EXPIRY: Metric = Metric::gauge(
    "permguard_tls_crl_expiry_timestamp_seconds",
    "When the revocation list stops being usable, in seconds since the epoch.",
);

/// How close to expiry a certificate has to be before starting is worth a warning.
///
/// Thirty days is roughly what a renewal process needs to have gone wrong for: a 90-day certificate
/// renews at 60, and anything past 30 means two renewal windows were missed.
const NOTICE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Records when the certificate `settings` names stops being valid, and says so if that is soon.
///
/// Called when a surface starts and again every time material is reloaded, which is what makes the
/// number follow a renewal rather than describe the certificate this process happened to start with.
///
/// Anything unreadable here is reported and dropped. This is a measurement: a listener that is
/// serving correctly must not be brought down because the thing watching it could not parse a date.
pub fn record_certificate_expiry(surface: &'static str, metrics: &Metrics, settings: &TlsSettings) {
    let path = settings.certificate();

    let expiry = match crate::material::load_certificates(path).map(|chain| expiry_of(&chain)) {
        Ok(Some(expiry)) => expiry,
        Ok(None) => {
            tracing::warn!(
                event.name = "transport.certificate_unreadable",
                component = "transport",
                surface = surface,
                path = %path.display(),
                "the certificate this surface presents has no expiry this build could read"
            );

            return;
        }
        Err(error) => {
            tracing::warn!(
                event.name = "transport.certificate_unreadable",
                component = "transport",
                surface = surface,
                path = %path.display(),
                error = %error,
                "the certificate this surface presents could not be read back to check its expiry"
            );

            return;
        }
    };

    metrics.set(&CERTIFICATE_EXPIRY, &[("surface", surface)], expiry as f64);

    record_crl_expiry(surface, metrics, settings);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();
    let remaining = expiry - now;

    if remaining <= 0 {
        tracing::error!(
            event.name = "transport.certificate_expired",
            component = "transport",
            surface = surface,
            expired_days_ago = -remaining / 86_400,
            "this surface is presenting a certificate that has already expired"
        );
    } else if remaining < NOTICE.as_secs() as i64 {
        tracing::warn!(
            event.name = "transport.certificate_expiring",
            component = "transport",
            surface = surface,
            days_remaining = remaining / 86_400,
            "the certificate this surface presents expires soon"
        );
    }
}

/// Reads when the leaf of `chain` stops being valid, as a Unix timestamp.
///
/// The leaf, which is the first: it is the one this surface presents and therefore the one that ends
/// the handshake when it expires. An authority further up the chain outliving it is the normal case
/// and not the one worth watching.
/// Records when the revocation list stops being usable, when this surface checks one.
///
/// Expiry is enforced at the handshake, so this number is the difference between "the renewal
/// process died and we found out when every client was refused" and "the renewal process died and
/// an alert said so a week early".
fn record_crl_expiry(surface: &'static str, metrics: &Metrics, settings: &TlsSettings) {
    let Some(path) = settings.crl() else {
        return;
    };
    let expiry = crate::material::load_revocations(path)
        .ok()
        .and_then(|lists| {
            lists
                .iter()
                .filter_map(|der| {
                    let (_, parsed) =
                        x509_parser::revocation_list::CertificateRevocationList::from_der(
                            der.as_ref(),
                        )
                        .ok()?;

                    parsed.next_update().map(|at| at.timestamp())
                })
                // Several lists in one bundle: the first to expire is the one that starts refusing.
                .min()
        });
    let Some(expiry) = expiry else {
        tracing::warn!(
            event.name = "transport.crl_unreadable",
            component = "transport",
            surface = surface,
            path = %path.display(),
            "the revocation list has no next-update this build could read: its expiry cannot be watched"
        );

        return;
    };

    metrics.set(&CRL_EXPIRY, &[("surface", surface)], expiry as f64);
}

fn expiry_of(chain: &[CertificateDer<'_>]) -> Option<i64> {
    let leaf = chain.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;

    Some(parsed.validity().not_after.timestamp())
}

/// Reduces a request method to one of a fixed set.
///
/// The set is the standard methods plus `other`. A client may send any token it likes; what it may not
/// do is decide how many series this process holds.
pub fn method_of<B>(request: &Request<B>) -> &'static str {
    match *request.method() {
        http::Method::GET => "GET",
        http::Method::POST => "POST",
        http::Method::PUT => "PUT",
        http::Method::DELETE => "DELETE",
        http::Method::HEAD => "HEAD",
        http::Method::OPTIONS => "OPTIONS",
        http::Method::PATCH => "PATCH",
        http::Method::TRACE => "TRACE",
        _ => "other",
    }
}

/// Times every request and records how it ended.
#[derive(Debug, Clone)]
pub struct MeasureLayer {
    surface: &'static str,
    metrics: Metrics,
}

impl MeasureLayer {
    /// Measures requests to the surface called `surface`, into `metrics`.
    pub fn new(surface: &'static str, metrics: Metrics) -> Self {
        Self { surface, metrics }
    }
}

impl<S> tower_layer::Layer<S> for MeasureLayer {
    type Service = Measured<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Measured {
            inner,
            surface: self.surface,
            metrics: self.metrics.clone(),
        }
    }
}

/// A service that records what each request cost and how it ended.
#[derive(Debug, Clone)]
pub struct Measured<S> {
    inner: S,
    surface: &'static str,
    metrics: Metrics,
}

impl<S, B, C> Service<Request<B>> for Measured<S>
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

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let surface = self.surface;
        let metrics = self.metrics.clone();
        let method = method_of(&request);

        // Started before the inner service, so the measurement covers everything below this layer —
        // including the wait for a concurrency slot, which is exactly the time a client feels and the
        // time a handler-only measurement hides.
        let started = Instant::now();
        let called = self.inner.call(request);

        Box::pin(async move {
            let answered = called.await?;
            let elapsed = started.elapsed().as_secs_f64();

            metrics.observe(
                &LATENCY,
                &[("surface", surface), ("method", method)],
                elapsed,
            );
            metrics.count(
                &REQUESTS,
                &[
                    ("surface", surface),
                    ("method", method),
                    ("status", answered.status().as_str()),
                ],
            );

            Ok(answered)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_a_method_a_client_invented_is_not_a_series_of_its_own() {
        // The attack: `FOO1 / HTTP/1.1`, `FOO2 / HTTP/1.1`, … every one a label value, every one a
        // series held until the process exits.
        let invented = Request::builder()
            .method(http::Method::from_bytes(b"WHATEVER").expect("a valid token"))
            .uri("/")
            .body(())
            .expect("the request builds");

        assert_eq!(method_of(&invented), "other");
    }

    #[test]
    fn test_the_methods_that_are_actually_used_keep_their_names() {
        for method in [http::Method::GET, http::Method::POST, http::Method::DELETE] {
            let request = Request::builder()
                .method(method.clone())
                .uri("/")
                .body(())
                .expect("the request builds");

            assert_eq!(method_of(&request), method.as_str());
        }
    }

    #[test]
    fn test_the_declarations_say_what_they_are() {
        // A counter named without `_total`, or a duration without `_seconds`, is one every dashboard
        // and every alerting rule has to special-case.
        assert!(REQUESTS.name().ends_with("_total"));
        assert!(ACCEPTED.name().ends_with("_total"));
        assert!(REFUSED.name().ends_with("_total"));
        assert!(LATENCY.name().ends_with("_seconds"));
        assert!(!CONNECTIONS.name().ends_with("_total"));
    }
}
