// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Carrying who the client is from the handshake to the handler.
//!
//! `rustls` finishes a mutual handshake knowing exactly which certificate the client presented, and
//! then the connection becomes a stream of requests that know nothing about it. This is the piece
//! that keeps the answer: an acceptor that reads the peer certificate once per connection and hands
//! every request on that connection an [`Arc<PeerIdentity>`] extension.
//!
//! # Once per connection, not once per request
//!
//! Parsing a certificate costs something, and a connection presents the same one for its whole life
//! — a gRPC channel may carry thousands of calls. Doing it in the acceptor rather than in a
//! middleware is what makes the cost proportional to connections rather than to traffic.
//!
//! # What a missing identity means
//!
//! No extension at all, which is different from an empty one. A surface without mutual TLS never
//! sees this type, and a surface with it can treat absence as "unauthenticated" without wondering
//! whether it merely failed to parse — because a client whose certificate does not parse never
//! completes the handshake in the first place.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use x509_parser::prelude::{FromDer, X509Certificate};

use permguard_core::PeerIdentity;

/// Terminates TLS and remembers who was on the other end.
#[derive(Clone)]
pub struct PeerAcceptor {
    inner: RustlsAcceptor,
}

impl PeerAcceptor {
    /// Wraps the acceptor that does the handshake.
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for PeerAcceptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PeerAcceptor").finish()
    }
}

impl<I, S> Accept<I, S> for PeerAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = WithPeer<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake = self.inner.accept(stream, service);

        Box::pin(async move {
            let (stream, service) = handshake.await?;

            // `peer_certificates` is populated only when the verifier demanded one, so a surface
            // without mutual TLS produces no identity and pays for no parsing.
            let identity = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(<[CertificateDer<'_>]>::first)
                .and_then(identity_of)
                .map(Arc::new);

            Ok((
                stream,
                WithPeer {
                    inner: service,
                    identity,
                },
            ))
        })
    }
}

/// A service that hands every request the identity of the connection it arrived on.
#[derive(Clone)]
pub struct WithPeer<S> {
    inner: S,
    identity: Option<Arc<PeerIdentity>>,
}

impl<S, B> tower_service::Service<http::Request<B>> for WithPeer<S>
where
    S: tower_service::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if let Some(identity) = &self.identity {
            request.extensions_mut().insert(Arc::clone(identity));
        }

        self.inner.call(request)
    }
}

/// Reads what a certificate asserts about its holder.
///
/// Returns nothing when the certificate cannot be parsed, which in practice cannot happen here: a
/// certificate that reached this point was already parsed and verified by the handshake. It is
/// expressed as an option anyway, because "we could not tell who this is" must never be expressible
/// as an identity that happens to be empty.
pub fn identity_of(certificate: &CertificateDer<'_>) -> Option<PeerIdentity> {
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref()).ok()?;

    let common_name = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attribute| attribute.as_str().ok())
        .map(str::to_owned);

    Some(PeerIdentity::new(
        parsed.subject().to_string(),
        common_name,
        fingerprint(certificate),
        crate::digest::hex(parsed.raw_serial()),
    ))
}

/// Returns the SHA-256 of a certificate, lowercase hex — the value every other tool prints.
///
/// One line, because the digest itself lives in [`crate::digest`]: an allowlist entry, a reload
/// record and an audit chain all have to agree on what "the fingerprint of these bytes" is, and two
/// implementations of it eventually do not.
pub fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    crate::digest::digest(certificate.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something_that_is_not_a_certificate_yields_no_identity() {
        let nonsense = CertificateDer::from(vec![0_u8; 16]);

        assert!(identity_of(&nonsense).is_none());
    }

    #[test]
    fn test_a_fingerprint_is_a_sha256() {
        let certificate = CertificateDer::from(b"not really a certificate".to_vec());

        // 32 bytes, two characters each — and the value every other tool prints for these bytes.
        assert_eq!(fingerprint(&certificate).len(), 64);
    }
}
