// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reading transport material off the disk, and building a listener configuration out of it.
//!
//! # What revocation is checked against
//!
//! The **client certificate**, and not the authority above it. Revoking an authority is not something
//! a list expresses usefully — it is done by taking the authority out of the bundle this listener
//! trusts, which is a configuration change and takes effect on the next reload. Checking the whole
//! chain instead would mean every issuer in it needs a published, current list, and the failure when
//! one is missing is that every client is refused. That is a worse failure than the one it prevents.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{RootCertStore, ServerConfig};

use permguard_core::{TlsSettings, TlsVersion};

use crate::digest::digest;
pub use permguard_tls::{load_certificates, load_key, load_revocations};

/// Builds the TLS configuration a listener serves with.
pub fn server_config(settings: &TlsSettings) -> Result<Arc<ServerConfig>> {
    Ok(build(settings)?.config)
}

/// A listener's configuration, the certificate it serves, and the verifier its clients meet.
pub(crate) struct Built {
    pub(crate) config: Arc<ServerConfig>,
    /// The fingerprint of the certificate served.
    pub(crate) fingerprint: String,
    /// What a client certificate is verified with, revocation list included; `None` without
    /// `client_ca`. A reload re-verifies the connections already open with it (BUG-0101).
    pub(crate) verifier: Option<Arc<dyn ClientCertVerifier>>,
}

/// Builds the configuration and says which certificate it ended up with.
///
/// The fingerprint is what makes a reload verifiable: a log record saying material was re-read, with
/// no way to tell whether it is the same material, is a record that answers nothing.
pub(crate) fn build(settings: &TlsSettings) -> Result<Built> {
    // rustls asks for a process-wide provider; installing it more than once is not an error worth
    // reporting, because the second caller wanted exactly what the first one installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certificates = load_certificates(settings.certificate())?;
    let key = load_key(settings.key())?;

    let leaf = certificates
        .first()
        .map(|certificate| digest(certificate.as_ref()))
        .unwrap_or_default();

    let versions: &[&'static rustls::SupportedProtocolVersion] = match settings.min_version() {
        TlsVersion::V1_2 => &[&rustls::version::TLS12, &rustls::version::TLS13],
        TlsVersion::V1_3 => &[&rustls::version::TLS13],
    };

    let builder = ServerConfig::builder_with_provider(permguard_tls::provider())
        .with_protocol_versions(versions)
        .context("the pinned algorithm policy refuses these TLS versions")?;

    let mut client_verifier = None;
    let mut config = match settings.client_ca() {
        Some(client_ca) => {
            let mut roots = RootCertStore::empty();
            for certificate in load_certificates(client_ca)? {
                roots.add(certificate).with_context(|| {
                    format!("adding {} to the client authorities", client_ca.display())
                })?;
            }

            let mut verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                permguard_tls::provider(),
            );

            if let Some(path) = settings.crl() {
                let revoked = load_revocations(path)?;

                // See the crate documentation: the client certificate is checked, the authority
                // above it is trusted by configuration rather than by a list.
                //
                // Expiry is enforced, and that is a deliberate fail-closed: a list past its
                // `nextUpdate` is revocation data nobody is maintaining, and trusting it forever is
                // how a revoked client stays admitted for months. rustls's default is to ignore
                // expiry; with enforcement, an expired list refuses handshakes — loud, immediate,
                // and pointing at the renewal process that died. The CRL expiry gauge and its alert
                // exist so that moment is predicted instead of discovered.
                verifier = verifier
                    .with_crls(revoked)
                    .only_check_end_entity_revocation()
                    .enforce_revocation_expiration();
            }

            // A connection without a certificate reaches the application, where only a bearer
            // token authenticates it (WP-8.1); one presented is verified all the same.
            if settings.client_auth() == permguard_core::ClientAuth::Optional {
                verifier = verifier.allow_unauthenticated();
            }

            let verifier = verifier.build().with_context(|| {
                format!("building the client verifier from {}", client_ca.display())
            })?;
            client_verifier = Some(Arc::clone(&verifier));

            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificates, key)
        }
        None => builder
            .with_no_client_auth()
            .with_single_cert(certificates, key),
    }
    .with_context(|| {
        format!(
            "using the certificate {} with the key {}",
            settings.certificate().display(),
            settings.key().display()
        )
    })?;

    // Without this a client speaking HTTP/2 — which every gRPC client does — cannot negotiate it.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Built {
        config: Arc::new(config),
        fingerprint: leaf,
        verifier: client_verifier,
    })
}
