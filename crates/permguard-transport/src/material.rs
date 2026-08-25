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

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use permguard_core::{TlsSettings, TlsVersion};

use crate::digest::digest;

/// Builds the TLS configuration a listener serves with.
pub fn server_config(settings: &TlsSettings) -> Result<Arc<ServerConfig>> {
    Ok(build(settings)?.0)
}

/// Builds the configuration and says which certificate it ended up with.
///
/// The fingerprint is what makes a reload verifiable: a log record saying material was re-read, with
/// no way to tell whether it is the same material, is a record that answers nothing.
pub(crate) fn build(settings: &TlsSettings) -> Result<(Arc<ServerConfig>, String)> {
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

    let builder = ServerConfig::builder_with_protocol_versions(versions);

    let mut config = match settings.client_ca() {
        Some(client_ca) => {
            let mut roots = RootCertStore::empty();
            for certificate in load_certificates(client_ca)? {
                roots.add(certificate).with_context(|| {
                    format!("adding {} to the client authorities", client_ca.display())
                })?;
            }

            let mut verifier = WebPkiClientVerifier::builder(Arc::new(roots));

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

            let verifier = verifier.build().with_context(|| {
                format!("building the client verifier from {}", client_ca.display())
            })?;

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

    Ok((Arc::new(config), leaf))
}

/// Reads a PEM file of certificates.
///
/// Public because a build that verifies a peer, or a test that acts as a client, needs the same
/// reader the listener uses — and two readers of the same format eventually disagree.
pub fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certificates: Vec<_> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("opening {}", path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))?;

    if certificates.is_empty() {
        bail!("{} contains no certificate", path.display());
    }

    Ok(certificates)
}

/// Reads a PEM private key, in whichever of the three encodings it was written.
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("reading a private key from {}", path.display()))
}

/// Reads a PEM file of certificate revocation lists.
///
/// A file with no list in it is refused rather than treated as "nothing is revoked". The two look
/// identical to a listener and mean opposite things to an operator, and the one that silently
/// accepts every revoked certificate is not the one to guess.
pub fn load_revocations(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let revocations: Vec<_> = CertificateRevocationListDer::pem_file_iter(path)
        .with_context(|| format!("opening {}", path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("reading revocation lists from {}", path.display()))?;

    if revocations.is_empty() {
        bail!(
            "{} contains no revocation list: an empty file and a file that revokes nothing are \
             indistinguishable here, and only one of them is safe to assume",
            path.display()
        );
    }

    Ok(revocations)
}
