// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reading TLS material off the disk: one reader for a listener, a peer client and a test that
//! acts as either, since two readers of the same format eventually disagree.

use std::path::Path;

use anyhow::{Context, Result, bail};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

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
