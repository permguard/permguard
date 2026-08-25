// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The client side of TLS: who we trust, and who we say we are.
//!
//! # One-way and mutual are the same handshake
//!
//! A TLS endpoint always authenticates itself to us, and we check it against a trust anchor — the
//! platform's store, or an authority given by name with `--tls-ca-file`, which is what a private
//! certificate authority needs. Mutual TLS adds one thing: a certificate and key of *our own*, sent
//! when the server asks for one. That is why there is no `mtls` mode here. There is material or
//! there is not, and the server decides whether it needs it.
//!
//! # Skipping verification
//!
//! `--tls-skip-verify` turns off the check that the endpoint is who it says it is, which leaves
//! encryption with no authentication — the connection is private with *somebody*. It exists because
//! a development runtime with a self-signed certificate is a real situation, and it says so on
//! stderr every time it is used, because the failure it hides is exactly the one worth seeing.
//!
//! When the certificate is fine but the *name* does not match — an endpoint reached by IP address,
//! whose certificate names a host — `--tls-server-name` is the answer, and it keeps verification on.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// What the operator supplied for reaching TLS endpoints.
#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    /// The authority the endpoint's certificate is checked against, instead of the platform store.
    pub ca_file: Option<PathBuf>,
    /// Our own certificate, for a server that asks for one.
    pub cert_file: Option<PathBuf>,
    /// The key belonging to that certificate.
    pub key_file: Option<PathBuf>,
    /// The name to check the endpoint's certificate against, when it is not the endpoint's host.
    pub server_name: Option<String>,
    /// Whether to accept any certificate at all.
    pub skip_verify: bool,
}

impl TlsOptions {
    /// Resolves every path against the working directory.
    ///
    /// A relative path in a runbook means "next to the runbook", and `--workdir` is what says where
    /// that is. An absolute path is left alone.
    pub fn rooted_at(mut self, workdir: &Path) -> Self {
        for path in [&mut self.ca_file, &mut self.cert_file, &mut self.key_file] {
            if let Some(value) = path.as_ref().filter(|value| value.is_relative()) {
                *path = Some(workdir.join(value));
            }
        }

        self
    }

    /// Whether the operator supplied a client identity.
    pub fn is_mutual(&self) -> bool {
        self.cert_file.is_some() || self.key_file.is_some()
    }

    /// The name an endpoint's certificate is checked against.
    pub fn name_for<'a>(&'a self, host: &'a str) -> &'a str {
        self.server_name.as_deref().unwrap_or(host)
    }

    /// Builds the configuration a TLS connection is made with.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, Error> {
        // The provider is passed in rather than installed process-wide: a CLI has one job and then
        // exits, and process-global state that has to be installed before first use is a footgun in
        // a library that a later command might link.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|error| Error::Config {
                detail: error.to_string(),
            })?;

        let builder = if self.skip_verify {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServer { provider }))
        } else {
            builder.with_root_certificates(self.roots()?)
        };

        let config = match (self.cert_file.as_deref(), self.key_file.as_deref()) {
            (Some(certificate), Some(key)) => builder
                .with_client_auth_cert(load_certificates(certificate)?, load_key(key)?)
                .map_err(|error| Error::ClientAuth {
                    detail: error.to_string(),
                })?,
            (None, None) => builder.with_no_client_auth(),
            // Half a client identity is not a posture, it is a typo, and the handshake it produces
            // fails with a message from the server about a certificate the operator thinks they sent.
            (Some(_), None) => return Err(Error::Incomplete { missing: "key" }),
            (None, Some(_)) => {
                return Err(Error::Incomplete {
                    missing: "certificate",
                });
            }
        };

        Ok(Arc::new(config))
    }

    /// The trust anchors an endpoint's certificate is checked against.
    fn roots(&self) -> Result<RootCertStore, Error> {
        let mut roots = RootCertStore::empty();

        if let Some(path) = self.ca_file.as_deref() {
            for certificate in load_certificates(path)? {
                roots.add(certificate).map_err(|error| Error::Material {
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                })?;
            }

            return Ok(roots);
        }

        // No authority named, so the platform's store — which is what a certificate from a public
        // authority is checked against, and the only sane default for a client.
        let native = rustls_native_certs::load_native_certs();

        for certificate in native.certs {
            let _ = roots.add(certificate);
        }

        if roots.is_empty() {
            return Err(Error::NoRoots {
                detail: native
                    .errors
                    .first()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "the platform store holds no certificates".to_owned()),
            });
        }

        Ok(roots)
    }
}

/// The name to present and check, as rustls wants it.
pub fn server_name(name: &str) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(name.to_owned()).map_err(|_| Error::ServerName {
        name: name.to_owned(),
    })
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certificates: Vec<_> = CertificateDer::pem_file_iter(path)
        .map_err(|error| Error::Material {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?
        .collect::<Result<_, _>>()
        .map_err(|error| Error::Material {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;

    if certificates.is_empty() {
        return Err(Error::Material {
            path: path.to_path_buf(),
            detail: "it holds no certificate".to_owned(),
        });
    }

    Ok(certificates)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| Error::Material {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

/// A verifier that checks nothing, for `--tls-skip-verify`.
///
/// Signature verification is still real — it has to be, or the handshake cannot complete. What is
/// dropped is the question of whose certificate it is.
#[derive(Debug)]
struct AcceptAnyServer {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Every way the client side of TLS can be misconfigured.
#[derive(Debug)]
pub enum Error {
    Material { path: PathBuf, detail: String },
    NoRoots { detail: String },
    ClientAuth { detail: String },
    Incomplete { missing: &'static str },
    ServerName { name: String },
    Config { detail: String },
}

impl Error {
    /// The stable code for this failure.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Material { .. } => "tls_material_unreadable",
            Self::NoRoots { .. } => "tls_no_trust_anchors",
            Self::ClientAuth { .. } => "tls_client_identity_rejected",
            Self::Incomplete { .. } => "tls_client_identity_incomplete",
            Self::ServerName { .. } => "tls_server_name_invalid",
            Self::Config { .. } => "tls_unsupported",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Material { path, detail } => {
                write!(f, "reading {}: {detail}", path.display())
            }
            Self::NoRoots { detail } => write!(
                f,
                "no certificate authority to check the endpoint against: {detail}. Pass --tls-ca-file"
            ),
            Self::ClientAuth { detail } => {
                write!(f, "the client certificate and key were refused: {detail}")
            }
            Self::Incomplete { missing } => write!(
                f,
                "a client identity needs both a certificate and a key, and the {missing} is missing"
            ),
            Self::ServerName { name } => {
                write!(
                    f,
                    "`{name}` is not a name a certificate can be checked against"
                )
            }
            Self::Config { detail } => write!(f, "building the TLS configuration: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permguard-cli-tls-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    /// Self-signed material, enough for the loading paths — the handshake
    /// itself belongs to the transport tests.
    fn write_material(dir: &Path) -> (PathBuf, PathBuf) {
        let key = rcgen::KeyPair::generate().expect("a key generates");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .expect("params build")
            .self_signed(&key)
            .expect("the certificate signs");
        let cert_path = dir.join("client.pem");
        let key_path = dir.join("client.key");
        std::fs::write(&cert_path, cert.pem()).expect("the certificate writes");
        std::fs::write(&key_path, key.serialize_pem()).expect("the key writes");
        (cert_path, key_path)
    }

    #[test]
    fn relative_paths_root_at_the_workdir_and_absolute_ones_stay() {
        let rooted = TlsOptions {
            ca_file: Some(PathBuf::from("ca.pem")),
            cert_file: Some(PathBuf::from("/abs/client.pem")),
            ..Default::default()
        }
        .rooted_at(Path::new("/work"));

        assert_eq!(rooted.ca_file.expect("kept"), PathBuf::from("/work/ca.pem"));
        assert_eq!(
            rooted.cert_file.expect("kept"),
            PathBuf::from("/abs/client.pem")
        );
    }

    #[test]
    fn any_half_of_an_identity_counts_as_mutual_so_the_pairing_check_fires() {
        assert!(!TlsOptions::default().is_mutual());
        // Even half an identity flags mutual: the loading path is where the
        // missing half becomes an explicit error rather than a silent one-way.
        assert!(
            TlsOptions {
                cert_file: Some("c.pem".into()),
                ..Default::default()
            }
            .is_mutual()
        );
    }

    #[test]
    fn the_server_name_override_wins_over_the_host() {
        let options = TlsOptions {
            server_name: Some("control.internal".into()),
            ..Default::default()
        };
        assert_eq!(options.name_for("10.0.0.9"), "control.internal");
        assert_eq!(TlsOptions::default().name_for("10.0.0.9"), "10.0.0.9");
    }

    #[test]
    fn a_config_builds_from_real_material() {
        let dir = scratch();
        let (cert, key) = write_material(&dir);

        // A private CA plus a client identity: the mutual-TLS shape.
        let config = TlsOptions {
            ca_file: Some(cert.clone()),
            cert_file: Some(cert),
            key_file: Some(key),
            ..Default::default()
        }
        .client_config();
        assert!(config.is_ok(), "{config:?}");

        // Verification off still builds — and is a choice the caller made.
        let config = TlsOptions {
            skip_verify: true,
            ..Default::default()
        }
        .client_config();
        assert!(config.is_ok(), "{config:?}");
    }

    #[test]
    fn missing_or_broken_material_is_refused_with_the_path() {
        let dir = scratch();

        let missing = TlsOptions {
            ca_file: Some(dir.join("nope.pem")),
            ..Default::default()
        }
        .client_config();
        assert!(missing.is_err());

        std::fs::write(dir.join("garbage.pem"), "not pem").expect("writes");
        let garbage = TlsOptions {
            ca_file: Some(dir.join("garbage.pem")),
            ..Default::default()
        }
        .client_config();
        assert!(garbage.is_err());

        // A certificate whose key is missing: half an identity is none.
        let (cert, _) = write_material(&dir);
        let half = TlsOptions {
            cert_file: Some(cert),
            key_file: Some(dir.join("nope.key")),
            ..Default::default()
        }
        .client_config();
        assert!(half.is_err());
    }

    #[test]
    fn server_names_parse_or_refuse() {
        assert!(server_name("control.example.com").is_ok());
        assert!(server_name("127.0.0.1").is_ok());
        assert!(server_name("").is_err());
    }
}
