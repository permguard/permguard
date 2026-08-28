// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Re-reading transport material without dropping a connection.
//!
//! # Why this is one test
//!
//! A reload is asked for by SIGHUP, which is a process-wide event with no argument: it acts on every
//! surface in the process. So an assertion about *how many* surfaces were re-read is only meaningful
//! if no other surface exists while it is made — and Rust runs the tests in one binary concurrently.
//!
//! Splitting this into six tests would produce six tests that pass alone and fail together, which is
//! the worst kind. One test, in a binary of its own, tells the whole story in order instead.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use permguard_core::TlsSettings;
use permguard_transport::{Surface, digest, load_certificates, reload_all};

/// An authority that can issue a fresh certificate for the same name, which is what a renewal is.
struct Authority {
    directory: PathBuf,
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
    params: rcgen::CertificateParams,
}

impl Authority {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "permguard-renewal-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("the fixture directory is created");

        let mut params =
            rcgen::CertificateParams::new(Vec::new()).expect("the authority parameters build");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let key = rcgen::KeyPair::generate().expect("the authority key is generated");
        let certificate = params
            .self_signed(&key)
            .expect("the authority signs itself");

        Self {
            directory,
            certificate,
            key,
            params,
        }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.directory.join(name);
        std::fs::write(&path, contents).expect("the fixture is written");

        path
    }

    fn authority_pem(&self) -> PathBuf {
        self.write("ca.pem", &self.certificate.pem())
    }

    /// Issues a certificate for `localhost` and writes it to the paths the listener is watching.
    fn issue_into(&self, certificate_path: &Path, key_path: &Path) {
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("parameters build");
        let key = rcgen::KeyPair::generate().expect("the key is generated");
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let certificate = params
            .signed_by(&key, &issuer)
            .expect("the authority signs it");

        std::fs::write(certificate_path, certificate.pem()).expect("the certificate is written");
        std::fs::write(key_path, key.serialize_pem()).expect("the key is written");
    }
}

fn router() -> Router {
    Router::new().route("/", get(|| async { "served\n" }))
}

fn roots_of(certificate: &Path) -> RootCertStore {
    let mut roots = RootCertStore::empty();

    for certificate in load_certificates(certificate).expect("the certificate reads") {
        roots.add(certificate).expect("the root is added");
    }

    roots
}

/// What the server said, and which certificate it said it with.
struct Answer {
    body: String,
    certificate: String,
}

/// Connects, completes a handshake, and reports both the answer and the certificate behind it.
///
/// The fingerprint is the assertion that matters: a counter saying a reload happened proves nothing
/// about what the listener is now serving.
async fn speak_tls(address: SocketAddr, authority: &Path) -> Result<Answer, String> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(authority))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let name = ServerName::try_from("localhost").map_err(|error| error.to_string())?;

    let mut stream = connector
        .connect(name, stream)
        .await
        .map_err(|error| error.to_string())?;

    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| digest(leaf.as_ref()))
        .ok_or_else(|| "the server presented no certificate".to_owned())?;

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| error.to_string())?;

    let mut said = Vec::new();
    stream
        .read_to_end(&mut said)
        .await
        .map_err(|error| error.to_string())?;

    Ok(Answer {
        body: String::from_utf8_lossy(&said).into_owned(),
        certificate,
    })
}

#[tokio::test]
async fn test_the_life_of_a_renewal() {
    let authority = Authority::new("story");
    let authority_pem = authority.authority_pem();
    let certificate = authority.directory.join("server.pem");
    let key = authority.directory.join("server.key");
    authority.issue_into(&certificate, &key);

    let settings = TlsSettings::new(&certificate, &key);
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    // 1. It serves what it was given.
    let first = speak_tls(address, &authority_pem)
        .await
        .expect("the original certificate serves");
    assert!(first.body.contains("served"), "{}", first.body);

    // 2. The renewal: a new certificate for the same name, written over the same paths, which is
    //    what certbot, cert-manager and every other renewal does.
    authority.issue_into(&certificate, &key);

    let reloaded = reload_all();
    assert_eq!(reloaded.reloaded, 1, "the live surface was not re-read");
    assert_eq!(reloaded.failed, 0);

    // 3. It is now serving something different — which is the claim, and the only one worth making.
    let renewed = speak_tls(address, &authority_pem)
        .await
        .expect("the renewed certificate serves");
    assert!(renewed.body.contains("served"), "{}", renewed.body);
    assert_ne!(
        renewed.certificate, first.certificate,
        "the reload was reported as done but the listener is serving the old certificate"
    );

    // 4. A renewal caught half-written: the material will not build.
    std::fs::write(&certificate, "-----BEGIN CERTIFICATE-----\ntrunca")
        .expect("the certificate is damaged");

    let broken = reload_all();
    assert_eq!(broken.failed, 1, "a broken reload was reported as done");
    assert_eq!(broken.reloaded, 0);

    // 5. And nothing happened to the service. A failed reload is a warning, never an outage.
    let after = speak_tls(address, &authority_pem)
        .await
        .expect("the listener kept the material it already had");
    assert!(after.body.contains("served"), "{}", after.body);
    assert_eq!(
        after.certificate, renewed.certificate,
        "a failed reload changed what is being served"
    );

    // 6. A surface that has stopped leaves the set that SIGHUP walks, so the damaged material above
    //    is not reported again for the rest of the process's life.
    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");

    let afterwards = reload_all();
    assert_eq!(afterwards.reloaded, 0);
    assert_eq!(
        afterwards.failed, 0,
        "a stopped surface is still being asked to reload"
    );
}
