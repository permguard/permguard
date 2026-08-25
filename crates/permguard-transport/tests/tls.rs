// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a listener does with certificates, driven from outside the crate.
//!
//! Here rather than beside the code because the interesting cases need a certificate authority, a
//! server certificate, a client certificate and a real handshake — that is a fixture, not a unit
//! test, and burying it in `lib.rs` makes the module twice as long as the thing it describes.
//!
//! The short checks that fit in three lines stayed inline. This is the other kind.

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use permguard_core::{TlsSettings, TlsVersion};
use permguard_transport::{Surface, load_certificates, load_key, server_config};

/// A little certificate authority, and the certificates it signed.
///
/// Generated per test rather than checked in: a committed test certificate is a certificate that
/// expires one day and fails a build nobody changed.
struct Pki {
    directory: std::path::PathBuf,
    authority: rcgen::Certificate,
    authority_key: rcgen::KeyPair,
    authority_params: rcgen::CertificateParams,
}

impl Pki {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!("permguard-tls-{name}"));
        std::fs::create_dir_all(&directory).expect("creating the fixture directory");

        let mut params =
            rcgen::CertificateParams::new(Vec::new()).expect("the authority parameters build");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let authority_key = rcgen::KeyPair::generate().expect("the authority key is generated");
        let authority = params
            .self_signed(&authority_key)
            .expect("the authority signs itself");
        let params = params.clone();

        Self {
            directory,
            authority,
            authority_key,
            authority_params: params,
        }
    }

    fn write(&self, name: &str, contents: &str) -> std::path::PathBuf {
        let path = self.directory.join(name);
        let mut file = std::fs::File::create(&path).expect("writing the fixture");
        file.write_all(contents.as_bytes())
            .expect("writing the fixture");

        path
    }

    /// Writes the authority certificate, which is what a verifier is built from.
    fn authority_pem(&self) -> std::path::PathBuf {
        self.write("ca.pem", &self.authority.pem())
    }

    /// Issues a certificate for `name`, signed by this authority.
    fn issue(&self, stem: &str, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let params =
            rcgen::CertificateParams::new(vec![name.to_owned()]).expect("parameters build");
        let key = rcgen::KeyPair::generate().expect("the key is generated");
        let issuer = rcgen::Issuer::from_params(&self.authority_params, &self.authority_key);
        let certificate = params
            .signed_by(&key, &issuer)
            .expect("the authority signs it");

        (
            self.write(&format!("{stem}.pem"), &certificate.pem()),
            self.write(&format!("{stem}.key"), &key.serialize_pem()),
        )
    }
}

/// Issues a self-signed certificate for `localhost` and writes it out.
fn self_signed(pki: &Pki, stem: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("the certificate is issued");

    (
        pki.write(&format!("{stem}.pem"), &issued.cert.pem()),
        pki.write(&format!("{stem}.key"), &issued.signing_key.serialize_pem()),
    )
}

fn router() -> Router {
    Router::new().route("/", get(|| async { "served\n" }))
}

#[tokio::test]
async fn test_a_plain_listener_binds_serves_and_reports_the_port_it_got() {
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .start()
        .await
        .expect("the listener binds");

    assert_ne!(
        surface.address().port(),
        0,
        "port zero resolves to a real one"
    );

    let address = surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
    assert_ne!(address.port(), 0);
}

#[tokio::test]
async fn test_a_port_already_taken_is_a_failure_to_start() {
    let taken = Surface::listener("test", "127.0.0.1:0", router())
        .start()
        .await
        .expect("the first listener binds");
    let address = taken.address().to_string();

    let error = Surface::listener("test", &address, router())
        .start()
        .await
        .expect_err("the port is taken");

    assert!(format!("{error:#}").contains(&address));
    taken
        .stop(Duration::from_secs(5))
        .await
        .expect("the first listener stops");
}

#[tokio::test]
async fn test_an_unreadable_address_never_reaches_the_socket() {
    let error = Surface::listener("test", "not-an-address", router())
        .start()
        .await
        .expect_err("the address is unreadable");

    assert!(format!("{error:#}").contains("not-an-address"));
}

#[test]
fn test_material_that_is_not_a_certificate_is_reported_as_such() {
    let pki = Pki::new("garbage");
    let certificate = pki.write("garbage.pem", "not a certificate at all\n");
    let key = pki.write("garbage.key", "not a key either\n");

    let error = server_config(&TlsSettings::new(&certificate, &key))
        .expect_err("neither file is what it claims");

    assert!(format!("{error:#}").contains("garbage.pem"));
}

#[test]
fn test_the_protocol_floor_is_what_the_settings_asked_for() {
    let pki = Pki::new("floor");
    let (certificate, key) = self_signed(&pki, "server");

    // Both build; what differs is what a 1.2 client will be allowed to negotiate.
    let modern =
        server_config(&TlsSettings::new(&certificate, &key)).expect("the modern floor builds");
    let permissive =
        server_config(&TlsSettings::new(&certificate, &key).with_min_version(TlsVersion::V1_2))
            .expect("the permissive floor builds");

    assert!(
        !modern.alpn_protocols.is_empty(),
        "gRPC needs h2 advertised"
    );
    assert_eq!(modern.alpn_protocols, permissive.alpn_protocols);
}

/// Connects and completes a TLS handshake, returning what the server said.
async fn speak_tls(address: SocketAddr, config: rustls::ClientConfig) -> Result<String, String> {
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let name = ServerName::try_from("localhost").map_err(|error| error.to_string())?;

    let mut stream = connector
        .connect(name, stream)
        .await
        .map_err(|error| error.to_string())?;

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| error.to_string())?;

    let mut said = Vec::new();
    stream
        .read_to_end(&mut said)
        .await
        .map_err(|error| error.to_string())?;

    Ok(String::from_utf8_lossy(&said).into_owned())
}

/// The root store a client uses to decide it is talking to the right server.
fn roots_of(certificate: &Path) -> RootCertStore {
    let mut roots = RootCertStore::empty();

    for certificate in load_certificates(certificate).expect("the certificate reads") {
        roots.add(certificate).expect("the root is added");
    }

    roots
}

#[tokio::test]
async fn test_mutual_tls_turns_away_a_client_with_no_certificate() {
    let pki = Pki::new("mtls");
    let authority = pki.authority_pem();
    let (server_cert, server_key) = pki.issue("server", "localhost");
    let (client_cert, client_key) = pki.issue("client", "a-client");

    let settings = TlsSettings::new(&server_cert, &server_key).with_client_ca(&authority);
    assert!(settings.is_mutual());

    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    // Without a certificate the connection never becomes a request: the server ends the
    // handshake, and the application is never reached at all.
    let anonymous = rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(&authority))
        .with_no_client_auth();
    let refused = speak_tls(address, anonymous).await;
    assert!(
        refused.is_err(),
        "a client with no certificate was served: {refused:?}"
    );

    // With one the authority signed, the same request is answered.
    let identified = rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(&authority))
        .with_client_auth_cert(
            load_certificates(&client_cert).expect("the client certificate reads"),
            load_key(&client_key).expect("the client key reads"),
        )
        .expect("the client identity builds");
    let said = speak_tls(address, identified)
        .await
        .expect("an identified client is served");
    assert!(said.contains("served"), "{said}");

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_a_tls_listener_serves_a_client_that_trusts_it() {
    let pki = Pki::new("tls");
    let (certificate, key) = self_signed(&pki, "server");
    let settings = TlsSettings::new(&certificate, &key);

    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(&certificate))
        .with_no_client_auth();

    let said = speak_tls(address, client)
        .await
        .expect("the handshake works");
    assert!(said.contains("served"), "{said}");

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}
