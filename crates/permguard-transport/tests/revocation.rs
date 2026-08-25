// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Taking a client certificate back before it expires.
//!
//! A revocation is something a deployment finds out it needs at the worst possible moment, so it is
//! exercised here against a real authority, a real revocation list and a real handshake rather than
//! asserted about in prose.
//!
//! Re-reading material lives in `renewal.rs`, because that is process-wide and has to be the only
//! thing happening while it is asserted on.

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
use permguard_transport::{Surface, load_certificates, load_key, server_config};

/// An authority, and the certificates it signed — including the ones it has taken back.
struct Authority {
    directory: PathBuf,
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
    params: rcgen::CertificateParams,
}

impl Authority {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!("permguard-crl-{name}"));
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

    fn issuer(&self) -> rcgen::Issuer<'_, &rcgen::KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }

    /// Issues a certificate for `name` under a serial the test can later revoke.
    ///
    /// The common name is set explicitly: `rcgen` supplies one of its own otherwise, and a fixture
    /// that quietly identifies every client as "rcgen self signed cert" would let an allowlist test
    /// pass without the allowlist working.
    fn issue(&self, stem: &str, name: &str, serial: u64) -> (PathBuf, PathBuf) {
        let mut params =
            rcgen::CertificateParams::new(vec![name.to_owned()]).expect("parameters build");
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);

        let key = rcgen::KeyPair::generate().expect("the key is generated");
        let certificate = params
            .signed_by(&key, &self.issuer())
            .expect("the authority signs it");

        (
            self.write(&format!("{stem}.pem"), &certificate.pem()),
            self.write(&format!("{stem}.key"), &key.serialize_pem()),
        )
    }

    /// Publishes a list taking `serials` back.
    fn revoke(&self, stem: &str, serials: &[u64]) -> PathBuf {
        let params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2099, 1, 1),
            crl_number: rcgen::SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|serial| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(*serial),
                    revocation_time: rcgen::date_time_ymd(2020, 6, 1),
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };

        let list = params
            .signed_by(&self.issuer())
            .expect("the authority signs the list");

        self.write(stem, &list.pem().expect("the list writes as PEM"))
    }

    /// Publishes a list whose `next_update` has already passed.
    fn revoke_expired(&self, stem: &str) -> PathBuf {
        let params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            // Long gone. An expired list is revocation data nobody is maintaining.
            next_update: rcgen::date_time_ymd(2021, 1, 1),
            crl_number: rcgen::SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };

        let list = params
            .signed_by(&self.issuer())
            .expect("the authority signs the list");

        self.write(stem, &list.pem().expect("the list writes as PEM"))
    }
}

fn router() -> Router {
    Router::new().route("/", get(|| async { "served\n" }))
}

/// A router that answers with whoever the connection said it was.
fn identifying_router() -> Router {
    use axum::Extension;

    Router::new().route(
        "/",
        get(
            |identity: Option<Extension<Arc<permguard_core::PeerIdentity>>>| async move {
                match identity {
                    Some(Extension(peer)) => {
                        format!("who={} fingerprint={}\n", peer.label(), peer.fingerprint())
                    }
                    None => "who=nobody\n".to_owned(),
                }
            },
        ),
    )
}

/// The root store a client uses to decide it is talking to the right server.
fn roots_of(certificate: &Path) -> RootCertStore {
    let mut roots = RootCertStore::empty();

    for certificate in load_certificates(certificate).expect("the certificate reads") {
        roots.add(certificate).expect("the root is added");
    }

    roots
}

/// A client that presents `certificate` and trusts `authority`.
fn client(authority: &Path, certificate: &Path, key: &Path) -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(authority))
        .with_client_auth_cert(
            load_certificates(certificate).expect("the client certificate reads"),
            load_key(key).expect("the client key reads"),
        )
        .expect("the client identity builds")
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

#[tokio::test]
async fn test_a_revoked_client_is_turned_away_and_an_untouched_one_is_not() {
    let authority = Authority::new("refuses");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);
    let (revoked_cert, revoked_key) = authority.issue("revoked", "gone-rogue", 42);
    let (good_cert, good_key) = authority.issue("good", "still-trusted", 43);

    // The authority has taken back exactly one of the two.
    let crl = authority.revoke("ca.crl", &[42]);

    let settings = TlsSettings::new(&server_cert, &server_key)
        .with_client_ca(&authority_pem)
        .with_crl(&crl);

    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    let refused = speak_tls(address, client(&authority_pem, &revoked_cert, &revoked_key)).await;
    assert!(
        refused.is_err(),
        "a revoked certificate was served: {refused:?}"
    );

    // The revocation must be about that certificate and not about the authority: everybody else it
    // signed keeps working.
    let said = speak_tls(address, client(&authority_pem, &good_cert, &good_key))
        .await
        .expect("a client that was not revoked is still served");
    assert!(said.contains("served"), "{said}");

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_without_a_list_a_revoked_certificate_keeps_working() {
    // The situation the setting exists to end: nothing checks, so a compromised certificate is
    // valid until it expires on its own.
    let authority = Authority::new("unchecked");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);
    let (revoked_cert, revoked_key) = authority.issue("revoked", "gone-rogue", 42);
    authority.revoke("ca.crl", &[42]);

    let settings = TlsSettings::new(&server_cert, &server_key).with_client_ca(&authority_pem);

    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");

    let said = speak_tls(
        surface.address(),
        client(&authority_pem, &revoked_cert, &revoked_key),
    )
    .await
    .expect("nothing is checking, so it is served");
    assert!(said.contains("served"), "{said}");

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[test]
fn test_a_file_that_revokes_nothing_is_refused_rather_than_assumed_harmless() {
    let authority = Authority::new("empty-list");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);
    let empty = authority.write("ca.crl", "");

    let error = server_config(
        &TlsSettings::new(&server_cert, &server_key)
            .with_client_ca(&authority_pem)
            .with_crl(&empty),
    )
    .expect_err("an empty list is not a list");

    assert!(format!("{error:#}").contains("no revocation list"));
}

#[tokio::test]
async fn test_the_certificate_the_client_presented_reaches_the_handler() {
    // The whole reason authorisation is possible: a mutual handshake knows exactly which certificate
    // it accepted, and by default a request handler knows nothing about it.
    let authority = Authority::new("identity");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);
    let (client_cert, client_key) = authority.issue("client", "local-operator", 7);

    let settings = TlsSettings::new(&server_cert, &server_key).with_client_ca(&authority_pem);
    let surface = Surface::listener("test", "127.0.0.1:0", identifying_router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");

    let said = speak_tls(
        surface.address(),
        client(&authority_pem, &client_cert, &client_key),
    )
    .await
    .expect("the identified client is served");

    // The common name out of the subject, and the fingerprint of the certificate itself — the two
    // forms an allowlist can be written in.
    assert!(said.contains("who=local-operator"), "{said}");

    let presented = permguard_transport::digest(
        load_certificates(&client_cert).expect("the client certificate reads")[0].as_ref(),
    );
    assert!(
        said.contains(&format!("fingerprint={presented}")),
        "the handler saw a different certificate than the client sent: {said}"
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_a_surface_without_mutual_tls_produces_no_identity_at_all() {
    // Absence has to be expressible, and has to be different from an identity that happens to be
    // empty: a surface that demands no certificate must not look like one that accepted a blank.
    let authority = Authority::new("anonymous");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);

    let settings = TlsSettings::new(&server_cert, &server_key);
    let surface = Surface::listener("test", "127.0.0.1:0", identifying_router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(&authority_pem))
        .with_no_client_auth();
    let said = speak_tls(surface.address(), config)
        .await
        .expect("an anonymous client is served");

    assert!(said.contains("who=nobody"), "{said}");

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

/// An expired list refuses everybody, and that is the deliberate reading: a list past its
/// `nextUpdate` is revocation data nobody is maintaining, and the alternative — trusting it forever —
/// is a revoked client that stays admitted for months. The CRL expiry gauge exists so this moment is
/// predicted by an alert instead of discovered by an outage.
#[tokio::test]
async fn test_an_expired_revocation_list_refuses_rather_than_trusts() {
    let authority = Authority::new("expired-list");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);
    let (client_cert, client_key) = authority.issue("client", "an-untouched-client", 7);
    let crl = authority.revoke_expired("expired.crl");

    let settings = TlsSettings::new(&server_cert, &server_key)
        .with_client_ca(&authority_pem)
        .with_crl(&crl);
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");

    let outcome = speak_tls(
        surface.address(),
        client(&authority_pem, &client_cert, &client_key),
    )
    .await;

    assert!(
        outcome.is_err(),
        "a client was admitted against an expired revocation list: {outcome:?}"
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

/// The handshake settles who a client *is*; the allow list settles whether this surface is *for*
/// them. Both clients below carry genuine certificates from the same authority — and only the named
/// one is served, because an authority signs every client it was ever asked to.
#[tokio::test]
async fn test_an_authenticated_peer_off_the_allow_list_is_refused() {
    let authority = Authority::new("allow-list");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);
    let (named_cert, named_key) = authority.issue("named", "the-billing-service", 21);
    let (other_cert, other_key) = authority.issue("other", "some-other-workload", 22);

    let settings = TlsSettings::new(&server_cert, &server_key)
        .with_client_ca(&authority_pem)
        .with_allow(vec![
            "cn:the-billing-service"
                .parse()
                .expect("a valid allow entry"),
        ]);
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    let served = speak_tls(address, client(&authority_pem, &named_cert, &named_key))
        .await
        .expect("the named peer is served");
    assert!(served.contains("served"), "{served}");

    // Authenticated perfectly well — that is how the refusal can name it — and turned away: 403,
    // not a handshake failure, so the operator on the other end fixes the list, not their cert.
    let refused = speak_tls(address, client(&authority_pem, &other_cert, &other_key))
        .await
        .expect("the connection itself completes: the refusal is an answer, not a hangup");
    assert!(
        refused.contains("403") && !refused.contains("served"),
        "an authenticated peer off the list was served: {refused}"
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

/// No list means the handshake is the whole decision — the behaviour every deployment had before
/// allow lists existed, and the correct one for a data plane that answers any workload the mesh
/// signed.
#[tokio::test]
async fn test_without_a_list_every_authenticated_peer_is_served() {
    let authority = Authority::new("no-list");
    let authority_pem = authority.authority_pem();
    let (server_cert, server_key) = authority.issue("server", "localhost", 1);
    let (client_cert, client_key) = authority.issue("client", "any-workload", 31);

    let settings = TlsSettings::new(&server_cert, &server_key).with_client_ca(&authority_pem);
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .start()
        .await
        .expect("the listener binds");

    let served = speak_tls(
        surface.address(),
        client(&authority_pem, &client_cert, &client_key),
    )
    .await
    .expect("an authenticated peer is served");
    assert!(served.contains("served"), "{served}");

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}
