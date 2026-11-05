// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The identity providers' key refresh (WP-8.1, `1-architecture/1` Identity providers): one task
//! per provider whose keys are fetched, never a request.
//!
//! | Rule        | Here                                                                                   |
//! | ----------- | -------------------------------------------------------------------------------------- |
//! | cadence     | every `refresh`, spread by up to a tenth by the provider's name                         |
//! | unknown key | the verifier wakes the task, at most once a minute                                     |
//! | discovery   | `<issuer>/.well-known/openid-configuration`, whose `issuer` must equal the provider's  |
//! | transport   | HTTPS with the system's authorities and `ca_file`; HTTP only under `development`; no redirect; 5 s to connect, 15 s in all |
//! | size        | over 256 KiB refused                                                                   |
//! | failure     | recorded on the verifier, retried from 10 s, doubling up to `refresh`                  |

use std::sync::Arc;
use std::time::Duration;

use permguard_host::authz::{KeySource, OidcRule, Verifier};

/// The first retry after a failed fetch.
pub const FIRST_RETRY: Duration = Duration::from_secs(10);
/// How long a connection may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a whole fetch may take, connection included.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// The running refresh tasks; dropping them stops them.
pub struct Refreshing(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Refreshing {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Starts one task per provider whose keys are fetched; `None` when none is.
pub fn drive(providers: &[Arc<Verifier>], allow_http: bool) -> Option<Refreshing> {
    let tasks: Vec<_> = providers
        .iter()
        .filter(|verifier| verifier.rule().keys.is_fetched())
        .map(|verifier| {
            let wake = Arc::new(tokio::sync::Notify::new());
            let waking = Arc::clone(&wake);
            verifier.set_waker(Box::new(move || waking.notify_one()));
            tokio::spawn(run(Arc::clone(verifier), wake, allow_http))
        })
        .collect();
    (!tasks.is_empty()).then_some(Refreshing(tasks))
}

async fn run(verifier: Arc<Verifier>, wake: Arc<tokio::sync::Notify>, allow_http: bool) {
    let mut retry = FIRST_RETRY;
    loop {
        let Some(due) = verifier.next_fetch_in() else {
            return;
        };
        if !due.is_zero() {
            tokio::select! {
                () = tokio::time::sleep(spread(verifier.name(), due)) => {}
                () = wake.notified() => {}
            }
        }
        let outcome = match fetch(verifier.rule(), allow_http).await {
            Ok(document) => verifier.install(&document).map(|_| ()),
            Err(reason) => Err(reason),
        };
        match outcome {
            Ok(()) => retry = FIRST_RETRY,
            Err(reason) => {
                verifier.failed(reason);
                tokio::select! {
                    () = tokio::time::sleep(retry) => {}
                    () = wake.notified() => {}
                }
                retry = (retry * 2).min(verifier.rule().refresh);
            }
        }
    }
}

/// `due`, plus up to a tenth of it, fixed per provider: providers configured together are not
/// asked at the same instant, and one provider keeps its own rhythm.
pub fn spread(name: &str, due: Duration) -> Duration {
    // FNV-1a: stable across runs and platforms.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let permille = u32::try_from(hash % 101).unwrap_or(0);
    due + due * permille / 1000
}

/// The provider's key set, fetched: through its discovery document, or from its pinned URL.
pub async fn fetch(rule: &OidcRule, allow_http: bool) -> Result<Vec<u8>, String> {
    let tls = connector(rule.ca_file.as_deref())?;
    let jwks_uri = match &rule.keys {
        KeySource::Uri(uri) => uri.clone(),
        KeySource::Discovery => {
            let url = rule.discovery_url();
            let document = get(&url, &tls, allow_http).await?;
            let discovery: serde_json::Value = serde_json::from_slice(&document)
                .map_err(|error| format!("the discovery document {url} is not JSON: {error}"))?;
            let issuer = discovery.get("issuer").and_then(serde_json::Value::as_str);
            if issuer != Some(rule.issuer.as_str()) {
                return Err(format!(
                    "the discovery document {url} names the issuer {}, not `{}`",
                    issuer.map_or_else(|| "none".to_owned(), |issuer| format!("`{issuer}`")),
                    rule.issuer
                ));
            }
            let uri = discovery
                .get("jwks_uri")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("the discovery document {url} names no jwks_uri"))?;
            permguard_core::authz::check_provider_url(uri, allow_http)
                .map_err(|error| format!("the discovery document {url}: jwks_uri {error}"))?;
            uri.to_owned()
        }
        KeySource::File(_) => return Err("a key file is read, not fetched".to_owned()),
    };
    get(&jwks_uri, &tls, allow_http).await
}

fn connector(ca: Option<&std::path::Path>) -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(certificate);
    }
    if let Some(path) = ca {
        use rustls::pki_types::pem::PemObject as _;
        let pem =
            std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
        for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
            let certificate =
                certificate.map_err(|error| format!("reading {}: {error:?}", path.display()))?;
            roots
                .add(certificate)
                .map_err(|error| format!("adding {}: {error}", path.display()))?;
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("the TLS versions: {error}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// One `GET`, bounded: HTTPS unless `allow_http`, no redirect followed, 200 only, at most
/// [`permguard_host::authz::oidc::MAX_DOCUMENT_BYTES`].
async fn get(
    url: &str,
    tls: &tokio_rustls::TlsConnector,
    allow_http: bool,
) -> Result<Vec<u8>, String> {
    permguard_core::authz::check_provider_url(url, allow_http)?;
    permguard_core::egress::check(permguard_core::egress::Target::IdentityProvider)
        .map_err(|refused| refused.to_string())?;
    let uri: http::Uri = url
        .parse()
        .map_err(|error| format!("`{url}` is not a URL: {error}"))?;
    let secure = uri.scheme_str() == Some("https");
    let host = uri.host().ok_or_else(|| format!("`{url}` names no host"))?;
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let authority = uri.authority().map_or_else(
        || host.to_owned(),
        |authority| authority.as_str().to_owned(),
    );
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str)
        .to_owned();
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header(http::header::HOST, authority)
        .header(http::header::ACCEPT, "application/json")
        .header(
            http::header::USER_AGENT,
            concat!("permguard/", env!("CARGO_PKG_VERSION")),
        )
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|error| error.to_string())?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let exchange = async {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| {
            format!(
                "connecting to {url}: no answer within {}s",
                CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("connecting to {url}: {error}"))?;
        let response = if secure {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|error| format!("the host name of {url}: {error}"))?;
            let stream = tls
                .connect(name, tcp)
                .await
                .map_err(|error| format!("the TLS handshake with {url}: {error}"))?;
            send(hyper_util::rt::TokioIo::new(stream), request).await?
        } else {
            send(hyper_util::rt::TokioIo::new(tcp), request).await?
        };
        let status = response.status();
        if status.is_redirection() {
            return Err(format!(
                "{url} answered {status}: redirects are not followed; configure the final URL"
            ));
        }
        if status != http::StatusCode::OK {
            return Err(format!("{url} answered {status}"));
        }
        use http_body_util::BodyExt as _;
        let bytes = http_body_util::Limited::new(
            response.into_body(),
            permguard_host::authz::oidc::MAX_DOCUMENT_BYTES,
        )
        .collect()
        .await
        .map_err(|error| format!("reading {url}: {error}"))?
        .to_bytes();
        Ok(bytes.to_vec())
    };
    tokio::time::timeout(FETCH_TIMEOUT, exchange)
        .await
        .map_err(|_| {
            format!(
                "{url}: no complete answer within {}s",
                FETCH_TIMEOUT.as_secs()
            )
        })?
}

async fn send<S>(
    stream: S,
    request: http::Request<http_body_util::Empty<bytes::Bytes>>,
) -> Result<http::Response<hyper::body::Incoming>, String>
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(stream)
        .await
        .map_err(|error| format!("the connection: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(request)
        .await
        .map_err(|error| format!("the request: {error}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// What the provider answers on one path: a status line, extra headers and a body.
    type Answer = (u16, Vec<(String, String)>, Vec<u8>);

    /// A provider on loopback, over TLS under a test authority, answering what `routes` holds.
    struct Provider {
        base: String,
        ca: std::path::PathBuf,
        routes: Arc<Mutex<HashMap<String, Answer>>>,
        hits: Arc<Mutex<Vec<String>>>,
        _dir: std::path::PathBuf,
    }

    impl Provider {
        async fn start(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("pg-oidc-refresh-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch");
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("parameters");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let authority_key = rcgen::KeyPair::generate().expect("a key");
            let authority = params.self_signed(&authority_key).expect("self-signed");
            let issuer = rcgen::Issuer::from_params(&params, &authority_key);
            let leaf_params =
                rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("parameters");
            let leaf_key = rcgen::KeyPair::generate().expect("a key");
            let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("signed");
            let ca = dir.join("ca.pem");
            std::fs::write(&ca, authority.pem()).expect("written");
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
                    .expect("a key"),
            )
            .expect("the server config");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bound");
            let port = listener.local_addr().expect("an address").port();
            let routes: Arc<Mutex<HashMap<String, Answer>>> = Arc::default();
            let hits: Arc<Mutex<Vec<String>>> = Arc::default();
            let (serving, hit) = (Arc::clone(&routes), Arc::clone(&hits));
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    let (acceptor, routes, hits) =
                        (acceptor.clone(), Arc::clone(&serving), Arc::clone(&hit));
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let mut request = Vec::new();
                        let mut buffer = [0u8; 1024];
                        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                            let Ok(read) = stream.read(&mut buffer).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            request.extend_from_slice(&buffer[..read]);
                        }
                        let line = String::from_utf8_lossy(&request);
                        let path = line.split(' ').nth(1).unwrap_or("/").to_owned();
                        hits.lock().expect("hits").push(path.clone());
                        let (status, headers, body) = routes
                            .lock()
                            .expect("routes")
                            .get(&path)
                            .cloned()
                            .unwrap_or((404, Vec::new(), b"{}".to_vec()));
                        let mut head = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                            body.len()
                        );
                        for (name, value) in headers {
                            head.push_str(&format!("{name}: {value}\r\n"));
                        }
                        head.push_str("\r\n");
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.write_all(&body).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                base: format!("https://127.0.0.1:{port}"),
                ca,
                routes,
                hits,
                _dir: dir,
            }
        }

        fn serve(&self, path: &str, status: u16, body: Vec<u8>) {
            self.routes
                .lock()
                .expect("routes")
                .insert(path.to_owned(), (status, Vec::new(), body));
        }

        fn issuer(&self) -> String {
            format!("{}/realm", self.base)
        }

        fn discovery(&self, issuer: &str) {
            let document = serde_json::json!({
                "issuer": issuer, "jwks_uri": format!("{}/realm/keys", self.base),
            });
            self.serve(
                "/realm/.well-known/openid-configuration",
                200,
                serde_json::to_vec(&document).expect("json"),
            );
        }

        fn keys(&self, pairs: &[(&Ed25519KeyPair, &str)]) {
            let keys: Vec<serde_json::Value> = pairs
                .iter()
                .map(|(pair, kid)| {
                    serde_json::json!({
                        "kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig",
                        "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
                    })
                })
                .collect();
            self.serve(
                "/realm/keys",
                200,
                serde_json::to_vec(&serde_json::json!({"keys": keys})).expect("json"),
            );
        }

        fn hits(&self, path: &str) -> usize {
            self.hits
                .lock()
                .expect("hits")
                .iter()
                .filter(|hit| *hit == path)
                .count()
        }

        fn rule(&self) -> OidcRule {
            OidcRule {
                name: "realm".to_owned(),
                issuer: self.issuer(),
                audience: "permguard".to_owned(),
                algorithms: vec!["EdDSA".to_owned()],
                claim: "sub".to_owned(),
                keys: KeySource::Discovery,
                ca_file: Some(self.ca.clone()),
                refresh: Duration::from_secs(3_600),
                max_stale: Duration::from_secs(86_400),
                clients: Vec::new(),
                token_types: vec!["JWT".to_owned()],
            }
        }
    }

    fn verifier(rule: OidcRule) -> Arc<Verifier> {
        Arc::new(
            Verifier::new(
                rule,
                0,
                Arc::new(permguard_host::time::TimeGuard::system(
                    Duration::from_secs(30),
                )),
            )
            .expect("builds"),
        )
    }

    fn token(pair: &Ed25519KeyPair, kid: &str, issuer: &str) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("now")
            .as_secs()
            + 600;
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"alg": "EdDSA", "kid": kid})).expect("json")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"iss": issuer, "aud": "permguard", "exp": exp, "sub": "alice"})).expect("json"))
        );
        format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(pair.sign(signed.as_bytes()).as_ref())
        )
    }

    async fn eventually(what: &str, check: impl Fn() -> bool) {
        for _ in 0..200 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("{what}: not within five seconds");
    }

    #[tokio::test]
    async fn the_keys_are_found_through_discovery_and_held_by_the_task() {
        let provider = Provider::start("discovery").await;
        let pair = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).expect("a seed");
        provider.discovery(&provider.issuer());
        provider.keys(&[(&pair, "k1")]);
        let fetched = fetch(&provider.rule(), false).await.expect("fetched");
        assert!(String::from_utf8_lossy(&fetched).contains("\"k1\""));

        let verifier = verifier(provider.rule());
        let _refreshing = drive(&[Arc::clone(&verifier)], false).expect("one fetched provider");
        eventually("the first fetch", || {
            verifier.state() == permguard_host::authz::KeyState::Fresh
        })
        .await;
        let actor = verifier
            .verify(&token(&pair, "k1", &provider.issuer()))
            .expect("verifies")
            .expect("this issuer");
        assert_eq!(
            actor.authorization_principal().as_str(),
            format!("oidc:{}#alice", provider.issuer())
        );
    }

    #[tokio::test]
    async fn a_rotated_key_is_fetched_early_when_a_token_names_it() {
        let provider = Provider::start("rotation").await;
        let first = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).expect("a seed");
        let second = Ed25519KeyPair::from_seed_unchecked(&[2u8; 32]).expect("a seed");
        provider.discovery(&provider.issuer());
        provider.keys(&[(&first, "k1")]);
        let verifier = verifier(provider.rule());
        let _refreshing = drive(&[Arc::clone(&verifier)], false).expect("one fetched provider");
        eventually("the first fetch", || {
            verifier.state() == permguard_host::authz::KeyState::Fresh
        })
        .await;
        let fetches = provider.hits("/realm/keys");

        // The provider rotates; an hour before the next scheduled fetch, a token names the new key.
        provider.keys(&[(&first, "k1"), (&second, "k2")]);
        let rotated = token(&second, "k2", &provider.issuer());
        assert!(
            verifier.verify(&rotated).is_err(),
            "refused: the request never fetches"
        );
        eventually("the early fetch", || verifier.verify(&rotated).is_ok()).await;
        assert_eq!(
            provider.hits("/realm/keys"),
            fetches + 1,
            "one early fetch, not one per request"
        );
    }

    #[tokio::test]
    async fn a_mismatched_issuer_a_redirect_an_oversized_set_and_plain_http_are_refused() {
        let provider = Provider::start("refusals").await;
        let rule = provider.rule();

        provider.discovery("https://somebody.else/realm");
        let refused = fetch(&rule, false).await.expect_err("another issuer");
        assert!(
            refused.contains("names the issuer `https://somebody.else/realm`"),
            "{refused}"
        );

        provider.discovery(&provider.issuer());
        provider.routes.lock().expect("routes").insert(
            "/realm/keys".to_owned(),
            (
                302,
                vec![(
                    "Location".to_owned(),
                    "https://evil.example/keys".to_owned(),
                )],
                Vec::new(),
            ),
        );
        let refused = fetch(&rule, false).await.expect_err("a redirect");
        assert!(refused.contains("redirects are not followed"), "{refused}");

        provider.serve(
            "/realm/keys",
            200,
            vec![b' '; permguard_host::authz::oidc::MAX_DOCUMENT_BYTES + 1],
        );
        let refused = fetch(&rule, false).await.expect_err("too large");
        assert!(refused.contains("reading"), "{refused}");

        let mut plain = rule.clone();
        plain.keys = KeySource::Uri(format!(
            "http://127.0.0.1:{}/realm/keys",
            provider.base.rsplit(':').next().expect("a port")
        ));
        let refused = fetch(&plain, false).await.expect_err("plain HTTP");
        assert!(refused.contains("plain HTTP"), "{refused}");

        let mut unknown_authority = rule;
        unknown_authority.ca_file = None;
        let refused = fetch(&unknown_authority, false)
            .await
            .expect_err("an unknown authority");
        assert!(refused.contains("TLS handshake"), "{refused}");
    }

    #[tokio::test]
    async fn a_failed_fetch_is_recorded_and_retried() {
        let provider = Provider::start("retry").await;
        let pair = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).expect("a seed");
        provider.discovery(&provider.issuer());
        provider.serve("/realm/keys", 503, b"{}".to_vec());
        let verifier = verifier(provider.rule());
        let _refreshing = drive(&[Arc::clone(&verifier)], false).expect("one fetched provider");
        eventually("the failure recorded", || {
            verifier.status().failure.is_some()
        })
        .await;
        assert!(
            verifier
                .status()
                .failure
                .expect("a failure")
                .reason
                .contains("503"),
            "the status says why"
        );
        // The provider answers again: the next retry, ten seconds later, installs the keys.
        provider.keys(&[(&pair, "k1")]);
        tokio::time::pause();
        tokio::time::advance(FIRST_RETRY).await;
        tokio::time::resume();
        eventually("the retry", || {
            verifier.state() == permguard_host::authz::KeyState::Fresh
        })
        .await;
        assert!(verifier.status().failure.is_none());
    }

    #[test]
    fn the_cadence_is_spread_by_up_to_a_tenth_and_fixed_per_provider() {
        let due = Duration::from_secs(1_000);
        for name in ["entra", "okta", "keycloak", "auth0", "a"] {
            let spread = spread(name, due);
            assert!(
                spread >= due && spread <= due + due / 10,
                "{name}: {spread:?}"
            );
            assert_eq!(spread, super::spread(name, due), "the same every time");
        }
        assert_ne!(spread("entra", due), spread("okta", due));
    }
}
