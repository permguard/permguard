// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The remote custody providers the server composes (WP-3.2, owner decisions of 2026-10-08).
//!
//! | Provider       | Holds                                                     | Reached through                         |
//! | -------------- | --------------------------------------------------------- | --------------------------------------- |
//! | Vault Transit  | non-exportable signing keys, and a derived AES KEK        | HTTPS to `operations.keys.kms.address`  |
//!
//! A Transit key is named by the provider, `pg-<ring>-<random>`, and the ring keeps the name in
//! `private/<slot>.ref`: the slot is the key's thumbprint, so the reference cannot name other
//! material. Signing keys are created non-exportable; the KEK is a Transit key created with
//! `derived: true` by the operator, so the wrap context is cryptographically bound as the
//! Transit `context`. The token is resolved from the secret store and sent as `X-Vault-Token`,
//! never logged.
//!
//! The key providers' API is synchronous; every request runs on a thread of the provider's own,
//! with a runtime of its own, so a signing never blocks the server's runtime on the network.

use std::fmt;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use permguard_host::identity::Suite;
use permguard_host::keys::custody::{Remote, Wrap};
use permguard_host::keys::{Custody, KeyError, KeyProvider, PublicKey};
use permguard_host::storage::Dir;
use permguard_host::storage::write::{Published, publish_immutable};

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

/// How long one Transit request may take before it fails.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The most bytes a Transit answer may carry.
const MAX_ANSWER_BYTES: usize = 64 * 1024;
/// The wrapping algorithm a Transit KEK writes.
pub const WRAP_TRANSIT: &str = permguard_core::domains::format::TRANSIT_KEK_WRAP_V1;

/// One request to Transit, and where its answer goes.
struct Job {
    method: http::Method,
    path: String,
    body: Option<Zeroizing<String>>,
    answer: mpsc::Sender<Result<Value, CallError>>,
}

/// Why a Transit request failed.
#[derive(Debug)]
enum CallError {
    /// Transit answered and refused: its status and what it said, never the request.
    Refused(http::StatusCode, String),
    /// Transit was not reached, or did not answer in time.
    Unreachable(String),
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(status, errors) => write!(f, "the KMS refused ({status}): {errors}"),
            Self::Unreachable(why) => f.write_str(why),
        }
    }
}

/// A Vault (or OpenBao) Transit mount.
pub struct Transit {
    jobs: Mutex<mpsc::Sender<Job>>,
    mount: String,
}

impl fmt::Debug for Transit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transit")
            .field("mount", &self.mount)
            .finish_non_exhaustive()
    }
}

/// Where Transit is and how the Host reaches it.
pub struct Endpoint {
    /// `https://host:port`, or `http://` in development.
    pub address: String,
    pub mount: String,
    /// The token, from the secret store.
    pub token: Zeroizing<String>,
    /// The CA bundle the Vault's certificate is checked against; the system's otherwise.
    pub ca: Option<std::path::PathBuf>,
}

impl Transit {
    /// Starts the provider's thread for `endpoint`.
    pub fn start(endpoint: Endpoint) -> anyhow::Result<Arc<Self>> {
        let uri: http::Uri = endpoint
            .address
            .parse()
            .with_context(|| format!("`{}` is not a URL", endpoint.address))?;
        let tls = match uri.scheme_str() {
            Some("https") => Some(client_tls(endpoint.ca.as_deref())?),
            Some("http") => None,
            _ => anyhow::bail!("the KMS address is `https://…`"),
        };
        let host = uri
            .host()
            .context("the KMS address names no host")?
            .to_owned();
        let port = uri
            .port_u16()
            .unwrap_or(if tls.is_some() { 443 } else { 80 });
        let (jobs, received) = mpsc::channel::<Job>();
        let token = endpoint.token;
        std::thread::Builder::new()
            .name("permguard-transit".to_owned())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                for job in received {
                    let answer = runtime.block_on(async {
                        tokio::time::timeout(
                            TIMEOUT,
                            request(&host, port, tls.as_ref(), &token, &job),
                        )
                        .await
                        .unwrap_or_else(|_| {
                            Err(CallError::Unreachable(
                                "the KMS did not answer in time".to_owned(),
                            ))
                        })
                    });
                    let _ = job.answer.send(answer);
                }
            })
            .context("starting the KMS client")?;
        Ok(Arc::new(Self {
            jobs: Mutex::new(jobs),
            mount: endpoint.mount,
        }))
    }

    /// One request, answered with the `data` member of Vault's answer.
    fn call(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, CallError> {
        self.send(
            method,
            path,
            body.map(|body| Zeroizing::new(body.to_string())),
        )
    }

    /// One request whose body is already serialised, in a buffer wiped when the request is done.
    fn send(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Zeroizing<String>>,
    ) -> Result<Value, CallError> {
        let (answer, received) = mpsc::channel();
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(Job {
                method,
                path: format!("/v1/{}/{path}", self.mount),
                body,
                answer,
            })
            .map_err(|_| CallError::Unreachable("the KMS client stopped".to_owned()))?;
        received
            .recv()
            .map_err(|_| CallError::Unreachable("the KMS client stopped".to_owned()))?
    }
}

fn client_tls(ca: Option<&std::path::Path>) -> anyhow::Result<tokio_rustls::TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    match ca {
        Some(path) => {
            let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            for certificate in rustls_pemfile_certs(&pem)? {
                roots.add(certificate).context("adding the KMS CA")?;
            }
        }
        None => {
            for certificate in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(certificate);
            }
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("the TLS versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// The certificates of a PEM bundle.
fn rustls_pemfile_certs(
    pem: &[u8],
) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject as _;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("reading the KMS CA bundle: {error:?}"))
}

async fn request(
    host: &str,
    port: u16,
    tls: Option<&tokio_rustls::TlsConnector>,
    token: &str,
    job: &Job,
) -> Result<Value, CallError> {
    use http_body_util::BodyExt as _;

    let unreachable = CallError::Unreachable;
    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|error| unreachable(format!("reaching the KMS: {error}")))?;
    // hyper's own buffers are not wiped: the limit the owner accepted for library internals.
    let body = job
        .body
        .as_ref()
        .map(|body| bytes::Bytes::copy_from_slice(body.as_bytes()))
        .unwrap_or_default();
    let request = http::Request::builder()
        .method(job.method.clone())
        .uri(&job.path)
        .header(http::header::HOST, host)
        .header("X-Vault-Token", {
            // Marked sensitive, so no debug output of the request shows it.
            let mut value = http::HeaderValue::from_str(token)
                .map_err(|_| unreachable("the KMS token is not a header value".to_owned()))?;
            value.set_sensitive(true);
            value
        })
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(body))
        .map_err(|error| unreachable(error.to_string()))?;
    let response = match tls {
        Some(tls) => {
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|error| unreachable(format!("the KMS host name: {error}")))?;
            let stream = tls
                .connect(name, tcp)
                .await
                .map_err(|error| unreachable(format!("the KMS TLS handshake: {error}")))?;
            send(hyper_util::rt::TokioIo::new(stream), request)
                .await
                .map_err(unreachable)?
        }
        None => send(hyper_util::rt::TokioIo::new(tcp), request)
            .await
            .map_err(unreachable)?,
    };
    let status = response.status();
    let bytes = http_body_util::Limited::new(response.into_body(), MAX_ANSWER_BYTES)
        .collect()
        .await
        .map_err(|error| unreachable(format!("reading the KMS answer: {error}")))?
        .to_bytes();
    let answer: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|error| unreachable(format!("the KMS answer: {error}")))?
    };
    if !status.is_success() {
        // Vault answers `{"errors": [...]}`: what it says, never the request.
        return Err(CallError::Refused(status, answer["errors"].to_string()));
    }
    Ok(answer["data"].clone())
}

async fn send<S>(
    stream: S,
    request: http::Request<http_body_util::Full<bytes::Bytes>>,
) -> Result<http::Response<hyper::body::Incoming>, String>
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(stream)
        .await
        .map_err(|error| format!("the KMS connection: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(request)
        .await
        .map_err(|error| format!("the KMS request: {error}"))
}

fn transit_error(error: CallError) -> KeyError {
    KeyError::Malformed(error.to_string())
}

/// The DER of a P-256 SubjectPublicKeyInfo up to its uncompressed point: `id-ecPublicKey`,
/// `prime256v1`, a 66-byte BIT STRING with no unused bits.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The Transit key type of `suite`.
fn key_type(suite: Suite) -> &'static str {
    match suite {
        Suite::Ed25519Sha256V1 => "ed25519",
        Suite::P256Sha256V1 => "ecdsa-p256",
    }
}

/// A ring's keys in Transit, their names in `<slot>.ref` below `dir`.
pub struct TransitKeys {
    transit: Arc<Transit>,
    dir: Dir,
    ring: &'static str,
}

impl fmt::Debug for TransitKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitKeys")
            .field("ring", &self.ring)
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

impl TransitKeys {
    fn reference(slot: &str) -> String {
        format!("{slot}.ref")
    }

    /// The prefix of every key name this ring creates: `pg-<ring>-`.
    fn prefix(&self) -> String {
        format!("pg-{}-", self.ring.replace('.', "-"))
    }

    /// The Transit key `<slot>.ref` names: one of this ring's, never a name copied in from another
    /// ring or the KEK's.
    fn name_of(&self, slot: &str) -> Result<String, KeyError> {
        let bytes = self
            .dir
            .read(&Self::reference(slot))?
            .ok_or_else(|| KeyError::Absent(slot.to_owned()))?;
        let refused = || KeyError::Malformed(format!("`{slot}.ref` names no key of this ring"));
        let name = String::from_utf8(bytes).map_err(|_| refused())?;
        let random = name.strip_prefix(&self.prefix()).ok_or_else(refused)?;
        if random.len() != 24
            || !random
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refused());
        }
        Ok(name)
    }

    /// Creates a non-exportable key, answering its name and public half.
    fn create(&self, suite: Suite) -> Result<(String, PublicKey), KeyError> {
        let mut random = [0u8; 12];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .map_err(|_| KeyError::Malformed("the random source refused".to_owned()))?;
        let name = format!(
            "{}{}",
            self.prefix(),
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        self.transit
            .call(
                http::Method::POST,
                &format!("keys/{name}"),
                Some(json!({ "type": key_type(suite), "exportable": false, "allow_plaintext_backup": false })),
            )
            .map_err(transit_error)?;
        let public = self.public_of(&name, suite)?;
        Ok((name, public))
    }

    /// The public half of the Transit key `name`, in the suite's raw encoding.
    fn public_of(&self, name: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        let data = self
            .transit
            .call(http::Method::GET, &format!("keys/{name}"), None)
            .map_err(transit_error)?;
        if data["type"] != key_type(suite)
            || data["exportable"] != false
            || data["allow_plaintext_backup"] != false
        {
            return Err(KeyError::Malformed(format!(
                "the KMS key `{name}` is not a `{}` key without export or plaintext backup",
                key_type(suite)
            )));
        }
        let text = data["keys"]["1"]["public_key"].as_str().ok_or_else(|| {
            KeyError::Malformed(format!("the KMS key `{name}` shows no public key"))
        })?;
        let bytes = match suite {
            Suite::Ed25519Sha256V1 => STANDARD
                .decode(text)
                .map_err(|error| KeyError::Malformed(error.to_string()))?,
            // A P-256 public key is a PEM SubjectPublicKeyInfo, read exactly.
            Suite::P256Sha256V1 => {
                let body: String = text
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect();
                let der = STANDARD
                    .decode(body)
                    .map_err(|error| KeyError::Malformed(error.to_string()))?;
                der.strip_prefix(&P256_SPKI_PREFIX[..])
                    .filter(|point| point.len() == 65 && point[0] == 0x04)
                    .ok_or_else(|| KeyError::Malformed(format!("`{name}` is not a P-256 key")))?
                    .to_vec()
            }
        };
        if bytes.len() != suite.public_key_len() {
            return Err(KeyError::Malformed(format!(
                "the KMS key `{name}` is not a {suite} key"
            )));
        }
        Ok(PublicKey { suite, bytes })
    }

    fn remember(&self, slot: &str, name: &str) -> Result<(), KeyError> {
        let reference = Self::reference(slot);
        let readable = |bytes: &[u8]| std::str::from_utf8(bytes).is_ok();
        let same = |bytes: &[u8]| bytes == name.as_bytes();
        match publish_immutable(&self.dir, &reference, name.as_bytes(), &readable, &same)? {
            Published::Written => Ok(()),
            Published::AlreadyThere => Err(KeyError::Exists(slot.to_owned())),
        }
    }
}

impl KeyProvider for TransitKeys {
    fn name(&self) -> &'static str {
        "vault-transit"
    }

    fn custody(&self) -> Custody {
        Custody::Kms
    }

    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        if self.dir.read(&Self::reference(slot))?.is_some() {
            return Err(KeyError::Exists(slot.to_owned()));
        }
        let (name, public) = self.create(suite)?;
        self.remember(slot, &name)?;
        Ok(public)
    }

    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), KeyError> {
        let (name, public) = self.create(suite)?;
        let slot = permguard_host::keys::thumbprint_of(&public)?;
        self.remember(&slot, &name)?;
        Ok((slot, public))
    }

    fn slots(&self) -> Result<Vec<String>, KeyError> {
        Ok(self
            .dir
            .names()?
            .into_iter()
            .filter_map(|name| name.strip_suffix(".ref").map(str::to_owned))
            .collect())
    }

    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        self.public_of(&self.name_of(slot)?, suite)
    }

    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let name = self.name_of(slot)?;
        // A key this provider created is never rotated in Transit (a ring rotates by a new key),
        // so its version 1 is the one key behind the slot: a rotation made in Vault is not used.
        let mut body = json!({ "input": STANDARD.encode(message), "key_version": 1 });
        if suite == Suite::P256Sha256V1 {
            body["hash_algorithm"] = json!("sha2-256");
            body["marshaling_algorithm"] = json!("jws");
        }
        let data = self
            .transit
            .call(http::Method::POST, &format!("sign/{name}"), Some(body))
            .map_err(transit_error)?;
        let signature = data["signature"]
            .as_str()
            .and_then(|text| text.splitn(3, ':').nth(2))
            .ok_or_else(|| KeyError::Malformed("the KMS answered no signature".to_owned()))?;
        let raw = match suite {
            Suite::Ed25519Sha256V1 => STANDARD.decode(signature),
            Suite::P256Sha256V1 => URL_SAFE_NO_PAD.decode(signature.trim_end_matches('=')),
        }
        .map_err(|error| KeyError::Malformed(format!("the KMS signature: {error}")))?;
        // Transit does not choose the low-s twin of a P-256 signature: this profile does.
        suite
            .canonical_signature(&raw)
            .map(|signature| signature.to_vec())
            .map_err(|error| KeyError::Malformed(format!("the KMS signature: {error}")))
    }

    fn destroy(&self, slot: &str) -> Result<(), KeyError> {
        let name = self.name_of(slot)?;
        // A key already gone — a destroy interrupted after Transit deleted it — is destroyed.
        // Transit answers a missing key's config or delete with a 400, and a wrong mount with a
        // 404, so neither says so: only a read of the key answering 404 does.
        let gone = |result: Result<Value, CallError>| match result {
            Ok(_) => Ok(()),
            Err(error @ CallError::Refused(..)) => {
                match self
                    .transit
                    .call(http::Method::GET, &format!("keys/{name}"), None)
                {
                    Err(CallError::Refused(http::StatusCode::NOT_FOUND, _)) => Ok(()),
                    _ => Err(transit_error(error)),
                }
            }
            Err(error) => Err(transit_error(error)),
        };
        gone(self.transit.call(
            http::Method::POST,
            &format!("keys/{name}/config"),
            Some(json!({ "deletion_allowed": true })),
        ))?;
        gone(
            self.transit
                .call(http::Method::DELETE, &format!("keys/{name}"), None),
        )?;
        permguard_host::storage::tombstone::delete(&self.dir, &Self::reference(slot))?;
        Ok(())
    }
}

impl Remote for Transit {
    fn provider(&self, ring: &'static str, dir: Dir) -> Result<Arc<dyn KeyProvider>, KeyError> {
        Ok(Arc::new(TransitKeys {
            transit: Arc::new(Self {
                jobs: Mutex::new(
                    self.jobs
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone(),
                ),
                mount: self.mount.clone(),
            }),
            dir,
            ring,
        }))
    }
}

/// A KEK in Transit: a key the operator created `derived`, so the wrap context is its derivation
/// context and an unwrap under another context fails.
pub struct TransitKek {
    transit: Arc<Transit>,
    name: String,
    version: u64,
}

impl fmt::Debug for TransitKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitKek")
            .field("name", &self.name)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl TransitKek {
    /// The Transit key `name` at `version`, checked to be what a KEK must be: `aes256-gcm96`,
    /// `derived` (the wrap context is its derivation context), not exportable, and holding the
    /// version.
    pub fn open(transit: Arc<Transit>, name: &str, version: u64) -> anyhow::Result<Self> {
        let data = transit
            .call(http::Method::GET, &format!("keys/{name}"), None)
            .map_err(|error| anyhow::anyhow!("reading the KMS KEK `{name}`: {error}"))?;
        if data["type"] != "aes256-gcm96"
            || data["derived"] != true
            || data["exportable"] != false
            || data["allow_plaintext_backup"] != false
        {
            anyhow::bail!(
                "the KMS KEK `{name}` is an `aes256-gcm96` key created `derived`, without export \
                 or plaintext backup"
            );
        }
        if data["keys"][version.to_string()].is_null() {
            anyhow::bail!("the KMS KEK `{name}` holds no version {version}");
        }
        Ok(Self {
            transit,
            name: name.to_owned(),
            version,
        })
    }

    /// The `vault:v<version>:` prefix of what this KEK wraps.
    fn prefix(&self) -> String {
        format!("vault:v{}:", self.version)
    }
}

impl Wrap for TransitKek {
    fn kek_ref(&self) -> &str {
        &self.name
    }

    fn kek_version(&self) -> u64 {
        self.version
    }

    fn wrap_algorithm(&self) -> &str {
        WRAP_TRANSIT
    }

    fn wrap(
        &self,
        dek: &permguard_host::keys::custody::Dek,
        context: &[u8],
    ) -> Result<Vec<u8>, permguard_host::keys::custody::WrapError> {
        use permguard_host::keys::custody::WrapError;
        // The body carries the DEK: written straight into a buffer that is wiped, never through
        // a JSON value (base64 needs no escaping).
        let plaintext = Zeroizing::new(STANDARD.encode(dek.expose()));
        let context = STANDARD.encode(context);
        let mut body = Zeroizing::new(String::with_capacity(plaintext.len() + context.len() + 64));
        for part in [
            r#"{"plaintext":""#,
            plaintext.as_str(),
            r#"","context":""#,
            context.as_str(),
            r#"","key_version":"#,
            &self.version.to_string(),
            "}",
        ] {
            body.push_str(part);
        }
        let data = self
            .transit
            .send(
                http::Method::POST,
                &format!("encrypt/{}", self.name),
                Some(body),
            )
            .map_err(|error| WrapError::Unavailable(error.to_string()))?;
        data["ciphertext"]
            .as_str()
            .filter(|text| text.starts_with(&self.prefix()))
            .map(|text| text.as_bytes().to_vec())
            .ok_or_else(|| {
                WrapError::Unavailable(format!(
                    "the KMS answered no ciphertext under version {}",
                    self.version
                ))
            })
    }

    fn unwrap(
        &self,
        kek_version: u64,
        wrapped: &[u8],
        context: &[u8],
    ) -> Result<permguard_host::keys::custody::Dek, permguard_host::keys::custody::WrapError> {
        use permguard_host::keys::custody::WrapError;
        if kek_version != self.version {
            return Err(WrapError::VersionUnknown(kek_version));
        }
        let ciphertext = std::str::from_utf8(wrapped).map_err(|_| WrapError::Rejected)?;
        if !ciphertext.starts_with(&self.prefix()) {
            return Err(WrapError::Rejected);
        }
        // Transit refusing the ciphertext is a rejection; Transit unreachable is not, and the
        // start says so rather than blaming the key.
        let data = self
            .transit
            .call(
                http::Method::POST,
                &format!("decrypt/{}", self.name),
                Some(json!({ "ciphertext": ciphertext, "context": STANDARD.encode(context) })),
            )
            .map_err(|error| match error {
                // Transit answers a ciphertext it cannot open with a 400; a 401 or a 403 is the
                // token or its policy, not the key.
                CallError::Refused(http::StatusCode::BAD_REQUEST, _) => WrapError::Rejected,
                error => WrapError::Unavailable(error.to_string()),
            })?;
        let plaintext = Zeroizing::new(
            STANDARD
                .decode(data["plaintext"].as_str().unwrap_or_default())
                .map_err(|_| WrapError::Rejected)?,
        );
        let mut bytes = Zeroizing::new([0u8; 32]);
        if plaintext.len() != bytes.len() {
            return Err(WrapError::Rejected);
        }
        bytes.copy_from_slice(&plaintext);
        Ok(permguard_host::keys::custody::Dek::from_unwrapped(bytes))
    }
}
