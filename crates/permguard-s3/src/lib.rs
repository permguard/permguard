// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The object store of Permguard's second storage backend (iteration 03, phase 27): one client
//! of one S3 bucket.
//!
//! | Request                         | What it is for                                             |
//! | ------------------------------- | ---------------------------------------------------------- |
//! | [`Bucket::put_new`]             | publish an object under a key that holds none: no replacement |
//! | [`Bucket::get`]                 | read an object whole, up to a bound                        |
//! | [`Bucket::head`]                | whether a key holds an object, and its size                |
//! | [`Bucket::delete`]              | remove an object                                           |
//! | [`Bucket::list`]                | every object under a prefix                                |
//!
//! No development kit: the five requests are HTTP over the TLS the product already links,
//! signed with AWS Signature Version 4 ([`sign`]). The connection is verified against the
//! roots the configuration names, and is in the clear only to a loopback address, a
//! development machine's.
//!
//! The calls are synchronous, as the store contracts are, and may be made from a thread that
//! drives asynchronous work: each request runs on the client's own runtime and the caller
//! waits for it, as it waits on a file. A request is bounded in time and an answer in size;
//! a bucket that does not answer is said unavailable, and nothing is answered from memory.

#[cfg(feature = "audit")]
pub mod audit;
#[cfg(feature = "backend")]
pub mod backend;
#[cfg(feature = "control-plane")]
pub mod control_plane;
#[cfg(feature = "backend")]
pub mod import;
mod listing;
mod sign;
#[cfg(feature = "streams")]
pub mod streams;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt as _, Full, Limited};
use zeroize::Zeroizing;

pub use listing::Listed;
use sign::{Signer, sha256_hex};

/// How the connection to the object store is protected.
#[derive(Clone)]
pub enum Tls {
    /// In the clear: refused unless the endpoint is a loopback address.
    Disabled,
    /// TLS, the store's certificate verified against these roots.
    Verified(Arc<rustls::RootCertStore>),
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disabled => "Disabled",
            Self::Verified(_) => "Verified",
        })
    }
}

/// How the object store encrypts what it is given, at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encryption {
    /// With keys the store manages (`AES256`).
    Managed,
    /// With the key of the store's key management service this names (`aws:kms`).
    Kms(String),
}

/// Where the bucket is and how it is reached.
#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    pub region: String,
    pub bucket: String,
    /// What every key of this client starts with, so that a bucket may hold more than one
    /// deployment; empty, or a path that ends with `/`.
    pub prefix: String,
    pub access_key: String,
    pub secret: Zeroizing<String>,
    /// The token of temporary credentials, when the credentials are temporary.
    pub session_token: Option<Zeroizing<String>>,
    pub encryption: Option<Encryption>,
    /// How long one request may take, connection included.
    pub timeout: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the credentials.
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("encryption", &self.encryption)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Why the object store did not do what it was asked.
#[derive(Debug)]
pub enum S3Error {
    /// The configuration cannot be used: nothing was sent.
    Config(String),
    /// The store was not reached, did not answer in time, or failed: the caller's subsystem is
    /// not ready. A write it did not answer may have been made all the same.
    Unavailable(String),
    /// The store answered and refused: its status and the code it gave, never the request.
    Refused { status: u16, code: String },
    /// The store answered something this build does not read as it expects.
    Record(String),
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(detail) => write!(f, "the object store's configuration: {detail}"),
            Self::Unavailable(detail) => write!(f, "the object store is not available: {detail}"),
            Self::Refused { status, code } => {
                write!(f, "the object store refused the request: {status} {code}")
            }
            Self::Record(detail) => write!(f, "the object store answered unreadably: {detail}"),
        }
    }
}

impl std::error::Error for S3Error {}

fn unavailable(detail: impl std::fmt::Display) -> S3Error {
    S3Error::Unavailable(detail.to_string())
}

/// What publishing under a key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    /// The object was written.
    Written,
    /// The key held an object already: nothing was written, and what it holds is as it was.
    Exists,
}

/// The most bytes an answer that is not an object may carry: an error, or a page of a listing.
const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// How many connections wait idle for the next request.
const IDLE: usize = 16;

type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

struct Inner {
    config: Config,
    tls: Option<tokio_rustls::TlsConnector>,
    /// The `Host` of every request.
    authority: String,
    /// The requests run here, on threads of the client's own.
    runtime: Option<tokio::runtime::Runtime>,
    idle: Mutex<Vec<Sender>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // The last holder may be a thread that drives asynchronous work: the runtime is let go
        // without waiting for it there.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// One request, as the caller states it.
struct Ask {
    method: Method,
    /// The key, without the client's prefix; empty for the bucket itself.
    key: String,
    query: Vec<(String, String)>,
    body: Bytes,
    /// Publish only where the key holds nothing.
    new: bool,
    /// The most bytes the answer may carry.
    limit: usize,
}

struct Answer {
    status: StatusCode,
    length: Option<u64>,
    body: Bytes,
}

/// The client of one bucket. Cloned freely: the clones share its connections.
#[derive(Clone)]
pub struct Bucket(Arc<Inner>);

impl std::fmt::Debug for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bucket").field(&self.0.config).finish()
    }
}

/// A key is a path of plain names: letters, digits, `.`, `_` and `-`, parted by `/`. Nothing a
/// request line or a signature could read two ways, and no name that climbs out of a prefix.
fn plain(key: &str) -> bool {
    !key.is_empty()
        && key.split('/').all(|name| {
            !name.is_empty()
                && name != "."
                && name != ".."
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

impl Bucket {
    /// The client of the bucket `config` names. Nothing is sent: [`Bucket::ready`] asks the
    /// store whether it answers.
    pub fn connect(config: Config) -> Result<Self, S3Error> {
        let refused = |detail: &str| Err(S3Error::Config(detail.to_owned()));
        if config.host.is_empty() || config.bucket.is_empty() || config.region.is_empty() {
            return refused("a host, a bucket and a region are named");
        }
        if !plain(&config.bucket) || config.bucket.contains('/') {
            return refused("the bucket is one plain name");
        }
        if !config.prefix.is_empty() && !config.prefix.strip_suffix('/').is_some_and(plain) {
            return refused("the prefix is a path of plain names that ends with `/`");
        }
        let tls = match &config.tls {
            Tls::Verified(roots) => Some(tokio_rustls::TlsConnector::from(Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|error| S3Error::Config(error.to_string()))?
                .with_root_certificates(Arc::clone(roots))
                .with_no_client_auth(),
            ))),
            Tls::Disabled => {
                let loopback = config.host == "localhost"
                    || config
                        .host
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback());
                if !loopback {
                    return refused("the connection is in the clear only to a loopback address");
                }
                None
            }
        };
        let default_port = if tls.is_some() { 443 } else { 80 };
        let authority = if config.port == default_port {
            config.host.clone()
        } else {
            format!("{}:{}", config.host, config.port)
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("permguard-s3")
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| unavailable(format!("starting the client's threads: {error}")))?;
        Ok(Self(Arc::new(Inner {
            config,
            tls,
            authority,
            runtime: Some(runtime),
            idle: Mutex::new(Vec::new()),
        })))
    }

    /// Whether the bucket answers now: what readiness asks.
    pub fn ready(&self) -> Result<(), S3Error> {
        let answer = self.call(Ask {
            method: Method::HEAD,
            key: String::new(),
            query: Vec::new(),
            body: Bytes::new(),
            new: false,
            limit: MAX_ANSWER_BYTES,
        })?;
        if answer.status.is_success() {
            Ok(())
        } else {
            Err(refusal(&answer))
        }
    }

    /// Publishes `bytes` under `key` where the key holds nothing: of the publications of one
    /// key that arrive together, on any instance, one is written and the others are answered
    /// [`Put::Exists`].
    pub fn put_new(&self, key: &str, bytes: &[u8]) -> Result<Put, S3Error> {
        let answer = self.call(Ask {
            method: Method::PUT,
            key: checked(key)?,
            query: Vec::new(),
            body: Bytes::copy_from_slice(bytes),
            new: true,
            limit: MAX_ANSWER_BYTES,
        })?;
        match answer.status {
            status if status.is_success() => Ok(Put::Written),
            StatusCode::PRECONDITION_FAILED => Ok(Put::Exists),
            _ => Err(refusal(&answer)),
        }
    }

    /// The object under `key`, whole; `None` when the key holds none. An object of more than
    /// `limit` bytes is not read.
    pub fn get(&self, key: &str, limit: usize) -> Result<Option<Vec<u8>>, S3Error> {
        let answer = self.call(Ask {
            method: Method::GET,
            key: checked(key)?,
            query: Vec::new(),
            body: Bytes::new(),
            new: false,
            limit,
        })?;
        match answer.status {
            status if status.is_success() => Ok(Some(answer.body.to_vec())),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(refusal(&answer)),
        }
    }

    /// The size of the object under `key`; `None` when the key holds none.
    pub fn head(&self, key: &str) -> Result<Option<u64>, S3Error> {
        let answer = self.call(Ask {
            method: Method::HEAD,
            key: checked(key)?,
            query: Vec::new(),
            body: Bytes::new(),
            new: false,
            limit: MAX_ANSWER_BYTES,
        })?;
        match answer.status {
            status if status.is_success() => answer.length.map(Some).ok_or_else(|| {
                S3Error::Record("an object was answered without its length".to_owned())
            }),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(refusal(&answer)),
        }
    }

    /// Removes the object under `key`; nothing when the key holds none.
    pub fn delete(&self, key: &str) -> Result<(), S3Error> {
        let answer = self.call(Ask {
            method: Method::DELETE,
            key: checked(key)?,
            query: Vec::new(),
            body: Bytes::new(),
            new: false,
            limit: MAX_ANSWER_BYTES,
        })?;
        if answer.status.is_success() || answer.status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(refusal(&answer))
        }
    }

    /// Every object whose key starts with `prefix`, in the order of the keys, each key without
    /// the client's own prefix. Every page is read: a listing is whole or it is an error.
    pub fn list(&self, prefix: &str) -> Result<Vec<Listed>, S3Error> {
        let prefix = if prefix.is_empty() {
            String::new()
        } else {
            match prefix.strip_suffix('/') {
                Some(path) if plain(path) => prefix.to_owned(),
                _ => {
                    return Err(S3Error::Config(
                        "a listing's prefix is a path of plain names that ends with `/`".to_owned(),
                    ));
                }
            }
        };
        let whole = format!("{}{prefix}", self.0.config.prefix);
        let mut listed = Vec::new();
        let mut from: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type".to_owned(), "2".to_owned()),
                ("prefix".to_owned(), whole.clone()),
            ];
            if let Some(token) = from.take() {
                query.push(("continuation-token".to_owned(), token));
            }
            let answer = self.call(Ask {
                method: Method::GET,
                key: String::new(),
                query,
                body: Bytes::new(),
                new: false,
                limit: MAX_ANSWER_BYTES,
            })?;
            if !answer.status.is_success() {
                return Err(refusal(&answer));
            }
            let xml = std::str::from_utf8(&answer.body)
                .map_err(|_| S3Error::Record("a listing is not text".to_owned()))?;
            let page = listing::page(xml).map_err(S3Error::Record)?;
            for mut object in page.objects {
                // A key outside what was asked for is an answer to another question.
                object.key = object
                    .key
                    .strip_prefix(&self.0.config.prefix)
                    .filter(|key| key.starts_with(&prefix))
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        S3Error::Record("a listing holds a key outside its prefix".to_owned())
                    })?;
                listed.push(object);
            }
            match page.next {
                Some(token) => from = Some(token),
                None => return Ok(listed),
            }
        }
    }

    /// Runs one request on the client's runtime and waits for its answer.
    fn call(&self, ask: Ask) -> Result<Answer, S3Error> {
        let Some(runtime) = self.0.runtime.as_ref() else {
            return Err(unavailable("the client is stopped"));
        };
        let (answered, answer) = mpsc::sync_channel(1);
        let inner = Arc::clone(&self.0);
        runtime.spawn(async move {
            let outcome = tokio::time::timeout(inner.config.timeout, inner.exchange(&ask)).await;
            let _ = answered.send(outcome.unwrap_or_else(|_| {
                Err(unavailable(format!(
                    "no answer in {:?}",
                    inner.config.timeout
                )))
            }));
        });
        answer
            .recv()
            .map_err(|_| unavailable("the client's threads stopped"))?
    }
}

fn checked(key: &str) -> Result<String, S3Error> {
    if plain(key) {
        Ok(key.to_owned())
    } else {
        Err(S3Error::Config(
            "an object's key is a path of plain names".to_owned(),
        ))
    }
}

/// What the store said when it refused: its status and its code, read from the answer.
fn refusal(answer: &Answer) -> S3Error {
    let text = String::from_utf8_lossy(&answer.body);
    let code = text
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.chars().filter(char::is_ascii_alphanumeric).collect())
        .unwrap_or_default();
    if answer.status.is_server_error() {
        return unavailable(format!("the store answered {} {code}", answer.status));
    }
    S3Error::Refused {
        status: answer.status.as_u16(),
        code,
    }
}

impl Inner {
    /// Sends `ask` and reads its answer: on a connection that waited idle when one does, and
    /// on a new one when that one turned out closed. Every request may be sent twice: a read,
    /// a removal and a publication where the key holds nothing say the same the second time.
    async fn exchange(&self, ask: &Ask) -> Result<Answer, S3Error> {
        let idle = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        if let Some(mut sender) = idle
            && sender.ready().await.is_ok()
            && let Ok(response) = sender.send_request(self.request(ask)?).await
        {
            return self.answer(ask, sender, response).await;
        }
        let mut sender = self.open().await?;
        let response = sender
            .send_request(self.request(ask)?)
            .await
            .map_err(|error| unavailable(format!("the request: {error}")))?;
        self.answer(ask, sender, response).await
    }

    async fn answer(
        &self,
        ask: &Ask,
        sender: Sender,
        response: http::Response<hyper::body::Incoming>,
    ) -> Result<Answer, S3Error> {
        let status = response.status();
        let length = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());
        // An object is read up to the caller's bound; anything else up to the client's.
        let limit = if status.is_success() {
            ask.limit
        } else {
            MAX_ANSWER_BYTES
        };
        let body = Limited::new(response.into_body(), limit)
            .collect()
            .await
            .map_err(|error| unavailable(format!("reading the answer: {error}")))?
            .to_bytes();
        // Read whole, the connection serves the next request.
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < IDLE && !sender.is_closed() {
            idle.push(sender);
        }
        Ok(Answer {
            status,
            length,
            body,
        })
    }

    async fn open(&self) -> Result<Sender, S3Error> {
        let tcp = tokio::net::TcpStream::connect((self.config.host.as_str(), self.config.port))
            .await
            .map_err(|error| unavailable(format!("reaching the store: {error}")))?;
        let _ = tcp.set_nodelay(true);
        match &self.tls {
            Some(tls) => {
                let name = rustls::pki_types::ServerName::try_from(self.config.host.clone())
                    .map_err(|error| S3Error::Config(format!("the store's host name: {error}")))?;
                let stream = tls
                    .connect(name, tcp)
                    .await
                    .map_err(|error| unavailable(format!("the TLS handshake: {error}")))?;
                handshake(hyper_util::rt::TokioIo::new(stream)).await
            }
            None => handshake(hyper_util::rt::TokioIo::new(tcp)).await,
        }
    }

    /// The request `ask` states, signed for this moment.
    fn request(&self, ask: &Ask) -> Result<http::Request<Full<Bytes>>, S3Error> {
        let config = &self.config;
        let path = if ask.key.is_empty() {
            format!("/{}", config.bucket)
        } else {
            format!("/{}/{}{}", config.bucket, config.prefix, ask.key)
        };
        let path = sign::encode(&path, true);
        let pairs: Vec<(&str, &str)> = ask
            .query
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let query = sign::query(&pairs);
        let at = permguard_core::time::to_rfc3339(
            i64::try_from(permguard_core::time::unix_now()).unwrap_or(i64::MAX),
        )
        .replace(['-', ':'], "");
        let payload = sha256_hex(&ask.body);

        let mut headers: Vec<(&str, String)> = vec![
            ("host", self.authority.clone()),
            ("x-amz-content-sha256", payload.clone()),
            ("x-amz-date", at.clone()),
        ];
        if ask.new {
            headers.push(("if-none-match", "*".to_owned()));
            match &config.encryption {
                Some(Encryption::Managed) => {
                    headers.push(("x-amz-server-side-encryption", "AES256".to_owned()));
                }
                Some(Encryption::Kms(key)) => {
                    headers.push(("x-amz-server-side-encryption", "aws:kms".to_owned()));
                    headers.push(("x-amz-server-side-encryption-aws-kms-key-id", key.clone()));
                }
                None => {}
            }
        }
        if let Some(token) = &config.session_token {
            headers.push(("x-amz-security-token", token.as_str().to_owned()));
        }
        let signed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let authorization = Signer {
            access_key: &config.access_key,
            secret: &config.secret,
            region: &config.region,
        }
        .authorization(ask.method.as_str(), &path, &query, &signed, &payload, &at);

        let uri = if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        };
        let mut request = http::Request::builder().method(ask.method.clone()).uri(uri);
        for (name, value) in &headers {
            let mut value = http::HeaderValue::from_str(value)
                .map_err(|_| S3Error::Config(format!("the header {name} is no header value")))?;
            // Marked sensitive, so no debug output of the request shows a credential.
            value.set_sensitive(*name == "x-amz-security-token");
            request = request.header(*name, value);
        }
        let mut authorization = http::HeaderValue::from_str(&authorization)
            .map_err(|_| S3Error::Config("the credentials are no header value".to_owned()))?;
        authorization.set_sensitive(true);
        request
            .header(http::header::AUTHORIZATION, authorization)
            .body(Full::new(ask.body.clone()))
            .map_err(|error| S3Error::Config(error.to_string()))
    }
}

async fn handshake<S>(stream: S) -> Result<Sender, S3Error>
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(stream)
        .await
        .map_err(|error| unavailable(format!("the connection: {error}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(host: &str, tls: Tls) -> Config {
        Config {
            host: host.to_owned(),
            port: 9000,
            tls,
            region: "us-east-1".to_owned(),
            bucket: "permguard".to_owned(),
            prefix: "lab/".to_owned(),
            access_key: "access".to_owned(),
            secret: Zeroizing::new("secret".to_owned()),
            session_token: None,
            encryption: None,
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn a_connection_in_the_clear_is_to_a_loopback_address_only() {
        for host in ["127.0.0.1", "::1", "localhost"] {
            assert!(
                Bucket::connect(config(host, Tls::Disabled)).is_ok(),
                "{host}"
            );
        }
        for host in ["10.0.0.7", "s3.example.com", "0.0.0.0"] {
            assert!(
                matches!(
                    Bucket::connect(config(host, Tls::Disabled)),
                    Err(S3Error::Config(_))
                ),
                "{host}"
            );
        }
    }

    #[test]
    fn a_key_is_a_path_of_plain_names() {
        for key in ["a", "zones/z1/ledgers/l1/objects/ab/cdef", "a.b_c-d"] {
            assert!(plain(key), "{key}");
        }
        for key in [
            "", "/a", "a/", "a//b", "a/../b", ".", "a b", "a?b", "a%2Fb", "a\nb",
        ] {
            assert!(!plain(key), "{key:?}");
        }
        let bucket = Bucket::connect(config("127.0.0.1", Tls::Disabled)).expect("a client");
        assert!(matches!(bucket.get("a/../b", 1), Err(S3Error::Config(_))));
        assert!(matches!(bucket.list("a"), Err(S3Error::Config(_))));
    }

    /// A publication asks the store to write only where the key holds nothing and to encrypt
    /// what it is given as the configuration says; both are signed with the request. No other
    /// request carries them.
    #[test]
    fn a_publication_is_conditional_and_asks_for_the_encryption_configured() {
        let ask = |new| Ask {
            method: if new { Method::PUT } else { Method::GET },
            key: "objects/ab/cd".to_owned(),
            query: Vec::new(),
            body: Bytes::from_static(b"x"),
            new,
            limit: 1,
        };
        for (encryption, expected) in [
            (None, vec![]),
            (
                Some(Encryption::Managed),
                vec![("x-amz-server-side-encryption", "AES256")],
            ),
            (
                Some(Encryption::Kms("key-1".to_owned())),
                vec![
                    ("x-amz-server-side-encryption", "aws:kms"),
                    ("x-amz-server-side-encryption-aws-kms-key-id", "key-1"),
                ],
            ),
        ] {
            let mut config = config("127.0.0.1", Tls::Disabled);
            config.encryption = encryption;
            let bucket = Bucket::connect(config).expect("a client");
            let publication = bucket.0.request(&ask(true)).expect("a request");
            assert_eq!(publication.uri().path(), "/permguard/lab/objects/ab/cd");
            assert_eq!(publication.headers()["if-none-match"], "*");
            let signed = publication.headers()["authorization"]
                .to_str()
                .expect("text")
                .to_owned();
            assert!(signed.contains("if-none-match"), "{signed}");
            for (name, value) in &expected {
                assert_eq!(publication.headers()[*name], *value);
                assert!(signed.contains(name), "{signed}");
            }
            let read = bucket.0.request(&ask(false)).expect("a request");
            assert!(!read.headers().contains_key("if-none-match"));
            assert!(!read.headers().contains_key("x-amz-server-side-encryption"));
        }
    }

    #[test]
    fn a_configuration_shows_no_credential() {
        let shown = format!("{:?}", config("127.0.0.1", Tls::Disabled));
        assert!(
            !shown.contains("secret") && !shown.contains("access"),
            "{shown}"
        );
    }
}
