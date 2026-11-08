// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Access tokens for a client (iteration 02, TC-7, `2-security/7` Access tokens): a service
//! account's application token, obtained at the IAM Host's token endpoint by its secret, a signed
//! assertion or its TLS client certificate, held while it serves and obtained again a minute before
//! it expires; or a person's, their session exchanged for it (RFC 8693). Nothing here prints,
//! traces or logs a token, a session, a secret or an assertion: `Debug` of every type that holds
//! one masks it.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use permguard_host::api::token_endpoint::{ACCESS_TOKEN_TYPE, CLIENT_CREDENTIALS, TOKEN_EXCHANGE};

use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::tls::{Credential, TlsOptions};

/// The token endpoint's path on the IAM Host's listener.
pub const TOKEN_PATH: &str = "/iam/v1/token";
/// How long before its `exp` a token is obtained again.
pub const REFRESH_AHEAD: Duration = Duration::from_secs(60);
/// How long a client assertion lives: the endpoint takes at most five minutes, and two leave room
/// for a client clock behind the Host's.
const ASSERTION_LIFETIME: u64 = 120;
/// Where the IAM Host publishes its token endpoint (RFC 8414).
const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
/// The assertion type of RFC 7523.
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How the client proves who it is.
pub enum Proof {
    /// A `client_secret`, sent as HTTP Basic.
    Secret(Credential),
    /// The private key of a `private_key_jwt` credential, PKCS#8 DER, Ed25519 or P-256: each
    /// request signs a fresh assertion.
    Key(Credential),
    /// The TLS client certificate the options carry: a `tls_client_auth` binding.
    Certificate,
    /// A person's password session or provider token, exchanged for the person's own token
    /// (RFC 8693): the subject of the exchange, with no client of its own.
    Session(Credential),
}

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Secret(_) => "Secret(********)",
            Self::Key(_) => "Key(********)",
            Self::Certificate => "Certificate",
            Self::Session(_) => "Session(********)",
        })
    }
}

/// What the token is for: its operations, the members it is addressed to and its targets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Asked {
    pub scope: String,
    pub audience: Vec<String>,
    pub target: Vec<String>,
}

/// A token, and when it stops serving (seconds since the epoch).
#[derive(Clone)]
pub struct Issued {
    pub token: Credential,
    pub expires_at: u64,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("token", &Credential::MASK)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A client's tokens from one IAM Host.
pub struct TokenSource {
    endpoint: Endpoint,
    client_id: String,
    proof: Proof,
    asked: Asked,
    tls: TlsOptions,
    timeout: Duration,
    held: Mutex<Option<Issued>>,
    /// The token endpoint the IAM Host names itself (RFC 8414), an assertion's `aud`: the URL a
    /// client typed may be another spelling of the same listener.
    audience: Mutex<Option<String>>,
}

impl std::fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSource")
            .field("endpoint", &self.endpoint.to_string())
            .field("client_id", &self.client_id)
            .field("proof", &self.proof)
            .field("asked", &self.asked)
            .finish_non_exhaustive()
    }
}

fn usage(detail: impl Into<String>) -> Failure {
    Failure {
        class: "validation".to_owned(),
        reason: permguard_core::codes::client::USAGE.to_owned(),
        detail: detail.into(),
        usage: true,
    }
}

fn unavailable(detail: impl Into<String>) -> Failure {
    Failure {
        class: "unavailable".to_owned(),
        reason: permguard_core::codes::common::UNAVAILABLE.to_owned(),
        detail: detail.into(),
        usage: false,
    }
}

fn refused(detail: impl Into<String>) -> Failure {
    Failure {
        class: "unauthenticated".to_owned(),
        reason: permguard_core::codes::common::UNAUTHENTICATED.to_owned(),
        detail: detail.into(),
        usage: false,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A form value, percent-encoded.
fn form(value: &str) -> String {
    crate::encode::value(value)
}

impl TokenSource {
    /// A source for `client_id` at the IAM Host `endpoint` (`https://`), proving itself by `proof`,
    /// asking for `asked`. The TLS options name the authority the IAM Host is checked against and
    /// the client certificate the connection presents, whatever the proof: the proof itself for
    /// [`Proof::Certificate`], the connection's beside any other; a bearer they carry is never sent
    /// here, a session being sent only as [`Proof::Session`]'s subject token.
    pub fn new(
        endpoint: Endpoint,
        client_id: &str,
        proof: Proof,
        asked: Asked,
        mut tls: TlsOptions,
        timeout: Duration,
    ) -> Result<Self, Failure> {
        if !endpoint.is_tls() {
            return Err(usage(
                "a token is obtained only over TLS: the IAM Host's endpoint is https://",
            ));
        }
        if client_id.trim().is_empty() && !matches!(proof, Proof::Session(_)) {
            return Err(usage("a client names its service account"));
        }
        if asked.scope.trim().is_empty() || asked.audience.is_empty() {
            return Err(usage(
                "a token names its scope and at least one audience (member:<id> or group:<name>)",
            ));
        }
        if tls.skip_verify {
            return Err(usage(
                "a client's proof is sent only over verified TLS: --tls-skip-verify would hand it \
                 to whoever answered; trust the IAM Host's authority instead",
            ));
        }
        if matches!(proof, Proof::Certificate) && tls.cert_file.is_none() && tls.key_pem.is_none() {
            return Err(usage(
                "a certificate proof needs the client certificate: --tls-cert-file and its key",
            ));
        }
        if let Proof::Key(key) = &proof {
            Signer::of(key.expose())?;
        }
        tls.token = None;
        Ok(Self {
            endpoint,
            client_id: client_id.to_owned(),
            proof,
            asked,
            tls,
            timeout,
            held: Mutex::new(None),
            audience: Mutex::new(None),
        })
    }

    /// The token to send: the one held while it serves past [`REFRESH_AHEAD`], otherwise a new
    /// one from the IAM Host.
    pub fn token(&self) -> Result<Issued, Failure> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(issued) = held.as_ref()
            && issued.expires_at > now() + REFRESH_AHEAD.as_secs()
        {
            return Ok(issued.clone());
        }
        let issued = self.obtain()?;
        *held = Some(issued.clone());
        Ok(issued)
    }

    /// Holds `issued`, a token obtained before and kept by the caller, when it still serves.
    pub fn hold(&self, issued: Issued) {
        if issued.expires_at > now() + REFRESH_AHEAD.as_secs() {
            *self
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(issued);
        }
    }

    fn obtain(&self) -> Result<Issued, Failure> {
        let grant_type = match self.proof {
            Proof::Session(_) => TOKEN_EXCHANGE,
            _ => CLIENT_CREDENTIALS,
        };
        let mut body = format!(
            "grant_type={}&scope={}",
            form(grant_type),
            form(&self.asked.scope)
        );
        for audience in &self.asked.audience {
            body.push_str(&format!("&audience={}", form(audience)));
        }
        for target in &self.asked.target {
            body.push_str(&format!("&target={}", form(target)));
        }
        let mut client = crate::http::Client::new(self.timeout, self.tls.clone(), true)
            .map_err(|error| usage(error.to_string()))?;
        match &self.proof {
            Proof::Secret(secret) => {
                let secret = std::str::from_utf8(secret.expose())
                    .map_err(|_| usage("the client secret is not text"))?;
                let pair = format!("{}:{}", form(&self.client_id), form(secret.trim()));
                client = client
                    .with_authorization(&format!("Basic {}", STANDARD.encode(pair)), true)
                    .map_err(|error| usage(error.to_string()))?;
            }
            Proof::Key(key) => {
                let audience = self.audience()?;
                let assertion = self.assertion(key.expose(), &audience)?;
                body.push_str(&format!(
                    "&client_id={}&client_assertion_type={}&client_assertion={}",
                    form(&self.client_id),
                    form(JWT_BEARER),
                    form(&assertion)
                ));
            }
            Proof::Certificate => {
                body.push_str(&format!("&client_id={}", form(&self.client_id)));
            }
            Proof::Session(session) => {
                let session = std::str::from_utf8(session.expose())
                    .map_err(|_| usage("the session is not text"))?;
                body.push_str(&format!(
                    "&subject_token={}&subject_token_type={}",
                    form(session.trim()),
                    form(ACCESS_TOKEN_TYPE)
                ));
            }
        }
        let answered = client
            .request_raw(
                &self.endpoint,
                "POST",
                TOKEN_PATH,
                "application/x-www-form-urlencoded",
                Some(body.as_bytes()),
            )
            .map_err(|error| unavailable(error.to_string()))?;
        let parsed: Option<serde_json::Value> = serde_json::from_slice(&answered.body).ok();
        if answered.status != 200 {
            // RFC 6749 §5.2: the error and its description, never anything the client sent, and
            // never a control character a terminal would act on.
            let printable = |text: &str| -> String {
                text.chars().filter(|c| !c.is_control()).take(256).collect()
            };
            let error = parsed
                .as_ref()
                .and_then(|value| value["error"].as_str())
                .map_or_else(|| format!("http_{}", answered.status), printable);
            let description = parsed
                .as_ref()
                .and_then(|value| value["error_description"].as_str())
                .map(printable)
                .unwrap_or_default();
            let class = match answered.status {
                401 => "unauthenticated",
                400 | 403 => "validation",
                _ => "unavailable",
            };
            return Err(Failure {
                class: class.to_owned(),
                reason: error.clone(),
                detail: format!("the IAM Host refused the token: {error} {description}")
                    .trim()
                    .to_owned(),
                usage: false,
            });
        }
        let Some(parsed) = parsed else {
            return Err(unavailable(
                "the IAM Host answered something that is not a token answer",
            ));
        };
        let (Some(token), Some(expires_in)) = (
            parsed["access_token"].as_str(),
            parsed["expires_in"].as_u64(),
        ) else {
            return Err(refused("the token endpoint answered no access token"));
        };
        Ok(Issued {
            token: Credential::new(token.as_bytes().to_vec()),
            expires_at: now().saturating_add(expires_in),
        })
    }

    /// A fresh RFC 7523 assertion: `iss` and `sub` the client, `aud` the token endpoint, a
    /// random `jti`, a minute of life, `kid` the key's RFC 7638 thumbprint.
    /// The token endpoint the IAM Host publishes, held once read.
    fn audience(&self) -> Result<String, Failure> {
        let mut held = self
            .audience
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(audience) = held.as_ref() {
            return Ok(audience.clone());
        }
        let client = crate::http::Client::new(self.timeout, self.tls.clone(), true)
            .map_err(|error| usage(error.to_string()))?;
        let answered = client
            .request_raw(
                &self.endpoint,
                "GET",
                METADATA_PATH,
                "application/json",
                None,
            )
            .map_err(|error| unavailable(error.to_string()))?;
        let metadata: serde_json::Value = serde_json::from_slice(&answered.body)
            .ok()
            .filter(|_| answered.status == 200)
            .ok_or_else(|| {
                unavailable("the IAM Host publishes no authorization server metadata")
            })?;
        let audience = metadata["token_endpoint"]
            .as_str()
            .filter(|endpoint| endpoint.starts_with("https://"))
            .ok_or_else(|| unavailable("the IAM Host's metadata names no https token endpoint"))?
            .to_owned();
        *held = Some(audience.clone());
        Ok(audience)
    }

    fn assertion(&self, key: &[u8], audience: &str) -> Result<String, Failure> {
        let signer = Signer::of(key)?;
        let issued_at = now();
        let mut jti = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut jti)
            .map_err(|_| usage("no randomness for the assertion's jti"))?;
        let header =
            serde_json::json!({"alg": signer.alg(), "kid": signer.thumbprint(), "typ": "JWT"});
        let claims = serde_json::json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": audience,
            "jti": URL_SAFE_NO_PAD.encode(jti),
            "iat": issued_at,
            "exp": issued_at + ASSERTION_LIFETIME,
        });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = signer.sign(signing_input.as_bytes())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

/// A `private_key_jwt` key: Ed25519 or P-256, from its PKCS#8 bytes (DER or PEM).
enum Signer {
    Ed25519(ring::signature::Ed25519KeyPair),
    P256(ring::signature::EcdsaKeyPair),
}

impl Signer {
    fn of(key: &[u8]) -> Result<Self, Failure> {
        use rustls::pki_types::pem::PemObject as _;

        let der = match rustls::pki_types::PrivateKeyDer::from_pem_slice(key) {
            Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(der)) => der.secret_pkcs8_der().to_vec(),
            Ok(_) => return Err(usage("the client key is PKCS#8: `BEGIN PRIVATE KEY`")),
            Err(_) => key.to_vec(),
        };
        if let Ok(pair) = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der) {
            return Ok(Self::Ed25519(pair));
        }
        ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &der,
            &ring::rand::SystemRandom::new(),
        )
        .map(Self::P256)
        .map_err(|_| usage("the client key is neither an Ed25519 nor a P-256 PKCS#8 key"))
    }

    fn alg(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "EdDSA",
            Self::P256(_) => "ES256",
        }
    }

    /// The RFC 7638 thumbprint of the public key: the `kid` the IAM Host holds the credential
    /// under, computed by the IAM Host's own definition.
    fn thumbprint(&self) -> String {
        use ring::signature::KeyPair as _;

        let public = match self {
            Self::Ed25519(pair) => pair.public_key().as_ref().to_vec(),
            Self::P256(pair) => pair.public_key().as_ref().to_vec(),
        };
        permguard_host::authz::credentials::thumbprint(self.alg(), &public).unwrap_or_default()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Failure> {
        match self {
            Self::Ed25519(pair) => Ok(pair.sign(message).as_ref().to_vec()),
            Self::P256(pair) => pair
                .sign(&ring::rand::SystemRandom::new(), message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| usage("the assertion could not be signed")),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn source(proof: Proof) -> Result<TokenSource, Failure> {
        TokenSource::new(
            Endpoint::parse("https://iam.example:5444").expect("an endpoint"),
            "billing",
            proof,
            Asked {
                scope: "decision.evaluate".to_owned(),
                audience: vec!["group:eu".to_owned()],
                target: vec!["plane/data/*".to_owned()],
            },
            TlsOptions::default(),
            Duration::from_secs(5),
        )
    }

    /// A key's assertion verifies under its public key, names the client and the endpoint, and is
    /// held by the thumbprint the IAM Host computes from the same key.
    #[test]
    fn an_assertion_is_signed_by_the_key_and_named_by_its_thumbprint() {
        use ring::signature::KeyPair as _;

        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .expect("a key");
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a pair");
        let source =
            source(Proof::Key(Credential::new(pkcs8.as_ref().to_vec()))).expect("a source");
        let assertion = source
            .assertion(pkcs8.as_ref(), "https://iam.example:5444/iam/v1/token")
            .expect("an assertion");
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            pair.public_key().as_ref(),
        )
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).expect("base64url"),
        )
        .expect("the signature verifies");
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("b64")).expect("json");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("b64")).expect("json");
        assert_eq!(header["alg"], "EdDSA");
        let jwk = std::collections::BTreeMap::from([
            ("kty".to_owned(), "OKP".to_owned()),
            ("crv".to_owned(), "Ed25519".to_owned()),
            (
                "x".to_owned(),
                URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            ),
        ]);
        let held = permguard_host::authz::credentials::public_key(&jwk).expect("a public key");
        assert_eq!(
            header["kid"].as_str(),
            Some(held.key_id.as_str()),
            "the IAM Host's own kid for this key"
        );
        assert_eq!(
            (claims["iss"].clone(), claims["sub"].clone()),
            ("billing".into(), "billing".into())
        );
        assert_eq!(claims["aud"], "https://iam.example:5444/iam/v1/token");
        assert!(claims["exp"].as_u64() > claims["iat"].as_u64());
    }

    /// What a source refuses before it sends anything, and what it never shows.
    #[test]
    fn a_source_refuses_the_clear_an_empty_ask_and_shows_no_secret() {
        let clear = TokenSource::new(
            Endpoint::parse("http://iam.example:5443").expect("an endpoint"),
            "billing",
            Proof::Secret(Credential::new(b"pgc_secret".to_vec())),
            Asked {
                scope: "decision.evaluate".to_owned(),
                audience: vec!["group:eu".to_owned()],
                target: Vec::new(),
            },
            TlsOptions::default(),
            Duration::from_secs(5),
        );
        assert!(
            clear.is_err_and(|failure| failure.detail.contains("only over TLS")),
            "a secret never travels in the clear"
        );
        assert!(
            source(Proof::Key(Credential::new(b"not a key".to_vec())))
                .is_err_and(|failure| failure.detail.contains("PKCS#8")),
        );
        assert!(
            source(Proof::Certificate).is_err_and(|failure| failure.detail.contains("certificate")),
            "no certificate configured"
        );
        // No proof, a secret or a signed assertion alike, is sent where the IAM Host is not
        // verified.
        for proof in [
            Proof::Secret(Credential::new(b"pgc_secret".to_vec())),
            Proof::Key(Credential::new(
                ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .expect("a key")
                    .as_ref()
                    .to_vec(),
            )),
        ] {
            let skipped = TokenSource::new(
                Endpoint::parse("https://iam.example:5444").expect("an endpoint"),
                "billing",
                proof,
                Asked {
                    scope: "decision.evaluate".to_owned(),
                    audience: vec!["group:eu".to_owned()],
                    target: Vec::new(),
                },
                TlsOptions {
                    skip_verify: true,
                    ..TlsOptions::default()
                },
                Duration::from_secs(5),
            );
            assert!(
                skipped.is_err_and(|failure| failure.detail.contains("--tls-skip-verify")),
                "refused under --tls-skip-verify"
            );
        }
        let held =
            source(Proof::Secret(Credential::new(b"pgc_topsecret".to_vec()))).expect("a source");
        let shown = format!("{held:?}");
        assert!(!shown.contains("pgc_topsecret"), "{shown}");
        held.hold(Issued {
            token: Credential::new(b"eyJ.the.token".to_vec()),
            expires_at: now() + 3_600,
        });
        let issued = held.token().expect("the held token serves");
        assert_eq!(issued.token.expose(), b"eyJ.the.token");
        assert!(!format!("{issued:?}").contains("eyJ"));
        // One about to expire is not held: the next call would obtain another.
        let expiring = source(Proof::Secret(Credential::new(b"s".to_vec()))).expect("a source");
        expiring.hold(Issued {
            token: Credential::new(b"old".to_vec()),
            expires_at: now() + 30,
        });
        assert!(expiring.held.lock().expect("lock").is_none());
    }
}
