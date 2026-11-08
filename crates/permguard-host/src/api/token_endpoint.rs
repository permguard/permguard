// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The IAM Host's token endpoint (iteration 02, WP-11.4, `2-security/8` Token endpoint):
//! `POST /iam/v1/token`, RFC 6749 with the profile of RFC 9068.
//!
//! | `grant_type`                                       | Client proof                                                   |
//! | -------------------------------------------------- | -------------------------------------------------------------- |
//! | `client_credentials`                               | Basic secret, `client_assertion` (RFC 7523) or the certificate |
//! | `urn:ietf:params:oauth:grant-type:token-exchange`  | `subject_token`: a password session or a provider's token      |
//!
//! A token is issued only within what its subject may do at that moment, in the IAM Host's
//! grants, and carries one family: an `application` token never administers a Host. A refusal says
//! which rule of the protocol failed, never which grant is missing.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_core::authz::{Principal, Resource, Selector, operations};

use super::HostApi;
use super::tokens::{TENANT, Tokens};
use crate::authz::credentials;
use crate::authz::directory::{
    AccountStatus, CredentialMaterial, ServiceAccount, UserStatus, service_account_principal,
    user_principal,
};
use crate::authz::tokens::{IssuedToken, TokenDraft};
use crate::identity::record::uuid_text;

/// `client_credentials`.
pub const CLIENT_CREDENTIALS: &str = "client_credentials";
/// RFC 8693's token exchange.
pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693's access token type: what a subject token is.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 7523's client assertion type.
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The families of a token.
pub const APPLICATION: &str = permguard_core::authz::families::APPLICATION;
pub const ADMINISTRATION: &str = permguard_core::authz::families::ADMINISTRATION;
/// The operations of an `application` token.
pub const APPLICATION_OPERATIONS: &[&str] =
    &[operations::DECISION_EVALUATE, operations::EVENT_SUBMIT];
/// The per-Host operations of a member an `administration` token may carry.
pub const ADMINISTRATION_OPERATIONS: &[&str] = &[
    operations::IDENTITY_READ,
    operations::IDENTITY_ADMIN,
    operations::KEYS_READ,
    operations::KEYS_ADMIN,
    operations::MEMBERSHIP_READ,
    operations::MEMBERSHIP_ADMIN,
    operations::CONFIG_READ,
    operations::LIFECYCLE_READ,
    operations::BACKUP_READ,
    operations::BACKUP_MANAGE,
    operations::AUDIT_READ,
    operations::STREAMS_READ,
    operations::GC_MANAGE,
];
/// The most bytes an access token takes.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// The most selectors a token's target names.
pub const MAX_TARGETS: usize = 64;
/// The most bytes a client assertion takes, checked before it is split.
pub const MAX_ASSERTION_BYTES: usize = 8 * 1024;
/// The longest a client assertion may live, from now: a short one keeps its replay window small.
pub const MAX_ASSERTION_LIFETIME: u64 = 300;
/// Requests per minute a client may make, and a source address.
pub const CLIENT_REQUESTS_PER_MINUTE: u32 = 60;
pub const SOURCE_REQUESTS_PER_MINUTE: u32 = 300;

/// The lifetimes of a family: its default and its bound, seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    pub application_default: u64,
    pub application_max: u64,
    pub administration_default: u64,
    pub administration_max: u64,
    /// Whether an administration token is bound to its client's certificate (`cnf`, RFC 8705):
    /// required under `regulated`.
    pub administration_bound: bool,
}

impl Lifetimes {
    /// The profile's bounds (`2-security/8` Families, Profiles).
    pub fn of(profile: permguard_core::assurance::AssuranceProfile) -> Self {
        let regulated = profile == permguard_core::assurance::AssuranceProfile::Regulated;
        Self {
            application_default: 3_600,
            application_max: if regulated { 3_600 } else { 24 * 3_600 },
            administration_default: 600,
            administration_max: 900,
            administration_bound: regulated,
        }
    }
}

/// What a token request carries, its form fields read once.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TokenRequest {
    pub grant_type: String,
    pub scope: Option<String>,
    pub audience: Vec<String>,
    pub target: Vec<String>,
    pub requested_lifetime: Option<String>,
    pub client_id: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
}

/// Never an assertion or a subject token: whether the request holds one.
impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("scope", &self.scope)
            .field("audience", &self.audience)
            .field("target", &self.target)
            .field("client_id", &self.client_id)
            .field(
                "client_assertion",
                &self.client_assertion.as_ref().map(|_| "<set>"),
            )
            .field(
                "subject_token",
                &self.subject_token.as_ref().map(|_| "<set>"),
            )
            .finish_non_exhaustive()
    }
}

impl TokenRequest {
    /// Reads an `application/x-www-form-urlencoded` body: each member once, `audience` and
    /// `target` repeatable, an unknown member ignored as RFC 6749 asks.
    pub fn from_form(pairs: Vec<(String, String)>) -> Result<Self, TokenRefusal> {
        let mut request = Self::default();
        let mut seen = BTreeSet::new();
        for (name, value) in pairs {
            let once = |field: &mut Option<String>, seen: &mut BTreeSet<String>| {
                if !seen.insert(name.clone()) {
                    return Err(TokenRefusal::InvalidRequest(format!(
                        "`{name}` is given more than once"
                    )));
                }
                *field = Some(value.clone());
                Ok(())
            };
            match name.as_str() {
                "grant_type" => {
                    let mut grant = None;
                    once(&mut grant, &mut seen)?;
                    request.grant_type = grant.unwrap_or_default();
                }
                "scope" => once(&mut request.scope, &mut seen)?,
                "requested_lifetime" => once(&mut request.requested_lifetime, &mut seen)?,
                "client_id" => once(&mut request.client_id, &mut seen)?,
                "client_assertion_type" => once(&mut request.client_assertion_type, &mut seen)?,
                "client_assertion" => once(&mut request.client_assertion, &mut seen)?,
                "subject_token" => once(&mut request.subject_token, &mut seen)?,
                "subject_token_type" => once(&mut request.subject_token_type, &mut seen)?,
                "client_secret" => {
                    return Err(TokenRefusal::InvalidRequest(
                        "a client secret travels in the Authorization header, client_secret_basic"
                            .to_owned(),
                    ));
                }
                "audience" => request.audience.push(value),
                "target" | "resource" => request.target.push(value),
                _ => {}
            }
        }
        Ok(request)
    }
}

/// What the connection proves of the client beside the form: its Basic credentials and its
/// certificate.
#[derive(Clone, Default)]
pub struct ClientProof {
    /// `client_secret_basic`: the client id and secret, form-decoded.
    pub basic: Option<(String, String)>,
    /// The TLS client certificate's SPKI digest, `spki:sha256:<hex>`.
    pub spki: Option<String>,
    /// The TLS client certificate's SAN URIs.
    pub san_uris: Vec<String>,
    /// The TLS client certificate's SHA-256, lowercase hex: what `cnf.x5t#S256` binds.
    pub certificate_sha256: Option<String>,
    /// The address the request came from, for the per-source bound.
    pub source: Option<String>,
}

/// Never the secret: whether Basic credentials were given, and for which client.
impl std::fmt::Debug for ClientProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProof")
            .field(
                "basic",
                &self.basic.as_ref().map(|(id, _)| (id, "<secret>")),
            )
            .field("spki", &self.spki)
            .field("san_uris", &self.san_uris)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// What an issued token answers (RFC 6749 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TokenAnswer {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

/// Why a token was not issued, as RFC 6749 §5.2 names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRefusal {
    /// `401`: the client's proof failed.
    InvalidClient(String),
    /// `400`.
    InvalidRequest(String),
    /// `400`: an exchanged subject token that is not one.
    InvalidGrant(String),
    /// `400`: what may not be issued for the scope.
    InvalidScope(String),
    /// `400`: an audience or a target that may not be named.
    InvalidTarget(String),
    UnsupportedGrantType(String),
    /// `429`, with the seconds after which to come back.
    TooManyRequests(u64),
    /// `503`.
    Unavailable(String),
}

impl TokenRefusal {
    /// The RFC 6749 `error`.
    pub fn error(&self) -> &'static str {
        match self {
            Self::InvalidClient(_) => "invalid_client",
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidScope(_) => "invalid_scope",
            Self::InvalidTarget(_) => "invalid_target",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::TooManyRequests(_) => "slow_down",
            Self::Unavailable(_) => "temporarily_unavailable",
        }
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidClient(_) => 401,
            Self::TooManyRequests(_) => 429,
            Self::Unavailable(_) => 503,
            _ => 400,
        }
    }

    /// The description: the rule that failed, never the grant that is missing.
    pub fn description(&self) -> &str {
        match self {
            Self::TooManyRequests(_) => "too many requests: come back after Retry-After",
            Self::InvalidClient(detail)
            | Self::InvalidRequest(detail)
            | Self::InvalidGrant(detail)
            | Self::InvalidScope(detail)
            | Self::InvalidTarget(detail)
            | Self::UnsupportedGrantType(detail)
            | Self::Unavailable(detail) => detail,
        }
    }
}

/// The client's requests within the current minute, per client and per source.
/// The most keys one minute counts: past it, the minute refuses every new key, so a flood of
/// distinct sources cannot grow the map without bound.
const MAX_WINDOW_KEYS: usize = 100_000;

#[derive(Default)]
pub(super) struct Limiter {
    /// The minute counted and each key's requests in it; a new minute starts empty.
    window: Mutex<(u64, HashMap<String, u32>)>,
}

impl Limiter {
    /// Counts one request of `key` at `now`, refusing past `limit` in the minute.
    pub(super) fn admit(&self, key: String, limit: u32, now: u64) -> Result<(), TokenRefusal> {
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        let minute = now / 60;
        if window.0 != minute {
            *window = (minute, HashMap::new());
        }
        let wait = TokenRefusal::TooManyRequests(60 - now % 60);
        if !window.1.contains_key(&key) && window.1.len() >= MAX_WINDOW_KEYS {
            return Err(wait);
        }
        let count = window.1.entry(key).or_insert(0);
        if *count >= limit {
            return Err(wait);
        }
        *count += 1;
        Ok(())
    }
}

/// The client assertions seen, each refused a second time within its lifetime.
#[derive(Default)]
pub(super) struct Replays {
    seen: Mutex<HashMap<(String, String), u64>>,
}

impl Replays {
    fn first_use(&self, account: &str, jti: &str, expires_at: u64, now: u64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, until| *until > now);
        seen.insert((account.to_owned(), jti.to_owned()), expires_at)
            .is_none()
    }
}

/// Who a request is for, once its proof held.
struct Subject {
    principal: Principal,
    client_id: String,
    account: Option<ServiceAccount>,
    credential_id: Option<[u8; 16]>,
    /// The latest a token for it may expire: its credential's expiry, its session's end.
    expires_by: Option<u64>,
}

fn client_failed() -> TokenRefusal {
    TokenRefusal::InvalidClient("the client could not be authenticated".to_owned())
}

/// Lowercase hex, two characters a byte.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    hex.len()
        .is_multiple_of(2)
        .then(|| {
            (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
                .collect()
        })
        .flatten()
}

fn decode_part(part: &str) -> Option<serde_json::Value> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}

impl HostApi {
    /// `POST /iam/v1/token`: authenticates the client or the exchanged subject, checks what is
    /// asked against what the subject may do now, and issues one token of one family.
    pub fn issue_token(
        &self,
        request: &TokenRequest,
        proof: &ClientProof,
    ) -> Result<TokenAnswer, TokenRefusal> {
        let tokens = self
            .tokens
            .as_deref()
            .ok_or_else(|| TokenRefusal::Unavailable("no token registry is open".to_owned()))?;
        let now = self.time.now_secs();
        if let Some(source) = &proof.source {
            tokens
                .limiter
                .admit(format!("source:{source}"), SOURCE_REQUESTS_PER_MINUTE, now)?;
        }
        // A client is counted by the name it claims, before anything is hashed or verified: a
        // failing guess spends its client's budget as a success does.
        let claimed = proof
            .basic
            .as_ref()
            .map(|(id, _)| id.clone())
            .or_else(|| request.client_id.clone())
            .or_else(|| {
                request
                    .client_assertion
                    .as_deref()
                    .and_then(|jwt| jwt.split('.').nth(1))
                    .and_then(decode_part)
                    .and_then(|claims| claims.get("sub")?.as_str().map(str::to_owned))
            })
            .unwrap_or_else(|| "exchange".to_owned());
        tokens
            .limiter
            .admit(format!("client:{claimed}"), CLIENT_REQUESTS_PER_MINUTE, now)?;
        let subject = match request.grant_type.as_str() {
            CLIENT_CREDENTIALS => self.authenticate_client(tokens, request, proof, now),
            TOKEN_EXCHANGE => self.exchanged_subject(request),
            other => Err(TokenRefusal::UnsupportedGrantType(format!(
                "`{other}` is not a grant type this endpoint serves"
            ))),
        };
        let subject = match subject {
            Ok(subject) => subject,
            Err(refusal) => {
                self.record_refusal(&claimed, &refusal);
                return Err(refusal);
            }
        };
        let answer = self.mint(tokens, request, &subject, proof, now);
        if let Err(refusal) = &answer {
            self.record_refusal(&claimed, refusal);
        }
        // The subject and its client are the audit's to name, never the log's.
        match &answer {
            Ok(issued) => tracing::info!(
                event.name = "iam.token_issued",
                component = super::COMPONENT,
                scope = %issued.scope,
                expires_in = issued.expires_in,
                "an access token was issued"
            ),
            Err(refusal) => tracing::info!(
                event.name = "iam.token_refused",
                component = super::COMPONENT,
                error = refusal.error(),
                "a token request was refused"
            ),
        }
        answer
    }

    /// The service account a `client_credentials` request proves, by exactly one proof.
    fn authenticate_client(
        &self,
        tokens: &Tokens,
        request: &TokenRequest,
        proof: &ClientProof,
        now: u64,
    ) -> Result<Subject, TokenRefusal> {
        let identities = self
            .identities
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no directory is open".to_owned()))?;
        let assertion =
            request.client_assertion.is_some() || request.client_assertion_type.is_some();
        let certificate = !assertion && proof.basic.is_none();
        if proof.basic.is_some() && assertion {
            return Err(TokenRefusal::InvalidRequest(
                "one client proof: a secret or an assertion, not both".to_owned(),
            ));
        }
        let name = match (&proof.basic, &request.client_id) {
            (Some((basic, _)), Some(form)) if basic != form => {
                return Err(TokenRefusal::InvalidRequest(
                    "the client_id differs from the Basic credentials'".to_owned(),
                ));
            }
            (Some((basic, _)), _) => basic.clone(),
            (None, Some(form)) => form.clone(),
            (None, None) if assertion => String::new(),
            (None, None) => {
                return Err(TokenRefusal::InvalidClient(
                    "no client proof: a secret, an assertion or a certificate with client_id"
                        .to_owned(),
                ));
            }
        };
        if let Some((_, secret)) = &proof.basic {
            // An unknown account, a malformed secret and an account holding no secret each cost
            // one Argon2id, as a wrong secret against one credential does: the answer's time
            // says no more than its content. An account holding several secrets costs one each.
            let account = identities.directory.service_account(&name);
            let secrets: Vec<(crate::authz::directory::Credential, String)> = account
                .as_ref()
                .filter(|_| credentials::is_secret(secret))
                .map(|account| {
                    account
                        .live_credentials(now)
                        .filter_map(|credential| match &credential.material {
                            CredentialMaterial::Secret { phc } => {
                                Some((credential.clone(), phc.clone()))
                            }
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            if secrets.is_empty() {
                crate::authz::password::burn(secret);
                return Err(client_failed());
            }
            let matched = secrets
                .into_iter()
                .find(|(_, phc)| crate::authz::password::verify(secret, phc));
            let (Some(account), Some((credential, _))) = (account, matched) else {
                return Err(client_failed());
            };
            return active_subject(account, &credential);
        }
        if assertion {
            if request.client_assertion_type.as_deref() != Some(JWT_BEARER) {
                return Err(TokenRefusal::InvalidRequest(format!(
                    "client_assertion_type is `{JWT_BEARER}`"
                )));
            }
            let jwt = request
                .client_assertion
                .as_deref()
                .ok_or_else(|| TokenRefusal::InvalidRequest("no client_assertion".to_owned()))?;
            return self.assertion_subject(tokens, jwt, &name, now);
        }
        if certificate {
            let account = identities
                .directory
                .service_account(&name)
                .ok_or_else(client_failed)?;
            // An SPKI binding matches the certificate's key, a SAN URI binding its SAN URIs: a SAN
            // URI spelled as a digest never matches a key.
            let matches = |binding: &str| {
                if binding.starts_with("spki:sha256:") {
                    proof.spki.as_deref() == Some(binding)
                } else {
                    proof.san_uris.iter().any(|uri| uri == binding)
                }
            };
            let credential = account
                .live_credentials(now)
                .find(|credential| {
                    matches!(&credential.material, CredentialMaterial::Binding { binding }
                        if matches(binding))
                })
                .cloned()
                .ok_or_else(client_failed)?;
            return active_subject(account, &credential);
        }
        Err(client_failed())
    }

    /// The service account a client assertion proves (RFC 7523 §3).
    fn assertion_subject(
        &self,
        tokens: &Tokens,
        jwt: &str,
        client_id: &str,
        now: u64,
    ) -> Result<Subject, TokenRefusal> {
        let identities = self
            .identities
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no directory is open".to_owned()))?;
        if jwt.len() > MAX_ASSERTION_BYTES {
            return Err(client_failed());
        }
        let mut parts = jwt.split('.');
        let (Some(protected), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(client_failed());
        };
        let header = decode_part(protected).ok_or_else(client_failed)?;
        let claims = decode_part(payload).ok_or_else(client_failed)?;
        let text = |value: &serde_json::Value, name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let (Some(alg), Some(kid)) = (text(&header, "alg"), text(&header, "kid")) else {
            return Err(client_failed());
        };
        let (Some(issuer), Some(subject), Some(jti)) = (
            text(&claims, "iss"),
            text(&claims, "sub"),
            text(&claims, "jti"),
        ) else {
            return Err(client_failed());
        };
        if issuer != subject || (!client_id.is_empty() && client_id != subject) {
            return Err(client_failed());
        }
        let endpoint = format!("{}/iam/v1/token", tokens.base_url);
        let audience_holds = match claims.get("aud") {
            Some(serde_json::Value::String(one)) => *one == endpoint || *one == tokens.issuer,
            Some(serde_json::Value::Array(many)) => many.iter().any(|one| {
                one.as_str()
                    .is_some_and(|one| one == endpoint || one == tokens.issuer)
            }),
            _ => false,
        };
        let expires_at = claims.get("exp").and_then(serde_json::Value::as_u64);
        let Some(expires_at) =
            expires_at.filter(|exp| *exp > now && *exp <= now + MAX_ASSERTION_LIFETIME)
        else {
            return Err(client_failed());
        };
        if !audience_holds || jti.is_empty() || jti.len() > 128 {
            return Err(client_failed());
        }
        let account = identities
            .directory
            .service_account(&subject)
            .ok_or_else(client_failed)?;
        let credential = account
            .live_credentials(now)
            .find(|credential| {
                matches!(&credential.material, CredentialMaterial::Key { key_id, algorithm, .. }
                    if *key_id == kid && *algorithm == alg)
            })
            .cloned()
            .ok_or_else(client_failed)?;
        let CredentialMaterial::Key { key, .. } = &credential.material else {
            return Err(client_failed());
        };
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| client_failed())?;
        let algorithm: &dyn ring::signature::VerificationAlgorithm = match alg.as_str() {
            credentials::EDDSA => &ring::signature::ED25519,
            credentials::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED,
            _ => return Err(client_failed()),
        };
        ring::signature::UnparsedPublicKey::new(algorithm, key)
            .verify(format!("{protected}.{payload}").as_bytes(), &signature)
            .map_err(|_| client_failed())?;
        // Verified, then recorded: an assertion is used once within its lifetime.
        if !tokens.replays.first_use(&subject, &jti, expires_at, now) {
            return Err(client_failed());
        }
        active_subject(account, &credential)
    }

    /// The person a token exchange is for: a password session, or a provider's token.
    fn exchanged_subject(&self, request: &TokenRequest) -> Result<Subject, TokenRefusal> {
        let identities = self
            .identities
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no directory is open".to_owned()))?;
        let token = request
            .subject_token
            .as_deref()
            .ok_or_else(|| TokenRefusal::InvalidRequest("no subject_token".to_owned()))?;
        // RFC 8693 §2.1: the type is stated, and the only one served is an access token, which a
        // password session and a provider's token both are.
        if request.subject_token_type.as_deref() != Some(ACCESS_TOKEN_TYPE) {
            return Err(TokenRefusal::InvalidRequest(format!(
                "subject_token_type is `{ACCESS_TOKEN_TYPE}`"
            )));
        }
        let invalid = || TokenRefusal::InvalidGrant("the subject token is not valid".to_owned());
        if let Some(signin) = &identities.signin
            && let Some(session) = signin.session(token)
        {
            // A session that serves only the enrollment of a second factor proves a password
            // alone, which is what the factor is there to refuse: it is exchanged for nothing.
            if session.opened == crate::authz::sessions::Opened::EnrollFactor {
                return Err(invalid());
            }
            let user = identities
                .directory
                .user(&session.user)
                .filter(|user| user.status == UserStatus::Active)
                .ok_or_else(invalid)?;
            return Ok(Subject {
                principal: Principal::new(user_principal(&user.name)).map_err(|_| invalid())?,
                client_id: "password-session".to_owned(),
                account: None,
                credential_id: None,
                expires_by: Some(session.expires_at),
            });
        }
        // A provider's token, only where `oidc` is among the deployment's methods, and as the
        // mapper reads it: the user its subject is linked to, or whose email it verifies when the
        // provider links by email; a disabled user is refused, never its bare subject.
        let providers: &[std::sync::Arc<crate::authz::oidc::Verifier>] =
            if identities.exchange_provider_tokens {
                &identities.providers
            } else {
                &[]
            };
        for verifier in providers {
            if let Ok(Some(verified)) = verifier.verify_token(token) {
                let subject = verified.context.authorization_principal().clone();
                let linked = identities
                    .directory
                    .user_of_subject(subject.as_str())
                    .or_else(|| {
                        verifier
                            .rule()
                            .link_email
                            .then(|| {
                                verified
                                    .verified_email
                                    .as_deref()
                                    .and_then(|email| identities.directory.user_by_email(email))
                            })
                            .flatten()
                    });
                let principal = match linked {
                    Some(user) if user.status == UserStatus::Active => {
                        Principal::new(user_principal(&user.name)).map_err(|_| invalid())?
                    }
                    Some(_) => return Err(invalid()),
                    None => subject,
                };
                return Ok(Subject {
                    principal,
                    client_id: format!("oidc:{}", verifier.name()),
                    account: None,
                    credential_id: None,
                    expires_by: None,
                });
            }
        }
        Err(invalid())
    }

    /// Checks what `request` asks against what `subject` may do now, records the token and signs
    /// it.
    fn mint(
        &self,
        tokens: &Tokens,
        request: &TokenRequest,
        subject: &Subject,
        proof: &ClientProof,
        now: u64,
    ) -> Result<TokenAnswer, TokenRefusal> {
        let scope: Vec<&str> = request
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if scope.is_empty() {
            return Err(TokenRefusal::InvalidScope(
                "the scope names no operation".to_owned(),
            ));
        }
        let family = if scope.iter().all(|op| APPLICATION_OPERATIONS.contains(op)) {
            APPLICATION
        } else if scope
            .iter()
            .all(|op| ADMINISTRATION_OPERATIONS.contains(op))
        {
            ADMINISTRATION
        } else {
            return Err(TokenRefusal::InvalidScope(
                "the scope is one family's operations: application or administration, never both"
                    .to_owned(),
            ));
        };
        let lifetimes = tokens.lifetimes;
        let (default, max) = if family == APPLICATION {
            (lifetimes.application_default, lifetimes.application_max)
        } else {
            (
                lifetimes.administration_default,
                lifetimes.administration_max,
            )
        };
        let lifetime = match request.requested_lifetime.as_deref() {
            None => default,
            Some(text) => text
                .parse::<u64>()
                .ok()
                .filter(|seconds| (1..=max).contains(seconds))
                .ok_or_else(|| {
                    TokenRefusal::InvalidRequest(format!(
                        "requested_lifetime is 1 to {max} seconds for an {family} token"
                    ))
                })?,
        };
        let mut expires_at = now.saturating_add(lifetime);
        if let Some(by) = subject.expires_by {
            expires_at = expires_at.min(by);
        }
        if expires_at <= now {
            return Err(TokenRefusal::InvalidGrant(
                "the credential has expired".to_owned(),
            ));
        }
        let audience = self.checked_audience(request, family)?;
        let denied = || {
            TokenRefusal::InvalidScope(
                "the subject may not do what the scope asks on what the target names".to_owned(),
            )
        };
        let targets: Vec<String> = if family == ADMINISTRATION {
            if !request.target.is_empty() {
                return Err(TokenRefusal::InvalidTarget(
                    "an administration token's target is its member's Host: name none".to_owned(),
                ));
            }
            let member = audience[0]
                .strip_prefix("member:")
                .ok_or_else(|| TokenRefusal::InvalidTarget("no member".to_owned()))?;
            let resource = Resource::member(member);
            for op in &scope {
                let granted_by = self
                    .authorization
                    .granted_to(&subject.principal, op, &resource)
                    .ok_or_else(denied)?;
                // D20: a service account administers a member only by a grant of its own, never
                // through a role or a public grant.
                if subject.account.is_some() && granted_by != subject.principal {
                    return Err(denied());
                }
            }
            vec!["host".to_owned()]
        } else {
            if request.target.is_empty() || request.target.len() > MAX_TARGETS {
                return Err(TokenRefusal::InvalidTarget(format!(
                    "an application token names 1 to {MAX_TARGETS} targets"
                )));
            }
            let mut targets = BTreeSet::new();
            for target in &request.target {
                let selector = Selector::parse(target).map_err(|_| {
                    TokenRefusal::InvalidTarget(format!("`{target}` is not a selector"))
                })?;
                if selector.prefix().plane_id().is_none() {
                    return Err(TokenRefusal::InvalidTarget(format!(
                        "`{target}` is not a resource of a member's Planes"
                    )));
                }
                for op in &scope {
                    let held = if selector.covers_descendants() {
                        self.authorization.principal_covers_whole(
                            &subject.principal,
                            op,
                            selector.prefix(),
                        )
                    } else {
                        self.authorization
                            .granted_to(&subject.principal, op, selector.prefix())
                            .is_some()
                    };
                    if !held {
                        return Err(denied());
                    }
                }
                targets.insert(selector.to_string());
            }
            targets.into_iter().collect()
        };
        // An administration token is bound to the certificate of the connection that asked for it,
        // when there is one, and must be under `regulated` (RFC 8705 §3).
        let bound = (family == ADMINISTRATION)
            .then(|| {
                proof
                    .certificate_sha256
                    .as_deref()
                    .and_then(decode_hex)
                    .map(|digest| URL_SAFE_NO_PAD.encode(digest))
            })
            .flatten();
        if family == ADMINISTRATION && lifetimes.administration_bound && bound.is_none() {
            return Err(TokenRefusal::InvalidRequest(
                "under `regulated` an administration token is bound to the client's certificate: \
                 ask over mutual TLS"
                    .to_owned(),
            ));
        }
        let scope_text = scope.join(" ");
        // The token's size is known before it is recorded: a token too large to answer is never
        // given an entry. The jti and the index are bounded, so a draft with the largest stands for
        // the token.
        let draft_size = {
            let mut largest = IssuedToken {
                jti: [0xff; 16],
                list_id: [0xff; 16],
                index: u64::try_from(permguard_objects::status_list::ENTRIES).unwrap_or(u64::MAX),
                subject: subject.principal.as_str().to_owned(),
                client_id: subject.client_id.clone(),
                family: family.to_owned(),
                audience: audience.clone(),
                scope: scope_text.clone(),
                issued_at: now,
                expires_at,
                account: None,
                credential_id: None,
                status: 0,
            };
            largest.expires_at = expires_at;
            claims_of(tokens, &largest, &targets, bound.as_deref(), now)
                .to_string()
                .len()
        };
        // Header, three base64url parts, two dots and a 64-byte signature.
        if (draft_size + 128) * 4 / 3 + 96 > MAX_TOKEN_BYTES {
            return Err(TokenRefusal::InvalidRequest(format!(
                "the token would take more than {MAX_TOKEN_BYTES} bytes: fewer targets or audiences"
            )));
        }
        let _ = tokens.registry.retire_expired("iam", now);
        let issued = tokens
            .registry
            .issue(
                TokenDraft {
                    subject: subject.principal.as_str().to_owned(),
                    client_id: subject.client_id.clone(),
                    family: family.to_owned(),
                    audience: audience.clone(),
                    scope: scope_text.clone(),
                    expires_at,
                    account: subject.account.as_ref().map(|account| account.name.clone()),
                    credential_id: subject.credential_id,
                },
                "iam",
                now,
            )
            .map_err(|error| {
                tracing::error!(
                    event.name = "iam.token_unrecorded",
                    component = super::COMPONENT,
                    error = %error,
                    "a token could not be recorded"
                );
                TokenRefusal::Unavailable("the token could not be recorded".to_owned())
            })?;
        // Read again once recorded: a revocation, a suspension or a deletion that committed while
        // the client was being authenticated has its sync run before this token existed, so it is
        // this check that brings the token to what the directory says now, and refuses it.
        if let Some(identities) = self.identities.as_ref()
            && let Some(decided) =
                super::tokens::status_from_directory(&identities.directory, &issued)
            && decided != crate::authz::tokens::status::VALID
        {
            let jti = issued.jti;
            let _ = tokens
                .registry
                .set_status(None, |token| token.jti == jti, decided, "iam", now);
            return Err(client_failed());
        }
        let access_token = sign(tokens, &issued, &targets, bound.as_deref(), now)?;
        self.record_issued(&issued, &targets);
        Ok(TokenAnswer {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: expires_at - now,
            scope: scope_text,
        })
    }

    /// The audiences asked, each one this IAM Host may name: an `administration` token exactly
    /// one live member, an `application` token live members or groups holding one.
    fn checked_audience(
        &self,
        request: &TokenRequest,
        family: &str,
    ) -> Result<Vec<String>, TokenRefusal> {
        let asked: Vec<String> = request
            .audience
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if asked.is_empty() || asked.len() > crate::authz::tokens::MAX_AUDIENCE {
            return Err(TokenRefusal::InvalidTarget(format!(
                "a token names 1 to {} audiences",
                crate::authz::tokens::MAX_AUDIENCE
            )));
        }
        if family == ADMINISTRATION && (asked.len() != 1 || !asked[0].starts_with("member:")) {
            return Err(TokenRefusal::InvalidTarget(
                "an administration token is addressed to exactly one member:<member_id>".to_owned(),
            ));
        }
        let members = self
            .memberships
            .as_ref()
            .map(|service| service.store.live_members())
            .unwrap_or_default();
        for audience in &asked {
            let local = self
                .tokens
                .as_deref()
                .is_some_and(|tokens| tokens.is_local_member(audience));
            let held = if local {
                true
            } else if let Some(id) = audience.strip_prefix("member:") {
                members
                    .iter()
                    .any(|(record, _)| uuid_text(&record.member_id) == id)
            } else if let Some(group) = audience.strip_prefix("group:") {
                members
                    .iter()
                    .any(|(record, _)| record.groups.iter().any(|held| held == group))
            } else {
                // `*` stays refused: `iam.tokens.wildcard_audience` is not served by this build.
                false
            };
            if !held {
                return Err(TokenRefusal::InvalidTarget(format!(
                    "`{audience}` is not a live member or a group of one"
                )));
            }
        }
        Ok(asked)
    }
}

impl HostApi {
    /// `iam.token.issued`: who, for what, until when; never the token.
    fn record_issued(&self, issued: &IssuedToken, targets: &[String]) {
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        let target = targets.join(" ");
        let audience = issued.audience.join(" ");
        let jti = issued.jti_text();
        let facts = [
            ("client_id", permguard_core::Fact::Text(&issued.client_id)),
            ("family", permguard_core::Fact::Text(&issued.family)),
            ("scope", permguard_core::Fact::Text(&issued.scope)),
            ("target", permguard_core::Fact::Text(&target)),
            ("audience", permguard_core::Fact::Text(&audience)),
            ("jti", permguard_core::Fact::Text(&jti)),
            ("expires_at", permguard_core::Fact::Uint(issued.expires_at)),
        ];
        let event = permguard_core::AuditEvent::new(
            crate::audit::AUDIT_TOKEN_ISSUED,
            permguard_core::Subject::Principal(&issued.subject),
        )
        .with_facts(&facts);
        if let Err(error) = audit.append(&event, None) {
            tracing::warn!(
                event.name = "iam.token_issued_unrecorded",
                component = super::COMPONENT,
                error = %error,
                "an issued token could not be recorded in the audit trail"
            );
        }
    }

    /// `iam.token.refused`: the client it claimed to be and the error class; never the proof.
    fn record_refusal(&self, claimed: &str, refusal: &TokenRefusal) {
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        let client: String = claimed.chars().take(256).collect();
        let facts = [
            ("client_id", permguard_core::Fact::Text(&client)),
            ("reason", permguard_core::Fact::Text(refusal.error())),
        ];
        let event = permguard_core::AuditEvent::new(
            crate::audit::AUDIT_TOKEN_REFUSED,
            permguard_core::Subject::System("iam"),
        )
        .with_facts(&facts);
        if let Err(error) = audit.append(&event, None) {
            tracing::warn!(
                event.name = "iam.token_refused_unrecorded",
                component = super::COMPONENT,
                error = %error,
                "a refused token request could not be recorded in the audit trail"
            );
        }
    }
}

/// The subject of `account` proved by `credential`, while both are good.
fn active_subject(
    account: ServiceAccount,
    credential: &crate::authz::directory::Credential,
) -> Result<Subject, TokenRefusal> {
    if account.status != AccountStatus::Active {
        return Err(client_failed());
    }
    Ok(Subject {
        principal: Principal::new(service_account_principal(&account.name))
            .map_err(|_| client_failed())?,
        client_id: credential.id_text(),
        credential_id: Some(credential.id),
        expires_by: credential.expires_at,
        account: Some(account),
    })
}

/// Signs `issued` as an `at+jwt` under `iam.tokens`.
/// The claims of `issued`.
fn claims_of(
    tokens: &Tokens,
    issued: &IssuedToken,
    targets: &[String],
    bound: Option<&str>,
    now: u64,
) -> serde_json::Value {
    let mut claims = serde_json::json!({
        "iss": tokens.issuer,
        "permguard_tenant": TENANT,
        "sub": issued.subject,
        "client_id": issued.client_id,
        "aud": issued.audience,
        "permguard_family": issued.family,
        "scope": issued.scope,
        "permguard_target": targets,
        "iat": now,
        "nbf": now,
        "exp": issued.expires_at,
        "jti": issued.jti_text(),
        "status": {"status_list": {"idx": issued.index, "uri": tokens.list_uri(&issued.list_id)}},
    });
    if let Some(thumbprint) = bound {
        claims["cnf"] = serde_json::json!({ "x5t#S256": thumbprint });
    }
    claims
}

/// Signs `issued` as an `at+jwt` under `iam.tokens`.
fn sign(
    tokens: &Tokens,
    issued: &IssuedToken,
    targets: &[String],
    bound: Option<&str>,
    now: u64,
) -> Result<String, TokenRefusal> {
    let claims = claims_of(tokens, issued, targets, bound, now);
    let payload = serde_json::to_vec(&claims)
        .map_err(|error| TokenRefusal::Unavailable(error.to_string()))?;
    let parts = crate::composition::sign_jws::<crate::composition::AccessTokenV1>(
        &payload,
        tokens.ring.as_ref(),
    )
    .map_err(|error| TokenRefusal::Unavailable(format!("signing the token: {error}")))?;
    let token = format!("{}.{}.{}", parts.protected, parts.payload, parts.signature);
    if token.len() > MAX_TOKEN_BYTES {
        return Err(TokenRefusal::InvalidRequest(format!(
            "the token would take {} bytes, past {MAX_TOKEN_BYTES}",
            token.len()
        )));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_core::assurance::AssuranceProfile;

    #[test]
    fn regulated_bounds_lifetimes_and_binds_administration() {
        let regulated = Lifetimes::of(AssuranceProfile::Regulated);
        assert_eq!(regulated.application_max, 3_600);
        assert!(regulated.administration_bound);
        let production = Lifetimes::of(AssuranceProfile::Production);
        assert_eq!(production.application_max, 24 * 3_600);
        assert_eq!(production.administration_max, 900);
        assert!(!production.administration_bound);
    }

    #[test]
    fn a_form_member_given_twice_or_a_secret_in_the_form_is_refused() {
        let pair = |name: &str, value: &str| (name.to_owned(), value.to_owned());
        let twice = TokenRequest::from_form(vec![
            pair("grant_type", "client_credentials"),
            pair("scope", "a"),
            pair("scope", "b"),
        ]);
        assert!(matches!(twice, Err(TokenRefusal::InvalidRequest(_))));
        let secret = TokenRequest::from_form(vec![pair("client_secret", "x")]);
        assert!(matches!(secret, Err(TokenRefusal::InvalidRequest(_))));
        let read = TokenRequest::from_form(vec![
            pair("grant_type", "client_credentials"),
            pair("audience", "member:a"),
            pair("audience", "group:b"),
            pair("target", "plane/data/*"),
            pair("unknown", "ignored"),
        ])
        .expect("read");
        assert_eq!(read.audience, vec!["member:a", "group:b"]);
        assert_eq!(read.target, vec!["plane/data/*"]);
    }

    #[test]
    fn every_refusal_is_its_rfc_6749_error_and_status() {
        for (refusal, error, status) in [
            (
                TokenRefusal::InvalidClient(String::new()),
                "invalid_client",
                401,
            ),
            (
                TokenRefusal::InvalidScope(String::new()),
                "invalid_scope",
                400,
            ),
            (
                TokenRefusal::InvalidTarget(String::new()),
                "invalid_target",
                400,
            ),
            (TokenRefusal::TooManyRequests(3), "slow_down", 429),
            (
                TokenRefusal::Unavailable(String::new()),
                "temporarily_unavailable",
                503,
            ),
        ] {
            assert_eq!((refusal.error(), refusal.status()), (error, status));
        }
    }

    #[test]
    fn the_limiter_admits_a_minutes_bound_then_says_when_to_come_back() {
        let limiter = Limiter::default();
        for _ in 0..3 {
            limiter
                .admit("client:x".to_owned(), 3, 120)
                .expect("admitted");
        }
        assert_eq!(
            limiter.admit("client:x".to_owned(), 3, 130),
            Err(TokenRefusal::TooManyRequests(50))
        );
        limiter
            .admit("client:x".to_owned(), 3, 180)
            .expect("the next minute");
    }
}
