// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The IAM Host's security token service (iteration 02, WP-11.4, `2-security/8` Token endpoint):
//! `POST /iam/v1/token`, RFC 6749 with the profile of RFC 9068, and RFC 8693's token exchange.
//! Who the subject is, federation establishes ([`super::federation`]); every token, its scope,
//! audience, target, lifetime and the role it was elevated to, is this module's.
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
use permguard_core::authz::{Resource, Selector, operations};

use super::HostApi;
use super::federation::{Subject, client_failed, decode_part};
use super::tokens::{TENANT, Tokens};
use crate::authz::directory::role_principal;
use crate::authz::tokens::{IssuedToken, TokenDraft};
use crate::identity::record::uuid_text;

/// `client_credentials`.
pub const CLIENT_CREDENTIALS: &str = "client_credentials";
/// RFC 8693's token exchange.
pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693's access token type: what a subject token is.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 8693 §3: a JWT, the type a provider's token is exchanged as.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
/// RFC 8693 §3: an OpenID Connect ID Token, the other type a provider's token is exchanged as.
pub const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";
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
    /// RFC 8693 §2.1: what the token is for, as an absolute URI; no resource indicator is served.
    pub resource: Vec<String>,
    pub requested_token_type: Option<String>,
    /// RFC 8693 delegation, which is not served: present, the request is refused.
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
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
            .field("resource", &self.resource)
            .field("requested_token_type", &self.requested_token_type)
            .field("actor_token", &self.actor_token.as_ref().map(|_| "<set>"))
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
                "requested_token_type" => once(&mut request.requested_token_type, &mut seen)?,
                "actor_token" => once(&mut request.actor_token, &mut seen)?,
                "actor_token_type" => once(&mut request.actor_token_type, &mut seen)?,
                "client_secret" => {
                    return Err(TokenRefusal::InvalidRequest(
                        "a client secret travels in the Authorization header, client_secret_basic"
                            .to_owned(),
                    ));
                }
                "audience" => request.audience.push(value),
                "target" => request.target.push(value),
                "resource" => request.resource.push(value),
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

/// What an issued token answers (RFC 6749 §5.1), and for a token exchange the type of what was
/// issued (RFC 8693 §2.2.1).
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct TokenAnswer {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

/// Never the token: what it is for and how long it serves.
impl std::fmt::Debug for TokenAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenAnswer")
            .field("access_token", &"********")
            .field("issued_token_type", &self.issued_token_type)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Why a token was not issued, as RFC 6749 §5.2 names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRefusal {
    /// `401`: the client's proof failed.
    InvalidClient(String),
    /// `400`.
    InvalidRequest(String),
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
            | Self::InvalidScope(detail)
            | Self::InvalidTarget(detail)
            | Self::UnsupportedGrantType(detail)
            | Self::Unavailable(detail) => detail,
        }
    }
}

/// The client's requests within the current minute, per client and per source.
/// The most keys one minute counts. Past it, a new source is refused for the rest of the minute,
/// so a flood of distinct sources cannot grow the map without bound; a new client is admitted
/// uncounted, still bound by its source's count, so a flood never locks every client out.
const MAX_WINDOW_KEYS: usize = 100_000;

/// What a full minute does with a key it does not count yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WhenFull {
    Refuse,
    Admit,
}

#[derive(Default)]
pub(super) struct Limiter {
    /// The minute counted and each key's requests in it, by the key's digest: a fixed size
    /// whatever a caller claims. A new minute starts empty.
    window: Mutex<(u64, HashMap<[u8; 16], u32>)>,
}

impl Limiter {
    /// Counts one request of `key` at `now`, refusing past `limit` in the minute.
    pub(super) fn admit(
        &self,
        key: &str,
        limit: u32,
        when_full: WhenFull,
        now: u64,
    ) -> Result<(), TokenRefusal> {
        let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest.as_ref()[..16]);
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        let minute = now / 60;
        if window.0 != minute {
            *window = (minute, HashMap::new());
        }
        let wait = TokenRefusal::TooManyRequests(60 - now % 60);
        if !window.1.contains_key(&id) && window.1.len() >= MAX_WINDOW_KEYS {
            return match when_full {
                WhenFull::Refuse => Err(wait),
                WhenFull::Admit => Ok(()),
            };
        }
        let count = window.1.entry(id).or_insert(0);
        if *count >= limit {
            return Err(wait);
        }
        *count += 1;
        Ok(())
    }
}

/// The source a request is counted as: its IPv4 address, or the /64 of its IPv6 address, which
/// one subscriber holds whole; anything else as given.
fn source_key(source: &str) -> String {
    match source.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(address)) if address.to_ipv4_mapped().is_none() => {
            let segments = address.segments();
            format!(
                "source:{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
        Ok(std::net::IpAddr::V6(address)) => format!(
            "source:{}",
            address
                .to_ipv4_mapped()
                .map_or_else(|| address.to_string(), |v4| v4.to_string())
        ),
        _ => format!("source:{source}"),
    }
}

/// The scope word that elevates to a role: `role:<name>`.
pub const ROLE_SCOPE: &str = "role:";

/// What a token is issued for, once checked: its family, operations, audiences, targets and the
/// role it was elevated to.
pub(super) struct Asked {
    pub(super) family: &'static str,
    pub(super) scope: Vec<String>,
    pub(super) audience: Vec<String>,
    pub(super) targets: Vec<String>,
    pub(super) role: Option<String>,
}

/// The one family `operations` belong to (D19).
pub(super) fn family_of(operations: &[&str]) -> Result<&'static str, TokenRefusal> {
    if operations.is_empty() {
        return Err(TokenRefusal::InvalidScope(
            "the scope names no operation".to_owned(),
        ));
    }
    if operations
        .iter()
        .all(|op| APPLICATION_OPERATIONS.contains(op))
    {
        Ok(APPLICATION)
    } else if operations
        .iter()
        .all(|op| ADMINISTRATION_OPERATIONS.contains(op))
    {
        Ok(ADMINISTRATION)
    } else {
        Err(TokenRefusal::InvalidScope(
            "the scope is one family's operations: application or administration, never both"
                .to_owned(),
        ))
    }
}

/// An application token's targets: 1 to [`MAX_TARGETS`] selectors of a member's Planes.
pub(super) fn selectors_of(targets: &[String]) -> Result<Vec<Selector>, TokenRefusal> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(TokenRefusal::InvalidTarget(format!(
            "an application token names 1 to {MAX_TARGETS} targets"
        )));
    }
    targets
        .iter()
        .map(|target| {
            let selector = Selector::parse(target).map_err(|_| {
                TokenRefusal::InvalidTarget(format!("`{target}` is not a selector"))
            })?;
            if selector.prefix().plane_id().is_none() {
                return Err(TokenRefusal::InvalidTarget(format!(
                    "`{target}` is not a resource of a member's Planes"
                )));
            }
            Ok(selector)
        })
        .collect()
}

/// What RFC 8693 asks of a request before anything is proved (§2.1): no delegation, an access
/// token or nothing asked as the issued type, and a `resource` an absolute URI without fragment,
/// answered `invalid_target` since no resource indicator is served; `audience` names a member.
fn conforms(request: &TokenRequest) -> Result<(), TokenRefusal> {
    if request.grant_type == TOKEN_EXCHANGE {
        if request.actor_token.is_some() || request.actor_token_type.is_some() {
            return Err(TokenRefusal::InvalidRequest(
                "delegation is not served: a token exchange takes no actor_token".to_owned(),
            ));
        }
        if let Some(asked) = request.requested_token_type.as_deref()
            && asked != ACCESS_TOKEN_TYPE
        {
            return Err(TokenRefusal::InvalidRequest(format!(
                "requested_token_type is `{ACCESS_TOKEN_TYPE}`, the only type issued"
            )));
        }
    }
    if let Some(resource) = request.resource.iter().find(|uri| !is_absolute_uri(uri)) {
        return Err(TokenRefusal::InvalidRequest(format!(
            "`{}` is not an absolute URI without a fragment",
            resource.chars().take(256).collect::<String>()
        )));
    }
    if !request.resource.is_empty() {
        return Err(TokenRefusal::InvalidTarget(
            "no resource indicator is served: name the member as audience, member:<member_id>"
                .to_owned(),
        ));
    }
    Ok(())
}

/// RFC 3986 §4.3: a scheme, `:`, and the rest, with no fragment; never a space or a control.
fn is_absolute_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut letters = scheme.chars();
    letters.next().is_some_and(|c| c.is_ascii_alphabetic())
        && letters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
        && !text.contains('#')
        && !text.chars().any(|c| c.is_whitespace() || c.is_control())
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

/// Who a request is counted as, before anything is hashed or verified, so a failing guess spends
/// its budget as a success does: a client by the name it claims; an exchange always by its subject
/// token, digested, whatever client it names, so each session or provider token has its own
/// budget, one person never spends everyone's, and no exchange spends a service account's. The
/// digest's first eight bytes name it, never the token.
fn claimed_by(request: &TokenRequest, proof: &ClientProof) -> String {
    if request.grant_type == TOKEN_EXCHANGE {
        let digest = ring::digest::digest(
            &ring::digest::SHA256,
            request
                .subject_token
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        let prefix: String = digest.as_ref()[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        return format!("exchange:{prefix}");
    }
    proof
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
        .unwrap_or_default()
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
        tokens.replays.since(now);
        if let Some(source) = &proof.source {
            tokens.limiter.admit(
                &source_key(source),
                SOURCE_REQUESTS_PER_MINUTE,
                WhenFull::Refuse,
                now,
            )?;
        }
        let claimed = claimed_by(request, proof);
        tokens.limiter.admit(
            &format!("client:{claimed}"),
            CLIENT_REQUESTS_PER_MINUTE,
            WhenFull::Admit,
            now,
        )?;
        if let Err(refusal) = conforms(request) {
            self.record_refusal(&claimed, &refusal);
            return Err(refusal);
        }
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
        let Asked {
            family,
            scope,
            audience,
            targets,
            role,
        } = self.asked(request, subject)?;
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
            // An expired credential fails the client's proof; an expired subject token is not
            // acceptable (RFC 8693 §2.2.2).
            return Err(if subject.account.is_some() {
                client_failed()
            } else {
                TokenRefusal::InvalidRequest("the subject token has expired".to_owned())
            });
        }
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
                role: role.as_ref().map(|name| role_principal(name)),
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
                    role: role.as_ref().map(|name| role_principal(name)),
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
            issued_token_type: (request.grant_type == TOKEN_EXCHANGE)
                .then(|| ACCESS_TOKEN_TYPE.to_owned()),
            token_type: "Bearer".to_owned(),
            expires_in: expires_at - now,
            scope: scope_text,
        })
    }

    /// What `request` asks for `subject`, checked: within everything the subject holds, or, with
    /// one `role:<name>` in its scope, within that role alone (`2-security/8` Roles and
    /// elevation).
    fn asked(&self, request: &TokenRequest, subject: &Subject) -> Result<Asked, TokenRefusal> {
        let words: BTreeSet<&str> = request
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        let roles: Vec<&str> = words
            .iter()
            .filter_map(|word| word.strip_prefix(ROLE_SCOPE))
            .collect();
        let operations: Vec<&str> = words
            .iter()
            .copied()
            .filter(|word| !word.starts_with(ROLE_SCOPE))
            .collect();
        match roles.as_slice() {
            [] => self.within_grants(request, subject, &subject.principal, &operations),
            [role] => self.elevated(request, subject, role, &operations),
            _ => Err(TokenRefusal::InvalidScope(
                "a scope names at most one role".to_owned(),
            )),
        }
    }

    /// `operations` on what `request` names, each held by `holder`: the subject itself, or the
    /// role it elevated to. A service account administers only by a grant of its own (D20).
    pub(super) fn within_grants(
        &self,
        request: &TokenRequest,
        subject: &Subject,
        holder: &permguard_core::authz::Principal,
        operations: &[&str],
    ) -> Result<Asked, TokenRefusal> {
        let family = family_of(operations)?;
        let audience = self.checked_audience(&request.audience, family)?;
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
            for op in operations {
                let granted_by = self
                    .authorization
                    .granted_to(holder, op, &resource)
                    .ok_or_else(denied)?;
                // D20: a service account administers a member only by a grant of its own, never
                // through a role or a public grant.
                if subject.account.is_some() && granted_by != subject.principal {
                    return Err(denied());
                }
            }
            vec!["host".to_owned()]
        } else {
            let mut targets = BTreeSet::new();
            for selector in selectors_of(&request.target)? {
                for op in operations {
                    let held = if selector.covers_descendants() {
                        self.authorization
                            .principal_covers_whole(holder, op, selector.prefix())
                    } else {
                        self.authorization
                            .granted_to(holder, op, selector.prefix())
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
        Ok(Asked {
            family,
            scope: operations.iter().map(|op| (*op).to_owned()).collect(),
            audience,
            targets,
            role: None,
        })
    }

    /// The audiences asked, each one this IAM Host may name: an `administration` token exactly
    /// one live member, an `application` token live members or groups holding one.
    pub(super) fn checked_audience(
        &self,
        audience: &[String],
        family: &str,
    ) -> Result<Vec<String>, TokenRefusal> {
        let asked: Vec<String> = audience
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
        let mut facts = vec![
            ("client_id", permguard_core::Fact::Text(&issued.client_id)),
            ("family", permguard_core::Fact::Text(&issued.family)),
            ("scope", permguard_core::Fact::Text(&issued.scope)),
            ("target", permguard_core::Fact::Text(&target)),
            ("audience", permguard_core::Fact::Text(&audience)),
            ("jti", permguard_core::Fact::Text(&jti)),
            ("expires_at", permguard_core::Fact::Uint(issued.expires_at)),
        ];
        // The role the subject elevated to, when it did (`2-security/8` Roles and elevation).
        if let Some(role) = issued.role.as_deref() {
            facts.push(("role", permguard_core::Fact::Text(role)));
        }
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
    // RFC 9068 §2.2.3.1: the role the subject elevated to, by its name; `sub` stays the subject.
    if let Some(role) = issued
        .role
        .as_deref()
        .and_then(|role| role.strip_prefix(crate::authz::directory::ROLE_PREFIX))
    {
        claims["roles"] = serde_json::json!([role]);
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

    fn form(pairs: &[(&str, &str)]) -> TokenRequest {
        TokenRequest::from_form(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        )
        .expect("read")
    }

    /// RFC 8693 §2.1: `resource` is its own parameter, never a target; delegation and the asked
    /// type are read, so they can be answered.
    #[test]
    fn rfc_8693_parameters_are_read_apart() {
        let read = form(&[
            ("grant_type", TOKEN_EXCHANGE),
            ("resource", "https://backend.example.com/api"),
            ("target", "plane/data/*"),
            ("requested_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", "eyJ.actor.token"),
            ("actor_token_type", JWT_TOKEN_TYPE),
        ]);
        assert_eq!(read.resource, vec!["https://backend.example.com/api"]);
        assert_eq!(read.target, vec!["plane/data/*"]);
        assert_eq!(
            read.requested_token_type.as_deref(),
            Some(ACCESS_TOKEN_TYPE)
        );
        assert!(read.actor_token.is_some() && read.actor_token_type.is_some());
        assert!(!format!("{read:?}").contains("eyJ.actor.token"));
    }

    /// RFC 8693 §2.1 and §2.2.2, before anything is proved: no delegation, only an access token
    /// as the issued type, a `resource` an absolute URI without fragment and then not served.
    #[test]
    fn a_request_rfc_8693_does_not_allow_is_refused_by_its_rule() {
        let exchange = |extra: &[(&str, &str)]| {
            let mut pairs = vec![("grant_type", TOKEN_EXCHANGE)];
            pairs.extend_from_slice(extra);
            conforms(&form(&pairs))
        };
        let error = |result: Result<(), TokenRefusal>| result.expect_err("refused").error();
        assert!(exchange(&[]).is_ok());
        assert!(exchange(&[("requested_token_type", ACCESS_TOKEN_TYPE)]).is_ok());
        for refused in [
            vec![("actor_token", "a"), ("actor_token_type", JWT_TOKEN_TYPE)],
            vec![("actor_token", "a")],
            vec![("actor_token_type", JWT_TOKEN_TYPE)],
            vec![("requested_token_type", JWT_TOKEN_TYPE)],
            vec![("requested_token_type", ID_TOKEN_TYPE)],
            vec![("resource", "/relative/api")],
            vec![("resource", "https://backend.example.com/api#part")],
            vec![("resource", "https://backend example.com")],
            vec![("resource", "1https://backend.example.com")],
        ] {
            assert_eq!(error(exchange(&refused)), "invalid_request", "{refused:?}");
        }
        assert_eq!(
            error(exchange(&[(
                "resource",
                "https://backend.example.com/api?x=1"
            )])),
            "invalid_target"
        );
        assert_eq!(
            error(exchange(&[("resource", "urn:example:cooperation-context")])),
            "invalid_target"
        );
        // RFC 8693's own parameters are a token exchange's; `resource` is any grant's.
        let credentials = |extra: &[(&str, &str)]| {
            let mut pairs = vec![("grant_type", CLIENT_CREDENTIALS)];
            pairs.extend_from_slice(extra);
            conforms(&form(&pairs))
        };
        assert!(credentials(&[("actor_token", "a")]).is_ok());
        assert_eq!(
            error(credentials(&[("resource", "https://backend.example.com")])),
            "invalid_target"
        );
    }

    /// RFC 8693 §2.2.1: an exchange's answer names what it issued; a client credentials answer is
    /// RFC 6749's alone.
    #[test]
    fn an_exchange_answer_names_the_issued_token_type() {
        let answer = |issued: Option<&str>| {
            serde_json::to_value(TokenAnswer {
                access_token: "t".to_owned(),
                issued_token_type: issued.map(str::to_owned),
                token_type: "Bearer".to_owned(),
                expires_in: 60,
                scope: "decision.evaluate".to_owned(),
            })
            .expect("json")
        };
        assert_eq!(
            answer(Some(ACCESS_TOKEN_TYPE))["issued_token_type"],
            ACCESS_TOKEN_TYPE
        );
        assert!(answer(None).get("issued_token_type").is_none());
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
    fn an_exchange_is_counted_by_its_subject_token_and_never_names_it() {
        let exchange = |token: &str| TokenRequest {
            grant_type: TOKEN_EXCHANGE.to_owned(),
            subject_token: Some(token.to_owned()),
            ..TokenRequest::default()
        };
        let none = ClientProof::default();
        let alice = claimed_by(&exchange("pgs_alice-session"), &none);
        let bob = claimed_by(&exchange("pgs_bob-session"), &none);
        assert_ne!(alice, bob, "each session its own budget");
        assert_eq!(alice, claimed_by(&exchange("pgs_alice-session"), &none));
        assert!(alice.starts_with("exchange:") && alice.len() == "exchange:".len() + 16);
        assert!(
            !alice.contains("alice"),
            "the key never names the token: {alice}"
        );
        let named = TokenRequest {
            client_id: Some("billing".to_owned()),
            ..exchange("pgs_alice-session")
        };
        assert_eq!(
            claimed_by(&named, &none),
            alice,
            "an exchange naming a client is still its session's: it spends no account's budget"
        );
        let client = TokenRequest {
            grant_type: CLIENT_CREDENTIALS.to_owned(),
            client_id: Some("billing".to_owned()),
            ..TokenRequest::default()
        };
        assert_eq!(
            claimed_by(&client, &none),
            "billing",
            "a client by its name"
        );
    }

    /// T14: an answer printed never carries its token.
    #[test]
    fn an_answer_never_prints_its_token() {
        let answer = TokenAnswer {
            access_token: "eyJhbGciOiJFZERTQSJ9.secret.part".to_owned(),
            issued_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
            token_type: "Bearer".to_owned(),
            expires_in: 3_600,
            scope: "decision.evaluate".to_owned(),
        };
        let printed = format!("{answer:?}");
        assert!(!printed.contains("secret"), "{printed}");
        assert!(printed.contains("decision.evaluate"));
    }

    #[test]
    fn the_limiter_admits_a_minutes_bound_then_says_when_to_come_back() {
        let limiter = Limiter::default();
        for _ in 0..3 {
            limiter
                .admit("client:x", 3, WhenFull::Refuse, 120)
                .expect("admitted");
        }
        assert_eq!(
            limiter.admit("client:x", 3, WhenFull::Refuse, 130),
            Err(TokenRefusal::TooManyRequests(50))
        );
        limiter
            .admit("client:x", 3, WhenFull::Refuse, 180)
            .expect("the next minute");
    }

    /// A full minute refuses a new source and admits a new client uncounted: a flood of claimed
    /// names never locks every client out, and never grows the map.
    #[test]
    fn a_full_minute_refuses_new_sources_and_admits_new_clients_uncounted() {
        let limiter = Limiter::default();
        for n in 0..MAX_WINDOW_KEYS {
            limiter
                .admit(&format!("client:{n}"), 1, WhenFull::Admit, 60)
                .expect("counted");
        }
        assert_eq!(
            limiter.admit("source:198.51.100.7", 300, WhenFull::Refuse, 61),
            Err(TokenRefusal::TooManyRequests(59))
        );
        for _ in 0..5 {
            limiter
                .admit("client:billing", 1, WhenFull::Admit, 61)
                .expect("admitted uncounted");
        }
        assert_eq!(
            limiter
                .window
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .1
                .len(),
            MAX_WINDOW_KEYS
        );
    }

    /// One IPv6 subscriber's /64 is one source; an IPv4 address, mapped or not, is itself.
    #[test]
    fn an_ipv6_source_is_counted_by_its_64() {
        assert_eq!(
            source_key("2001:db8:1:2:aaaa::1"),
            source_key("2001:db8:1:2:bbbb::9")
        );
        assert_ne!(source_key("2001:db8:1:2::1"), source_key("2001:db8:1:3::1"));
        assert_eq!(source_key("::ffff:198.51.100.7"), "source:198.51.100.7");
        assert_eq!(source_key("198.51.100.7"), "source:198.51.100.7");
    }
}
