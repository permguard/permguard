// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane's facade (`2-security/8`): every operation of `/authority/v1` and
//! `permguard.authority.v1`, defined once; the transports decode, hand the actor to it and map
//! its answer.
//!
//! | Part             | Here                                                                         |
//! | ---------------- | ---------------------------------------------------------------------------- |
//! | token endpoint   | an access key and its secret key for a token of the account's scopes          |
//! | keys and lists   | the `authority.tokens` key set; each list signed again on a change or its `ttl` |
//! | trust            | the key set and every list handed to this Host in-process, after each change  |
//! | accounts         | every change one security mutation of `authority.accounts`, tokens following |
//! | tokens           | listed and revoked, a revocation one mutation of `authority.tokens`           |

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Actor, Resource, Selector, TokenScope, operations};
use permguard_core::keys::PublicSet as _;
use permguard_core::{AccessDenial, ApiError, ErrorClass, Fact, Subject, codes};
use permguard_host::authz::{AuthorityTrust, Authorization};
use permguard_host::composition::{
    AccessTokenV1, AuditHandle, AuditSchema, Jws, MutationHandle, Signer, StatusListTokenV1,
};
use permguard_host::identity::record::uuid_text;
use permguard_host::operations::journal::{Initiator, RequestKey};
use permguard_host::operations::mutation::{
    Applied, Applying, Begin, Failure, MutationError, Outcome,
};
use permguard_host::time::TimeGuard;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::access_keys;
use crate::accounts::{self, AccessKey, Account, AccountStore, AccountsError, Status};
use crate::marks::MarkStore;
use crate::tokens::{self, IssuedToken, TokenDraft, TokenError, TokenStore, status};

/// The resource every operation of this plane is authorized on.
pub fn resource() -> Resource {
    Resource::plane(crate::PLANE)
}

/// Every action this plane records itself; its mutations are the engine's to record.
pub struct AuthorityAudit;

impl AuditSchema for AuthorityAudit {
    const NAME: &'static str = "authority-plane.v1";
    const ACTIONS: &'static [&'static str] = &[
        permguard_host::audit::AUDIT_TOKEN_ISSUED,
        permguard_host::audit::AUDIT_TOKEN_REFUSED,
        permguard_host::audit::AUDIT_ADMIN_KEY_OFFLINE,
        permguard_host::audit::AUDIT_TOKENS_COMPLETED,
    ];
}

/// The mutations' audit actions, registered by the Host.
pub mod actions {
    pub const CREATED: &str = "authority.service_account.created";
    pub const UPDATED: &str = "authority.service_account.updated";
    pub const SCOPES_SET: &str = "authority.service_account.scopes_set";
    pub const SUSPENDED: &str = "authority.service_account.suspended";
    pub const RESUMED: &str = "authority.service_account.resumed";
    pub const DELETED: &str = "authority.service_account.deleted";
    pub const KEY_CREATED: &str = "authority.access_key.created";
    pub const KEY_DELETED: &str = "authority.access_key.deleted";
    pub const TOKEN_REVOKED: &str = "authority.token.revoked";
}

/// How long a status list token is valid and how soon a fresher one is fetched, per profile
/// (`2-security/8` Profiles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListTiming {
    /// `exp - iat`.
    pub lifetime: u64,
    /// `ttl`.
    pub ttl: u64,
}

impl ListTiming {
    pub fn of(profile: AssuranceProfile) -> Self {
        match profile {
            AssuranceProfile::Development => Self {
                lifetime: 24 * 3_600,
                ttl: 30,
            },
            AssuranceProfile::Production => Self {
                lifetime: 3_600,
                ttl: 30,
            },
            AssuranceProfile::Regulated => Self {
                lifetime: 10 * 60,
                ttl: 30,
            },
        }
    }
}

/// A token's lifetime when none is asked.
pub const DEFAULT_LIFETIME: u64 = 3_600;

/// The longest lifetime a token may be issued for under `profile`.
pub fn max_lifetime(profile: AssuranceProfile) -> u64 {
    match profile {
        AssuranceProfile::Regulated => 3_600,
        _ => 24 * 3_600,
    }
}

/// The token requests per access key and per source within a minute.
pub const CLIENT_REQUESTS_PER_MINUTE: u32 = 60;
pub const SOURCE_REQUESTS_PER_MINUTE: u32 = 300;
/// How many Argon2id verifications run at once, every hashing route together.
pub const CONCURRENT_HASHES: usize = 4;
/// The most bytes a token takes.
pub const MAX_TOKEN_BYTES: usize = permguard_host::authz::access_tokens::MAX_TOKEN_BYTES;
/// The most bytes a list token takes.
pub const MAX_LIST_TOKEN_BYTES: usize = permguard_host::authz::status_lists::MAX_LIST_TOKEN_BYTES;
/// The only grant of the community edition.
pub const CLIENT_CREDENTIALS: &str = "client_credentials";
/// The edition this build serves.
pub const EDITION: &str = "community";

/// What a token request carries, its fields read once.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    /// Operations, space separated, narrowing the account's.
    pub scope: Option<String>,
    pub requested_lifetime: Option<u64>,
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("requested_lifetime", &self.requested_lifetime)
            .finish_non_exhaustive()
    }
}

/// What the token endpoint answers (RFC 6749 §5.1).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenAnswer {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

impl std::fmt::Debug for TokenAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenAnswer")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// Why a token request was refused (RFC 6749 §5.2): a refusal says which rule of the protocol
/// failed, never which key, account or secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRefusal {
    InvalidRequest(String),
    InvalidClient,
    InvalidScope(String),
    UnsupportedGrantType(String),
    /// Seconds until the minute ends.
    SlowDown(u64),
    Unavailable(String),
}

impl TokenRefusal {
    /// RFC 6749's `error`.
    pub fn error(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidScope(_) => "invalid_scope",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::SlowDown(_) => "slow_down",
            Self::Unavailable(_) => "temporarily_unavailable",
        }
    }

    /// The HTTP status it answers.
    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidClient => 401,
            Self::SlowDown(_) => 429,
            Self::Unavailable(_) => 503,
            _ => 400,
        }
    }

    /// What the caller is told; never the cause of an `invalid_client`.
    pub fn description(&self) -> String {
        match self {
            Self::InvalidRequest(detail)
            | Self::InvalidScope(detail)
            | Self::UnsupportedGrantType(detail) => detail.clone(),
            Self::InvalidClient => "the client could not be authenticated".to_owned(),
            Self::SlowDown(_) => "too many token requests: slow down".to_owned(),
            Self::Unavailable(_) => "the token endpoint cannot answer now".to_owned(),
        }
    }
}

/// What the facade refuses with.
#[derive(Debug, Clone)]
pub enum Refusal {
    Api(ApiError),
    Denied(AccessDenial),
}

impl From<ApiError> for Refusal {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<AccessDenial> for Refusal {
    fn from(denial: AccessDenial) -> Self {
        Self::Denied(denial)
    }
}

fn refused(class: ErrorClass, code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal::Api(ApiError::new(class, code, message))
}

fn invalid(message: impl Into<String>) -> Refusal {
    refused(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        message,
    )
}

/// The bearer's principal, when `jti` names the very token it presents.
/// Whether every operation `held` grants, where it grants it, is granted by `scopes` too.
pub(crate) fn granted_within(held: &[TokenScope], scopes: &[TokenScope]) -> bool {
    held.iter().all(|scope| {
        scope.operations.iter().all(|operation| {
            scopes.iter().any(|granted| {
                granted.operations.contains(operation) && granted.selector.covers(&scope.selector)
            })
        })
    })
}

fn own_token(actor: &Actor, jti: &str) -> Option<String> {
    let Actor::Authenticated(context) = actor else {
        return None;
    };
    let presented = tokens::parse_id(&context.token()?.jti)?;
    (tokens::parse_id(jti)? == presented)
        .then(|| context.authorization_principal().as_str().to_owned())
}

fn not_found(message: impl Into<String>) -> Refusal {
    refused(ErrorClass::NotFound, codes::common::NOT_FOUND, message)
}

fn conflict(message: impl Into<String>) -> Refusal {
    refused(ErrorClass::Conflict, codes::common::CONFLICT, message)
}

fn unavailable(internal: impl std::fmt::Display) -> Refusal {
    Refusal::Api(
        ApiError::new(
            ErrorClass::Unavailable,
            codes::common::UNAVAILABLE,
            "the Authority Plane's state could not be read or written",
        )
        .with_internal(internal.to_string()),
    )
}

fn refusal_of(error: AccountsError) -> Refusal {
    match error {
        AccountsError::Invalid(detail) => invalid(detail),
        AccountsError::NotFound(detail) => not_found(detail),
        AccountsError::Conflict(detail) => conflict(detail),
        other => unavailable(other),
    }
}

fn failure(error: AccountsError) -> Failure<AccountsError> {
    match error {
        AccountsError::Unavailable(_) => Failure::Indeterminate(error),
        other => Failure::Refused(other),
    }
}

fn token_failure(error: TokenError) -> Failure<AccountsError> {
    Failure::Indeterminate(AccountsError::Invalid(error.to_string()))
}

fn mutation_refusal(error: MutationError<AccountsError>) -> Refusal {
    match error {
        MutationError::Refused(error) => refusal_of(error),
        MutationError::RequestIdReused(detail) => {
            refused(ErrorClass::Conflict, codes::host::REQUEST_ID_REUSED, detail)
        }
        MutationError::InFlight(detail) => refused(
            ErrorClass::Unavailable,
            codes::host::REQUEST_IN_FLIGHT,
            detail,
        ),
        MutationError::AuditUnavailable(detail) => Refusal::Api(
            ApiError::new(
                ErrorClass::Unavailable,
                codes::host::AUDIT_UNAVAILABLE,
                "the change was not made: its audit record could not be written",
            )
            .with_internal(detail),
        ),
        MutationError::Quiesced(detail) => {
            refused(ErrorClass::Unavailable, codes::common::UNAVAILABLE, detail)
        }
        MutationError::Unrecorded(detail) | MutationError::Unavailable(detail) => Refusal::Api(
            ApiError::new(
                ErrorClass::Internal,
                codes::host::MUTATION_UNRECORDED,
                "the change may have been made: read the state before retrying",
            )
            .with_internal(detail),
        ),
        MutationError::Indeterminate(error) => Refusal::Api(
            ApiError::new(
                ErrorClass::Internal,
                codes::host::MUTATION_UNRECORDED,
                "the change may have been made: read the state before retrying",
            )
            .with_internal(error.to_string()),
        ),
    }
}

/// One scope, as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeView {
    pub operations: Vec<String>,
    pub selector: String,
}

impl ScopeView {
    pub fn of(scope: &TokenScope) -> Self {
        Self {
            operations: scope.operations.iter().cloned().collect(),
            selector: scope.selector.to_string(),
        }
    }

    /// The scope this view names, its selector read.
    pub fn read(&self) -> Result<TokenScope, Refusal> {
        let selector = Selector::parse(self.selector.trim())
            .map_err(|error| invalid(format!("`{}` is not a selector: {error}", self.selector)))?;
        Ok(TokenScope {
            operations: self
                .operations
                .iter()
                .map(|op| op.trim().to_owned())
                .collect(),
            selector,
        })
    }
}

/// One access key, as the API shows it: never its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyView {
    pub access_key: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// `active` or `expired`.
    pub status: String,
}

/// One service account, as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    pub name: String,
    pub description: String,
    /// `active` or `suspended`.
    pub status: String,
    pub scopes: Vec<ScopeView>,
    pub keys: Vec<KeyView>,
    pub administrator: bool,
    pub created_at: String,
    pub updated_at: String,
    pub revision: u64,
}

/// One token, as the API shows it: never the token itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenView {
    pub jti: String,
    pub subject: String,
    pub account: String,
    pub access_key: String,
    pub scopes: Vec<ScopeView>,
    pub issued_at: String,
    pub expires_at: String,
    /// `valid`, `invalid` or `suspended`.
    pub status: String,
    pub status_list: String,
    pub index: u64,
}

/// `POST /authority/v1/service-accounts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccount {
    pub request_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scopes: Vec<ScopeView>,
}

/// `PATCH /authority/v1/service-accounts/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAccount {
    pub request_id: String,
    pub description: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

/// A change that carries nothing but its request: delete, suspend, resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

/// `PUT /authority/v1/service-accounts/{name}/scopes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetScopes {
    pub request_id: String,
    pub scopes: Vec<ScopeView>,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    /// Revokes every live token of the account, not only those holding a scope the change
    /// removes, which are revoked whether or not this is asked.
    #[serde(default)]
    pub revoke_tokens: bool,
}

/// What a scope change answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopesView {
    pub name: String,
    pub scopes: Vec<ScopeView>,
    pub revision: u64,
    pub tokens_revoked: u64,
}

/// `POST /authority/v1/service-accounts/{name}/keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateKey {
    pub request_id: String,
    /// RFC 3339; never expires when absent.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// What a key creation answers: the secret once, by the call that made it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCreated {
    pub key: KeyView,
    /// Empty on a retry answered from what the first attempt committed.
    pub secret_key: String,
}

impl std::fmt::Debug for KeyCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCreated")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// What an account's deletion answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deleted {
    pub name: String,
    pub tokens_revoked: u64,
}

/// What an access key's deletion answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDeleted {
    pub access_key: String,
    pub tokens_revoked: u64,
}

/// `POST /authority/v1/tokens/{jti}/revoke`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeToken {
    pub request_id: String,
}

fn rfc3339(seconds: u64) -> String {
    permguard_core::time::to_rfc3339(i64::try_from(seconds).unwrap_or(i64::MAX))
}

fn parse_time(text: &str, what: &str) -> Result<u64, Refusal> {
    permguard_core::time::from_rfc3339(text.trim())
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or_else(|| invalid(format!("`{what}` is an RFC 3339 time")))
}

/// A list token signed, and what it was signed over.
#[derive(Clone)]
struct SignedList {
    iat: u64,
    changed_at: u64,
    compact: String,
}

/// How far ahead the first list a process signs of a list it inherited is dated when the volume
/// holds no mark of what an earlier process signed: one written before the marks were kept. A
/// Plane refuses a list not after the one it holds.
pub const INHERITED_AHEAD: u64 = 60;

/// The `iat` the next list token of a list is signed at: past the one this process signed, past
/// the mark an earlier process left, and never before `now`; a list inherited with no mark is
/// dated the fixed lead ahead.
fn next_iat(held: Option<u64>, mark: Option<u64>, inherited: bool, now: u64) -> u64 {
    let past = held.max(mark).map(|iat| iat.saturating_add(1));
    match past {
        Some(past) => now.max(past),
        None if inherited => now.saturating_add(INHERITED_AHEAD),
        None => now,
    }
}

/// The token requests within the current minute, by key digest: a fixed size whatever a caller
/// claims.
#[derive(Default)]
struct Limiter {
    window: Mutex<(u64, HashMap<[u8; 16], u32>)>,
}

const MAX_WINDOW_KEYS: usize = 100_000;

impl Limiter {
    fn admit(&self, key: &str, limit: u32, now: u64) -> Result<(), TokenRefusal> {
        let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest.as_ref()[..16]);
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        let minute = now / 60;
        if window.0 != minute {
            *window = (minute, HashMap::new());
        }
        let wait = TokenRefusal::SlowDown(60 - now % 60);
        if !window.1.contains_key(&id) && window.1.len() >= MAX_WINDOW_KEYS {
            return Err(wait);
        }
        let count = window.1.entry(id).or_insert(0);
        if *count >= limit {
            return Err(wait);
        }
        *count += 1;
        Ok(())
    }
}

/// The source a request is counted as: its IPv4 address, or the /64 of its IPv6 address.
pub fn source_key(source: &str) -> String {
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

/// What the facade is built from.
pub struct Parts {
    pub accounts: Arc<dyn AccountStore>,
    pub registry: Arc<dyn TokenStore>,
    pub tokens: Option<Signer<AccessTokenV1>>,
    pub lists: Option<Signer<StatusListTokenV1>>,
    pub issuer: String,
    pub audience: String,
    pub profile: AssuranceProfile,
    pub authorization: Arc<Authorization>,
    pub mutations: Option<MutationHandle>,
    pub audit: Option<AuditHandle<AuthorityAudit>>,
    pub trust: Option<Arc<AuthorityTrust>>,
    pub time: Arc<TimeGuard>,
    /// Where the highest `iat` signed of each list is kept (BUG-0278); `None` keeps none.
    pub marks: Option<Arc<dyn MarkStore>>,
}

/// The Authority Plane's facade: one per process, shared by both transports.
pub struct Authority {
    accounts: Arc<dyn AccountStore>,
    registry: Arc<dyn TokenStore>,
    tokens: Option<Signer<AccessTokenV1>>,
    lists: Option<Signer<StatusListTokenV1>>,
    issuer: String,
    audience: String,
    profile: AssuranceProfile,
    timing: ListTiming,
    authorization: Arc<Authorization>,
    mutations: Option<MutationHandle>,
    audit: Option<AuditHandle<AuthorityAudit>>,
    trust: Option<Arc<AuthorityTrust>>,
    time: Arc<TimeGuard>,
    signed: Mutex<BTreeMap<[u8; 16], SignedList>>,
    inherited: BTreeSet<[u8; 16]>,
    /// The highest `iat` signed of each list, as the volume holds it, and where.
    marks: Mutex<BTreeMap<[u8; 16], u64>>,
    mark_store: Option<Arc<dyn MarkStore>>,
    limiter: Limiter,
    /// Every Argon2id verification, one bound.
    pub hashing: Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authority")
            .field("issuer", &self.issuer)
            .field("accounts", &self.accounts.count().ok())
            .finish_non_exhaustive()
    }
}

/// What a token issued is recorded with.
#[derive(Debug, Clone)]
pub struct Issued {
    pub answer: TokenAnswer,
    pub account: String,
    pub access_key: String,
    pub jti: String,
    pub expires_at: u64,
}

impl Authority {
    /// The facade over `parts`. The lists the store holds are read once: a list held before
    /// this process signed it is dated past whatever an earlier process signed.
    pub fn new(parts: Parts) -> Result<Self, TokenError> {
        let inherited = parts.registry.list_ids()?.into_iter().collect();
        let marks = parts
            .marks
            .as_ref()
            .map(|store| store.held())
            .unwrap_or_default();
        Ok(Self {
            inherited,
            marks: Mutex::new(marks),
            mark_store: parts.marks,
            accounts: parts.accounts,
            registry: parts.registry,
            tokens: parts.tokens,
            lists: parts.lists,
            issuer: permguard_host::authz::authority::normalized(&parts.issuer),
            audience: parts.audience,
            timing: ListTiming::of(parts.profile),
            profile: parts.profile,
            authorization: parts.authorization,
            mutations: parts.mutations,
            audit: parts.audit,
            trust: parts.trust,
            time: parts.time,
            signed: Mutex::default(),
            limiter: Limiter::default(),
            hashing: Arc::new(tokio::sync::Semaphore::new(CONCURRENT_HASHES)),
        })
    }

    /// The issuer every token names.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The accounts.
    pub fn accounts(&self) -> &Arc<dyn AccountStore> {
        &self.accounts
    }

    /// The token registry.
    pub fn registry(&self) -> &Arc<dyn TokenStore> {
        &self.registry
    }

    fn now(&self) -> u64 {
        self.time.now_secs()
    }

    // ---- keys, lists, metadata -------------------------------------------------------------

    /// The `uri` of the list `list_id` names.
    pub fn list_uri(&self, list_id: &[u8; 16]) -> String {
        format!(
            "{}/authority/v1/status-lists/{}",
            self.issuer,
            uuid_text(list_id)
        )
    }

    /// The `authority.tokens` key set, a JWK set document.
    pub fn keys_document(&self) -> Result<serde_json::Value, Refusal> {
        let signer = self.tokens.as_ref().ok_or_else(|| {
            unavailable("no authority.tokens ring is composed in this deployment")
        })?;
        let keys = signer.public_keys().map_err(unavailable)?;
        serde_json::to_value(permguard_core::keys::JwkSet::new(keys)).map_err(unavailable)
    }

    /// The RFC 8414 authorization server metadata.
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "issuer": self.issuer,
            "token_endpoint": format!("{}/authority/v1/token", self.issuer),
            "jwks_uri": format!("{}/authority/v1/keys", self.issuer),
            "grant_types_supported": [CLIENT_CREDENTIALS],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "response_types_supported": [],
            "scopes_supported": operations::ALL,
            "permguard_edition": EDITION,
            "permguard_audience": self.audience,
            "permguard_status_lists": format!("{}/authority/v1/status-lists", self.issuer),
        })
    }

    /// The id of every list a live token may name.
    pub fn list_ids(&self) -> Result<Vec<String>, Refusal> {
        Ok(self
            .registry
            .list_ids()
            .map_err(unavailable)?
            .iter()
            .map(uuid_text)
            .collect())
    }

    /// The signed list `id` names at `now`: the one already signed while the list has not changed
    /// and its `ttl` has not elapsed, a new one otherwise, its `iat` strictly after the previous
    /// one's, across a restart too.
    pub fn list_token(&self, id: &str) -> Result<String, Refusal> {
        let list_id =
            tokens::parse_id(id).ok_or_else(|| not_found(format!("no status list `{id}`")))?;
        self.signed_list(&list_id, self.now())?
            .ok_or_else(|| not_found(format!("no status list `{id}`")))
    }

    fn signed_list(&self, list_id: &[u8; 16], now: u64) -> Result<Option<String>, Refusal> {
        let Some(changed_at) = self.registry.changed_at(list_id).map_err(unavailable)? else {
            return Ok(None);
        };
        let signer = self.lists.as_ref().ok_or_else(|| {
            unavailable("no authority.tokens ring is composed in this deployment")
        })?;
        let mut signed = self.signed.lock().unwrap_or_else(PoisonError::into_inner);
        // A list the store no longer holds is forgotten; one it could not answer for is kept.
        signed.retain(|id, _| !matches!(self.registry.changed_at(id), Ok(None)));
        if let Some(held) = signed.get(list_id)
            && held.changed_at == changed_at
            && now < held.iat.saturating_add(self.timing.ttl)
        {
            return Ok(Some(held.compact.clone()));
        }
        let Some(view) = self.registry.list(list_id).map_err(unavailable)? else {
            return Ok(None);
        };
        // A change is signed at once, so a revocation holds here at once; `iat` grows strictly.
        let mut marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);
        let iat = next_iat(
            signed.get(list_id).map(|held| held.iat),
            marks.get(list_id).copied(),
            self.inherited.contains(list_id),
            now,
        );
        // The mark is on the volume before the list leaves this process: a restart then signs
        // past it. A mark that cannot be kept is a list not signed, never one a restart could
        // date before (BUG-0278).
        if let Some(store) = &self.mark_store
            && marks.get(list_id).is_none_or(|held| *held < iat)
        {
            let previous = marks.insert(*list_id, iat);
            if let Err(error) = store.keep(&marks) {
                match previous {
                    Some(previous) => marks.insert(*list_id, previous),
                    None => marks.remove(list_id),
                };
                return Err(unavailable(format!(
                    "keeping the list's signed mark: {error}"
                )));
            }
        }
        drop(marks);
        let lst = view.list.encode().map_err(unavailable)?;
        let payload = serde_json::json!({
            "iss": self.issuer,
            "sub": self.list_uri(list_id),
            "iat": iat,
            "exp": iat.saturating_add(self.timing.lifetime),
            "ttl": self.timing.ttl,
            "status_list": {"bits": tokens::BITS, "lst": lst},
        });
        let bytes = serde_json::to_vec(&payload).map_err(unavailable)?;
        let parts = signer
            .sign(&Jws::<StatusListTokenV1>::new(&bytes))
            .map_err(|error| unavailable(format!("signing the list: {error}")))?;
        let compact = format!("{}.{}.{}", parts.protected, parts.payload, parts.signature);
        if compact.len() > MAX_LIST_TOKEN_BYTES {
            return Err(unavailable(format!(
                "the list token takes {} bytes, past {MAX_LIST_TOKEN_BYTES}",
                compact.len()
            )));
        }
        signed.insert(
            *list_id,
            SignedList {
                iat,
                changed_at: view.changed_at,
                compact: compact.clone(),
            },
        );
        Ok(Some(compact))
    }

    /// Hands this Host the key set and every list as they stand: what a change or a tick of the
    /// plane calls, so the Planes in this process verify with what was just decided.
    pub fn feed_trust(&self) {
        let Some(trust) = &self.trust else {
            return;
        };
        trust.announce(&self.issuer);
        match self.keys_document() {
            Ok(jwks) => {
                if let Err(reason) = trust.accept_keys(&jwks) {
                    tracing::warn!(
                        event.name = "authority.trust_keys_refused",
                        component = crate::COMPONENT,
                        reason = %reason,
                        "this Host did not take the Authority Plane's key set"
                    );
                }
            }
            Err(_) => return,
        }
        let now = self.now();
        // Without the lists' names nothing is fed: naming none would drop every list held.
        let ids = match self.registry.list_ids() {
            Ok(ids) => ids,
            Err(error) => {
                tracing::warn!(
                    event.name = "authority.lists_unread",
                    component = crate::COMPONENT,
                    reason = %error,
                    "the status lists could not be read: the ones held stay in use"
                );
                return;
            }
        };
        for list_id in &ids {
            match self.signed_list(list_id, now) {
                Ok(Some(token)) => {
                    let _ = trust.accept_list(&token, now);
                }
                Ok(None) => {}
                Err(refusal) => tracing::warn!(
                    event.name = "authority.list_unsigned",
                    component = crate::COMPONENT,
                    refusal = ?refusal,
                    "a status list could not be signed: the one held stays in use"
                ),
            }
        }
        trust.keep_named(&ids.iter().map(uuid_text).collect::<Vec<_>>());
    }

    /// Retires the lists whose tokens have all expired: the plane's periodic pass.
    pub fn retire_expired(&self) -> Result<usize, Refusal> {
        self.registry
            .retire_expired("authority", self.now())
            .map_err(unavailable)
    }

    // ---- the token endpoint ------------------------------------------------------------------

    /// Issues a token for `request`, from `source` (`2-security/8` Token endpoint). Verifies the
    /// secret key with Argon2id: called off the async workers, within [`Self::hashing`].
    pub fn issue_token(
        &self,
        request: &TokenRequest,
        source: &str,
    ) -> Result<Issued, TokenRefusal> {
        let now = self.now();
        if request.grant_type != CLIENT_CREDENTIALS {
            return Err(TokenRefusal::UnsupportedGrantType(format!(
                "`{}` is not a grant this Authority Plane serves: {CLIENT_CREDENTIALS}",
                request.grant_type
            )));
        }
        self.limiter
            .admit(&source_key(source), SOURCE_REQUESTS_PER_MINUTE, now)?;
        if !access_keys::is_access_key(&request.client_id)
            || !access_keys::is_secret_key(&request.client_secret)
        {
            access_keys::burn(&request.client_secret);
            return Err(TokenRefusal::InvalidClient);
        }
        let found = match self.accounts.by_access_key(&request.client_id) {
            Ok(found) => found,
            Err(error) => {
                // The same work as a refusal costs, whatever the store could not answer.
                access_keys::burn(&request.client_secret);
                return Err(TokenRefusal::Unavailable(error.to_string()));
            }
        };
        let Some((account, key)) = found else {
            access_keys::burn(&request.client_secret);
            return Err(TokenRefusal::InvalidClient);
        };
        if !access_keys::verify(&request.client_secret, &key.secret_hash) {
            return Err(TokenRefusal::InvalidClient);
        }
        // Only a request that proved the key counts against it: an access key is no secret, and
        // wrong secrets counted here would let anybody who knows one keep its account from
        // obtaining tokens (BUG-0334). Refused proofs stay limited at their source, above.
        self.limiter
            .admit(&request.client_id, CLIENT_REQUESTS_PER_MINUTE, now)?;
        if account.status != Status::Active || !key.is_live(now) {
            return Err(TokenRefusal::InvalidClient);
        }
        // Refused here from the account as it was read: what a caller is told first is the same
        // whatever else arrives. What the token carries is decided again below, under the gate.
        narrowed(&account.scopes, request.scope.as_deref())?;
        let lifetime = match request.requested_lifetime {
            None => DEFAULT_LIFETIME,
            Some(0) => {
                return Err(TokenRefusal::InvalidRequest(
                    "`requested_lifetime` is at least one second".to_owned(),
                ));
            }
            Some(asked) if asked > max_lifetime(self.profile) => {
                return Err(TokenRefusal::InvalidRequest(format!(
                    "`requested_lifetime` is at most {} seconds under the `{}` profile",
                    max_lifetime(self.profile),
                    self.profile.as_str()
                )));
            }
            Some(asked) => asked,
        };
        let signer = self
            .tokens
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no authority.tokens ring".to_owned()))?;
        signer
            .ready()
            .map_err(|error| TokenRefusal::Unavailable(error.to_string()))?;
        // The account is read again and the token recorded as one step with any change of the
        // account (decision E26): a token is never issued for an account, a key or a scope that
        // a change which has already ended its tokens took away.
        let record = || {
            let current = self
                .accounts
                .get(&account.name)
                .map_err(|error| TokenRefusal::Unavailable(error.to_string()))?
                .ok_or(TokenRefusal::InvalidClient)?;
            let key = current
                .key(&key.access_key)
                .ok_or(TokenRefusal::InvalidClient)?;
            if current.status != Status::Active || !key.is_live(now) {
                return Err(TokenRefusal::InvalidClient);
            }
            let scopes = narrowed(&current.scopes, request.scope.as_deref())?;
            let lifetime = match key.expires_at {
                Some(expires) => lifetime.min(expires.saturating_sub(now)),
                None => lifetime,
            };
            let issued = self
                .registry
                .issue(
                    TokenDraft {
                        account: current.name.clone(),
                        access_key: key.access_key.clone(),
                        scopes: scopes.clone(),
                        expires_at: now.saturating_add(lifetime),
                    },
                    now,
                )
                .map_err(|error| TokenRefusal::Unavailable(error.to_string()))?;
            Ok((issued, scopes))
        };
        let (issued, scopes) = match &self.mutations {
            Some(mutations) => mutations.consistent(record),
            // No change of an account is made on a process with no mutation journal.
            None => record(),
        }?;
        let scope = scope_words(&scopes);
        let claims = serde_json::json!({
            "iss": self.issuer,
            "sub": accounts::principal_of(&account.name),
            "client_id": key.access_key,
            "aud": self.audience,
            "scope": scope,
            "permguard_scopes": scopes.iter().map(ScopeView::of).collect::<Vec<_>>(),
            "iat": now,
            "nbf": now,
            "exp": issued.expires_at,
            "jti": issued.jti_text(),
            "status": {"status_list": {"idx": issued.index, "uri": self.list_uri(&issued.list_id)}},
        });
        let bytes = serde_json::to_vec(&claims)
            .map_err(|error| TokenRefusal::Unavailable(error.to_string()))?;
        let parts = signer
            .sign(&Jws::<AccessTokenV1>::new(&bytes))
            .map_err(|error| TokenRefusal::Unavailable(format!("signing the token: {error}")))?;
        let token = format!("{}.{}.{}", parts.protected, parts.payload, parts.signature);
        if token.len() > MAX_TOKEN_BYTES {
            // Never handed out: an over-long token is revoked at once.
            let _ = self.registry.set_status(
                None,
                &|held: &IssuedToken| held.jti == issued.jti,
                status::INVALID,
                "authority",
                now,
            );
            return Err(TokenRefusal::InvalidScope(format!(
                "the token would take {} bytes, past {MAX_TOKEN_BYTES}: ask fewer scopes",
                token.len()
            )));
        }
        // A token's list changed: this Host's Planes hold it before anyone presents the token.
        self.feed_trust();
        Ok(Issued {
            answer: TokenAnswer {
                access_token: token,
                token_type: "Bearer".to_owned(),
                expires_in: issued.expires_at.saturating_sub(now),
                scope,
            },
            account: account.name,
            access_key: key.access_key,
            jti: issued.jti_text(),
            expires_at: issued.expires_at,
        })
    }

    /// Records a token issued, never the token.
    pub async fn record_issued(&self, issued: &Issued) {
        let Some(audit) = &self.audit else {
            return;
        };
        let principal = accounts::principal_of(&issued.account);
        let facts = [
            ("client_id", Fact::Text(&issued.access_key)),
            ("scope", Fact::Text(&issued.answer.scope)),
            ("jti", Fact::Text(&issued.jti)),
            ("expires_at", Fact::Uint(issued.expires_at)),
        ];
        let event = permguard_core::AuditEvent::new(
            permguard_host::audit::AUDIT_TOKEN_ISSUED,
            Subject::Principal(&principal),
        )
        .with_facts(&facts);
        if let Err(error) = audit.record_event(&event).await {
            tracing::warn!(
                event.name = "authority.token_unrecorded",
                component = crate::COMPONENT,
                error = %error,
                "a token issued could not be recorded in the audit trail"
            );
        }
    }

    /// Records a token request refused, by the reason's class.
    pub async fn record_refused(&self, client_id: &str, refusal: &TokenRefusal) {
        let Some(audit) = &self.audit else {
            return;
        };
        // What a caller claims is recorded only when it has the form of an access key.
        let claimed = if access_keys::is_access_key(client_id) {
            client_id
        } else {
            "unknown"
        };
        let facts = [
            ("client_id", Fact::Text(claimed)),
            ("reason", Fact::Text(refusal.error())),
        ];
        let event = permguard_core::AuditEvent::new(
            permguard_host::audit::AUDIT_TOKEN_REFUSED,
            Subject::System("token-endpoint"),
        )
        .with_facts(&facts);
        if let Err(error) = audit.record_event(&event).await {
            tracing::warn!(
                event.name = "authority.token_unrecorded",
                component = crate::COMPONENT,
                error = %error,
                "a refused token request could not be recorded in the audit trail"
            );
        }
    }

    // ---- reads -------------------------------------------------------------------------------

    fn admit(&self, actor: &Actor, operation: &str) -> Result<String, Refusal> {
        self.authorization
            .authorize(actor, operation, &resource())?;
        Ok(actor.principal()?.as_str().to_owned())
    }

    fn view(&self, account: &Account) -> AccountView {
        let now = self.now();
        AccountView {
            name: account.name.clone(),
            description: account.description.clone(),
            status: account.status.as_str().to_owned(),
            scopes: account.scopes.iter().map(ScopeView::of).collect(),
            keys: account
                .keys
                .iter()
                .map(|key| self.key_view(key, now))
                .collect(),
            administrator: account.is_admin(),
            created_at: rfc3339(account.created_at),
            updated_at: rfc3339(account.updated_at),
            revision: account.revision,
        }
    }

    fn key_view(&self, key: &AccessKey, now: u64) -> KeyView {
        KeyView {
            access_key: key.access_key.clone(),
            created_at: rfc3339(key.created_at),
            expires_at: key.expires_at.map(rfc3339),
            // A view never fails for it: a store that cannot say shows no last use.
            last_used_at: self
                .registry
                .last_used(&key.access_key)
                .ok()
                .flatten()
                .map(rfc3339),
            status: if key.is_live(now) {
                "active"
            } else {
                "expired"
            }
            .to_owned(),
        }
    }

    fn token_view(&self, token: &IssuedToken) -> TokenView {
        TokenView {
            jti: token.jti_text(),
            subject: accounts::principal_of(&token.account),
            account: token.account.clone(),
            access_key: token.access_key.clone(),
            scopes: token.scopes.iter().map(ScopeView::of).collect(),
            issued_at: rfc3339(token.issued_at),
            expires_at: rfc3339(token.expires_at),
            status: status::name(token.status).to_owned(),
            status_list: self.list_uri(&token.list_id),
            index: token.index,
        }
    }

    fn held(&self, name: &str) -> Result<Account, Refusal> {
        self.accounts
            .get(name)
            .map_err(refusal_of)?
            .ok_or_else(|| not_found(format!("no service account `{name}`")))
    }

    /// `GET /authority/v1/service-accounts`.
    pub fn list_accounts(&self, actor: &Actor) -> Result<Vec<AccountView>, Refusal> {
        self.admit(actor, operations::ACCOUNTS_READ)?;
        Ok(self
            .accounts
            .list()
            .map_err(refusal_of)?
            .iter()
            .map(|account| self.view(account))
            .collect())
    }

    /// `GET /authority/v1/service-accounts/{name}`.
    pub fn get_account(&self, actor: &Actor, name: &str) -> Result<AccountView, Refusal> {
        self.admit(actor, operations::ACCOUNTS_READ)?;
        Ok(self.view(&self.held(name)?))
    }

    /// `GET /authority/v1/service-accounts/{name}/scopes`.
    pub fn get_scopes(&self, actor: &Actor, name: &str) -> Result<ScopesView, Refusal> {
        self.admit(actor, operations::ACCOUNTS_READ)?;
        let account = self.held(name)?;
        Ok(ScopesView {
            name: account.name.clone(),
            scopes: account.scopes.iter().map(ScopeView::of).collect(),
            revision: account.revision,
            tokens_revoked: 0,
        })
    }

    /// `GET /authority/v1/service-accounts/{name}/keys`.
    pub fn list_keys(&self, actor: &Actor, name: &str) -> Result<Vec<KeyView>, Refusal> {
        self.admit(actor, operations::ACCOUNTS_READ)?;
        let now = self.now();
        Ok(self
            .held(name)?
            .keys
            .iter()
            .map(|key| self.key_view(key, now))
            .collect())
    }

    /// `GET /authority/v1/tokens?account&status`.
    pub fn list_tokens(
        &self,
        actor: &Actor,
        account: Option<&str>,
        wanted: Option<&str>,
    ) -> Result<Vec<TokenView>, Refusal> {
        self.admit(actor, operations::TOKENS_READ)?;
        let wanted = wanted
            .filter(|wanted| !wanted.is_empty())
            .map(|wanted| {
                status::parse(wanted)
                    .ok_or_else(|| invalid("`status` is `valid`, `invalid` or `suspended`"))
            })
            .transpose()?;
        Ok(self
            .registry
            .live_tokens(self.now())
            .map_err(unavailable)?
            .iter()
            .filter(|token| {
                account.is_none_or(|account| account.is_empty() || token.account == account)
            })
            .filter(|token| wanted.is_none_or(|wanted| token.status == wanted))
            .map(|token| self.token_view(token))
            .collect())
    }

    // ---- changes -----------------------------------------------------------------------------

    /// Runs one change as `principal` through the transaction: once per `(principal, request
    /// id)` inside the window. `rebuild` answers an operation recovery committed without its
    /// answer, from the state.
    #[allow(clippy::too_many_arguments)]
    fn transact<T, R>(
        &self,
        principal: &str,
        domain: &'static str,
        operation: &'static str,
        action: &'static str,
        request_id: &str,
        request: &R,
        target: &str,
        check: impl FnOnce() -> Result<(), AccountsError>,
        apply: impl FnOnce(&Applying<'_>) -> Result<Applied<T>, Failure<AccountsError>>,
        rebuild: impl FnOnce() -> Result<T, Refusal>,
    ) -> Result<(T, bool), Refusal>
    where
        T: Serialize + serde::de::DeserializeOwned,
        R: Serialize,
    {
        let request_id = request_id.trim();
        if request_id.is_empty()
            || request_id.len() > 128
            || request_id.chars().any(char::is_control)
        {
            return Err(refused(
                ErrorClass::Validation,
                codes::host::REQUEST_ID_REQUIRED,
                "every change carries a `request_id` of 1 to 128 printable bytes",
            ));
        }
        let mutations = self.mutations.as_ref().ok_or_else(|| {
            unavailable("no mutation journal is open on this process: nothing was applied")
        })?;
        let digest = {
            use sha2::Digest as _;
            let bytes = serde_json::to_vec(&(operation, target, request)).map_err(unavailable)?;
            sha2::Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        // The engine's handle runs one domain; a token revocation runs in the tokens' domain on
        // a handle of its own.
        let handle = if domain == mutations.domain() {
            mutations.clone()
        } else {
            mutations.for_domain(domain)
        };
        let outcome = handle
            .run_checked(
                Begin {
                    domain,
                    operation,
                    action,
                    initiator: Initiator::Principal(principal.to_owned()),
                    request: Some(RequestKey {
                        request_id: request_id.to_owned(),
                        digest,
                    }),
                    target: Some(target.to_owned()),
                },
                check,
                apply,
            )
            .map_err(mutation_refusal)?;
        let answered = match outcome {
            Outcome::Applied(value) => (value, true),
            Outcome::Replayed(value) => (value, false),
            Outcome::Reconciled { .. } => (rebuild()?, false),
        };
        // Whatever changed, this Host's Planes verify with it now.
        self.feed_trust();
        Ok(answered)
    }

    /// `POST /authority/v1/service-accounts`.
    pub fn create_account(
        &self,
        actor: &Actor,
        create: CreateAccount,
    ) -> Result<AccountView, Refusal> {
        let principal = self.admit(actor, operations::ACCOUNTS_WRITE)?;
        let scopes = create
            .scopes
            .iter()
            .map(ScopeView::read)
            .collect::<Result<Vec<_>, _>>()?;
        let name = create.name.trim().to_owned();
        let now = self.now();
        let account = Account::new(&name, &create.description, scopes, now);
        let rebuilt = || self.held(&name).map(|account| self.view(&account));
        self.transact(
            &principal,
            accounts::DOMAIN,
            "authority.accounts.create",
            actions::CREATED,
            &create.request_id,
            &create,
            &name,
            || {
                accounts::check_name(&name).map_err(AccountsError::Invalid)?;
                if self.accounts.get(&name)?.is_some() {
                    return Err(AccountsError::Conflict(format!(
                        "the service account `{name}` exists"
                    )));
                }
                Ok(())
            },
            |applying| {
                let written = self
                    .accounts
                    .create(Some(applying), account, &principal, now)
                    .map_err(failure)?;
                Ok(Applied {
                    revision: written.revision,
                    target: Some(written.name.clone()),
                    value: self.view(&written),
                })
            },
            rebuilt,
        )
        .map(|(view, _)| view)
    }

    fn expect_revision(account: &Account, expected: Option<u64>) -> Result<(), AccountsError> {
        match expected {
            Some(expected) if expected != account.revision => {
                Err(AccountsError::Conflict(format!(
                    "the change expected revision {expected}, the account is at {}",
                    account.revision
                )))
            }
            _ => Ok(()),
        }
    }

    /// `PATCH /authority/v1/service-accounts/{name}`: the description.
    pub fn update_account(
        &self,
        actor: &Actor,
        name: &str,
        update: UpdateAccount,
    ) -> Result<AccountView, Refusal> {
        let principal = self.admit(actor, operations::ACCOUNTS_WRITE)?;
        let held = self.held(name)?;
        let now = self.now();
        // Decided again on the account as it stands when the change is applied.
        let changed = |current: &Account| {
            Self::expect_revision(current, update.expected_revision)?;
            Ok(Account {
                description: update.description.clone(),
                ..current.clone()
            })
        };
        self.transact(
            &principal,
            accounts::DOMAIN,
            "authority.accounts.update",
            actions::UPDATED,
            &update.request_id,
            &update,
            name,
            || changed(&held).map(|_| ()),
            |applying| {
                let written = self
                    .accounts
                    .update(Some(applying), name, &changed, &principal, now)
                    .map_err(failure)?;
                Ok(Applied {
                    revision: written.revision,
                    target: Some(written.name.clone()),
                    value: self.view(&written),
                })
            },
            || self.held(name).map(|account| self.view(&account)),
        )
        .map(|(view, _)| view)
    }

    /// `POST /authority/v1/service-accounts/{name}/suspend` and `/resume`: the account's live
    /// tokens are `SUSPENDED` while it is, and `INVALID` once it resumes, which obtains new ones.
    pub fn set_account_status(
        &self,
        actor: &Actor,
        name: &str,
        suspended: bool,
        change: Change,
    ) -> Result<AccountView, Refusal> {
        let principal = self.admit(actor, operations::ACCOUNTS_WRITE)?;
        let held = self.held(name)?;
        let now = self.now();
        let (operation, action, wanted, from, to) = if suspended {
            (
                "authority.accounts.suspend",
                actions::SUSPENDED,
                Status::Suspended,
                status::VALID,
                status::SUSPENDED,
            )
        } else {
            // A resumed account obtains new tokens; those it held when suspended end for good,
            // so a suspension is never undone for a token somebody may have taken meanwhile
            // (BUG-0340).
            (
                "authority.accounts.resume",
                actions::RESUMED,
                Status::Active,
                status::SUSPENDED,
                status::INVALID,
            )
        };
        // Decided again on the account as it stands when the change is applied.
        let changed = |current: &Account| {
            if current.is_admin() {
                return Err(AccountsError::Conflict(
                    "`admin` is never suspended: there is always one account that can repair \
                     the others"
                        .to_owned(),
                ));
            }
            Self::expect_revision(current, change.expected_revision)?;
            Ok(Account {
                status: wanted,
                ..current.clone()
            })
        };
        self.transact(
            &principal,
            accounts::DOMAIN,
            operation,
            action,
            &change.request_id,
            &change,
            name,
            || changed(&held).map(|_| ()),
            |applying| {
                let written = self
                    .accounts
                    .update(Some(applying), name, &changed, &principal, now)
                    .map_err(failure)?;
                self.registry
                    .set_status(
                        None,
                        &|token: &IssuedToken| token.account == name && token.status == from,
                        to,
                        &principal,
                        now,
                    )
                    .map_err(token_failure)?;
                Ok(Applied {
                    revision: written.revision,
                    target: Some(written.name.clone()),
                    value: self.view(&written),
                })
            },
            || self.held(name).map(|account| self.view(&account)),
        )
        .map(|(view, _)| view)
    }

    /// `DELETE /authority/v1/service-accounts/{name}`: its keys with it, every live token of it
    /// `INVALID`.
    pub fn delete_account(
        &self,
        actor: &Actor,
        name: &str,
        change: Change,
    ) -> Result<Deleted, Refusal> {
        let principal = self.admit(actor, operations::ACCOUNTS_WRITE)?;
        let now = self.now();
        let held = self.accounts.get(name).map_err(refusal_of)?;
        self.transact(
            &principal,
            accounts::DOMAIN,
            "authority.accounts.delete",
            actions::DELETED,
            &change.request_id,
            &change,
            name,
            || {
                let held = held.as_ref().ok_or_else(|| {
                    AccountsError::NotFound(format!("no service account `{name}`"))
                })?;
                if held.is_admin() {
                    return Err(AccountsError::Conflict(
                        "`admin` is never deleted: there is always one account that can repair \
                         the others"
                            .to_owned(),
                    ));
                }
                Self::expect_revision(held, change.expected_revision)
            },
            |applying| {
                // The revision the caller expects is the account's when it is deleted.
                self.accounts
                    .delete(
                        Some(applying),
                        name,
                        &|current| Self::expect_revision(current, change.expected_revision),
                        &principal,
                        now,
                    )
                    .map_err(failure)?;
                let revoked = self
                    .registry
                    .set_status(
                        None,
                        &|token: &IssuedToken| token.account == name,
                        status::INVALID,
                        &principal,
                        now,
                    )
                    .map_err(token_failure)?;
                Ok(Applied {
                    revision: self.accounts.revision().map_err(failure)?,
                    target: Some(name.to_owned()),
                    value: Deleted {
                        name: name.to_owned(),
                        tokens_revoked: revoked as u64,
                    },
                })
            },
            || {
                Ok(Deleted {
                    name: name.to_owned(),
                    tokens_revoked: 0,
                })
            },
        )
        .map(|(deleted, _)| deleted)
    }

    /// `PUT /authority/v1/service-accounts/{name}/scopes`: replaced whole; the live tokens holding
    /// a scope it removes revoked at once, and every live token of the account when asked.
    pub fn set_scopes(
        &self,
        actor: &Actor,
        name: &str,
        set: SetScopes,
    ) -> Result<ScopesView, Refusal> {
        let principal = self.admit(actor, operations::ACCOUNTS_WRITE)?;
        let held = self.held(name)?;
        let scopes = set
            .scopes
            .iter()
            .map(ScopeView::read)
            .collect::<Result<Vec<_>, _>>()?;
        let now = self.now();
        // Decided again on the account as it stands when the change is applied.
        let changed = |current: &Account| {
            if current.is_admin() {
                return Err(AccountsError::Conflict(
                    "`admin`'s scopes are every operation on every resource, and never change"
                        .to_owned(),
                ));
            }
            accounts::check_scopes(&scopes).map_err(AccountsError::Invalid)?;
            Self::expect_revision(current, set.expected_revision)?;
            Ok(Account {
                scopes: scopes.clone(),
                ..current.clone()
            })
        };
        self.transact(
            &principal,
            accounts::DOMAIN,
            "authority.accounts.scopes",
            actions::SCOPES_SET,
            &set.request_id,
            &set,
            name,
            || changed(&held).map(|_| ()),
            |applying| {
                let written = self
                    .accounts
                    .update(Some(applying), name, &changed, &principal, now)
                    .map_err(failure)?;
                // A narrowing holds at once: a live token holding anything the new scopes do not
                // grant is revoked, and with `revoke_tokens` every live token of the account is
                // (BUG-0339). A widening revokes nothing.
                let revoked = self
                    .registry
                    .set_status(
                        None,
                        &|token: &IssuedToken| {
                            token.account == name
                                && (set.revoke_tokens || !granted_within(&token.scopes, &scopes))
                        },
                        status::INVALID,
                        &principal,
                        now,
                    )
                    .map_err(token_failure)?;
                Ok(Applied {
                    revision: written.revision,
                    target: Some(written.name.clone()),
                    value: ScopesView {
                        name: written.name.clone(),
                        scopes: written.scopes.iter().map(ScopeView::of).collect(),
                        revision: written.revision,
                        tokens_revoked: revoked as u64,
                    },
                })
            },
            || self.get_scopes(actor, name),
        )
        .map(|(view, _)| view)
    }

    /// `POST /authority/v1/service-accounts/{name}/keys`: the secret key answered once, by the
    /// call that made it; the engine keeps the answer without it.
    pub fn create_key(
        &self,
        actor: &Actor,
        name: &str,
        create: CreateKey,
    ) -> Result<KeyCreated, Refusal> {
        let principal = self.admit(actor, operations::ACCOUNTS_WRITE)?;
        let held = self.held(name)?;
        let now = self.now();
        let expires_at = create
            .expires_at
            .as_deref()
            .map(|text| parse_time(text, "expires_at"))
            .transpose()?;
        if expires_at.is_some_and(|expires| expires <= now) {
            return Err(invalid("`expires_at` is in the future"));
        }
        let access_key = access_keys::draw_access_key().map_err(unavailable)?;
        let secret = access_keys::draw_secret_key().map_err(unavailable)?;
        let secret_hash = access_keys::hash(&secret).map_err(unavailable)?;
        let key = AccessKey {
            access_key: access_key.clone(),
            secret_hash,
            created_at: now,
            expires_at,
        };
        // Decided again on the account as it stands when the key is added: the keys it holds
        // then are the ones the new key joins.
        let with_key = |current: &Account| {
            if current.live_keys(now).count() >= accounts::MAX_LIVE_KEYS {
                return Err(AccountsError::Conflict(format!(
                    "`{name}` holds {} live access keys already: delete one first",
                    accounts::MAX_LIVE_KEYS
                )));
            }
            let mut keys = current.keys.clone();
            keys.push(key.clone());
            Ok(Account {
                keys,
                ..current.clone()
            })
        };
        let (view, applied) = self.transact(
            &principal,
            accounts::DOMAIN,
            "authority.keys.create",
            actions::KEY_CREATED,
            &create.request_id,
            &create,
            name,
            || with_key(&held).map(|_| ()),
            |applying| {
                let written = self
                    .accounts
                    .update(Some(applying), name, &with_key, &principal, now)
                    .map_err(failure)?;
                Ok(Applied {
                    revision: written.revision,
                    target: Some(written.name.clone()),
                    value: self.key_view(&key, now),
                })
            },
            || {
                Err(conflict(
                    "the key was made before a restart and its secret is gone: delete it and \
                     make another",
                ))
            },
        )?;
        Ok(KeyCreated {
            key: view,
            secret_key: if applied {
                secret.to_string()
            } else {
                String::new()
            },
        })
    }

    /// `DELETE /authority/v1/service-accounts/{name}/keys/{access_key}`: every live token it
    /// obtained `INVALID`; `admin`'s last live key is never deleted.
    pub fn delete_key(
        &self,
        actor: &Actor,
        name: &str,
        access_key: &str,
        change: Change,
    ) -> Result<KeyDeleted, Refusal> {
        let principal = self.admit(actor, operations::ACCOUNTS_WRITE)?;
        let held = self.held(name)?;
        let now = self.now();
        // Decided again on the account as it stands when the key is removed: `admin`'s last
        // live key is judged among the keys it holds then.
        let without_key = |current: &Account| {
            if current.key(access_key).is_none() {
                return Err(AccountsError::NotFound(format!(
                    "`{name}` holds no access key {access_key}"
                )));
            }
            if current.is_admin()
                && current
                    .live_keys(now)
                    .all(|key| key.access_key == access_key)
            {
                return Err(AccountsError::Conflict(
                    "`admin`'s last live access key is never deleted: make another first"
                        .to_owned(),
                ));
            }
            Ok(Account {
                keys: current
                    .keys
                    .iter()
                    .filter(|key| key.access_key != access_key)
                    .cloned()
                    .collect(),
                ..current.clone()
            })
        };
        self.transact(
            &principal,
            accounts::DOMAIN,
            "authority.keys.delete",
            actions::KEY_DELETED,
            &change.request_id,
            &(access_key, &change),
            name,
            || without_key(&held).map(|_| ()),
            |applying| {
                let written = self
                    .accounts
                    .update(Some(applying), name, &without_key, &principal, now)
                    .map_err(failure)?;
                let revoked = self
                    .registry
                    .set_status(
                        None,
                        &|token: &IssuedToken| token.access_key == access_key,
                        status::INVALID,
                        &principal,
                        now,
                    )
                    .map_err(token_failure)?;
                Ok(Applied {
                    revision: written.revision,
                    target: Some(written.name.clone()),
                    value: KeyDeleted {
                        access_key: access_key.to_owned(),
                        tokens_revoked: revoked as u64,
                    },
                })
            },
            || {
                Ok(KeyDeleted {
                    access_key: access_key.to_owned(),
                    tokens_revoked: 0,
                })
            },
        )
        .map(|(deleted, _)| deleted)
    }

    /// `POST /authority/v1/tokens/{jti}/revoke`: `INVALID` in its list, at once here and on each
    /// Plane once it holds the list; under `tokens.revoke`, or by the token's own bearer.
    pub fn revoke_token(
        &self,
        actor: &Actor,
        jti: &str,
        revoke: RevokeToken,
    ) -> Result<TokenView, Refusal> {
        // A bearer may always end its own token: that widens nothing. Any other is
        // `tokens.revoke`'s.
        let principal = match own_token(actor, jti) {
            Some(principal) => principal,
            None => self.admit(actor, operations::TOKENS_REVOKE)?,
        };
        let id = tokens::parse_id(jti).ok_or_else(|| not_found(format!("no token `{jti}`")))?;
        let now = self.now();
        let rebuild = || {
            self.registry
                .token(&id)
                .map_err(unavailable)?
                .map(|token| self.token_view(&token))
                .ok_or_else(|| not_found(format!("no token `{jti}`")))
        };
        self.transact(
            &principal,
            tokens::DOMAIN,
            "authority.tokens.revoke",
            actions::TOKEN_REVOKED,
            &revoke.request_id,
            &revoke,
            jti,
            || {
                let token = self
                    .registry
                    .token(&id)
                    .map_err(|error| AccountsError::Unavailable(error.to_string()))?
                    .ok_or_else(|| AccountsError::NotFound(format!("no token `{jti}`")))?;
                if token.status == status::INVALID {
                    return Err(AccountsError::Conflict(format!(
                        "the token `{jti}` is revoked already"
                    )));
                }
                Ok(())
            },
            |applying| {
                self.registry
                    .set_status(
                        Some(applying),
                        &|token: &IssuedToken| token.jti == id,
                        status::INVALID,
                        &principal,
                        now,
                    )
                    .map_err(token_failure)?;
                let token = self
                    .registry
                    .token(&id)
                    .map_err(token_failure)?
                    .ok_or_else(|| failure(AccountsError::NotFound(format!("no token `{jti}`"))))?;
                Ok(Applied {
                    revision: self.registry.revision().map_err(token_failure)?,
                    target: Some(jti.to_owned()),
                    value: self.token_view(&token),
                })
            },
            rebuild,
        )
        .map(|(view, _)| view)
    }
}

/// The scopes a token carries: the account's, narrowed to the operations `asked` names when it
/// names some; an operation the account does not hold is `invalid_scope`.
pub fn narrowed(
    scopes: &[TokenScope],
    asked: Option<&str>,
) -> Result<Vec<TokenScope>, TokenRefusal> {
    let asked: BTreeSet<&str> = asked
        .map(|asked| asked.split_whitespace().collect())
        .unwrap_or_default();
    if let Some(missing) = asked.iter().find(|operation| {
        !scopes
            .iter()
            .any(|scope| scope.operations.contains(**operation))
    }) {
        return Err(TokenRefusal::InvalidScope(format!(
            "the account holds no scope with `{missing}`"
        )));
    }
    let narrowed: Vec<TokenScope> = scopes
        .iter()
        .filter_map(|scope| {
            let operations: BTreeSet<String> = scope
                .operations
                .iter()
                .filter(|operation| asked.is_empty() || asked.contains(operation.as_str()))
                .cloned()
                .collect();
            (!operations.is_empty()).then(|| TokenScope {
                operations,
                selector: scope.selector.clone(),
            })
        })
        .collect();
    if narrowed.is_empty() {
        return Err(TokenRefusal::InvalidScope(
            "the account holds no scope: a token would allow nothing".to_owned(),
        ));
    }
    Ok(narrowed)
}

/// The operations of `scopes`, space separated, as OAuth tools read `scope`.
pub fn scope_words(scopes: &[TokenScope]) -> String {
    scopes
        .iter()
        .flat_map(|scope| scope.operations.iter().map(String::as_str))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(operations: &[&str], selector: &str) -> TokenScope {
        TokenScope {
            operations: operations.iter().map(|op| (*op).to_owned()).collect(),
            selector: Selector::parse(selector).unwrap_or_else(|_| unreachable!("a selector")),
        }
    }

    /// What a token is issued with is within its account's scopes, whatever was asked: a start
    /// ends the tokens that hold more than their account grants, and must end none of these.
    #[test]
    fn what_a_token_is_issued_with_is_within_its_accounts_scopes() {
        let held = vec![
            scope(&["decision.evaluate", "event.submit"], "plane/data/*"),
            scope(&["catalog.read"], "plane/control/*"),
        ];
        for asked in [
            None,
            Some("decision.evaluate"),
            Some("event.submit catalog.read"),
            Some("catalog.read"),
        ] {
            let issued = narrowed(&held, asked).unwrap_or_else(|_| unreachable!("granted"));
            assert!(granted_within(&issued, &held), "{asked:?}: {issued:?}");
        }
    }

    #[test]
    fn a_token_narrows_to_what_is_asked_and_never_widens() {
        let held = vec![
            scope(&["decision.evaluate", "event.submit"], "plane/data/*"),
            scope(&["catalog.read"], "plane/control/*"),
        ];
        assert_eq!(narrowed(&held, None).ok(), Some(held.clone()));
        assert_eq!(
            narrowed(&held, Some("decision.evaluate")).ok(),
            Some(vec![scope(&["decision.evaluate"], "plane/data/*")])
        );
        assert!(matches!(
            narrowed(&held, Some("catalog.write")),
            Err(TokenRefusal::InvalidScope(_))
        ));
        assert!(narrowed(&[], None).is_err());
        assert_eq!(
            scope_words(&held),
            "catalog.read decision.evaluate event.submit"
        );
    }

    #[test]
    fn a_refusal_names_the_rule_never_the_cause() {
        assert_eq!(TokenRefusal::InvalidClient.status(), 401);
        assert_eq!(TokenRefusal::SlowDown(3).status(), 429);
        assert_eq!(
            TokenRefusal::InvalidClient.description(),
            "the client could not be authenticated"
        );
        let limiter = Limiter::default();
        for _ in 0..3 {
            limiter
                .admit("k", 3, 60)
                .unwrap_or_else(|_| unreachable!("admitted"));
        }
        assert!(matches!(
            limiter.admit("k", 3, 61),
            Err(TokenRefusal::SlowDown(59))
        ));
        assert!(limiter.admit("k", 3, 120).is_ok(), "a new minute");
        assert_eq!(
            source_key("2001:db8:1:2:3:4:5:6"),
            "source:2001:db8:1:2::/64"
        );
    }

    /// A token's scopes are within new scopes when every operation it holds is granted where it
    /// holds it: a narrowing that takes any away is not (BUG-0339).
    #[test]
    fn a_token_is_within_new_scopes_only_when_they_grant_all_it_holds() {
        let held = [scope(
            &["decision.evaluate", "catalog.read"],
            "plane/data/zone/z/*",
        )];
        assert!(granted_within(
            &held,
            &[scope(
                &["decision.evaluate", "catalog.read"],
                "plane/data/*"
            )]
        ));
        assert!(granted_within(
            &held,
            &[
                scope(&["decision.evaluate"], "plane/data/*"),
                scope(&["catalog.read"], "plane/data/zone/z/*"),
            ]
        ));
        assert!(
            !granted_within(&held, &[scope(&["decision.evaluate"], "plane/data/*")]),
            "an operation taken away"
        );
        assert!(
            !granted_within(
                &held,
                &[scope(
                    &["decision.evaluate", "catalog.read"],
                    "plane/data/zone/other/*"
                )]
            ),
            "a resource taken away"
        );
        assert!(
            granted_within(&[], &[]),
            "a token holding nothing loses nothing"
        );
    }

    /// A bearer names its own token by its `jti`, however it is spelt; any other `jti`, or a
    /// caller without a token, is left to `tokens.revoke`.
    #[test]
    fn a_bearer_may_revoke_its_own_token_only() {
        use permguard_core::authz::{ActorContext, Credential, Principal, TokenGrant};

        let jti = "0198f2aa-0000-7000-8000-000000000001";
        let bearer = Actor::Authenticated(ActorContext::of_token(
            Principal::new("sa:billing").unwrap_or_else(|_| unreachable!("a principal")),
            TokenGrant {
                scopes: vec![scope(&["decision.evaluate"], "plane/data/*")],
                jti: jti.to_owned(),
                list_uri: String::new(),
                list_iat: 0,
                list_digest: [0; 32],
                list_index: 0,
            },
        ));
        assert_eq!(own_token(&bearer, jti).as_deref(), Some("sa:billing"));
        assert_eq!(
            own_token(&bearer, &jti.to_uppercase()).as_deref(),
            Some("sa:billing")
        );
        assert_eq!(
            own_token(&bearer, "0198f2aa-0000-7000-8000-000000000002"),
            None
        );
        assert_eq!(own_token(&bearer, "not-a-jti"), None);
        let certificate = Actor::Authenticated(ActorContext::new(
            Principal::new("cert:sha256:ab").unwrap_or_else(|_| unreachable!("a principal")),
            Credential::Certificate,
            None,
        ));
        assert_eq!(own_token(&certificate, jti), None);
        assert_eq!(own_token(&Actor::Anonymous, jti), None);
    }
}

#[cfg(test)]
mod signed_marks {
    #![allow(clippy::expect_used)]

    use permguard_host::storage::Dir;

    use super::*;
    use crate::marks::files::{FileMarks, SIGNED_MARKS};

    /// BUG-0278: 150 changes signed within a few seconds run `iat` ahead of the clock by about as
    /// many seconds; the mark kept on the volume makes the first list a restarted process signs
    /// strictly later than every list signed before, which a fixed lead did not.
    #[test]
    fn a_restarted_authority_signs_past_every_list_it_signed_before() {
        let root = std::env::temp_dir().join(format!(
            "permguard-authority-marks-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("created");
        let store = FileMarks::new(Dir::open(&root).expect("the directory"));
        let list = [7u8; 16];
        let start = 1_794_213_639;

        let mut held = None;
        let mut marks = BTreeMap::new();
        for change in 0..150 {
            let now = start + change / 40;
            let iat = next_iat(held, marks.get(&list).copied(), false, now);
            assert!(held.is_none_or(|before| iat > before), "strictly later");
            held = Some(iat);
            marks.insert(list, iat);
            store.keep(&marks).expect("kept");
        }
        let last = held.expect("signed");
        assert!(last >= start + 145, "ahead of the clock: {last}");

        // Restarted a second later: what the volume says, not the fixed lead.
        let reopened = store.held();
        assert_eq!(reopened.get(&list), Some(&last));
        let first = next_iat(None, reopened.get(&list).copied(), true, start + 5);
        assert!(first > last, "{first} after {last}");
        assert!(
            start + 5 + INHERITED_AHEAD < last,
            "the fixed lead alone would have dated it before"
        );

        // With no mark, the fixed lead still applies to an inherited list; a fresh list is now.
        assert_eq!(next_iat(None, None, true, 100), 100 + INHERITED_AHEAD);
        assert_eq!(next_iat(None, None, false, 100), 100);
        assert_eq!(next_iat(Some(250), None, false, 100), 251);
        assert_eq!(next_iat(Some(5), Some(300), true, 100), 301);

        // A file that does not read is no mark.
        std::fs::write(root.join(SIGNED_MARKS), b"not json").expect("written");
        assert!(store.held().is_empty());
    }
}
