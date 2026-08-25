// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a realm is at runtime, and the registry that holds them.
//!
//! A realm is one issuer: its own signing keys, its own audit trail, its own pseudonymisation. The
//! server that hosts them is **not** one of them — it signs the system trail and lists the realms,
//! and it issues nothing. So this module carries two things: the bundle of collaborators that *is* a
//! realm, and a registry that resolves a request to one.
//!
//! # Resolution is by path, never by a header
//!
//! A realm selects which key signs and which trail records. If a client could choose it with a
//! header, it could choose whose key signs its request and whose trail bears it — a cross-tenant
//! escalation. So the registry is keyed by the mount path the request actually arrived on, which is
//! part of the request line and not forgeable, and by name for the code that already knows which
//! realm it means.
//!
//! # One process, one registry
//!
//! The registry is built once, at the composition root, from the resolved configuration. Nothing
//! mutates it while the server runs. The periodic work a realm needs — key rotation — is done by a
//! single loop that walks this registry in sequence, not by a task per realm: see the key service.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// The lifetime a runtime realm falls back to when nothing set one.
///
/// Configuration requires the value explicitly for a realm that issues tokens; this exists so a
/// realm assembled in a test or an embedding build is never left with a zero-length token.
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(3_600);

/// How long a runtime realm serves cached upstream JWKS after refresh starts failing.
const DEFAULT_KEY_CACHE_STALE_FOR: Duration = Duration::from_secs(3_600);

/// The algorithm a realm signs with when configuration names none.
const DEFAULT_SIGNING_ALGORITHM: &str = "EdDSA";

use crate::audit::{AuditDestination, AuditSink};
use crate::keys::KeyManager;
use crate::pseudonym::Pseudonymizer;
use crate::secrets::{SecretProvider, SecretRef};

/// The PIC profile every realm this build serves conforms to.
///
/// A constant, not configuration: this build implements one profile. The server document exposes it
/// inside a generic `profiles` array so a future profile — a new crate claiming its own configuration
/// section — is an added entry rather than a breaking change, but the code here knows exactly one.
pub const PIC_PROFILE: &str = "https://pic-protocol.org/profiles/0.2";

/// OAuth RFC 8693 subject-token type for an access token.
pub const OAUTH_ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The source token kind an Exchange Profile accepts.
pub const EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN: &str = "oauth-access-token";

/// The JWT source format named by the Exchange Profile article.
pub const EXCHANGE_SOURCE_FORMAT_JWT: &str = "jwt";

/// The only unmatched-scope policy implemented by Profile 0.2 Permguard exchange.
pub const EXCHANGE_ON_UNMATCHED_SCOPE_REJECT: &str = "reject";

/// How initial PIC Token expiration is chosen when the source token also has an expiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenInitialExpiryPolicy {
    /// Use whichever absolute expiration is later.
    Later,
    /// Use the realm's configured PIC Token lifetime.
    Pic,
    /// Use the OAuth source token expiration when it exists.
    OAuth,
}

impl TokenInitialExpiryPolicy {
    /// Stable configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Later => "later",
            Self::Pic => "pic",
            Self::OAuth => "oauth",
        }
    }
}

/// A realm-scoped Exchange Profile: validation and mapping rules for one upstream token source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeProfileConfig {
    pub id: String,
    pub source: ExchangeProfileSource,
    pub claims: ExchangeProfileClaims,
    pub privileges: ExchangeProfilePrivileges,
    pub on_unmatched_scope: String,
}

/// The upstream token shape and validation policy a profile accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeProfileSource {
    pub token_type: String,
    pub format: String,
    /// The identity the provider puts in `iss`, and what an access token is matched against.
    pub issuer: String,
    /// Where this deployment reaches that provider's OpenID Connect discovery, when it is not the
    /// issuer URL itself.
    ///
    /// The two differ whenever the provider is addressed differently from inside: a service mesh, a
    /// container network, a NAT. Keeping them apart is the same separation the trusted-attester
    /// configuration already makes between `issuer` and `jwks_uri` — identity is not an address.
    pub discovery_url: Option<String>,
    pub audience: String,
    pub validation: ExchangeTokenValidation,
}

impl ExchangeProfileSource {
    /// Where OpenID Connect discovery is fetched from for this provider.
    pub fn discovery_base(&self) -> &str {
        self.discovery_url.as_deref().unwrap_or(&self.issuer)
    }
}

/// Header and claim checks applied before any upstream claim is mapped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeTokenValidation {
    pub allowed_algorithms: Vec<String>,
    pub require_expiration: bool,
    pub require_token_type: Option<String>,
}

/// Claim mappings used to build the logical PIC authority input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeProfileClaims {
    pub identity_context: BTreeMap<String, ClaimMapping>,
    pub scopes: ClaimMapping,
}

/// One source or literal mapping from an upstream JWT to a PIC logical value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimMapping {
    pub from: Option<String>,
    pub value: Option<String>,
    pub value_type: Option<String>,
    pub encoding: Option<String>,
}

/// Scope-to-privilege mapping rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeProfilePrivileges {
    pub source: String,
    pub rules: Vec<PrivilegeRule>,
}

/// One ordered regular-expression rule over an upstream scope value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivilegeRule {
    pub name: String,
    pub priority: i32,
    pub pattern: String,
    pub emit: PrivilegeEmit,
}

/// The invariant fields emitted when a scope rule matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivilegeEmit {
    pub scope: String,
    pub operation: String,
    pub resource_type: String,
    pub resource_id: String,
}

/// A trusted Proof-of-Relationship attestation issuer configured for one realm.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedAttesterConfig {
    pub id: String,
    pub issuer: String,
    pub jwks_uri: String,
    pub proof_types: Vec<String>,
    pub formats: Vec<String>,
}

/// What a realm declared in a configuration file, before it is resolved against the server's values.
///
/// Every field is what the file literally said — a string, or absent — because parsing a duration or
/// a boolean needs the same rules the server settings use, and those live where the server config is
/// resolved. A field left absent inherits the server's, which is the whole point of an override: say
/// only what differs. `name` is the one thing that cannot be inherited.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RealmInput {
    pub name: String,
    pub issuer: Option<String>,
    pub listed: Option<String>,
    /// The realm's token-signing keys (the `keys` block). Its own ring.
    pub token_keys_enabled: Option<String>,
    pub token_keys_publish_ahead: Option<String>,
    pub token_keys_rotate_every: Option<String>,
    pub token_keys_retain: Option<String>,
    /// The realm's override of the shared `operations` block: the sealing keys, the trail, the
    /// pseudonymisation. Anything absent inherits the server's `operations`.
    pub operations_keys_enabled: Option<String>,
    pub operations_keys_publish_ahead: Option<String>,
    pub operations_keys_rotate_every: Option<String>,
    pub operations_keys_retain: Option<String>,
    pub audit_sink: Option<String>,
    pub audit_retention: Option<String>,
    pub audit_pseudonym_enabled: Option<String>,
    pub audit_pseudonym_key_ref: Option<String>,
    pub audit_pseudonym_key_version: Option<String>,
    pub secrets_provider: Option<String>,
    pub secrets_env_prefix: Option<String>,
    /// How long a PIC Token this realm issues is valid, when the caller asks for nothing else.
    pub token_lifetime: Option<String>,
    /// How initial PIC Token expiration is chosen against OAuth source expiration.
    pub token_initial_expiry_policy: Option<String>,
    /// How long to serve cached IdP/attester JWKS after refresh starts failing.
    pub key_cache_stale_for: Option<String>,
    /// Which algorithm this realm signs its tokens and COSE artifacts with.
    pub token_signing_algorithm: Option<String>,
    pub exchange_profiles: Vec<ExchangeProfileConfig>,
    pub trusted_attesters: Vec<TrustedAttesterConfig>,
}

/// One realm as the composition root reads it: identity **and** the full policy it runs under, each
/// field already resolved to the realm's own value or inherited from the server.
///
/// The rest of the build reads only this — never the raw override, never "the server's value unless
/// the realm said otherwise". Resolution happened once, where the server's defaults were known; from
/// here a realm is a complete, self-describing configuration. Built by [`Config::with_realms`]; the
/// fields are set there and read everywhere else through the getters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmConfig {
    pub(crate) name: String,
    pub(crate) mount_path: String,
    pub(crate) issuer: Option<String>,
    pub(crate) listed: bool,
    // The token-signing ring.
    pub(crate) token_keys_enabled: bool,
    pub(crate) token_keys_publish_ahead: Duration,
    pub(crate) token_keys_rotate_every: Duration,
    pub(crate) token_keys_retain: Duration,
    /// The default lifetime of a PIC Token this realm issues.
    pub(crate) token_lifetime: Duration,
    /// How the initial PIC Token expiration is chosen during OAuth-to-PIC exchange.
    pub(crate) token_initial_expiry_policy: TokenInitialExpiryPolicy,
    /// How long cached IdP/attester JWKS stay usable after refresh starts failing.
    pub(crate) key_cache_stale_for: Duration,
    /// The JOSE algorithm this realm signs with, e.g. `EdDSA` or `ES256`.
    pub(crate) token_signing_algorithm: String,
    // The operations ring — the one that seals this realm's trail.
    pub(crate) operations_keys_enabled: bool,
    pub(crate) operations_keys_publish_ahead: Duration,
    pub(crate) operations_keys_rotate_every: Duration,
    pub(crate) operations_keys_retain: Duration,
    pub(crate) audit_destination: AuditDestination,
    pub(crate) audit_retention: Duration,
    pub(crate) audit_pseudonym_enabled: bool,
    pub(crate) audit_pseudonym_key_ref: Option<SecretRef>,
    pub(crate) audit_pseudonym_key_version: String,
    pub(crate) secrets_provider: SecretProvider,
    pub(crate) secrets_env_prefix: String,
    pub(crate) exchange_profiles: Vec<ExchangeProfileConfig>,
    pub(crate) trusted_attesters: Vec<TrustedAttesterConfig>,
}

impl RealmConfig {
    /// The realm's name, unique within a deployment.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The path the realm's surface is mounted under, e.g. `/realms/acme`.
    pub fn mount_path(&self) -> &str {
        &self.mount_path
    }

    /// The realm's issuer, when one is configured.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Whether the realm opted into the server's public catalogue.
    pub fn listed(&self) -> bool {
        self.listed
    }

    /// Whether this realm signs tokens (its token ring is enabled).
    pub fn token_keys_enabled(&self) -> bool {
        self.token_keys_enabled
    }

    /// How long a new token key of this realm is published before it signs.
    pub fn token_keys_publish_ahead(&self) -> Duration {
        self.token_keys_publish_ahead
    }

    /// How long a token key of this realm signs before it is replaced.
    pub fn token_keys_rotate_every(&self) -> Duration {
        self.token_keys_rotate_every
    }

    /// How long a retired token key of this realm stays published.
    /// How long a PIC Token this realm issues is valid unless the caller asks for less.
    ///
    /// Stated per realm rather than defaulted globally: the lifetime of issued authority is a
    /// deployment decision, and a build that guesses it is a build that guesses wrong somewhere.
    pub fn token_lifetime(&self) -> Duration {
        self.token_lifetime
    }

    /// How the initial PIC Token expiration is chosen during OAuth-to-PIC exchange.
    pub fn token_initial_expiry_policy(&self) -> TokenInitialExpiryPolicy {
        self.token_initial_expiry_policy
    }

    /// How long cached upstream JWKS stay usable after refresh starts failing.
    pub fn key_cache_stale_for(&self) -> Duration {
        self.key_cache_stale_for
    }

    /// The JOSE algorithm this realm signs with.
    pub fn token_signing_algorithm(&self) -> &str {
        &self.token_signing_algorithm
    }

    pub fn token_keys_retain(&self) -> Duration {
        self.token_keys_retain
    }

    /// Whether this realm's operations ring — the one that seals its trail — is enabled.
    pub fn operations_keys_enabled(&self) -> bool {
        self.operations_keys_enabled
    }

    /// How long a new operations key of this realm is published before it signs.
    pub fn operations_keys_publish_ahead(&self) -> Duration {
        self.operations_keys_publish_ahead
    }

    /// How long an operations key of this realm signs before it is replaced.
    pub fn operations_keys_rotate_every(&self) -> Duration {
        self.operations_keys_rotate_every
    }

    /// How long a retired operations key of this realm stays published.
    pub fn operations_keys_retain(&self) -> Duration {
        self.operations_keys_retain
    }

    /// Where this realm's trail is written.
    pub fn audit_destination(&self) -> AuditDestination {
        self.audit_destination
    }

    /// How long a day of this realm's records is kept.
    pub fn audit_retention(&self) -> Duration {
        self.audit_retention
    }

    /// Whether this realm pseudonymises its audit subjects.
    pub fn audit_pseudonym_enabled(&self) -> bool {
        self.audit_pseudonym_enabled
    }

    /// The secret this realm's pseudonymisation key is resolved from.
    pub fn audit_pseudonym_key_ref(&self) -> Option<&SecretRef> {
        self.audit_pseudonym_key_ref.as_ref()
    }

    /// The version this realm's pseudonyms name.
    pub fn audit_pseudonym_key_version(&self) -> &str {
        &self.audit_pseudonym_key_version
    }

    /// How this realm resolves its secret material.
    pub fn secrets_provider(&self) -> SecretProvider {
        self.secrets_provider
    }

    /// The environment prefix this realm resolves secrets under, when its provider is the environment.
    pub fn secrets_env_prefix(&self) -> &str {
        &self.secrets_env_prefix
    }

    /// The Exchange Profiles this realm accepts, in configuration order.
    pub fn exchange_profiles(&self) -> &[ExchangeProfileConfig] {
        &self.exchange_profiles
    }

    /// The trusted PoR attestation issuers this realm advertises.
    pub fn trusted_attesters(&self) -> &[TrustedAttesterConfig] {
        &self.trusted_attesters
    }
}

/// One issuer: everything a realm signs, records and is reached at.
///
/// Cloneable because the collaborators are all `Arc`: a surface handling a request clones the realm
/// it resolved and holds it for the length of the call.
#[derive(Clone)]
pub struct Realm {
    name: String,
    mount_path: String,
    issuer: Option<String>,
    listed: bool,
    operations_keys: Option<Arc<dyn KeyManager>>,
    token_keys: Option<Arc<dyn KeyManager>>,
    audit: Arc<dyn AuditSink>,
    pseudonymizer: Option<Arc<dyn Pseudonymizer>>,
    exchange_profiles: Vec<ExchangeProfileConfig>,
    trusted_attesters: Vec<TrustedAttesterConfig>,
    /// How long the PIC Tokens this realm issues stay valid.
    token_lifetime: Duration,
    /// How the initial PIC Token expiration is chosen during OAuth-to-PIC exchange.
    token_initial_expiry_policy: TokenInitialExpiryPolicy,
    /// How long cached IdP/attester JWKS stay usable after refresh starts failing.
    key_cache_stale_for: Duration,
    /// The JOSE algorithm this realm signs with.
    token_signing_algorithm: String,
}

impl Realm {
    /// Assembles a realm from its identity and the collaborators composed for it.
    ///
    /// `mount_path` is where its surface lives — `/realms/{name}` — and is what the registry resolves
    /// a request against. Both key rings are optional: `operations_keys` (which signs the realm's
    /// trail) because a realm may keep its trail unsigned, and `token_keys` (which signs the tokens it
    /// issues, and is the ring its `jwks_uri` publishes) because token issuance may not exist yet.
    /// `pseudonymizer` is optional because a realm may record subjects masked rather than pseudonymised.
    // A realm *is* the bundle of collaborators an issuer needs, so its constructor names them all —
    // grouping them behind a struct only to satisfy the argument-count heuristic would hide what a
    // realm is made of rather than clarify it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        mount_path: impl Into<String>,
        issuer: Option<String>,
        listed: bool,
        operations_keys: Option<Arc<dyn KeyManager>>,
        token_keys: Option<Arc<dyn KeyManager>>,
        audit: Arc<dyn AuditSink>,
        pseudonymizer: Option<Arc<dyn Pseudonymizer>>,
    ) -> Self {
        Self {
            name: name.into(),
            mount_path: mount_path.into(),
            issuer,
            listed,
            operations_keys,
            token_keys,
            audit,
            pseudonymizer,
            exchange_profiles: Vec::new(),
            trusted_attesters: Vec::new(),
            token_lifetime: DEFAULT_TOKEN_LIFETIME,
            token_initial_expiry_policy: TokenInitialExpiryPolicy::Later,
            key_cache_stale_for: DEFAULT_KEY_CACHE_STALE_FOR,
            token_signing_algorithm: DEFAULT_SIGNING_ALGORITHM.to_owned(),
        }
    }

    /// Sets how long the PIC Tokens this realm issues stay valid.
    pub fn with_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = lifetime;

        self
    }

    /// Sets how initial PIC Token expiration is chosen during OAuth-to-PIC exchange.
    pub fn with_token_initial_expiry_policy(mut self, policy: TokenInitialExpiryPolicy) -> Self {
        self.token_initial_expiry_policy = policy;

        self
    }

    /// Sets how long cached upstream JWKS stay usable after refresh starts failing.
    pub fn with_key_cache_stale_for(mut self, stale_for: Duration) -> Self {
        self.key_cache_stale_for = stale_for;

        self
    }

    /// Sets the JOSE algorithm this realm signs with.
    pub fn with_token_signing_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.token_signing_algorithm = algorithm.into();

        self
    }

    /// Attaches the Exchange Profiles loaded for this realm.
    pub fn with_exchange_profiles(
        mut self,
        profiles: impl IntoIterator<Item = ExchangeProfileConfig>,
    ) -> Self {
        self.exchange_profiles = profiles.into_iter().collect();
        self
    }

    /// Attaches the trusted PoR attestation issuers configured for this realm.
    pub fn with_trusted_attesters(
        mut self,
        attesters: impl IntoIterator<Item = TrustedAttesterConfig>,
    ) -> Self {
        self.trusted_attesters = attesters.into_iter().collect();
        self
    }

    /// Returns the realm's name, which is unique within a deployment.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the path the realm's surface is mounted under, e.g. `/realms/acme`.
    pub fn mount_path(&self) -> &str {
        &self.mount_path
    }

    /// Returns the public URL clients are told this realm issues from, when one is configured.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Reports whether this realm appears in the server's public catalogue.
    ///
    /// False unless the deployment opted in. The realm's own discovery is reachable at its path either
    /// way — a token verifier must read its key set — but the world does not get to enumerate the
    /// realms a deployment hosts unless it was asked to publish them.
    pub fn listed(&self) -> bool {
        self.listed
    }

    /// Returns the ring that signs this realm's trail — its operations ring, when it has one.
    ///
    /// An internal duty: these keys seal the realm's audit and their public halves are never served
    /// over HTTP. The ring that signs *tokens* is [`Realm::token_keys`].
    pub fn operations_keys(&self) -> Option<&Arc<dyn KeyManager>> {
        self.operations_keys.as_ref()
    }

    /// Returns the ring this realm signs tokens with — the one its `jwks_uri` publishes — when it has
    /// one.
    ///
    /// `None` until token issuance exists, which is the honest state today: the realm's `jwks_uri`
    /// then publishes an empty set, because there is nothing yet that a relying party would verify.
    pub fn token_keys(&self) -> Option<&Arc<dyn KeyManager>> {
        self.token_keys.as_ref()
    }

    /// Returns the sink this realm's events are recorded to.
    pub fn audit(&self) -> &Arc<dyn AuditSink> {
        &self.audit
    }

    /// Returns the privacy policy this realm's subjects are recorded under, when it has one.
    pub fn pseudonymizer(&self) -> Option<&Arc<dyn Pseudonymizer>> {
        self.pseudonymizer.as_ref()
    }

    /// The Exchange Profiles this realm accepts.
    pub fn exchange_profiles(&self) -> &[ExchangeProfileConfig] {
        &self.exchange_profiles
    }

    /// The trusted PoR attestation issuers this realm advertises.
    pub fn trusted_attesters(&self) -> &[TrustedAttesterConfig] {
        &self.trusted_attesters
    }

    /// How long the PIC Tokens this realm issues stay valid, unless the exchange asks for less.
    pub fn token_lifetime(&self) -> Duration {
        self.token_lifetime
    }

    /// How the initial PIC Token expiration is chosen during OAuth-to-PIC exchange.
    pub fn token_initial_expiry_policy(&self) -> TokenInitialExpiryPolicy {
        self.token_initial_expiry_policy
    }

    /// How long cached upstream JWKS stay usable after refresh starts failing.
    pub fn key_cache_stale_for(&self) -> Duration {
        self.key_cache_stale_for
    }

    /// The JOSE algorithm this realm signs its tokens and COSE artifacts with.
    ///
    /// The discovery document publishes exactly this value, so what a client is told and what the
    /// realm does are one thing rather than two that can drift apart.
    pub fn token_signing_algorithm(&self) -> &str {
        &self.token_signing_algorithm
    }

    /// Returns the absolute URL a client should use for `path` within this realm.
    ///
    /// Rooted at the realm's issuer when it has one, and at the realm's mount path otherwise — a
    /// relative reference that is at least never wrong for a deployment that was told no public name.
    pub fn url(&self, path: &str) -> String {
        match &self.issuer {
            Some(issuer) => format!("{}{path}", issuer.trim_end_matches('/')),
            None => format!("{}{path}", self.mount_path),
        }
    }
}

impl std::fmt::Debug for Realm {
    /// Names the realm and its path. The collaborators are machinery, and printing an `Arc<dyn …>`
    /// says nothing a reader can act on.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Realm")
            .field("name", &self.name)
            .field("mount_path", &self.mount_path)
            .field("listed", &self.listed)
            .finish_non_exhaustive()
    }
}

/// Every realm a deployment hosts, resolvable by name and by the path a request arrived on.
///
/// Built once and never mutated: a lookup is a read, so it takes no lock and cannot be a point of
/// contention no matter how many requests resolve a realm at once.
#[derive(Clone, Default, Debug)]
pub struct Realms {
    by_name: BTreeMap<String, Realm>,
    by_mount: BTreeMap<String, String>,
}

impl Realms {
    /// Builds a registry from the realms a deployment composed.
    ///
    /// The caller has already refused duplicate names — see the configuration's validation — so a
    /// later insert overwriting an earlier one cannot silently drop a realm here.
    pub fn new(realms: impl IntoIterator<Item = Realm>) -> Self {
        let mut by_name = BTreeMap::new();
        let mut by_mount = BTreeMap::new();

        for realm in realms {
            by_mount.insert(realm.mount_path().to_owned(), realm.name().to_owned());
            by_name.insert(realm.name().to_owned(), realm);
        }

        Self { by_name, by_mount }
    }

    /// Returns the realm called `name`.
    pub fn by_name(&self, name: &str) -> Option<&Realm> {
        self.by_name.get(name)
    }

    /// Returns the realm mounted exactly at `path`.
    pub fn by_mount(&self, path: &str) -> Option<&Realm> {
        self.by_mount
            .get(path)
            .and_then(|name| self.by_name.get(name))
    }

    /// Returns every realm, in a stable order.
    pub fn all(&self) -> impl Iterator<Item = &Realm> {
        self.by_name.values()
    }

    /// Returns only the realms that opted into the public catalogue.
    pub fn listed(&self) -> impl Iterator<Item = &Realm> {
        self.by_name.values().filter(|realm| realm.listed())
    }

    /// Returns how many realms are hosted.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Reports whether this deployment hosts no realm — a server that lists nothing and issues nothing.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::audit::{AuditEvent, Result};
    use crate::future::BoxFuture;
    use crate::pseudonym::Pseudonymizer;

    #[derive(Debug)]
    struct SilentSink;

    impl AuditSink for SilentSink {
        fn name(&self) -> &'static str {
            "silent"
        }

        fn record<'a>(
            &'a self,
            _event: &'a AuditEvent<'a>,
            _policy: Option<&'a dyn Pseudonymizer>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn realm(name: &str, listed: bool) -> Realm {
        Realm::new(
            name,
            format!("/realms/{name}"),
            Some(format!("https://host/realms/{name}")),
            listed,
            None,
            None,
            Arc::new(SilentSink),
            None,
        )
    }

    #[test]
    fn test_a_realm_is_resolved_by_the_path_it_is_mounted_at() {
        // The safe resolution: the registry answers to the path the request actually arrived on, which
        // is part of the request line, never a header a client can set.
        let realms = Realms::new([realm("acme", true), realm("beta", false)]);

        assert_eq!(
            realms.by_mount("/realms/acme").map(Realm::name),
            Some("acme")
        );
        assert_eq!(
            realms.by_mount("/realms/beta").map(Realm::name),
            Some("beta")
        );
        assert!(realms.by_mount("/realms/unknown").is_none());
        assert!(realms.by_mount("/realms/acme/extra").is_none());
    }

    #[test]
    fn test_only_opted_in_realms_are_listed() {
        // Fail-closed: a realm is enumerable in the catalogue only if it said so. `beta` did not.
        let realms = Realms::new([realm("acme", true), realm("beta", false)]);

        let listed: Vec<&str> = realms.listed().map(Realm::name).collect();
        assert_eq!(listed, vec!["acme"]);
        // But the hidden one is still resolvable at its path — a verifier must reach its key set.
        assert!(realms.by_mount("/realms/beta").is_some());
    }

    #[test]
    fn test_a_realm_builds_urls_from_its_issuer() {
        let acme = realm("acme", true);
        assert_eq!(
            acme.url("/.well-known/jwks.json"),
            "https://host/realms/acme/.well-known/jwks.json"
        );

        // With no issuer, the mount path is the honest fallback.
        let local = Realm::new(
            "local",
            "/realms/local",
            None,
            false,
            None,
            None,
            Arc::new(SilentSink),
            None,
        );
        assert_eq!(local.url("/keys"), "/realms/local/keys");
    }
}
