// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The OIDC adapter: one verifier per identity provider, authentication only, everything pinned
//! (`1-architecture/1` Identity providers).
//!
//! Issuer, audience, algorithms, accepted token types and clients, and the claim that names the
//! subject come from the rule. The verification keys come from exactly one source:
//!
//! | Source      | Who reads it                                                                           |
//! | ----------- | -------------------------------------------------------------------------------------- |
//! | `jwks_file` | this verifier, looked at again once half the stale window passed: a stat, a read only when it changed |
//! | `jwks_uri`  | the server's refresh task, every `refresh`, which hands the document to [`Verifier::install`] |
//! | discovery   | the same task, through `<issuer>/.well-known/openid-configuration` first               |
//!
//! Nothing here touches the network: a request only reads the keys held, and a token naming a key
//! the set does not hold asks the refresh task for an early fetch, at most once a minute. Fetched
//! keys are kept on the volume, so a restart without network serves them until their `max_stale`.
//!
//! A token is a compact JWS: `RS256`, `ES256` or `EdDSA`, the algorithm taken from the rule and
//! compared with the header's, never obeyed. The principal is `oidc:<issuer>#<claim value>`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_core::AccessDenial;
use permguard_core::authz::{ActorContext, Credential, Principal};

use super::mapper::MapperError;

pub use permguard_core::authz::OidcKeySource as KeySource;

/// One `host.principals[].oidc` rule: one identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRule {
    /// The short name operators type; never part of a principal.
    pub name: String,
    pub issuer: String,
    pub audience: String,
    pub algorithms: Vec<String>,
    pub claim: String,
    /// Where the keys come from; a file path already resolved beside the configuration.
    pub keys: KeySource,
    /// The authority of a private provider's TLS certificate, for the refresh task.
    pub ca_file: Option<PathBuf>,
    /// How often fetched keys are fetched again.
    pub refresh: Duration,
    pub max_stale: Duration,
    /// The `azp` or `client_id` values accepted; empty accepts any client of the audience.
    pub clients: Vec<String>,
    /// The accepted `typ` header values; a token with no `typ` is accepted.
    pub token_types: Vec<String>,
    /// Whether a token whose verified email equals a local user's acts as that user.
    pub link_email: bool,
}

/// A token that verified: the actor its subject names, and its email when the provider verified
/// it, for the link to a local user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub context: ActorContext,
    pub verified_email: Option<String>,
}

impl OidcRule {
    /// The provider's discovery document: the issuer without its trailing slash, then the
    /// well-known path (OpenID Connect Discovery 1.0, section 4).
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        )
    }
}

/// The algorithms the adapter verifies.
const ALGORITHMS: &[&str] = &["RS256", "ES256", "EdDSA"];

/// A token longer than this is refused before it is split: an access token is a few kilobytes at
/// most, and the bound keeps a hostile header from costing a base64 decode of its own size.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// A discovery document or a key set longer than this is refused.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

/// The smallest RSA modulus a key set may hold, in bits.
const MIN_RSA_BITS: usize = 2048;

/// The shortest time between two early fetches a provider's unknown keys ask for.
pub const EARLY_REFRESH_EVERY: Duration = Duration::from_secs(60);

/// Where fetched key sets are kept, under `host/authz/`.
pub const CACHE_DIRECTORY: &str = "oidc";

/// A key of the set, parsed once.
#[derive(Debug, Clone)]
enum Key {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256 { point: Vec<u8> },
    Ed25519 { public: Vec<u8> },
}

/// What a status report says of one key: never the key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub kid: Option<String>,
    pub algorithm: &'static str,
}

/// A key held: its id, the key, the one algorithm it verifies.
type ParsedKey = (Option<String>, Key, &'static str);

#[derive(Debug, Clone)]
struct Loaded {
    keys: Vec<ParsedKey>,
    /// When these keys were last found to be the keys, on the guard's monotonic clock: fetched,
    /// read, or the file seen unchanged. The stale window is a duration, never a wall time.
    at: Duration,
    /// Their age at `at`: zero when fetched now, the time since the fetch when restored from disk.
    age_at: Duration,
    /// When the file was last looked at, whatever it said: one stat per half-window.
    checked: Duration,
    modified: Option<SystemTime>,
    /// Unix seconds of the fetch or read that produced them.
    fetched_at: u64,
}

/// How a provider's keys stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// No key yet: its tokens are refused until the first fetch.
    Empty,
    /// Within twice `refresh` of their fetch, or a file within its window.
    Fresh,
    /// Older than twice `refresh`: the Host is `degraded: oidc`.
    Aging,
    /// Past `max_stale`: its tokens are refused.
    Stale,
}

impl KeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Fresh => "fresh",
            Self::Aging => "aging",
            Self::Stale => "stale",
        }
    }
}

/// A fetch or read that failed: when, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub at: u64,
    pub reason: String,
}

/// One provider as the Host API and the health report show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    pub name: String,
    pub issuer: String,
    pub claim: String,
    /// `discovery`, `jwks_uri` or `jwks_file`.
    pub source: &'static str,
    /// The discovery URL, the key set URL or the file.
    pub location: String,
    pub keys: Vec<KeyInfo>,
    pub fetched_at: Option<u64>,
    pub age: Option<Duration>,
    pub failure: Option<Failure>,
    pub state: KeyState,
}

/// The verifier of one identity provider.
pub struct Verifier {
    rule: OidcRule,
    position: usize,
    loaded: RwLock<Option<Loaded>>,
    failure: Mutex<Option<Failure>>,
    /// When an unknown key last asked for an early fetch.
    early: Mutex<Option<Duration>>,
    /// How the refresh task is woken for an early fetch.
    waker: OnceLock<Box<dyn Fn() + Send + Sync>>,
    /// Where fetched sets are kept: `host/authz/oidc/`.
    cache: OnceLock<crate::storage::Dir>,
    time: Arc<crate::time::TimeGuard>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("name", &self.rule.name)
            .field("issuer", &self.rule.issuer)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// Builds the verifier. A file source is read at once and a rule that cannot be honoured
    /// fails; a fetched source starts with no key, and its tokens are refused until the refresh
    /// task's first fetch or the set kept on the volume.
    pub fn new(
        rule: OidcRule,
        position: usize,
        time: Arc<crate::time::TimeGuard>,
    ) -> Result<Self, MapperError> {
        let at = format!("host.principals[{position}].oidc");
        if !permguard_core::authz::is_provider_name(&rule.name) {
            return Err(MapperError::Invalid(format!(
                "{at}: the name `{}` is not 1 to 63 lowercase letters, digits or `-`",
                rule.name
            )));
        }
        if rule.issuer.trim().is_empty() || rule.audience.trim().is_empty() {
            return Err(MapperError::Invalid(format!(
                "{at}: issuer and audience are required"
            )));
        }
        if rule.claim.trim().is_empty() {
            return Err(MapperError::Invalid(format!("{at}: claim is required")));
        }
        if rule.algorithms.is_empty() {
            return Err(MapperError::Invalid(format!(
                "{at}: algorithms names at least one of {}",
                ALGORITHMS.join(", ")
            )));
        }
        if let Some(unknown) = rule
            .algorithms
            .iter()
            .find(|algorithm| !ALGORITHMS.contains(&algorithm.as_str()))
        {
            return Err(MapperError::Invalid(format!(
                "{at}: `{unknown}` is not an algorithm this adapter verifies ({})",
                ALGORITHMS.join(", ")
            )));
        }
        if rule.max_stale.is_zero() {
            return Err(MapperError::Invalid(format!("{at}: max_stale is positive")));
        }
        if rule.keys.is_fetched() && (rule.refresh.is_zero() || rule.refresh > rule.max_stale) {
            return Err(MapperError::Invalid(format!(
                "{at}: refresh is positive and within max_stale"
            )));
        }
        let loaded = match &rule.keys {
            KeySource::File(path) => Some(
                load_file(path, &rule.algorithms, time.elapsed(), time.now_secs())
                    .map_err(|detail| MapperError::Keys(format!("{at}: {detail}")))?,
            ),
            KeySource::Discovery | KeySource::Uri(_) => None,
        };
        Ok(Self {
            rule,
            position,
            loaded: RwLock::new(loaded),
            failure: Mutex::new(None),
            early: Mutex::new(None),
            waker: OnceLock::new(),
            cache: OnceLock::new(),
            time,
        })
    }

    /// The provider's rule.
    pub fn rule(&self) -> &OidcRule {
        &self.rule
    }

    /// The provider's short name.
    pub fn name(&self) -> &str {
        &self.rule.name
    }

    /// `oidc:<issuer>#`: what every principal of this provider starts with.
    pub fn principal_prefix(&self) -> String {
        format!("oidc:{}#", self.rule.issuer)
    }

    /// `oidc:<issuer>`: the member that stands for every subject of this provider.
    pub fn issuer_principal(&self) -> String {
        format!("oidc:{}", self.rule.issuer)
    }

    /// The rule's position, for a log line.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Sets how the refresh task is woken when a token names a key the set does not hold.
    pub fn set_waker(&self, waker: Box<dyn Fn() + Send + Sync>) {
        let _ = self.waker.set(waker);
    }

    /// Keeps fetched sets in `dir` and restores the one kept there, when it is still within
    /// `max_stale`: a restart without network serves it. A file source keeps nothing.
    pub fn attach_cache(&self, dir: crate::storage::Dir) {
        if !self.rule.keys.is_fetched() {
            return;
        }
        if let Err(detail) = self.restore(&dir) {
            tracing::warn!(
                event.name = "oidc.keys_not_restored",
                component = "host",
                provider = %self.rule.name,
                error = %detail,
                "the key set kept on the volume was not restored; the provider waits for its first fetch"
            );
        }
        let _ = self.cache.set(dir);
    }

    /// The name of the file a provider's set is kept in: 32 hex characters of its issuer's
    /// SHA-256, so any issuer makes a plain file name on every platform.
    pub fn cache_name(&self) -> String {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(self.rule.issuer.as_bytes());
        let hex: String = digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("{hex}.json")
    }

    fn restore(&self, dir: &crate::storage::Dir) -> Result<(), String> {
        let Some(bytes) = dir
            .read(&self.cache_name())
            .map_err(|error| format!("reading the kept set: {error}"))?
        else {
            return Ok(());
        };
        let kept: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("the kept set is not JSON: {error}"))?;
        if kept.get("issuer").and_then(serde_json::Value::as_str) != Some(self.rule.issuer.as_str())
        {
            return Err("the kept set belongs to another issuer".to_owned());
        }
        let fetched_at = kept
            .get("fetched_at")
            .and_then(serde_json::Value::as_u64)
            .ok_or("the kept set carries no fetch time")?;
        let age = Duration::from_secs(self.time.now_secs().saturating_sub(fetched_at));
        if age > self.rule.max_stale {
            return Err(format!(
                "the kept set is {}s old, past max_stale",
                age.as_secs()
            ));
        }
        let document = kept.get("keys").ok_or("the kept set holds no key set")?;
        let document = serde_json::to_vec(document).map_err(|error| error.to_string())?;
        let (keys, _) = parse_key_set(&document, &self.rule.algorithms)?;
        let now = self.time.elapsed();
        *self.loaded.write().unwrap_or_else(PoisonError::into_inner) = Some(Loaded {
            keys,
            at: now,
            age_at: age,
            checked: now,
            modified: None,
            fetched_at,
        });
        tracing::info!(
            event.name = "oidc.keys_restored",
            component = "host",
            provider = %self.rule.name,
            age_secs = age.as_secs(),
            "the provider's key set kept on the volume serves until the first fetch"
        );
        Ok(())
    }

    /// Installs a key set the refresh task fetched: parsed, filtered, held from now and kept on
    /// the volume. A document that holds no key this provider accepts changes nothing and is the
    /// refresh's failure. Answers the number of keys held and the reasons any were skipped.
    pub fn install(&self, document: &[u8]) -> Result<(usize, Vec<String>), String> {
        let (keys, skipped) = parse_key_set(document, &self.rule.algorithms)?;
        let count = keys.len();
        let kids: Vec<String> = keys
            .iter()
            .map(|(kid, _, _)| kid.clone().unwrap_or_else(|| "-".to_owned()))
            .collect();
        let now = self.time.elapsed();
        let fetched_at = self.time.now_secs();
        *self.loaded.write().unwrap_or_else(PoisonError::into_inner) = Some(Loaded {
            keys,
            at: now,
            age_at: Duration::ZERO,
            checked: now,
            modified: None,
            fetched_at,
        });
        *self.failure.lock().unwrap_or_else(PoisonError::into_inner) = None;
        if let Some(dir) = self.cache.get() {
            let kept = serde_json::json!({
                "issuer": self.rule.issuer,
                "fetched_at": fetched_at,
                "keys": serde_json::from_slice::<serde_json::Value>(document)
                    .map_err(|error| error.to_string())?,
            });
            let bytes = serde_json::to_vec(&kept).map_err(|error| error.to_string())?;
            if let Err(error) =
                crate::storage::write::replace_bytes(dir, &self.cache_name(), &bytes)
            {
                tracing::warn!(
                    event.name = "oidc.keys_not_kept",
                    component = "host",
                    provider = %self.rule.name,
                    error = %error,
                    "the fetched key set serves but was not kept on the volume"
                );
            }
        }
        tracing::info!(
            event.name = "oidc.keys_fetched",
            component = "host",
            provider = %self.rule.name,
            keys = count,
            kids = %kids.join(","),
            skipped = skipped.len(),
            "the provider's key set was fetched"
        );
        Ok((count, skipped))
    }

    /// Records a fetch that failed: the keys held serve until their `max_stale`.
    pub fn failed(&self, reason: impl Into<String>) {
        let reason = reason.into();
        tracing::warn!(
            event.name = "oidc.refresh_failed",
            component = "host",
            provider = %self.rule.name,
            error = %reason,
            "the provider's keys were not fetched; the keys held serve until their max_stale"
        );
        *self.failure.lock().unwrap_or_else(PoisonError::into_inner) = Some(Failure {
            at: self.time.now_secs(),
            reason,
        });
    }

    /// How old the keys held are; `None` before the first.
    pub fn age(&self) -> Option<Duration> {
        let held = self.loaded.read().unwrap_or_else(PoisonError::into_inner);
        held.as_ref().map(|loaded| self.age_of(loaded))
    }

    fn age_of(&self, loaded: &Loaded) -> Duration {
        self.time.elapsed().saturating_sub(loaded.at) + loaded.age_at
    }

    /// How long until the next scheduled fetch: none for a file, at once before the first keys.
    pub fn next_fetch_in(&self) -> Option<Duration> {
        if !self.rule.keys.is_fetched() {
            return None;
        }
        Some(
            self.age()
                .map_or(Duration::ZERO, |age| self.rule.refresh.saturating_sub(age)),
        )
    }

    /// How the provider's keys stand now.
    pub fn state(&self) -> KeyState {
        match self.age() {
            None => KeyState::Empty,
            Some(age) if age > self.rule.max_stale => KeyState::Stale,
            Some(age) if self.rule.keys.is_fetched() && age > self.rule.refresh * 2 => {
                KeyState::Aging
            }
            Some(_) => KeyState::Fresh,
        }
    }

    /// The provider as the Host API shows it: never the key material.
    pub fn status(&self) -> ProviderStatus {
        let (source, location) = match &self.rule.keys {
            KeySource::Discovery => ("discovery", self.rule.discovery_url()),
            KeySource::Uri(uri) => ("jwks_uri", uri.clone()),
            KeySource::File(path) => ("jwks_file", path.display().to_string()),
        };
        let held = self
            .loaded
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        ProviderStatus {
            name: self.rule.name.clone(),
            issuer: self.rule.issuer.clone(),
            claim: self.rule.claim.clone(),
            source,
            location,
            keys: held
                .as_ref()
                .map(|loaded| {
                    loaded
                        .keys
                        .iter()
                        .map(|(kid, _, algorithm)| KeyInfo {
                            kid: kid.clone(),
                            algorithm,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            fetched_at: held.as_ref().map(|loaded| loaded.fetched_at),
            age: held.as_ref().map(|loaded| self.age_of(loaded)),
            failure: self
                .failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            state: self.state(),
        }
    }

    /// A token named a key the set does not hold: the refresh task is asked for an early fetch,
    /// at most once per [`EARLY_REFRESH_EVERY`]. The request that asked is refused all the same.
    fn want_early(&self) {
        if !self.rule.keys.is_fetched() {
            return;
        }
        let now = self.time.elapsed();
        {
            let mut early = self.early.lock().unwrap_or_else(PoisonError::into_inner);
            if early.is_some_and(|last| now.saturating_sub(last) < EARLY_REFRESH_EVERY) {
                return;
            }
            *early = Some(now);
        }
        if let Some(wake) = self.waker.get() {
            wake();
        }
    }

    /// Looks at a file source again: unchanged restarts the stale window, since the file is the
    /// deployment's statement that these are the keys; changed is read anew; unreadable is an
    /// error that leaves the loaded set to age out. A fetched source answers `false`: its task
    /// fetches. `verify` calls it once half the window has passed; a maintenance pass may call it
    /// earlier.
    pub fn refresh(&self) -> Result<bool, String> {
        let KeySource::File(path) = &self.rule.keys else {
            return Ok(false);
        };
        let now = self.time.elapsed();
        let modified = std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .map_err(|error| format!("reading {}: {error}", path.display()));
        {
            let mut held = self.loaded.write().unwrap_or_else(PoisonError::into_inner);
            if let Some(held) = held.as_mut() {
                held.checked = now;
                let modified = modified.clone()?;
                if held.modified == Some(modified) {
                    held.at = now;
                    held.age_at = Duration::ZERO;
                    return Ok(false);
                }
            }
        }
        modified?;
        let loaded = load_file(path, &self.rule.algorithms, now, self.time.now_secs())?;
        *self.loaded.write().unwrap_or_else(PoisonError::into_inner) = Some(loaded);
        Ok(true)
    }

    /// Verifies `token`: `Ok(None)` when it names another issuer, the actor when it verifies,
    /// a denial when it names this issuer and does not.
    pub fn verify(&self, token: &str) -> Result<Option<ActorContext>, AccessDenial> {
        self.verify_token(token)
            .map(|verified| verified.map(|verified| verified.context))
    }

    /// [`Verifier::verify`], with the token's email when the provider verified it.
    pub fn verify_token(&self, token: &str) -> Result<Option<Verified>, AccessDenial> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(AccessDenial::unauthenticated(
                "the bearer token is longer than any token this adapter accepts",
            ));
        }
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AccessDenial::unauthenticated(
                "the bearer token is not a compact JWS",
            ));
        };
        let decode = |part: &str, what: &str| {
            URL_SAFE_NO_PAD.decode(part).map_err(|_| {
                AccessDenial::unauthenticated(format!("the token's {what} is not base64url"))
            })
        };
        let claims: serde_json::Value = serde_json::from_slice(&decode(payload, "payload")?)
            .map_err(|_| AccessDenial::unauthenticated("the token's payload is not JSON"))?;
        if claims.get("iss").and_then(serde_json::Value::as_str) != Some(self.rule.issuer.as_str())
        {
            return Ok(None);
        }
        let header: serde_json::Value = serde_json::from_slice(&decode(header, "header")?)
            .map_err(|_| AccessDenial::unauthenticated("the token's header is not JSON"))?;
        if header.get("crit").is_some() {
            return Err(AccessDenial::unauthenticated(
                "the token names critical header extensions, which this adapter does not process",
            ));
        }
        let algorithm = header
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AccessDenial::unauthenticated("the token names no algorithm"))?;
        if !self
            .rule
            .algorithms
            .iter()
            .any(|allowed| allowed == algorithm)
        {
            return Err(AccessDenial::unauthenticated(format!(
                "the token's algorithm `{algorithm}` is not one this provider is pinned to"
            )));
        }
        if let Some(typ) = header.get("typ") {
            let accepted = typ.as_str().is_some_and(|typ| {
                self.rule
                    .token_types
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(typ))
            });
            if !accepted {
                return Err(AccessDenial::unauthenticated(format!(
                    "the token's type {typ} is not one this provider accepts"
                )));
            }
        }
        let kid = header.get("kid").and_then(serde_json::Value::as_str);
        // A file source is looked at again half-way through its window, by the one request that
        // finds the half-window passed: a stat, a read only when it changed, never a network
        // fetch. A file that cannot be read leaves the loaded set to age out below.
        if let KeySource::File(_) = &self.rule.keys {
            let due = self
                .loaded
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_some_and(|held| {
                    self.time.elapsed().saturating_sub(held.checked) >= self.rule.max_stale / 2
                });
            if due && let Err(detail) = self.refresh() {
                tracing::warn!(
                    event.name = "oidc.keys_not_refreshed",
                    component = "host",
                    provider = %self.rule.name,
                    error = %detail,
                    "the provider's key file could not be re-read; the loaded set serves until its stale window ends"
                );
            }
        }
        let Some(loaded) = self
            .loaded
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return Err(AccessDenial::unauthenticated(format!(
                "the keys of the identity provider `{}` have not been fetched yet; authentication \
                 through it is unavailable until they are",
                self.rule.name
            )));
        };
        if self.age_of(&loaded) > self.rule.max_stale {
            return Err(AccessDenial::unauthenticated(format!(
                "the keys of the identity provider `{}` are past their stale window; \
                 authentication through it is unavailable until they are refreshed",
                self.rule.name
            )));
        }
        let candidates: Vec<&Key> = loaded
            .keys
            .iter()
            .filter(|(held, _, held_algorithm)| {
                *held_algorithm == algorithm && (kid.is_none() || held.as_deref() == kid)
            })
            .map(|(_, key, _)| key)
            .collect();
        if candidates.is_empty() {
            self.want_early();
            return Err(AccessDenial::unauthenticated(
                "the token names a key the provider's key set does not hold",
            ));
        }
        // Everything before the last dot: the header and the payload as sent, byte for byte.
        let signed = &token.as_bytes()[..token.len() - signature.len() - 1];
        let signature = decode(signature, "signature")?;
        let verified = candidates
            .iter()
            .any(|key| verify_with(key, algorithm, signed, &signature));
        if !verified {
            return Err(AccessDenial::unauthenticated(
                "the token's signature does not verify",
            ));
        }
        // Times are wall-time comparisons (WP-2.12), read through the guard, which notices a clock
        // set back, and allowed the Host's clock skew either way.
        let now = self.time.now_secs();
        let skew = self.time.bound().as_secs();
        let time_claim = |name: &str| claims.get(name).and_then(serde_json::Value::as_u64);
        match time_claim("exp") {
            Some(exp) if exp.saturating_add(skew) > now => {}
            _ => {
                return Err(AccessDenial::unauthenticated(
                    "the token has expired or carries no expiry",
                ));
            }
        }
        if time_claim("nbf").is_some_and(|nbf| nbf > now.saturating_add(skew)) {
            return Err(AccessDenial::unauthenticated("the token is not yet valid"));
        }
        if time_claim("iat").is_some_and(|iat| iat > now.saturating_add(skew)) {
            return Err(AccessDenial::unauthenticated(
                "the token says it was issued in the future",
            ));
        }
        let audience_ok = match claims.get("aud") {
            Some(serde_json::Value::String(aud)) => aud == &self.rule.audience,
            Some(serde_json::Value::Array(auds)) => auds
                .iter()
                .any(|aud| aud.as_str() == Some(self.rule.audience.as_str())),
            _ => false,
        };
        if !audience_ok {
            return Err(AccessDenial::unauthenticated(
                "the token's audience is not this deployment",
            ));
        }
        if !self.rule.clients.is_empty() {
            let client = claims
                .get("azp")
                .or_else(|| claims.get("client_id"))
                .and_then(serde_json::Value::as_str);
            if !client.is_some_and(|client| self.rule.clients.iter().any(|held| held == client)) {
                return Err(AccessDenial::unauthenticated(
                    "the token was issued to a client this provider does not accept",
                ));
            }
        }
        let subject = claims
            .get(&self.rule.claim)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AccessDenial::unauthenticated(format!(
                    "the token carries no `{}` claim to name its subject",
                    self.rule.claim
                ))
            })?;
        if self.rule.claim == "email" {
            // An address the provider did not verify can be anybody's: some providers spell the
            // flag as a string.
            let verified = match claims.get("email_verified") {
                Some(serde_json::Value::Bool(verified)) => *verified,
                Some(serde_json::Value::String(verified)) => verified == "true",
                _ => false,
            };
            if !verified {
                return Err(AccessDenial::unauthenticated(
                    "the token's email is not verified by the provider",
                ));
            }
        }
        let principal =
            Principal::new(format!("{}{subject}", self.principal_prefix())).map_err(|error| {
                AccessDenial::unauthenticated(format!("the token's subject: {error}"))
            })?;
        let verified_email = match claims.get("email_verified") {
            Some(serde_json::Value::Bool(true)) => true,
            Some(serde_json::Value::String(flag)) => flag == "true",
            _ => false,
        }
        .then(|| claims.get("email").and_then(serde_json::Value::as_str))
        .flatten()
        .filter(|email| !email.is_empty())
        .map(str::to_owned);
        Ok(Some(Verified {
            context: ActorContext::new(
                principal,
                Credential::Oidc,
                Some(format!("{subject} ({})", self.rule.name)),
            ),
            verified_email,
        }))
    }
}

fn verify_with(key: &Key, algorithm: &str, signed: &[u8], signature: &[u8]) -> bool {
    match (key, algorithm) {
        (Key::Rsa { n, e }, "RS256") => ring::signature::RsaPublicKeyComponents { n, e }
            .verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                signed,
                signature,
            )
            .is_ok(),
        (Key::P256 { point }, "ES256") => ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            point,
        )
        .verify(signed, signature)
        .is_ok(),
        (Key::Ed25519 { public }, "EdDSA") => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
                .verify(signed, signature)
                .is_ok()
        }
        _ => false,
    }
}

/// The keys a JWKS document holds that a provider pinned to `algorithms` verifies with, and why
/// every other was skipped. A document that is not a key set, or that holds no usable key, fails;
/// a key of another type, use, algorithm or an RSA modulus under 2,048 bits is skipped, never
/// fatal: providers publish encryption keys and keys for other algorithms beside their signing
/// keys.
fn parse_key_set(
    document: &[u8],
    algorithms: &[String],
) -> Result<(Vec<ParsedKey>, Vec<String>), String> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "the key set is {} bytes, over the {MAX_DOCUMENT_BYTES} accepted",
            document.len()
        ));
    }
    let set: serde_json::Value = serde_json::from_slice(document)
        .map_err(|error| format!("the key set is not JSON: {error}"))?;
    let keys = set
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or("the key set holds no `keys` array")?;
    let mut parsed = Vec::new();
    let mut skipped = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        match parse_key(key, algorithms) {
            Ok(entry) => parsed.push(entry),
            Err(reason) => skipped.push(format!("keys[{index}]: {reason}")),
        }
    }
    if parsed.is_empty() {
        return Err(if skipped.is_empty() {
            "the key set holds no key".to_owned()
        } else {
            format!(
                "the key set holds no key this provider accepts ({})",
                skipped.join("; ")
            )
        });
    }
    Ok((parsed, skipped))
}

fn parse_key(key: &serde_json::Value, algorithms: &[String]) -> Result<ParsedKey, String> {
    let text = |name: &str| key.get(name).and_then(serde_json::Value::as_str);
    let field = |name: &str| -> Result<Vec<u8>, String> {
        let value = text(name).ok_or_else(|| format!("no `{name}`"))?;
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| format!("`{name}` is not base64url"))
    };
    if let Some(usage) = text("use")
        && usage != "sig"
    {
        return Err(format!("for use `{usage}`, not signatures"));
    }
    let kty = text("kty").unwrap_or("");
    let crv = text("crv").unwrap_or("");
    let (parsed, algorithm) = match (kty, crv) {
        ("RSA", _) => {
            let n = field("n")?;
            let significant: Vec<u8> = n.iter().copied().skip_while(|byte| *byte == 0).collect();
            let bits = significant.first().map_or(0, |first| {
                significant.len() * 8 - first.leading_zeros() as usize
            });
            if bits < MIN_RSA_BITS {
                return Err(format!("an RSA key of {bits} bits, under {MIN_RSA_BITS}"));
            }
            (
                Key::Rsa {
                    n: significant,
                    e: field("e")?,
                },
                "RS256",
            )
        }
        ("EC", "P-256") => {
            let (x, y) = (field("x")?, field("y")?);
            if x.len() != 32 || y.len() != 32 {
                return Err("not a P-256 point".to_owned());
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend(x);
            point.extend(y);
            (Key::P256 { point }, "ES256")
        }
        ("OKP", "Ed25519") => {
            let public = field("x")?;
            if public.len() != 32 {
                return Err("not an Ed25519 public key".to_owned());
            }
            (Key::Ed25519 { public }, "EdDSA")
        }
        _ => {
            return Err(format!(
                "of a type this adapter does not verify ({kty} {crv})"
            ));
        }
    };
    if let Some(declared) = text("alg")
        && declared != algorithm
    {
        return Err(format!("declared for `{declared}`, not `{algorithm}`"));
    }
    if !algorithms.iter().any(|allowed| allowed == algorithm) {
        return Err(format!(
            "for `{algorithm}`, which this provider does not accept"
        ));
    }
    Ok((text("kid").map(str::to_owned), parsed, algorithm))
}

fn load_file(
    path: &std::path::Path,
    algorithms: &[String],
    now: Duration,
    wall: u64,
) -> Result<Loaded, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    let modified = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let (keys, _) = parse_key_set(&bytes, algorithms)
        .map_err(|detail| format!("{}: {detail}", path.display()))?;
    Ok(Loaded {
        keys,
        at: now,
        age_at: Duration::ZERO,
        checked: now,
        modified,
        fetched_at: wall,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    fn guard() -> Arc<crate::time::TimeGuard> {
        Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30)))
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-oidc-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn issuer(dir: &std::path::Path) -> (Ed25519KeyPair, OidcRule) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[3u8; 32]).expect("a seed");
        let jwks = serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        }]});
        let file = dir.join("jwks.json");
        std::fs::write(&file, serde_json::to_vec(&jwks).expect("json")).expect("written");
        (
            pair,
            OidcRule {
                name: "login".to_owned(),
                issuer: "https://login.example".to_owned(),
                audience: "permguard".to_owned(),
                algorithms: vec!["EdDSA".to_owned()],
                claim: "sub".to_owned(),
                keys: KeySource::File(file),
                ca_file: None,
                refresh: Duration::from_secs(3600),
                max_stale: Duration::from_secs(3600),
                clients: Vec::new(),
                token_types: permguard_core::authz::DEFAULT_TOKEN_TYPES
                    .iter()
                    .map(|typ| (*typ).to_owned())
                    .collect(),
                link_email: false,
            },
        )
    }

    fn token(
        pair: &Ed25519KeyPair,
        header: serde_json::Value,
        claims: serde_json::Value,
    ) -> String {
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("json"))
        );
        let signature = pair.sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    fn soon() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("now")
            .as_secs()
            + 600
    }

    #[test]
    fn a_pinned_token_verifies_and_names_the_principal_from_the_claim() {
        let dir = scratch("verifies");
        let (pair, rule) = issuer(&dir);
        let verifier = Verifier::new(rule, 0, guard()).expect("builds");
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA", "kid": "k1"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "alice"}),
        );
        let actor = verifier
            .verify(&token)
            .expect("verifies")
            .expect("this issuer");
        assert_eq!(
            actor.authorization_principal().as_str(),
            "oidc:https://login.example#alice"
        );
        assert_eq!(actor.credential(), Credential::Oidc);
    }

    #[test]
    fn another_issuer_is_not_this_verifiers_and_a_wrong_audience_algorithm_signature_or_expiry_is_refused()
     {
        let dir = scratch("refuses");
        let (pair, rule) = issuer(&dir);
        let verifier = Verifier::new(rule, 0, guard()).expect("builds");
        let other = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://other.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        assert!(verifier.verify(&other).expect("answers").is_none());
        let wrong_aud = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "else", "exp": soon(), "sub": "a"}),
        );
        assert!(verifier.verify(&wrong_aud).is_err());
        let wrong_alg = token(
            &pair,
            serde_json::json!({"alg": "none"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        assert!(
            verifier.verify(&wrong_alg).is_err(),
            "the header is compared, never obeyed"
        );
        let expired = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": 1, "sub": "a"}),
        );
        assert!(verifier.verify(&expired).is_err());
        let mut tampered = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        // One character in the middle of the signature, always changed: replacing the tail with a
        // fixed value left it as it was whenever the signature already ended that way.
        let at = tampered.len() - 20;
        let flipped = if &tampered[at..=at] == "A" { "B" } else { "A" };
        tampered.replace_range(at..=at, flipped);
        assert!(verifier.verify(&tampered).is_err());
        assert!(verifier.verify("not.a.jws.at.all").is_err());
        let no_subject = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon()}),
        );
        assert!(verifier.verify(&no_subject).is_err());
    }

    /// The window is measured on a manual monotonic clock: the test reads the same on every
    /// platform, whatever the granularity of its timers (Windows sleeps in steps of about 15 ms,
    /// which made a 20 ms window measured by `sleep` fail there now and then).
    #[test]
    fn the_key_set_is_looked_at_again_half_way_and_ages_out_only_when_the_file_is_gone() {
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

        let dir = scratch("stale");
        let (pair, mut rule) = issuer(&dir);
        rule.max_stale = Duration::from_secs(20);
        let KeySource::File(file) = rule.keys.clone() else {
            unreachable!("a file rule")
        };
        let jwks = std::fs::read(&file).expect("the key set reads");
        let mono = Arc::new(ManualMonotonic::default());
        let time = Arc::new(TimeGuard::new(
            Arc::new(ManualClock::at(
                i64::try_from(crate::authz::store::now()).expect("in range"),
            )),
            mono.clone(),
            Duration::from_secs(30),
        ));
        let verifier = Verifier::new(rule, 0, time).expect("builds");
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        // Past half the window with the file in place: `verify` looks again by itself and the
        // window restarts, so the token keeps verifying well past the original window.
        mono.advance(Duration::from_secs(12));
        assert!(verifier.verify(&token).expect("verifies").is_some());
        mono.advance(Duration::from_secs(12));
        assert!(
            verifier.verify(&token).expect("verifies").is_some(),
            "the window restarted when the file was seen unchanged"
        );
        // The file gone: the look fails, the loaded set ages past the window, authentication is
        // unavailable until the file is back and looked at again.
        std::fs::remove_file(&file).expect("removed");
        mono.advance(Duration::from_secs(25));
        let refused = verifier.verify(&token).expect_err("stale");
        assert!(refused.message().contains("stale window"), "{refused}");
        std::fs::write(&file, &jwks).expect("restored");
        mono.advance(Duration::from_secs(12));
        assert!(verifier.verify(&token).expect("verifies").is_some());
        // A new key in the file is read when the file changes.
        let other = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).expect("a seed");
        let rotated = serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k2", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(other.public_key().as_ref()),
        }]});
        // A real pause only so the file's modification time moves; the window reads the manual clock.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&file, serde_json::to_vec(&rotated).expect("json")).expect("rotated");
        assert!(verifier.refresh().expect("refreshes"), "the file changed");
        assert!(verifier.verify(&token).is_err(), "the old key is gone");
        let fresh = self::token(
            &other,
            serde_json::json!({"alg": "EdDSA", "kid": "k2"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "b"}),
        );
        assert!(verifier.verify(&fresh).expect("verifies").is_some());
    }

    /// WP-2.12: expiry is compared with the guard's wall time, which a clock set back does not
    /// move back; the stale window is measured in monotonic time, so a wall clock set back does not
    /// stretch it.
    #[test]
    fn expiry_reads_wall_time_and_the_stale_window_reads_monotonic_time() {
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

        const START: i64 = 1_800_000_000;
        let dir = scratch("guard");
        let (pair, mut rule) = issuer(&dir);
        rule.max_stale = Duration::from_secs(3_600);
        let KeySource::File(file) = rule.keys.clone() else {
            unreachable!("a file rule")
        };
        let wall = Arc::new(ManualClock::at(START));
        let mono = Arc::new(ManualMonotonic::default());
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            mono.clone(),
            Duration::from_secs(30),
        ));
        let verifier = Verifier::new(rule, 0, time).expect("builds");
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": START + 600, "sub": "a"}),
        );
        assert!(verifier.verify(&token).expect("verifies").is_some());
        // The Host's clock skew is allowed either way: at its expiry plus 20 s it still holds.
        wall.jump(620);
        assert!(
            verifier.verify(&token).expect("verifies").is_some(),
            "within the 30 s skew"
        );
        wall.jump(11);
        assert!(verifier.verify(&token).is_err(), "expired by wall time");
        // A clock set back does not bring the token back: in anomaly the guard's time stays where
        // the wall clock was expected.
        wall.jump(-631);
        assert!(verifier.verify(&token).is_err(), "still expired");

        // The file gone and two hours of monotonic time passed: stale, whatever the wall says.
        std::fs::remove_file(&file).expect("removed");
        mono.advance(Duration::from_secs(7_200));
        wall.jump(-7_200);
        let refused = verifier.verify(&token).expect_err("stale");
        assert!(refused.message().contains("stale window"), "{refused}");
    }

    #[test]
    fn a_rule_that_cannot_be_honoured_fails_startup() {
        let dir = scratch("rules");
        let (_, rule) = issuer(&dir);
        let mut no_keys = rule.clone();
        no_keys.keys = KeySource::File(dir.join("missing.json"));
        assert!(matches!(
            Verifier::new(no_keys, 0, guard()),
            Err(MapperError::Keys(_))
        ));
        let mut bad_alg = rule.clone();
        bad_alg.algorithms = vec!["HS256".to_owned()];
        assert!(matches!(
            Verifier::new(bad_alg, 0, guard()),
            Err(MapperError::Invalid(_))
        ));
        let mut no_claim = rule;
        no_claim.claim = String::new();
        assert!(matches!(
            Verifier::new(no_claim, 0, guard()),
            Err(MapperError::Invalid(_))
        ));
    }

    /// A provider whose keys are fetched, on manual clocks: the wall at `START`, monotonic at zero.
    fn fetched(
        source: KeySource,
    ) -> (
        Ed25519KeyPair,
        Verifier,
        Arc<crate::time::ManualClock>,
        Arc<crate::time::ManualMonotonic>,
    ) {
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};
        let pair = Ed25519KeyPair::from_seed_unchecked(&[3u8; 32]).expect("a seed");
        let wall = Arc::new(ManualClock::at(START));
        let mono = Arc::new(ManualMonotonic::default());
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            mono.clone(),
            Duration::from_secs(30),
        ));
        let rule = OidcRule {
            name: "login".to_owned(),
            issuer: "https://login.example/".to_owned(),
            audience: "permguard".to_owned(),
            algorithms: vec!["EdDSA".to_owned(), "RS256".to_owned()],
            claim: "sub".to_owned(),
            keys: source,
            ca_file: None,
            refresh: Duration::from_secs(600),
            max_stale: Duration::from_secs(3_600),
            clients: Vec::new(),
            token_types: permguard_core::authz::DEFAULT_TOKEN_TYPES
                .iter()
                .map(|typ| (*typ).to_owned())
                .collect(),
            link_email: false,
        };
        let verifier = Verifier::new(rule, 0, time).expect("builds");
        (pair, verifier, wall, mono)
    }

    const START: i64 = 1_800_000_000;

    fn okp(pair: &Ed25519KeyPair, kid: &str) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        })
    }

    fn claims(extra: serde_json::Value) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "iss": "https://login.example/", "aud": "permguard", "exp": START + 600, "sub": "alice",
        });
        if let (Some(claims), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
            for (name, value) in extra {
                claims.insert(name.clone(), value.clone());
            }
        }
        claims
    }

    #[test]
    fn a_fetched_provider_refuses_until_its_first_keys_and_then_verifies() {
        let (pair, verifier, _, _) = fetched(KeySource::Discovery);
        assert_eq!(verifier.state(), KeyState::Empty);
        assert_eq!(
            verifier.next_fetch_in(),
            Some(Duration::ZERO),
            "fetched at once"
        );
        assert_eq!(
            verifier.rule().discovery_url(),
            "https://login.example/.well-known/openid-configuration",
            "the issuer's trailing slash is not doubled"
        );
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA", "kid": "k1"}),
            claims(serde_json::json!({})),
        );
        let refused = verifier.verify(&token).expect_err("no keys yet");
        assert!(refused.message().contains("not been fetched"), "{refused}");
        let document = serde_json::json!({"keys": [okp(&pair, "k1")]});
        let (held, skipped) = verifier
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("installed");
        assert_eq!((held, skipped.len()), (1, 0));
        let actor = verifier
            .verify(&token)
            .expect("verifies")
            .expect("this issuer");
        assert_eq!(
            actor.authorization_principal().as_str(),
            "oidc:https://login.example/#alice"
        );
        assert_eq!(verifier.issuer_principal(), "oidc:https://login.example/");
        assert_eq!(verifier.state(), KeyState::Fresh);
        assert_eq!(verifier.next_fetch_in(), Some(Duration::from_secs(600)));
    }

    #[test]
    fn keys_of_another_use_type_size_or_algorithm_are_skipped_never_fatal() {
        let (pair, verifier, _, _) = fetched(KeySource::Discovery);
        let short_rsa = serde_json::json!({
            "kty": "RSA", "kid": "short", "n": URL_SAFE_NO_PAD.encode([0xc5u8; 128]), "e": "AQAB",
        });
        let document = serde_json::json!({"keys": [
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": URL_SAFE_NO_PAD.encode([0xc5u8; 256]), "e": "AQAB"},
            short_rsa,
            {"kty": "EC", "crv": "P-256", "kid": "ec", "x": URL_SAFE_NO_PAD.encode([1u8; 32]), "y": URL_SAFE_NO_PAD.encode([2u8; 32])},
            {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
            {"kty": "OKP", "crv": "Ed25519", "kid": "wrong-alg", "alg": "ES256", "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())},
            okp(&pair, "k1"),
        ]});
        let (held, skipped) = verifier
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("one usable key is enough");
        assert_eq!(held, 1);
        assert_eq!(skipped.len(), 5, "{skipped:?}");
        assert!(skipped.iter().any(|reason| reason.contains("use `enc`")));
        assert!(skipped.iter().any(|reason| reason.contains("1024 bits")));
        assert!(
            skipped
                .iter()
                .any(|reason| reason.contains("`ES256`, which this provider does not accept"))
        );
        let none = serde_json::json!({"keys": [{"kty": "oct", "k": "c2VjcmV0"}]});
        let refused = verifier
            .install(&serde_json::to_vec(&none).expect("json"))
            .expect_err("nothing usable");
        assert!(
            refused.contains("no key this provider accepts"),
            "{refused}"
        );
        assert_eq!(
            verifier.status().keys.len(),
            1,
            "a failed install changes nothing"
        );
        assert!(
            verifier
                .install(&vec![b' '; MAX_DOCUMENT_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn an_unknown_key_asks_for_an_early_fetch_at_most_once_a_minute() {
        let (pair, verifier, _, mono) =
            fetched(KeySource::Uri("https://login.example/keys".to_owned()));
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        verifier.set_waker(Box::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        let document = serde_json::json!({"keys": [okp(&pair, "k1")]});
        verifier
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("installed");
        let rotated = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("a seed");
        let unknown = token(
            &rotated,
            serde_json::json!({"alg": "EdDSA", "kid": "k2"}),
            claims(serde_json::json!({})),
        );
        for _ in 0..5 {
            assert!(
                verifier.verify(&unknown).is_err(),
                "refused, never fetched on the request"
            );
        }
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
        mono.advance(EARLY_REFRESH_EVERY);
        assert!(verifier.verify(&unknown).is_err());
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 2);
        // The task fetched the rotated set: the new key verifies at once.
        let both = serde_json::json!({"keys": [okp(&pair, "k1"), okp(&rotated, "k2")]});
        verifier
            .install(&serde_json::to_vec(&both).expect("json"))
            .expect("installed");
        assert!(verifier.verify(&unknown).expect("verifies").is_some());
    }

    #[test]
    fn a_failed_refresh_keeps_the_keys_until_max_stale_then_refuses() {
        let (pair, verifier, _, mono) = fetched(KeySource::Discovery);
        let document = serde_json::json!({"keys": [okp(&pair, "k1")]});
        verifier
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("installed");
        // Expiring long after the test's monotonic hours: the guard follows the monotonic clock
        // when the manual wall clock stands still.
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            claims(serde_json::json!({"exp": START + 10_000})),
        );
        mono.advance(Duration::from_secs(1_300));
        verifier.failed("the provider did not answer");
        assert_eq!(
            verifier.state(),
            KeyState::Aging,
            "older than twice refresh"
        );
        assert!(verifier.verify(&token).expect("still serves").is_some());
        let status = verifier.status();
        assert_eq!(
            status.failure.map(|failure| failure.reason).as_deref(),
            Some("the provider did not answer")
        );
        mono.advance(Duration::from_secs(2_400));
        assert_eq!(verifier.state(), KeyState::Stale);
        let refused = verifier.verify(&token).expect_err("stale");
        assert!(refused.message().contains("stale window"), "{refused}");
        verifier
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("fetched again");
        assert!(verifier.verify(&token).expect("verifies").is_some());
        assert!(
            verifier.status().failure.is_none(),
            "a success clears the failure"
        );
    }

    #[test]
    fn a_fetched_set_is_kept_on_the_volume_and_restored_until_its_max_stale() {
        let dir = scratch("cache");
        let (pair, verifier, wall, _) = fetched(KeySource::Discovery);
        verifier.attach_cache(crate::storage::Dir::create_root(&dir).expect("the cache folder"));
        let document = serde_json::json!({"keys": [okp(&pair, "k1")]});
        verifier
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("installed");
        assert!(dir.join(verifier.cache_name()).is_file());
        assert_eq!(
            verifier.cache_name().len(),
            37,
            "32 hex characters and `.json`"
        );

        // Restarted 20 minutes later, without network: the kept set serves, already 20 minutes old.
        wall.jump(1_200);
        let (_, restarted, wall2, _) = fetched(KeySource::Discovery);
        wall2.jump(1_200);
        restarted.attach_cache(crate::storage::Dir::create_root(&dir).expect("the cache folder"));
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({
                "iss": "https://login.example/", "aud": "permguard", "exp": START + 3_000, "sub": "alice",
            }),
        );
        assert!(restarted.verify(&token).expect("verifies").is_some());
        assert_eq!(restarted.age(), Some(Duration::from_secs(1_200)));
        assert_eq!(
            restarted.next_fetch_in(),
            Some(Duration::ZERO),
            "past its refresh"
        );

        // Restarted past max_stale: the kept set is not restored.
        let (_, late, wall3, _) = fetched(KeySource::Discovery);
        wall3.jump(3_700);
        late.attach_cache(crate::storage::Dir::create_root(&dir).expect("the cache folder"));
        assert_eq!(late.state(), KeyState::Empty);
    }

    #[test]
    fn critical_headers_other_types_other_clients_future_tokens_and_unverified_emails_are_refused()
    {
        let (pair, verifier, _, _) = fetched(KeySource::Discovery);
        let document = serde_json::json!({"keys": [okp(&pair, "k1")]});
        verifier
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("installed");
        let sign = |header: serde_json::Value, extra: serde_json::Value| {
            token(&pair, header, claims(extra))
        };
        let ok = serde_json::json!({});
        assert!(
            verifier
                .verify(&sign(
                    serde_json::json!({"alg": "EdDSA", "typ": "at+jwt"}),
                    ok.clone()
                ))
                .expect("verifies")
                .is_some()
        );
        assert!(
            verifier
                .verify(&sign(
                    serde_json::json!({"alg": "EdDSA", "typ": "JWT"}),
                    ok.clone()
                ))
                .expect("verifies")
                .is_some()
        );
        assert!(
            verifier
                .verify(&sign(
                    serde_json::json!({"alg": "EdDSA", "typ": "logout+jwt"}),
                    ok.clone()
                ))
                .is_err()
        );
        assert!(
            verifier
                .verify(&sign(
                    serde_json::json!({"alg": "EdDSA", "crit": ["exp"]}),
                    ok.clone()
                ))
                .is_err()
        );
        assert!(
            verifier
                .verify(&sign(
                    serde_json::json!({"alg": "EdDSA", "jku": "https://evil.example/keys"}),
                    ok.clone()
                ))
                .expect("jku is ignored")
                .is_some(),
            "a key URL in the header is never followed"
        );
        assert!(
            verifier
                .verify(&sign(
                    serde_json::json!({"alg": "EdDSA"}),
                    serde_json::json!({"iat": START + 3_600})
                ))
                .is_err()
        );
        assert!(
            verifier
                .verify(&sign(
                    serde_json::json!({"alg": "EdDSA"}),
                    serde_json::json!({"nbf": START + 20})
                ))
                .expect("within skew")
                .is_some()
        );

        let mut rule = verifier.rule().clone();
        rule.clients = vec!["cli".to_owned()];
        rule.claim = "email".to_owned();
        let (_, _, _, _) = fetched(KeySource::Discovery);
        let strict = Verifier::new(rule, 0, Arc::clone(&verifier.time)).expect("builds");
        strict
            .install(&serde_json::to_vec(&document).expect("json"))
            .expect("installed");
        let email = |extra: serde_json::Value| {
            strict.verify(&sign(serde_json::json!({"alg": "EdDSA"}), extra))
        };
        assert!(
            email(serde_json::json!({"azp": "cli", "email": "a@acme.com", "email_verified": true}))
                .expect("verifies")
                .is_some()
        );
        assert!(email(serde_json::json!({"client_id": "cli", "email": "a@acme.com", "email_verified": "true"})).expect("verifies").is_some());
        assert!(
            email(
                serde_json::json!({"azp": "cli", "email": "a@acme.com", "email_verified": false})
            )
            .is_err()
        );
        assert!(email(serde_json::json!({"azp": "cli", "email": "a@acme.com"})).is_err());
        assert!(
            email(serde_json::json!({"azp": "web", "email": "a@acme.com", "email_verified": true}))
                .is_err()
        );
        assert!(email(serde_json::json!({"email": "a@acme.com", "email_verified": true})).is_err());
        let actor =
            email(serde_json::json!({"azp": "cli", "email": "a@acme.com", "email_verified": true}))
                .expect("verifies")
                .expect("this issuer");
        assert_eq!(
            actor.authorization_principal().as_str(),
            "oidc:https://login.example/#a@acme.com"
        );
    }
}
