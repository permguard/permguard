// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The IAM Host's tokens and their status lists (iteration 02, WP-11.5, `2-security/9`): the
//! signed list tokens members hold, the live tokens an administrator reads and revokes, and the
//! statuses the directory decides.
//!
//! The directory is the truth of what a service account's tokens may be: a deleted account, or a
//! revoked or removed credential, makes its tokens `INVALID`; a suspended account makes them
//! `SUSPENDED`, and resuming it `VALID` again. [`HostApi::sync_token_statuses`] brings every live
//! token to what the directory says after each change and at start, so a crash between a
//! directory write and the statuses it implies is repaired, never left.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use permguard_core::authz::{Actor, Resource, operations};
use permguard_core::{ErrorClass, codes};
use serde::{Deserialize, Serialize};

use super::grants::rfc3339;
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::authz::directory::{AccountStatus, Directory};
use crate::authz::tokens::{IssuedToken, MUTATION_DOMAIN, TokenError, TokenRegistry, status};
use crate::identity::record::uuid_text;
use crate::operations::mutation::{Applied, Failure};

/// The fixed tenant of every token until a SaaS Control Plane exists.
pub const TENANT: &str = "default";
/// The bits per entry of every list, as its token states them.
const BITS: u8 = crate::authz::tokens::BITS;
/// The most bytes a status list token takes.
pub const MAX_LIST_TOKEN_BYTES: usize = 1024 * 1024;

/// How long a status list token is valid and how soon a fresher one is fetched, per profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListTiming {
    /// `exp - iat`.
    pub lifetime: u64,
    /// `ttl`.
    pub ttl: u64,
}

impl ListTiming {
    /// The profile's timing (`2-security/9` The status list token).
    pub fn of(profile: permguard_core::assurance::AssuranceProfile) -> Self {
        use permguard_core::assurance::AssuranceProfile;
        match profile {
            AssuranceProfile::Development => Self {
                lifetime: 24 * 3_600,
                ttl: 15 * 60,
            },
            AssuranceProfile::Production => Self {
                lifetime: 3_600,
                ttl: 5 * 60,
            },
            AssuranceProfile::Regulated => Self {
                lifetime: 10 * 60,
                ttl: 60,
            },
        }
    }
}

/// A list token signed, and what it was signed over.
#[derive(Clone)]
struct SignedList {
    iat: u64,
    changed_at: u64,
    compact: String,
    /// The same list as a member holds it: what the IAM Host's own Data Plane reads (WP-12.2).
    held: Arc<crate::membership::token_status::HeldList>,
}

/// What the facade signs tokens and lists with, given once the server built it on the IAM Host.
pub struct Tokens {
    pub registry: Arc<TokenRegistry>,
    /// The `iam.tokens` ring: what signs, and the keys it publishes.
    pub ring: Arc<dyn permguard_core::keys::SigningRing>,
    /// `urn:permguard:iam:<host_id>`.
    pub issuer: String,
    /// Where the IAM Host's listener is reached, `https://…`, without a trailing slash: the base
    /// of every list's `uri`.
    pub base_url: String,
    pub timing: ListTiming,
    /// The access tokens' lifetimes, by family.
    pub lifetimes: super::token_endpoint::Lifetimes,
    /// Whether the IAM Host runs a Data Plane too: it is then its own member, `member:<host_id>`.
    pub serves_data: bool,
    signed: Mutex<BTreeMap<[u8; 16], SignedList>>,
    /// The lists that existed when this process opened the registry: an earlier process may have
    /// signed them, ahead of the clock when they changed within one second, so the first list this
    /// one signs of them is dated [`INHERITED_AHEAD`] ahead, after anything an earlier one signed.
    inherited: std::collections::BTreeSet<[u8; 16]>,
    /// The token endpoint's requests per client and per source (WP-11.4).
    pub(super) limiter: super::token_endpoint::Limiter,
    /// The client assertions already used (WP-11.4).
    pub(super) replays: super::token_endpoint::Replays,
}

/// How far ahead the first list a process signs of a list it inherited is dated: past anything
/// an earlier process signed of it, which ran ahead of the clock only by the changes it made in
/// one second; a member accepts a list dated ahead, and refuses one not after the list it holds.
pub const INHERITED_AHEAD: u64 = 60;

impl Tokens {
    pub fn new(
        registry: Arc<TokenRegistry>,
        ring: Arc<dyn permguard_core::keys::SigningRing>,
        host_id: &[u8; 16],
        base_url: &str,
        profile: permguard_core::assurance::AssuranceProfile,
    ) -> Self {
        let inherited = registry.list_ids().into_iter().collect();
        Self {
            inherited,
            registry,
            ring,
            issuer: issuer_of(host_id),
            base_url: base_url.trim_end_matches('/').to_owned(),
            timing: ListTiming::of(profile),
            lifetimes: super::token_endpoint::Lifetimes::of(profile),
            serves_data: false,
            signed: Mutex::default(),
            limiter: super::token_endpoint::Limiter::default(),
            replays: super::token_endpoint::Replays::default(),
        }
    }

    /// Whether the IAM Host runs a Data Plane too, its own member `member:<host_id>` (WP-12.2).
    pub fn serving_data(mut self, serves: bool) -> Self {
        self.serves_data = serves;
        self
    }

    /// The `uri` of the list `list_id` names: its token's `sub`, and every token's
    /// `status.status_list.uri`.
    pub fn list_uri(&self, list_id: &[u8; 16]) -> String {
        format!(
            "{}/iam/v1/status-lists/{}",
            self.base_url,
            uuid_text(list_id)
        )
    }

    /// The signed list token of `list_id` at `now`: the one already signed while the list has not
    /// changed and its `ttl` has not elapsed, a new one otherwise, its `iat` strictly after the
    /// previous one's, across a restart too.
    pub fn list_token(&self, list_id: &[u8; 16], now: u64) -> Result<Option<String>, TokenError> {
        Ok(self
            .signed_and_held(list_id, now)?
            .map(|(compact, _)| compact))
    }

    /// The list `list_id` names as its signed token and as a member would hold it.
    fn signed_and_held(
        &self,
        list_id: &[u8; 16],
        now: u64,
    ) -> Result<Option<(String, Arc<crate::membership::token_status::HeldList>)>, TokenError> {
        let Some(changed_at) = self.registry.changed_at(list_id) else {
            return Ok(None);
        };
        let mut signed = self.signed.lock().unwrap_or_else(PoisonError::into_inner);
        // A retired list's token is never asked for again; its entries are never copied to say so.
        signed.retain(|id, _| self.registry.changed_at(id).is_some());
        if let Some(held) = signed.get(list_id)
            && held.changed_at == changed_at
            && now < held.iat.saturating_add(self.timing.ttl)
        {
            return Ok(Some((held.compact.clone(), Arc::clone(&held.held))));
        }
        let Some(view) = self.registry.list(list_id) else {
            return Ok(None);
        };
        // A change is signed at once, so a revocation holds on the IAM Host at once; `iat` grows
        // strictly, a second past the last when it changed within one.
        let iat = match signed.get(list_id) {
            Some(held) => now.max(held.iat.saturating_add(1)),
            None if self.inherited.contains(list_id) => now.saturating_add(INHERITED_AHEAD),
            None => now,
        };
        let lst = view
            .list
            .encode()
            .map_err(|error| TokenError::Invalid(error.to_string()))?;
        let payload = serde_json::json!({
            "iss": self.issuer,
            "permguard_tenant": TENANT,
            "sub": self.list_uri(list_id),
            "iat": iat,
            "exp": iat.saturating_add(self.timing.lifetime),
            "ttl": self.timing.ttl,
            "status_list": {"bits": BITS, "lst": lst},
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|error| TokenError::Invalid(error.to_string()))?;
        let ring: &dyn permguard_core::keys::Sign = self.ring.as_ref();
        let parts =
            crate::composition::sign_jws::<crate::composition::StatusListTokenV1>(&bytes, ring)
                .map_err(|error| TokenError::Invalid(format!("signing the list: {error}")))?;
        let compact = format!("{}.{}.{}", parts.protected, parts.payload, parts.signature);
        if compact.len() > MAX_LIST_TOKEN_BYTES {
            return Err(TokenError::Invalid(format!(
                "the list token takes {} bytes, past {MAX_LIST_TOKEN_BYTES}",
                compact.len()
            )));
        }
        let held = Arc::new(crate::membership::token_status::HeldList {
            issuer: self.issuer.clone(),
            uri: self.list_uri(list_id),
            iat,
            exp: iat.saturating_add(self.timing.lifetime),
            ttl: self.timing.ttl,
            list: view.list,
            digest: <sha2::Sha256 as sha2::Digest>::digest(compact.as_bytes()).into(),
            token: compact.clone(),
        });
        signed.insert(
            *list_id,
            SignedList {
                iat,
                changed_at: view.changed_at,
                compact: compact.clone(),
                held: Arc::clone(&held),
            },
        );
        Ok(Some((compact, held)))
    }

    /// The IAM Host's own trust (WP-12.2): its issuer, its ring's published keys, itself as the
    /// local member `member:<host_id>`, and its lists as signed now.
    pub fn local_anchor(&self) -> crate::authz::access_tokens::Anchor {
        let keys = self
            .ring
            .public_keys()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|jwk| serde_json::to_string(&jwk).ok())
            .collect();
        crate::authz::access_tokens::Anchor {
            issuer: self.issuer.clone(),
            tenant: TENANT.to_owned(),
            keys: crate::membership::token_status::pinned_keys(&crate::composition::PinnedRing {
                epoch: 0,
                key_set_digest: [0; 32],
                binding: Vec::new(),
                keys,
            }),
            member: self.local_member(),
            groups: Vec::new(),
            // The IAM Host's own grants decide with its tokens: no authority confines them.
            authority: None,
            bound_administration: self.lifetimes.administration_bound,
        }
    }

    /// The audience the IAM Host's own Data Plane answers to: `member:<host_id>`.
    pub fn local_member(&self) -> String {
        format!(
            "member:{}",
            self.issuer
                .strip_prefix(permguard_core::domains::subject::IAM_ISSUER_PREFIX)
                .unwrap_or_default()
        )
    }
}

/// The IAM Host's trust in its own tokens (WP-12.2), read on the Host's guarded clock.
pub struct LocalTrust {
    pub tokens: Arc<Tokens>,
    pub time: Arc<crate::time::TimeGuard>,
}

/// The lists as the IAM Host's own Data Plane reads them: signed now, as a member holds them.
impl crate::authz::access_tokens::StatusLists for LocalTrust {
    fn list(
        &self,
        issuer: &str,
        uri: &str,
    ) -> Option<Arc<crate::membership::token_status::HeldList>> {
        let id = crate::secrets::parse_uuid(uri.rsplit('/').next()?)?;
        if issuer != self.tokens.issuer || self.tokens.list_uri(&id) != uri {
            return None;
        }
        // A list is signed again only when it changed or its ttl elapsed.
        self.tokens
            .signed_and_held(&id, self.time.now_secs())
            .ok()
            .flatten()
            .map(|(_, held)| held)
    }
}

impl crate::authz::access_tokens::Trust for LocalTrust {
    fn anchors(&self) -> Vec<crate::authz::access_tokens::Anchor> {
        vec![self.tokens.local_anchor()]
    }

    fn lists(&self) -> &dyn crate::authz::access_tokens::StatusLists {
        self
    }
}

impl Tokens {
    /// Whether this IAM Host's own Data Plane is the member `audience` names.
    pub fn is_local_member(&self, audience: &str) -> bool {
        self.serves_data && audience == self.local_member()
    }
}

/// What `token.status` answers from (WP-12.1): the lists held, each signed now.
impl crate::membership::token_status::ListSource for Tokens {
    fn list_ids(&self) -> Vec<String> {
        self.registry.list_ids().iter().map(uuid_text).collect()
    }

    fn signed_list(&self, list_id: &str, now: u64) -> Result<Option<String>, String> {
        let Some(id) = crate::secrets::parse_uuid(list_id) else {
            return Ok(None);
        };
        self.list_token(&id, now).map_err(|error| error.to_string())
    }
}

/// The issuer every token and list of the IAM Host `host_id` names.
pub fn issuer_of(host_id: &[u8; 16]) -> String {
    format!(
        "{}{}",
        permguard_core::domains::subject::IAM_ISSUER_PREFIX,
        uuid_text(host_id)
    )
}

/// One live token, never the token itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenView {
    pub jti: String,
    pub subject: String,
    pub client_id: String,
    pub family: String,
    pub audience: Vec<String>,
    pub scope: String,
    pub issued_at: String,
    pub expires_at: String,
    /// `valid`, `invalid` or `suspended`.
    pub status: String,
    pub status_list: String,
    pub index: u64,
}

/// `GET /iam/v1/tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenList {
    pub tokens: Vec<TokenView>,
}

/// `POST /iam/v1/tokens/{jti}/revoke`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeToken {
    #[serde(default)]
    pub request_id: String,
}

/// What a revocation answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRevoked {
    pub receipt: Receipt,
    /// Whether it wrote anything: a token already invalid writes nothing.
    pub changed: bool,
}

fn refusal_of(error: TokenError) -> Refusal {
    match error {
        TokenError::NotFound(detail) => {
            Refusal::new(ErrorClass::NotFound, codes::common::NOT_FOUND, detail)
        }
        TokenError::Invalid(detail) => Refusal::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            detail,
        ),
        other @ (TokenError::Storage(_) | TokenError::Record(_) | TokenError::Random) => {
            Refusal::Api(
                permguard_core::ApiError::new(
                    ErrorClass::Unavailable,
                    codes::common::UNAVAILABLE,
                    "the token registry could not apply the change",
                )
                .with_internal(other.to_string()),
            )
        }
    }
}

fn view(tokens: &Tokens, token: &IssuedToken) -> TokenView {
    TokenView {
        jti: token.jti_text(),
        subject: token.subject.clone(),
        client_id: token.client_id.clone(),
        family: token.family.clone(),
        audience: token.audience.clone(),
        scope: token.scope.clone(),
        issued_at: rfc3339(token.issued_at),
        expires_at: rfc3339(token.expires_at),
        status: status::name(token.status).to_owned(),
        status_list: tokens.list_uri(&token.list_id),
        index: token.index,
    }
}

/// What the directory says `token`'s status must be: a local user's token follows its user,
/// disabled `SUSPENDED` and deleted `INVALID`; a service account's follows its account and its
/// credential; `None` for a provider subject's, which the directory does not hold.
pub fn status_from_directory(directory: &Directory, token: &IssuedToken) -> Option<u8> {
    if token.account.is_none() {
        let name = token
            .subject
            .strip_prefix(crate::authz::directory::USER_PREFIX)?;
        return Some(match directory.user(name) {
            None => status::INVALID,
            Some(user) if user.status == crate::authz::directory::UserStatus::Active => {
                status::VALID
            }
            Some(_) => status::SUSPENDED,
        });
    }
    let name = token.account.as_ref()?;
    let Some(account) = directory.service_account(name) else {
        return Some(status::INVALID);
    };
    if let Some(credential_id) = token.credential_id {
        let live = account
            .credentials
            .iter()
            .any(|credential| credential.id == credential_id && credential.revoked_at.is_none());
        if !live {
            return Some(status::INVALID);
        }
    }
    Some(match account.status {
        AccountStatus::Active => status::VALID,
        AccountStatus::Suspended => status::SUSPENDED,
    })
}

impl HostApi {
    /// The tokens of the IAM Host, or why there are none.
    pub(super) fn tokens(&self) -> Result<&Tokens, Refusal> {
        self.tokens.as_deref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "no token registry is open on this process",
            )
        })
    }

    /// Brings every live token of a service account to the status the directory decides. An
    /// `INVALID` token stays so. Answers how many changed.
    pub fn sync_token_statuses(&self, by: &str) -> Result<usize, Refusal> {
        let (Some(tokens), Some(identities)) = (self.tokens.as_deref(), self.identities.as_ref())
        else {
            return Ok(0);
        };
        let now = self.time.now_secs();
        let directory = &identities.directory;
        let mut changed = 0;
        for value in [status::INVALID, status::SUSPENDED, status::VALID] {
            changed += tokens
                .registry
                .set_status(
                    None,
                    |token| status_from_directory(directory, token) == Some(value),
                    value,
                    by,
                    now,
                )
                .map_err(refusal_of)?;
        }
        Ok(changed)
    }

    /// `GET /iam/v1/status-lists/{id}`: the signed list, under `keys.read` as the keys are.
    pub fn status_list(&self, actor: &Actor, list_id: &str) -> Result<String, Refusal> {
        self.admit(actor, operations::KEYS_READ)?;
        let tokens = self.tokens()?;
        let not_found = || {
            Refusal::new(
                ErrorClass::NotFound,
                codes::common::NOT_FOUND,
                format!("there is no status list `{list_id}`"),
            )
        };
        let id = crate::secrets::parse_uuid(list_id).ok_or_else(not_found)?;
        tokens
            .list_token(&id, self.time.now_secs())
            .map_err(refusal_of)?
            .ok_or_else(not_found)
    }

    /// `GET /iam/v1/keys`: the `iam.tokens` public keys, a JWKS, under `keys.read` as every key
    /// set is: what a verifier outside the cluster checks tokens and lists with.
    pub fn iam_keys(&self, actor: &Actor) -> Result<serde_json::Value, Refusal> {
        self.admit(actor, operations::KEYS_READ)?;
        let tokens = self.tokens()?;
        let keys = tokens.ring.public_keys().map_err(|error| {
            Refusal::Api(
                permguard_core::ApiError::new(
                    ErrorClass::Unavailable,
                    codes::common::UNAVAILABLE,
                    "the token ring publishes no key yet",
                )
                .with_internal(error.to_string()),
            )
        })?;
        Ok(serde_json::json!({ "keys": keys }))
    }

    /// `GET /.well-known/oauth-authorization-server` (RFC 8414): what a client needs to ask for a
    /// token, open to every caller as discovery is.
    pub fn authorization_server(&self) -> Result<serde_json::Value, Refusal> {
        let tokens = self.tokens()?;
        Ok(serde_json::json!({
            "issuer": tokens.issuer,
            "token_endpoint": format!("{}/iam/v1/token", tokens.base_url),
            "jwks_uri": format!("{}/iam/v1/keys", tokens.base_url),
            "grant_types_supported": [
                super::token_endpoint::CLIENT_CREDENTIALS,
                super::token_endpoint::TOKEN_EXCHANGE,
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "private_key_jwt",
                "tls_client_auth",
            ],
            "token_endpoint_auth_signing_alg_values_supported": [
                crate::authz::credentials::EDDSA,
                crate::authz::credentials::ES256,
            ],
            "permguard_tenant": TENANT,
        }))
    }

    /// `GET /iam/v1/tokens`: every live token, newest first, never a token's bytes.
    pub fn token_list(&self, actor: &Actor) -> Result<TokenList, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let tokens = self.tokens()?;
        Ok(TokenList {
            tokens: tokens
                .registry
                .live_tokens(self.time.now_secs())
                .iter()
                .map(|token| view(tokens, token))
                .collect(),
        })
    }

    /// `POST /iam/v1/tokens/{jti}/revoke`: the token is `INVALID` in its list from now on.
    pub async fn revoke_token(
        &self,
        actor: &Actor,
        jti: &str,
        revoke: RevokeToken,
    ) -> Result<TokenRevoked, Refusal> {
        let admitted = self.admit_on(actor, operations::AUTHZ_ADMIN, &Resource::host())?;
        let tokens = self.tokens()?;
        let id = crate::secrets::parse_uuid(jti).ok_or_else(|| {
            Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                format!("`{jti}` is not a token id"),
            )
        })?;
        let mutation = Mutation {
            request_id: revoke.request_id.clone(),
            expected_revision: None,
        };
        let now = self.time.now_secs();
        let by = admitted.principal.as_str().to_owned();
        let registry = Arc::clone(&tokens.registry);
        let target = uuid_text(&id);
        self.transact(
            MUTATION_DOMAIN,
            &admitted.principal,
            "tokens.revoke",
            "iam.token.revoked",
            &mutation,
            &(jti, &revoke),
            Some(target.clone()),
            || {
                registry
                    .token(&id)
                    .filter(|token| {
                        token
                            .expires_at
                            .saturating_add(crate::authz::access_tokens::CLOCK_SKEW)
                            > now
                    })
                    .map(|_| ())
                    .ok_or_else(|| {
                        Refusal::new(
                            ErrorClass::NotFound,
                            codes::common::NOT_FOUND,
                            format!("no live token `{jti}`"),
                        )
                    })
            },
            |applying| {
                let changed = registry
                    .set_status(
                        Some(applying),
                        |token| token.jti == id,
                        status::INVALID,
                        &by,
                        now,
                    )
                    .map_err(|error| match error {
                        TokenError::Storage(_) | TokenError::Record(_) => {
                            Failure::Indeterminate(refusal_of(error))
                        }
                        other => Failure::Refused(refusal_of(other)),
                    })?;
                let revision = registry.revision();
                Ok(Applied {
                    revision,
                    target: Some(target.clone()),
                    value: TokenRevoked {
                        receipt: self.receipt(applying.operation_id(), revision),
                        changed: changed > 0,
                    },
                })
            },
            |operation_id, revision, _| {
                Ok(TokenRevoked {
                    receipt: self.receipt(operation_id, revision),
                    changed: true,
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::authz::tokens::TokenDraft;
    use crate::storage::volume::Volume;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::keys::PublicSet as _;

    const NOW: u64 = 1_800_000_000;

    fn tokens(tag: &str) -> (Tokens, Arc<crate::keys::ring::Ring>) {
        let root = std::env::temp_dir().join(format!(
            "pg-api-tokens-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch directory");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let ring = Arc::new(
            crate::keys::ring::Ring::open(
                &volume,
                crate::keys::ring::IAM_TOKENS,
                crate::identity::Suite::Ed25519Sha256V1,
                crate::keys::ring::Policy {
                    publish_ahead: std::time::Duration::from_secs(600),
                    rotate_every: std::time::Duration::from_secs(3600),
                    retain: std::time::Duration::from_secs(7200),
                },
                Arc::new(crate::time::TimeGuard::system(
                    std::time::Duration::from_secs(30),
                )),
            )
            .expect("the ring opens"),
        );
        permguard_core::KeyManager::maintain(ring.as_ref()).expect("the ring is maintained");
        let (registry, _) = TokenRegistry::open(&volume).expect("the registry opens");
        (
            Tokens::new(
                registry,
                Arc::clone(&ring) as Arc<dyn permguard_core::keys::SigningRing>,
                &[7; 16],
                "https://iam.example:7443/",
                AssuranceProfile::Production,
            ),
            ring,
        )
    }

    fn issue(tokens: &Tokens, account: &str) -> IssuedToken {
        tokens
            .registry
            .issue(
                TokenDraft {
                    subject: format!("sa:{account}"),
                    client_id: "c".to_owned(),
                    family: "application".to_owned(),
                    audience: vec!["member:m".to_owned()],
                    scope: "decision.evaluate".to_owned(),
                    expires_at: NOW + 3_600,
                    account: Some(account.to_owned()),
                    credential_id: Some([1; 16]),
                },
                "iam",
                NOW,
            )
            .expect("issued")
    }

    fn part(compact: &str, at: usize) -> serde_json::Value {
        let encoded = compact.split('.').nth(at).expect("a part");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("base64url")).expect("JSON")
    }

    /// WP-11.5: a list token is a `statuslist+jwt` the ring's published key verifies, naming the
    /// issuer, the tenant, the list's `uri`, the profile's lifetime and its entries.
    #[test]
    fn a_status_list_token_is_signed_and_names_its_list() {
        let (tokens, ring) = tokens("signed");
        let token = issue(&tokens, "billing");
        let compact = tokens
            .list_token(&token.list_id, NOW)
            .expect("signed")
            .expect("the list is held");
        let header = part(&compact, 0);
        assert_eq!(header["typ"], "statuslist+jwt");
        assert_eq!(header["alg"], "EdDSA");
        let payload = part(&compact, 1);
        assert_eq!(
            payload["iss"],
            format!("urn:permguard:iam:{}", uuid_text(&[7; 16]))
        );
        assert_eq!(payload["permguard_tenant"], "default");
        assert_eq!(
            payload["sub"],
            format!(
                "https://iam.example:7443/iam/v1/status-lists/{}",
                uuid_text(&token.list_id)
            )
        );
        assert_eq!(payload["iat"], NOW);
        assert_eq!(payload["exp"], NOW + 3_600, "production: an hour");
        assert_eq!(payload["ttl"], 300);
        assert_eq!(payload["status_list"]["bits"], 2);
        let list = permguard_objects::status_list::StatusList::decode(
            2,
            payload["status_list"]["lst"].as_str().expect("lst"),
            MAX_LIST_TOKEN_BYTES,
            permguard_objects::status_list::ENTRIES,
        )
        .expect("the list decodes");
        assert_eq!(
            list.get(usize::try_from(token.index).expect("small")),
            Ok(0)
        );
        // The ring's published key verifies the signature over `protected.payload`.
        let kid = header["kid"].as_str().expect("a kid");
        let key = ring
            .public_keys()
            .expect("published")
            .into_iter()
            .find(|key| key.kid == kid)
            .expect("the kid is published");
        let public = URL_SAFE_NO_PAD.decode(&key.x).expect("base64url");
        let (signed, signature) = compact.rsplit_once('.').expect("three parts");
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
            .verify(
                signed.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).expect("base64url"),
            )
            .expect("the signature verifies");
    }

    /// The same token is answered while the list has not changed and its `ttl` has not elapsed;
    /// a change, or the `ttl`, signs a new one whose `iat` is strictly after the last.
    #[test]
    fn a_list_is_signed_again_on_a_change_or_its_ttl_and_iat_only_grows() {
        let (tokens, _) = tokens("fresh");
        let token = issue(&tokens, "billing");
        let first = tokens
            .list_token(&token.list_id, NOW)
            .expect("signed")
            .expect("held");
        assert_eq!(
            tokens
                .list_token(&token.list_id, NOW + 10)
                .expect("signed")
                .expect("held"),
            first,
            "unchanged and fresh"
        );
        tokens
            .registry
            .set_status(None, |_| true, status::SUSPENDED, "admin", NOW + 10)
            .expect("suspended");
        // Changed in the same second it was signed: signed at once, the new `iat` still the
        // greater.
        let changed = tokens
            .list_token(&token.list_id, NOW)
            .expect("signed")
            .expect("held");
        assert_ne!(changed, first);
        assert_eq!(part(&changed, 1)["iat"], NOW + 1);
        let entries = permguard_objects::status_list::StatusList::decode(
            2,
            part(&changed, 1)["status_list"]["lst"]
                .as_str()
                .expect("lst"),
            MAX_LIST_TOKEN_BYTES,
            permguard_objects::status_list::ENTRIES,
        )
        .expect("decodes");
        assert_eq!(
            entries.get(usize::try_from(token.index).expect("small")),
            Ok(status::SUSPENDED)
        );
        let after_ttl = tokens
            .list_token(&token.list_id, NOW + 1 + 300)
            .expect("signed")
            .expect("held");
        assert_eq!(part(&after_ttl, 1)["iat"], NOW + 301);
        assert!(tokens.list_token(&[9; 16], NOW).expect("nothing").is_none());
    }

    /// TS-10: the first list a process signs of a list an earlier one may have signed is dated
    /// ahead, so a restart never offers a member an `iat` it already holds; a list made since is
    /// dated now.
    #[test]
    fn a_restarted_iam_host_signs_its_inherited_lists_after_the_earlier_ones() {
        let (tokens, ring) = tokens("inherited");
        let token = issue(&tokens, "billing");
        let before = tokens
            .list_token(&token.list_id, NOW)
            .expect("signed")
            .expect("held");
        let restarted = Tokens::new(
            Arc::clone(&tokens.registry),
            Arc::clone(&ring) as Arc<dyn permguard_core::keys::SigningRing>,
            &[7; 16],
            "https://iam.example:7443/",
            AssuranceProfile::Production,
        );
        let after = restarted
            .list_token(&token.list_id, NOW)
            .expect("signed")
            .expect("held");
        assert_eq!(part(&before, 1)["iat"], NOW);
        assert_eq!(part(&after, 1)["iat"], NOW + INHERITED_AHEAD);
    }

    /// The directory decides a service account's tokens: active `VALID`, suspended `SUSPENDED`,
    /// deleted or its credential revoked `INVALID`; a person's token is not the directory's.
    #[test]
    fn the_directory_decides_a_service_accounts_token_status() {
        use crate::authz::directory::{Change, CredentialMaterial};
        use crate::operations::mutation::Applying;

        let root = std::env::temp_dir().join(format!(
            "pg-api-tokens-directory-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch directory");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (directory, _) = Directory::open(&volume).expect("the directory opens");
        let apply = |op: u8, change: Change| {
            directory
                .apply(&Applying::for_tests(op), change, "admin", NOW, None)
                .expect("applied");
        };
        apply(
            1,
            Change::CreateServiceAccount {
                name: "billing".to_owned(),
                owner: "payments".to_owned(),
                description: String::new(),
            },
        );
        apply(
            2,
            Change::AddCredential {
                account: "billing".to_owned(),
                id: [1; 16],
                material: CredentialMaterial::Binding {
                    binding: "spiffe://acme/billing".to_owned(),
                },
                expires_at: None,
            },
        );
        let token = |account: &str, credential: u8| IssuedToken {
            jti: [3; 16],
            list_id: [4; 16],
            index: 1,
            subject: format!("sa:{account}"),
            client_id: "c".to_owned(),
            family: "application".to_owned(),
            audience: vec!["member:m".to_owned()],
            scope: "decision.evaluate".to_owned(),
            issued_at: NOW,
            expires_at: NOW + 60,
            account: Some(account.to_owned()),
            credential_id: Some([credential; 16]),
            status: status::VALID,
        };
        assert_eq!(
            status_from_directory(&directory, &token("billing", 1)),
            Some(status::VALID)
        );
        assert_eq!(
            status_from_directory(&directory, &token("billing", 9)),
            Some(status::INVALID),
            "a credential the account does not hold"
        );
        assert_eq!(
            status_from_directory(&directory, &token("nobody", 1)),
            Some(status::INVALID),
            "an account that does not exist"
        );
        apply(
            3,
            Change::SetAccountStatus {
                name: "billing".to_owned(),
                active: false,
            },
        );
        assert_eq!(
            status_from_directory(&directory, &token("billing", 1)),
            Some(status::SUSPENDED)
        );
        apply(
            4,
            Change::RevokeCredential {
                account: "billing".to_owned(),
                id: [1; 16],
            },
        );
        assert_eq!(
            status_from_directory(&directory, &token("billing", 1)),
            Some(status::INVALID),
            "revoked outranks suspended"
        );
        // A local user's token follows its user; a provider subject's is not the directory's.
        let mut person = token("billing", 1);
        person.account = None;
        person.credential_id = None;
        person.subject = "user:paperino".to_owned();
        assert_eq!(
            status_from_directory(&directory, &person),
            Some(status::INVALID),
            "a user that does not exist"
        );
        apply(
            5,
            Change::CreateUser {
                name: "paperino".to_owned(),
                email: None,
                display: None,
                password: None,
            },
        );
        assert_eq!(
            status_from_directory(&directory, &person),
            Some(status::VALID)
        );
        apply(
            6,
            Change::SetStatus {
                name: "paperino".to_owned(),
                active: false,
            },
        );
        assert_eq!(
            status_from_directory(&directory, &person),
            Some(status::SUSPENDED)
        );
        person.subject = "oidc:https://login.example#0042".to_owned();
        assert_eq!(status_from_directory(&directory, &person), None);
    }
}
