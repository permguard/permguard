// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a Host trusts access tokens from: the Authority Plane's key set and status lists, as it
//! holds them (`2-security/8` Keys and lists on a Plane).
//!
//! ```text
//! host/authority/
//! ├── keys.json        the last good key set, with the issuer it was taken for
//! └── lists/           every status list held, a signed statuslist+jwt each
//! ```
//!
//! Two feeds fill it, through the same checks: a Host beside the Authority Plane, in an
//! all-in-one or on its own Server, is handed the key set and every list in-process; any other
//! Host fetches them from `authority.url`. A list is verified under the held key set and the
//! issuer before it replaces the one held, whatever brought it. What is held is kept on the volume,
//! so a restart decides at once, and an Authority Plane away keeps a Plane deciding until a list's
//! `exp`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError, RwLock};

use serde::{Deserialize, Serialize};

use super::access_tokens::{Anchor, StatusLists, Trust};
use super::status_lists::{HeldLists, ListRefusal, PinnedKey, Standing, keys_of, verify_list};
use crate::storage::dir::Dir;
use crate::storage::volume::Volume;
use crate::storage::{StorageError, write};

/// The directory below `host/`.
pub const DIRECTORY: &str = "authority";
const KEYS: &str = "keys.json";
const LISTS: &str = "lists";
/// The audience every token names unless `authority.audience` says otherwise.
pub const DEFAULT_AUDIENCE: &str = "permguard";
/// The most keys a held set takes: a rotation's current and retiring keys, with room to spare.
pub const MAX_KEYS: usize = 16;
/// The capability a Host reports degraded while a held list has expired.
pub const CAPABILITY: &str = "token-status";

/// The key set as it is kept: the issuer it was taken for and its JWKs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct KeptKeys {
    issuer: String,
    keys: Vec<serde_json::Value>,
}

/// The Authority Plane's key set and lists, as a Host holds them.
pub struct AuthorityTrust {
    /// The issuer every token and list must name: `authority.url`, or what the Authority Plane
    /// in this process announces.
    issuer: RwLock<Option<String>>,
    audience: String,
    keys: RwLock<Vec<PinnedKey>>,
    lists: HeldLists,
    dir: Option<Dir>,
    /// A token named a key the held set lacks: the next refresh fetches the key set.
    keys_wanted: AtomicBool,
    /// When the key set was last asked for after an unknown key, to bound how often.
    asked: Mutex<Option<std::time::Instant>>,
}

impl std::fmt::Debug for AuthorityTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityTrust")
            .field("issuer", &self.issuer())
            .field("audience", &self.audience)
            .field("keys", &self.keys().len())
            .finish_non_exhaustive()
    }
}

/// How often an unknown key may ask for the key set again.
const ASK_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

impl AuthorityTrust {
    /// A trust held in memory only: a test, or a Host with no volume. `issuer` is the configured
    /// `authority.url`, none while the Authority Plane in this process has not announced it.
    pub fn in_memory(issuer: Option<&str>, audience: &str) -> Self {
        Self {
            issuer: RwLock::new(issuer.map(normalized)),
            audience: audience.to_owned(),
            keys: RwLock::default(),
            lists: HeldLists::in_memory(),
            dir: None,
            keys_wanted: AtomicBool::new(false),
            asked: Mutex::default(),
        }
    }

    /// A trust kept in `host/authority/` of `volume`, what it held restored: the key set kept for
    /// the same issuer, then every list that still verifies under it and has not expired.
    pub fn kept_in(
        volume: &Volume,
        issuer: Option<&str>,
        audience: &str,
        now: u64,
    ) -> Result<Self, StorageError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        let lists_dir = dir.subdir(LISTS, true)?;
        let trust = Self {
            issuer: RwLock::new(issuer.map(normalized)),
            audience: audience.to_owned(),
            keys: RwLock::default(),
            lists: HeldLists::kept_in(lists_dir),
            dir: Some(dir),
            keys_wanted: AtomicBool::new(false),
            asked: Mutex::default(),
        };
        let kept = trust
            .dir
            .as_ref()
            .and_then(|dir| dir.read(KEYS).ok().flatten())
            .and_then(|bytes| serde_json::from_slice::<KeptKeys>(&bytes).ok());
        if let Some(kept) = kept {
            // A key set kept for another issuer is not this one's: the first fetch replaces it.
            let configured = trust.issuer();
            if configured.is_none() || configured.as_deref() == Some(kept.issuer.as_str()) {
                *trust.issuer.write().unwrap_or_else(PoisonError::into_inner) =
                    Some(kept.issuer.clone());
                *trust.keys.write().unwrap_or_else(PoisonError::into_inner) =
                    parse_keys(&kept.keys);
            }
        }
        if let Some(issuer) = trust.issuer() {
            let keys = trust.keys();
            trust
                .lists
                .restore(|token| verify_list(token, &keys, &issuer, None, now).ok());
        }
        Ok(trust)
    }

    /// The issuer tokens are verified for, once known.
    pub fn issuer(&self) -> Option<String> {
        self.issuer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The audience every token must name.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The key set held.
    pub fn keys(&self) -> Vec<PinnedKey> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The Authority Plane in this process announces its issuer. Another issuer than the one held
    /// drops the key set: nothing signed for one issuer stands for another.
    pub fn announce(&self, issuer: &str) {
        let issuer = normalized(issuer);
        let mut held = self.issuer.write().unwrap_or_else(PoisonError::into_inner);
        if held.as_deref() != Some(issuer.as_str()) {
            self.keys
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
            *held = Some(issuer);
        }
    }

    /// Replaces the key set with `jwks`, a JWK set document, once kept on the volume. Answers how
    /// many keys it holds; refused when it holds none this build verifies, or too many.
    pub fn accept_keys(&self, jwks: &serde_json::Value) -> Result<usize, String> {
        let issuer = self
            .issuer()
            .ok_or_else(|| "no issuer is known to take a key set for".to_owned())?;
        let documents = jwks
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "the key set is not a JWK set".to_owned())?
            .clone();
        if documents.len() > MAX_KEYS {
            return Err(format!(
                "the key set holds {} keys, past {MAX_KEYS}",
                documents.len()
            ));
        }
        let keys = parse_keys(&documents);
        if keys.is_empty() {
            return Err("the key set holds no key this build verifies".to_owned());
        }
        if let Some(dir) = &self.dir {
            let kept = serde_json::to_vec(&KeptKeys {
                issuer,
                keys: documents,
            })
            .map_err(|error| error.to_string())?;
            if let Err(error) = write::replace_bytes(dir, KEYS, &kept) {
                tracing::warn!(
                    event.name = "authz.authority_keys_unkept",
                    component = "host",
                    error = %error,
                    "the Authority Plane's key set could not be kept on the volume: it is held \
                     in memory only"
                );
            }
        }
        let count = keys.len();
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = keys;
        Ok(count)
    }

    /// Verifies `token`, a `statuslist+jwt`, under the held key set and issuer, and holds it in
    /// place of the list of its `uri` when it is newer. Answers whether it replaced one.
    pub fn accept_list(&self, token: &str, now: u64) -> Result<bool, ListRefusal> {
        let issuer = self.issuer().ok_or_else(|| {
            ListRefusal::Signature("no issuer is known to take a list for".to_owned())
        })?;
        let keys = self.keys();
        // Unverified, only to find the list held for the same `uri`: `verify_list` checks the
        // claims again under the key set.
        let uri = unverified_subject(token);
        let held_iat = uri
            .as_deref()
            .and_then(|uri| self.lists.iat_of(&issuer, uri));
        let list = match verify_list(token, &keys, &issuer, held_iat, now) {
            Ok(list) => list,
            // The same list again is no news, not a refusal.
            Err(ListRefusal::Rollback { held, offered }) if held == offered => return Ok(false),
            Err(refusal) => {
                self.lists.refused(&refusal);
                return Err(refusal);
            }
        };
        self.lists
            .accept(list)
            .map(|()| true)
            .inspect_err(|refusal| {
                self.lists.refused(refusal);
            })
    }

    /// Drops the lists the Authority Plane no longer names, `list_ids` being every one it serves.
    pub fn keep_named(&self, list_ids: &[String]) {
        if let Some(issuer) = self.issuer() {
            self.lists.keep_named(&issuer, list_ids);
        }
    }

    /// What the held lists say at `now`.
    pub fn standing(&self, now: u64) -> Standing {
        self.lists.standing(now)
    }

    /// The shortest `ttl` a held list states: how often the lists are fetched again.
    pub fn shortest_ttl(&self) -> Option<u64> {
        self.lists
            .all()
            .iter()
            .map(|list| list.ttl)
            .filter(|ttl| *ttl > 0)
            .min()
    }

    /// The lists refused since the last call, by reason.
    pub fn take_refused(&self) -> Vec<(&'static str, u64)> {
        self.lists.take_refused()
    }

    /// Whether a token asked for the key set since the last call.
    pub fn take_keys_wanted(&self) -> bool {
        self.keys_wanted.swap(false, Ordering::SeqCst)
    }
}

impl Trust for AuthorityTrust {
    fn anchor(&self) -> Option<Anchor> {
        let issuer = self.issuer()?;
        let keys = self.keys();
        (!keys.is_empty()).then(|| Anchor {
            issuer,
            audience: self.audience.clone(),
            keys,
        })
    }

    fn lists(&self) -> &dyn StatusLists {
        &self.lists
    }

    fn unknown_key(&self, _kid: &str) {
        let mut asked = self.asked.lock().unwrap_or_else(PoisonError::into_inner);
        if asked.is_none_or(|at| at.elapsed() >= ASK_EVERY) {
            *asked = Some(std::time::Instant::now());
            self.keys_wanted.store(true, Ordering::SeqCst);
        }
    }
}

/// An issuer URL as it is compared: without a trailing slash.
pub fn normalized(issuer: &str) -> String {
    issuer.trim().trim_end_matches('/').to_owned()
}

fn parse_keys(documents: &[serde_json::Value]) -> Vec<PinnedKey> {
    keys_of(
        &documents
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>(),
    )
}

/// The `sub` of a compact JWS, read without verifying it.
fn unverified_subject(token: &str) -> Option<String> {
    use base64::Engine as _;

    if token.len() > super::status_lists::MAX_LIST_TOKEN_BYTES {
        return None;
    }
    let payload = token.split('.').nth(1)?;
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?,
    )
    .ok()?;
    claims.get("sub")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use permguard_objects::status_list::{ENTRIES, StatusList};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde_json::json;

    const ISSUER: &str = "https://authority.example:8443";
    const URI: &str = "https://authority.example:8443/authority/v1/status-lists/l1";
    const NOW: u64 = 1_800_000_000;

    fn pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[3; 32]).expect("a key")
    }

    fn jwks(pair: &Ed25519KeyPair) -> serde_json::Value {
        json!({"keys": [{
            "kid": "authority.tokens:k1", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
            "use": "sig", "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        }]})
    }

    fn list_token(pair: &Ed25519KeyPair, iat: u64, revoked: &[usize]) -> String {
        let mut list = StatusList::new(2, ENTRIES).expect("a list");
        for index in revoked {
            list.set(*index, 1).expect("set");
        }
        let header = URL_SAFE_NO_PAD.encode(
            json!({"alg": "EdDSA", "kid": "authority.tokens:k1", "typ": "statuslist+jwt"})
                .to_string(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            json!({
                "iss": ISSUER, "sub": URI, "iat": iat, "exp": iat + 3_600, "ttl": 30,
                "status_list": {"bits": 2, "lst": list.encode().expect("encoded")},
            })
            .to_string(),
        );
        let signature = URL_SAFE_NO_PAD.encode(pair.sign(format!("{header}.{claims}").as_bytes()));
        format!("{header}.{claims}.{signature}")
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("pg-authority-trust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        root
    }

    #[test]
    fn keys_and_lists_are_verified_held_and_restored_after_a_restart() {
        let root = scratch("restore");
        let volume = Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let pair = pair();
        let trust =
            AuthorityTrust::kept_in(&volume, Some(&format!("{ISSUER}/")), DEFAULT_AUDIENCE, NOW)
                .expect("opens");
        assert_eq!(trust.anchor(), None, "no key set yet");
        // A list before its key set does not verify.
        assert!(
            trust
                .accept_list(&list_token(&pair, NOW, &[]), NOW)
                .is_err()
        );
        assert_eq!(trust.accept_keys(&jwks(&pair)).expect("held"), 1);
        let anchor = trust.anchor().expect("an anchor");
        assert_eq!(anchor.issuer, ISSUER);
        assert!(
            trust
                .accept_list(&list_token(&pair, NOW, &[]), NOW)
                .expect("held")
        );
        assert!(
            !trust
                .accept_list(&list_token(&pair, NOW, &[]), NOW)
                .expect("the same list again")
        );
        assert!(
            trust
                .accept_list(&list_token(&pair, NOW + 5, &[4]), NOW)
                .expect("a newer one")
        );
        assert!(matches!(
            trust.accept_list(&list_token(&pair, NOW + 1, &[]), NOW),
            Err(ListRefusal::Rollback { .. })
        ));
        // Another key's list is refused.
        let other = Ed25519KeyPair::from_seed_unchecked(&[4; 32]).expect("a key");
        assert!(matches!(
            trust.accept_list(&list_token(&other, NOW + 9, &[]), NOW),
            Err(ListRefusal::Signature(_))
        ));
        drop(trust);
        let restored = AuthorityTrust::kept_in(&volume, Some(ISSUER), DEFAULT_AUDIENCE, NOW + 10)
            .expect("reopens");
        assert_eq!(restored.keys().len(), 1);
        let held = restored.lists().list(ISSUER, URI).expect("restored");
        assert_eq!(held.iat, NOW + 5);
        assert_eq!(held.list.get(4).expect("in range"), 1);
        // Another issuer configured: what was kept is not its.
        let elsewhere = AuthorityTrust::kept_in(
            &volume,
            Some("https://other.example"),
            DEFAULT_AUDIENCE,
            NOW + 10,
        )
        .expect("reopens");
        assert_eq!(elsewhere.anchor(), None);
    }

    #[test]
    fn an_announced_issuer_and_an_unknown_key_are_taken_in_turn() {
        let trust = AuthorityTrust::in_memory(None, DEFAULT_AUDIENCE);
        assert!(trust.accept_keys(&jwks(&pair())).is_err(), "no issuer yet");
        trust.announce(ISSUER);
        trust.accept_keys(&jwks(&pair())).expect("held");
        assert!(trust.anchor().is_some());
        trust.announce(ISSUER);
        assert!(trust.anchor().is_some(), "the same issuer keeps its keys");
        trust.announce("https://moved.example");
        assert_eq!(trust.anchor(), None, "another issuer drops them");
        assert!(!trust.take_keys_wanted());
        trust.unknown_key("k9");
        trust.unknown_key("k9");
        assert!(trust.take_keys_wanted());
        assert!(!trust.take_keys_wanted(), "asked once a minute at most");
        assert!(
            trust
                .accept_keys(&json!({"keys": [{"kty": "RSA", "kid": "r", "x": "", "alg": "RS256", "use": "sig"}]}))
                .is_err()
        );
    }
}
