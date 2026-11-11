// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane's status lists as a verifying Host holds them (`2-security/9` Delivery):
//! each a signed `statuslist+jwt`, verified under the held `authority.tokens` key set and the
//! Authority Plane's issuer, refused when its `iat` is not after the one held for the same list,
//! and replaced atomically. What a Host holds is kept on its volume, signed as it arrived, and
//! verified again when the Host starts, so a Plane keeps deciding through an Authority Plane
//! outage until a list expires, and not one second longer.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_objects::status_list::{ENTRIES, StatusList};
use sha2::{Digest as _, Sha256};

/// The most bytes a list token takes, checked before it is parsed (`2-security/9` Delivery).
pub const MAX_LIST_TOKEN_BYTES: usize = 1024 * 1024;
/// The most lists an index names.
pub const MAX_LISTS: usize = 1_024;
/// The bits per entry every list carries.
pub const BITS: u8 = 2;

/// A public key of the held `authority.tokens` set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedKey {
    pub kid: String,
    /// `EdDSA` or `ES256`.
    pub algorithm: &'static str,
    pub public_key: Vec<u8>,
}

/// One list a Host holds, verified.
#[derive(Clone, PartialEq, Eq)]
pub struct HeldList {
    /// The Authority Plane that signed it, by its issuer URL: a list is held and read for the
    /// issuer it verified under, so no issuer's list stands for another's.
    pub issuer: String,
    /// Its `sub`: the `uri` every token of it names.
    pub uri: String,
    pub iat: u64,
    pub exp: u64,
    pub ttl: u64,
    pub list: StatusList,
    /// The SHA-256 of the token's bytes: what a decision names it by (WP-12.5).
    pub digest: [u8; 32],
    /// The signed token itself, as it arrived: what is kept, and verified again at start.
    pub token: String,
}

impl std::fmt::Debug for HeldList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldList")
            .field("issuer", &self.issuer)
            .field("uri", &self.uri)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

/// Why a list token was refused, by the reason the signals count (`2-security/9` Signals).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListRefusal {
    Size(String),
    Signature(String),
    Rollback { held: u64, offered: u64 },
    Expired(u64),
}

impl ListRefusal {
    /// The label the signals count it under (`2-security/9` Signals): a metric's, not a code.
    pub fn signal(&self) -> &'static str {
        match self {
            Self::Size(_) => "size",
            Self::Signature(_) => "signature",
            Self::Rollback { .. } => "rollback",
            Self::Expired(_) => "expired",
        }
    }
}

impl std::fmt::Display for ListRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Size(detail) | Self::Signature(detail) => f.write_str(detail),
            Self::Rollback { held, offered } => write!(
                f,
                "the list's iat {offered} is not after the {held} already held: a rollback"
            ),
            Self::Expired(exp) => write!(f, "the list expired at {exp}"),
        }
    }
}

/// Verifies a list token in the order of `2-security/9` Delivery: its size, `typ`, `alg` and
/// `kid` in the held set, the signature, `iss`, `iat` after `held_iat`, `exp`
/// not passed; then decodes its list within the bound of `2^20` entries.
pub fn verify_list(
    token: &str,
    keys: &[PinnedKey],
    issuer: &str,
    held_iat: Option<u64>,
    now: u64,
) -> Result<HeldList, ListRefusal> {
    let signature = |detail: &str| ListRefusal::Signature(detail.to_owned());
    if token.len() > MAX_LIST_TOKEN_BYTES {
        return Err(ListRefusal::Size(format!(
            "the list token takes {} bytes, past {MAX_LIST_TOKEN_BYTES}",
            token.len()
        )));
    }
    let mut parts = token.split('.');
    let (Some(protected), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(signature("a list token is a compact JWS"));
    };
    let decode = |part: &str| -> Option<serde_json::Value> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
    };
    let header = decode(protected).ok_or_else(|| signature("the header does not read"))?;
    if header.get("typ").and_then(serde_json::Value::as_str)
        != Some(permguard_core::domains::jwt::STATUS_LIST_TOKEN)
    {
        return Err(signature("the token is not a statuslist+jwt"));
    }
    let alg = header.get("alg").and_then(serde_json::Value::as_str);
    let kid = header.get("kid").and_then(serde_json::Value::as_str);
    let key = keys
        .iter()
        .find(|key| Some(key.kid.as_str()) == kid && Some(key.algorithm) == alg)
        .ok_or_else(|| signature("no key of the held authority.tokens set signs it"))?;
    let algorithm: &dyn ring::signature::VerificationAlgorithm = match key.algorithm {
        "EdDSA" => &ring::signature::ED25519,
        "ES256" => &ring::signature::ECDSA_P256_SHA256_FIXED,
        _ => return Err(signature("an algorithm the set does not sign with")),
    };
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| signature("the signature does not read"))?;
    ring::signature::UnparsedPublicKey::new(algorithm, &key.public_key)
        .verify(
            format!("{protected}.{payload}").as_bytes(),
            &signature_bytes,
        )
        .map_err(|_| signature("the signature does not verify"))?;
    let claims = decode(payload).ok_or_else(|| signature("the claims do not read"))?;
    let text = |name: &str| claims.get(name).and_then(serde_json::Value::as_str);
    let number = |name: &str| claims.get(name).and_then(serde_json::Value::as_u64);
    if text("iss") != Some(issuer) {
        return Err(signature("the list is not this Authority Plane's"));
    }
    let (Some(uri), Some(iat), Some(exp)) = (text("sub"), number("iat"), number("exp")) else {
        return Err(signature("the list names no sub, iat or exp"));
    };
    if let Some(held) = held_iat
        && iat <= held
    {
        return Err(ListRefusal::Rollback { held, offered: iat });
    }
    if exp <= now {
        return Err(ListRefusal::Expired(exp));
    }
    let status = claims
        .get("status_list")
        .ok_or_else(|| signature("the token carries no status_list"))?;
    if status.get("bits").and_then(serde_json::Value::as_u64) != Some(u64::from(BITS)) {
        return Err(signature("a list carries 2 bits per entry"));
    }
    let lst = status
        .get("lst")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| signature("the list carries no lst"))?;
    let list =
        StatusList::decode(BITS, lst, MAX_LIST_TOKEN_BYTES, ENTRIES).map_err(
            |error| match error {
                permguard_objects::status_list::StatusListError::TooLarge(_) => {
                    ListRefusal::Size(error.to_string())
                }
                other => ListRefusal::Signature(other.to_string()),
            },
        )?;
    // Exactly 2^20 entries (`2-security/9` The list): a shorter one is not what was issued.
    if list.len() != ENTRIES {
        return Err(signature("a list holds exactly 2^20 entries"));
    }
    Ok(HeldList {
        issuer: issuer.to_owned(),
        uri: uri.to_owned(),
        iat,
        exp,
        ttl: number("ttl").unwrap_or(0),
        list,
        digest: Sha256::digest(token.as_bytes()).into(),
        token: token.to_owned(),
    })
}

/// The lists a Host holds, by issuer and `uri`, and where they are kept.
pub struct HeldLists {
    held: Mutex<BTreeMap<(String, String), Arc<HeldList>>>,
    dir: Option<crate::storage::Dir>,
    /// The lists whose newest one could not be kept on the volume: held in memory only, and the
    /// older file removed, so a restart never brings back a list a fresher one replaced.
    unkept: Mutex<BTreeSet<(String, String)>>,
    /// The lists refused since the last report, by the reason the signals count.
    refused: Mutex<BTreeMap<&'static str, u64>>,
}

/// What the lists a Host holds say of it (`2-security/9` Signals), at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Standing {
    /// Seconds since the oldest held list's `iat`; `None` when none is held.
    pub oldest_age: Option<u64>,
    /// The lists past half their lifetime without a fresher one.
    pub aging: Vec<String>,
    /// The lists past their `exp`: every token of them is refused.
    pub expired: Vec<String>,
    /// The lists held in memory only: their newest could not be kept on the volume.
    pub unkept: Vec<String>,
}

impl std::fmt::Debug for HeldLists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldLists")
            .field(
                "lists",
                &self.held.lock().map(|held| held.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

/// The name a list is kept under: the SHA-256 of its issuer and `uri`, so no `uri` names a path
/// and no issuer's list takes another's place.
fn file_of(issuer: &str, uri: &str) -> String {
    let digest = Sha256::digest(format!("{issuer}\n{uri}").as_bytes());
    format!(
        "{}.jwt",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

impl HeldLists {
    /// Lists held in memory only: a test, or a Host with no volume.
    pub fn in_memory() -> Self {
        Self {
            held: Mutex::default(),
            dir: None,
            unkept: Mutex::default(),
            refused: Mutex::default(),
        }
    }

    /// Lists kept in `dir`. What it holds is read by [`Self::restore`], once the pins are known.
    pub fn kept_in(dir: crate::storage::Dir) -> Self {
        Self {
            held: Mutex::default(),
            dir: Some(dir),
            unkept: Mutex::default(),
            refused: Mutex::default(),
        }
    }

    /// Reads the kept tokens back, each verified as when it arrived by `verify`: one that no
    /// longer verifies, or has expired, is dropped. Answers how many were restored.
    pub fn restore(&self, verify: impl Fn(&str) -> Option<HeldList>) -> usize {
        let Some(dir) = &self.dir else {
            return 0;
        };
        let Ok(names) = dir.names() else {
            return 0;
        };
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let mut restored = 0;
        for name in names.iter().filter(|name| name.ends_with(".jwt")) {
            let token = dir
                .read(name)
                .ok()
                .flatten()
                .and_then(|bytes| String::from_utf8(bytes).ok());
            match token.as_deref().and_then(&verify) {
                Some(list) if file_of(&list.issuer, &list.uri) == *name => {
                    held.insert((list.issuer.clone(), list.uri.clone()), Arc::new(list));
                    restored += 1;
                }
                _ => {
                    let _ = dir.unlink(name);
                }
            }
        }
        restored
    }

    /// The list of `issuer` that `uri` names, while held.
    pub fn get(&self, issuer: &str, uri: &str) -> Option<Arc<HeldList>> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(issuer.to_owned(), uri.to_owned()))
            .cloned()
    }

    /// The `iat` of the list of `issuer` held for `uri`.
    pub fn iat_of(&self, issuer: &str, uri: &str) -> Option<u64> {
        self.get(issuer, uri).map(|list| list.iat)
    }

    /// Every list held.
    pub fn all(&self) -> Vec<Arc<HeldList>> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Replaces the list of its `uri` with `list`, atomically, once it is kept: the previous one
    /// stays in use until then. A list not after the one held is refused here too, whatever
    /// raced it.
    pub fn accept(&self, list: HeldList) -> Result<(), ListRefusal> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (list.issuer.clone(), list.uri.clone());
        if let Some(current) = held.get(&key)
            && list.iat <= current.iat
        {
            // Another list at the same `iat` is the issuer saying two things at once.
            if list.iat == current.iat && list.digest != current.digest {
                tracing::warn!(
                    event.name = "host.token_status_equivocation",
                    component = "host",
                    uri = %list.uri,
                    iat = list.iat,
                    "the Authority Plane signed two lists at one iat: the held one stays in use"
                );
            }
            return Err(ListRefusal::Rollback {
                held: current.iat,
                offered: list.iat,
            });
        }
        if let Some(dir) = &self.dir {
            let file = file_of(&list.issuer, &list.uri);
            let mut unkept = self.unkept.lock().unwrap_or_else(PoisonError::into_inner);
            match crate::storage::write::replace_bytes(dir, &file, list.token.as_bytes()) {
                Ok(()) => {
                    unkept.remove(&key);
                }
                Err(error) => {
                    // The older file goes: a restart then holds no list for it and refuses its
                    // tokens until a fresh one arrives, rather than bring back one this replaced.
                    let removed = dir.unlink(&file);
                    tracing::error!(
                        event.name = "host.token_status_unkept",
                        component = "host",
                        error = %error,
                        removed_older = removed.is_ok(),
                        "a status list could not be kept on the volume: it is held in memory only"
                    );
                    unkept.insert(key.clone());
                }
            }
        }
        held.insert(key, Arc::new(list));
        Ok(())
    }

    /// Drops the lists of `issuer` its index no longer names, `list_ids`, with their files: a
    /// retired list is never asked for again, and is no longer the Host's to report.
    pub fn keep_named(&self, issuer: &str, list_ids: &[String]) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let named = |uri: &str| {
            list_ids
                .iter()
                .any(|id| uri.rsplit('/').next() == Some(id.as_str()))
        };
        let gone: Vec<(String, String)> = held
            .keys()
            .filter(|(of, uri)| of == issuer && !named(uri))
            .cloned()
            .collect();
        for key in gone {
            held.remove(&key);
            self.unkept
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&key);
            if let Some(dir) = &self.dir {
                let _ = dir.unlink(&file_of(&key.0, &key.1));
            }
        }
    }

    /// Counts a list refused, for the next report.
    pub fn refused(&self, refusal: &ListRefusal) {
        *self
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(refusal.signal())
            .or_insert(0) += 1;
    }

    /// The lists refused since the last call, by reason.
    pub fn take_refused(&self) -> Vec<(&'static str, u64)> {
        std::mem::take(&mut *self.refused.lock().unwrap_or_else(PoisonError::into_inner))
            .into_iter()
            .collect()
    }

    /// What the lists held say at `now` (`2-security/9` Signals).
    pub fn standing(&self, now: u64) -> Standing {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let mut standing = Standing::default();
        for list in held.values() {
            let age = now.saturating_sub(list.iat);
            standing.oldest_age = Some(standing.oldest_age.map_or(age, |oldest| oldest.max(age)));
            if now >= list.exp {
                standing.expired.push(list.uri.clone());
            } else if now
                >= list
                    .iat
                    .saturating_add(list.exp.saturating_sub(list.iat) / 2)
            {
                standing.aging.push(list.uri.clone());
            }
        }
        standing.unkept = self
            .unkept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, uri)| uri.clone())
            .collect();
        standing
    }
}

/// The public keys of a JWK set, each JWK as JSON text: those of a suite this build verifies.
pub fn keys_of(jwks: &[String]) -> Vec<PinnedKey> {
    jwks.iter()
        .filter_map(|text| {
            let jwk: permguard_core::keys::Jwk = serde_json::from_str(text).ok()?;
            let (algorithm, public_key) = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
                ("OKP", Some("Ed25519")) => ("EdDSA", URL_SAFE_NO_PAD.decode(&jwk.x).ok()?),
                ("EC", Some("P-256")) => {
                    let mut point = vec![0x04];
                    point.extend(URL_SAFE_NO_PAD.decode(&jwk.x).ok()?);
                    point.extend(URL_SAFE_NO_PAD.decode(jwk.y.as_deref()?).ok()?);
                    ("ES256", point)
                }
                _ => return None,
            };
            Some(PinnedKey {
                kid: jwk.kid,
                algorithm,
                public_key,
            })
        })
        .collect()
}
