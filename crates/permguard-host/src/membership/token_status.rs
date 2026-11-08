// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `token.status` task, contract version 1 (iteration 02, WP-12.1, `2-security/9` Delivery).
//!
//! ```text
//! member       task session over the task's selector
//!   ─▶ { 1 action: "index" }
//! coordinator  the lists it holds
//!   ─▶ { 1 lists: [list_id, …] }
//! member       one list at a time: a list token can be large, a session frame is bounded
//!   ─▶ { 1 action: "list", 2 list_id }
//! coordinator  the signed `statuslist+jwt`, as `GET /iam/v1/status-lists/{id}` answers it
//!   ─▶ { 2 token }
//! ```
//!
//! The member never trusts the transport for a list: it verifies each under the `iam.tokens` set
//! its manifest pins, with the coordinator's issuer, refuses one whose `iat` is not after the one
//! it holds for the same list, and replaces the held list atomically. What it holds is kept on its
//! volume, signed as it arrived, and verified again when the Host starts, so a member keeps
//! deciding through a Control Plane outage until a list expires, and not one second longer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_objects::cbor::{self, Value};
use permguard_objects::status_list::{ENTRIES, StatusList};
use sha2::{Digest as _, Sha256};

use super::task::{TaskContext, TaskHandler};
use crate::session::Refusal;
use permguard_core::codes;

/// The contract version both sides speak.
pub const VERSION: u64 = 1;
/// The most lists one index names.
pub const MAX_LISTS: usize = 1_024;
/// The most bytes a list token takes, checked before it is parsed (`2-security/9` Delivery).
pub const MAX_LIST_TOKEN_BYTES: usize = 1024 * 1024;
/// The bits per entry every list carries.
const BITS: u8 = 2;
/// The files the member keeps its lists in, below its membership folder.
pub const DIRECTORY: &str = "token-status";

/// What the coordinator answers from: the lists it holds and each one signed now.
pub trait ListSource: Send + Sync {
    /// The ids of every list held, UUID text.
    fn list_ids(&self) -> Vec<String>;
    /// The signed list `list_id` names at `now`, when it is held.
    fn signed_list(&self, list_id: &str, now: u64) -> Result<Option<String>, String>;
}

/// One request of the task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Index,
    List(String),
}

fn malformed(reason: impl Into<String>) -> Refusal {
    Refusal {
        code: codes::common::INVALID_ARGUMENT,
        reason: reason.into(),
    }
}

impl Request {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let pairs = match self {
            Self::Index => vec![(Value::Int(1), Value::Text("index".to_owned()))],
            Self::List(list_id) => vec![
                (Value::Int(1), Value::Text("list".to_owned())),
                (Value::Int(2), Value::Text(list_id.clone())),
            ],
        };
        cbor::encode(&Value::Map(pairs)).map_err(|error| error.to_string())
    }

    /// Reads the canonical bytes: a closed map, `index` alone or `list` with its id.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let Value::Map(pairs) = cbor::decode_canonical(bytes).map_err(|error| error.to_string())?
        else {
            return Err("a token.status request is a map".to_owned());
        };
        match pairs.as_slice() {
            [(Value::Int(1), Value::Text(action))] if action == "index" => Ok(Self::Index),
            [
                (Value::Int(1), Value::Text(action)),
                (Value::Int(2), Value::Text(list_id)),
            ] if action == "list" && list_id.len() <= 64 => Ok(Self::List(list_id.clone())),
            _ => Err("a token.status request is `index`, or `list` and its id".to_owned()),
        }
    }
}

/// The index's answer, canonical bytes.
pub fn encode_index(list_ids: &[String]) -> Result<Vec<u8>, String> {
    cbor::encode(&Value::Map(vec![(
        Value::Int(1),
        Value::Array(list_ids.iter().cloned().map(Value::Text).collect()),
    )]))
    .map_err(|error| error.to_string())
}

/// Reads an index's answer.
pub fn decode_index(bytes: &[u8]) -> Result<Vec<String>, String> {
    match cbor::decode_canonical(bytes).map_err(|error| error.to_string())? {
        Value::Map(pairs) => match pairs.as_slice() {
            [(Value::Int(1), Value::Array(items))] if items.len() <= MAX_LISTS => items
                .iter()
                .map(|item| match item {
                    Value::Text(id) if id.len() <= 64 => Ok(id.clone()),
                    _ => Err("a list id is text".to_owned()),
                })
                .collect(),
            _ => Err("an index answers its lists".to_owned()),
        },
        _ => Err("an index answer is a map".to_owned()),
    }
}

/// A list's answer, canonical bytes.
pub fn encode_list(token: &str) -> Result<Vec<u8>, String> {
    cbor::encode(&Value::Map(vec![(
        Value::Int(2),
        Value::Text(token.to_owned()),
    )]))
    .map_err(|error| error.to_string())
}

/// Reads a list's answer.
pub fn decode_list(bytes: &[u8]) -> Result<String, String> {
    match cbor::decode_canonical(bytes).map_err(|error| error.to_string())? {
        Value::Map(pairs) => match pairs.as_slice() {
            [(Value::Int(2), Value::Text(token))] if token.len() <= MAX_LIST_TOKEN_BYTES => {
                Ok(token.clone())
            }
            _ => Err("a list answer is its token".to_owned()),
        },
        _ => Err("a list answer is a map".to_owned()),
    }
}

/// The coordinator's side: answers the index and each list, signed now. Its answers are never
/// kept by the replay window: a list repeated is a list signed again.
pub struct StatusLists {
    pub source: Arc<dyn ListSource>,
    pub time: Arc<crate::time::TimeGuard>,
}

impl std::fmt::Debug for StatusLists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusLists").finish_non_exhaustive()
    }
}

impl TaskHandler for StatusLists {
    fn handle(&self, _context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let unavailable = |reason: String| Refusal {
            code: codes::common::UNAVAILABLE,
            reason,
        };
        match Request::decode(body).map_err(malformed)? {
            Request::Index => encode_index(&self.source.list_ids()).map_err(unavailable),
            Request::List(list_id) => {
                let token = self
                    .source
                    .signed_list(&list_id, self.time.now_secs())
                    .map_err(unavailable)?
                    .ok_or_else(|| Refusal {
                        code: codes::common::NOT_FOUND,
                        reason: format!("no list `{list_id}` is held"),
                    })?;
                encode_list(&token).map_err(unavailable)
            }
        }
    }

    fn keeps_answers(&self) -> bool {
        false
    }
}

/// A public key of the pinned `iam.tokens` set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedKey {
    pub kid: String,
    /// `EdDSA` or `ES256`.
    pub algorithm: &'static str,
    pub public_key: Vec<u8>,
}

/// One list a member holds, verified.
#[derive(Clone, PartialEq, Eq)]
pub struct HeldList {
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
/// `kid` in the pinned set, the signature, `iss` and the tenant, `iat` after `held_iat`, `exp`
/// not passed; then decodes its list within the bound of `2^20` entries.
pub fn verify_list(
    token: &str,
    keys: &[PinnedKey],
    issuer: &str,
    tenant: &str,
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
        .ok_or_else(|| signature("no key of the pinned iam.tokens set signs it"))?;
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
    if text("iss") != Some(issuer) || text("permguard_tenant") != Some(tenant) {
        return Err(signature("the list is not this IAM Host's"));
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
    Ok(HeldList {
        uri: uri.to_owned(),
        iat,
        exp,
        ttl: number("ttl").unwrap_or(0),
        list,
        digest: Sha256::digest(token.as_bytes()).into(),
        token: token.to_owned(),
    })
}

/// The lists a member holds, by `uri`, and where they are kept.
pub struct HeldLists {
    held: Mutex<BTreeMap<String, Arc<HeldList>>>,
    dir: Option<crate::storage::Dir>,
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

/// The name a list is kept under: the SHA-256 of its `uri`, so no `uri` names a path.
fn file_of(uri: &str) -> String {
    let digest = Sha256::digest(uri.as_bytes());
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
        }
    }

    /// Lists kept in `dir`. What it holds is read by [`Self::restore`], once the pins are known.
    pub fn kept_in(dir: crate::storage::Dir) -> Self {
        Self {
            held: Mutex::default(),
            dir: Some(dir),
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
                Some(list) if file_of(&list.uri) == *name => {
                    held.insert(list.uri.clone(), Arc::new(list));
                    restored += 1;
                }
                _ => {
                    let _ = dir.unlink(name);
                }
            }
        }
        restored
    }

    /// The list `uri` names, while held.
    pub fn get(&self, uri: &str) -> Option<Arc<HeldList>> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(uri)
            .cloned()
    }

    /// The `iat` of the list held for `uri`.
    pub fn iat_of(&self, uri: &str) -> Option<u64> {
        self.get(uri).map(|list| list.iat)
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
        if let Some(current) = held.get(&list.uri)
            && list.iat <= current.iat
        {
            return Err(ListRefusal::Rollback {
                held: current.iat,
                offered: list.iat,
            });
        }
        if let Some(dir) = &self.dir
            && let Err(error) = crate::storage::write::replace_bytes(
                dir,
                &file_of(&list.uri),
                list.token.as_bytes(),
            )
        {
            tracing::warn!(
                event.name = "host.token_status_unkept",
                component = "host",
                error = %error,
                "a status list could not be kept on the volume: it is held in memory only"
            );
        }
        held.insert(list.uri.clone(), Arc::new(list));
        Ok(())
    }
}

/// The public keys of a pinned set, from its statement's JWKs.
pub fn pinned_keys(ring: &crate::composition::PinnedRing) -> Vec<PinnedKey> {
    ring.keys
        .iter()
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

/// The keys and issuer every membership's `token.status` lists verify under, from what the store
/// holds: the pinned `iam.tokens` statement of each active membership's manifest, whose binding
/// was verified when the pin was taken, and its coordinator's issuer. What restores the kept lists
/// at start, before any session.
pub fn held_trust(store: &super::Store) -> Vec<(Vec<PinnedKey>, String)> {
    use super::record::{Role, Status, TaskType};

    store
        .memberships()
        .into_iter()
        .filter(|(_, held)| held.role == Role::Member && held.status == Status::Active)
        .filter_map(|(id, held)| {
            let (manifest, ..) = held.manifest?;
            if !manifest
                .tasks
                .iter()
                .any(|task| task.task_type == TaskType::TokenStatus)
            {
                return None;
            }
            let pin = manifest.ring_pins.iter().find(|pin| {
                pin.owner == Role::Coordinator
                    && pin.ring == crate::keys::ring::IAM_TOKENS
                    && !pin.retiring
            })?;
            let statements = store.statements_held(&id, manifest.epoch);
            let statement = statements
                .iter()
                .find(|statement| super::statement_matches(statement, pin).is_ok())?;
            let keys = pinned_keys(&crate::composition::PinnedRing {
                epoch: pin.epoch,
                key_set_digest: pin.key_set_digest,
                binding: pin.binding.clone(),
                keys: statement.keys.clone(),
            });
            let issuer = format!(
                "{}{}",
                permguard_core::domains::subject::IAM_ISSUER_PREFIX,
                crate::identity::record::uuid_text(&manifest.coordinator.host_id)
            );
            Some((keys, issuer))
        })
        .collect()
}

/// Restores the lists kept on the volume, each verified again under the trust the store holds;
/// an expired one, or one no membership's set verifies, is dropped. Answers how many were restored.
pub fn restore_held(lists: &HeldLists, store: &super::Store, now: u64) -> usize {
    let trust = held_trust(store);
    lists.restore(|token| {
        trust.iter().find_map(|(keys, issuer)| {
            verify_list(token, keys, issuer, crate::api::tokens::TENANT, None, now).ok()
        })
    })
}

impl super::member::Member<'_> {
    /// Fetches the lists of every active membership whose manifest grants `token.status`
    /// (WP-12.1): the index, then each list, verified under the `iam.tokens` set the manifest
    /// pins and the coordinator's issuer, and kept in `lists`. A list that fails is refused and
    /// the held one stays in use. Answers the lists accepted.
    pub async fn refresh_token_status(
        &self,
        initiator: crate::operations::journal::Initiator,
        lists: &HeldLists,
    ) -> usize {
        use super::record::{Role, Status, TaskType};

        let mut accepted = 0;
        for (id, held) in self.store.memberships() {
            if held.role != Role::Member || held.status != Status::Active {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            let Some(task) = manifest
                .tasks
                .iter()
                .find(|task| task.task_type == TaskType::TokenStatus)
            else {
                continue;
            };
            let resource = task.selector.prefix().to_string();
            let mut session = match self
                .open_task(initiator.clone(), &id, &task.task_id, &resource, Vec::new())
                .await
            {
                Ok(session) => session,
                Err(error) => {
                    tracing::warn!(
                        event.name = "host.token_status_unreachable",
                        component = "host",
                        membership_id = %crate::identity::record::uuid_text(&id),
                        error = %error,
                        "the status lists could not be fetched: the held ones stay in use"
                    );
                    continue;
                }
            };
            let statements = self.store.statements_held(&id, manifest.epoch);
            let Some(ring) = super::verified_coordinator_ring(
                &manifest.ring_pins,
                &statements,
                session.peer(),
                crate::keys::ring::IAM_TOKENS,
            ) else {
                tracing::warn!(
                    event.name = "host.token_status_unpinned",
                    component = "host",
                    membership_id = %crate::identity::record::uuid_text(&id),
                    "the manifest pins no verifiable iam.tokens set: no list is accepted"
                );
                continue;
            };
            let keys = pinned_keys(&ring);
            let issuer = format!(
                "{}{}",
                permguard_core::domains::subject::IAM_ISSUER_PREFIX,
                crate::identity::record::uuid_text(&session.peer().host_id)
            );
            let index = match Request::Index.encode() {
                Ok(body) => session.send("token-status-index", body).await,
                Err(error) => Err(super::MembershipError::Invalid(error)),
            };
            let Ok(list_ids) = index
                .map_err(|error| error.to_string())
                .and_then(|bytes| decode_index(&bytes))
            else {
                continue;
            };
            for list_id in list_ids {
                let answer = match Request::List(list_id.clone()).encode() {
                    Ok(body) => session.send(&format!("token-status-{list_id}"), body).await,
                    Err(error) => Err(super::MembershipError::Invalid(error)),
                };
                let Ok(token) = answer
                    .map_err(|error| error.to_string())
                    .and_then(|bytes| decode_list(&bytes))
                else {
                    continue;
                };
                let now = self.time.now_secs();
                let uri_of = || {
                    token
                        .split('.')
                        .nth(1)
                        .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
                        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                        .and_then(|claims| claims.get("sub")?.as_str().map(str::to_owned))
                };
                let held_iat = uri_of().and_then(|uri| lists.iat_of(&uri));
                let verified = verify_list(
                    &token,
                    &keys,
                    &issuer,
                    crate::api::tokens::TENANT,
                    held_iat,
                    now,
                )
                .and_then(|list| lists.accept(list));
                match verified {
                    Ok(()) => accepted += 1,
                    // The same list again is no news: only a list that went back is reported.
                    Err(ListRefusal::Rollback { held, offered }) if held == offered => {}
                    Err(refusal) => tracing::warn!(
                        event.name = "host.token_status_refused",
                        component = "host",
                        reason = refusal.signal(),
                        error = %refusal,
                        "a status list was refused: the held one stays in use"
                    ),
                }
            }
        }
        accepted
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    const ISSUER: &str = "urn:permguard:iam:0198f2aa-0000-7000-8000-000000000001";
    const URI: &str =
        "https://iam.example/iam/v1/status-lists/0198f2aa-0000-7000-8000-000000000002";
    const NOW: u64 = 1_800_000_000;

    fn pair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("a key")
    }

    fn pinned(pair: &Ed25519KeyPair) -> Vec<PinnedKey> {
        vec![PinnedKey {
            kid: "iam.tokens:k1".to_owned(),
            algorithm: "EdDSA",
            public_key: pair.public_key().as_ref().to_vec(),
        }]
    }

    /// A list token signed by `pair`, `claims` over the defaults.
    fn token(pair: &Ed25519KeyPair, typ: &str, iat: u64, extra: serde_json::Value) -> String {
        let mut list = StatusList::new(BITS, ENTRIES).expect("a list");
        list.set(7, 1).expect("revoked");
        let mut claims = serde_json::json!({
            "iss": ISSUER, "permguard_tenant": "default", "sub": URI, "iat": iat,
            "exp": iat + 3_600, "ttl": 300,
            "status_list": {"bits": 2, "lst": list.encode().expect("encodes")},
        });
        if let (Some(claims), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
            for (name, value) in extra {
                claims.insert(name.clone(), value.clone());
            }
        }
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"alg": "EdDSA", "kid": "iam.tokens:k1", "typ": typ}).to_string(),
        );
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signature = URL_SAFE_NO_PAD.encode(pair.sign(format!("{header}.{payload}").as_bytes()));
        format!("{header}.{payload}.{signature}")
    }

    /// WP-12.1: a list the pinned set signed, of this IAM Host, fresher than the held one and
    /// unexpired, is held with its entries and digest.
    #[test]
    fn a_pinned_fresh_list_verifies_and_is_read() {
        let pair = pair(1);
        let signed = token(&pair, "statuslist+jwt", NOW, serde_json::json!({}));
        let held = verify_list(
            &signed,
            &pinned(&pair),
            ISSUER,
            "default",
            Some(NOW - 1),
            NOW,
        )
        .expect("verified");
        assert_eq!((held.uri.as_str(), held.iat, held.ttl), (URI, NOW, 300));
        assert_eq!(held.list.get(7), Ok(1));
        assert_eq!(held.list.get(8), Ok(0));
        assert_eq!(
            held.digest,
            <[u8; 32]>::from(Sha256::digest(signed.as_bytes()))
        );
    }

    /// Tampered, signed by another key, another type, another issuer or tenant, older or equal,
    /// expired, oversized: each refused with its reason.
    #[test]
    fn every_list_the_member_must_not_hold_is_refused_with_its_reason() {
        let pair = pair(1);
        let keys = pinned(&pair);
        let good = token(&pair, "statuslist+jwt", NOW, serde_json::json!({}));
        let mut tampered = good.clone();
        tampered.replace_range(
            tampered.len() - 4..,
            if tampered.ends_with("AAAA") {
                "BBBB"
            } else {
                "AAAA"
            },
        );
        for (offered, held, reason) in [
            (tampered, None, "signature"),
            (
                token(&self::pair(2), "statuslist+jwt", NOW, serde_json::json!({})),
                None,
                "signature",
            ),
            (
                token(&pair, "at+jwt", NOW, serde_json::json!({})),
                None,
                "signature",
            ),
            (
                token(
                    &pair,
                    "statuslist+jwt",
                    NOW,
                    serde_json::json!({"iss": "urn:permguard:iam:other"}),
                ),
                None,
                "signature",
            ),
            (
                token(
                    &pair,
                    "statuslist+jwt",
                    NOW,
                    serde_json::json!({"permguard_tenant": "other"}),
                ),
                None,
                "signature",
            ),
            (good.clone(), Some(NOW), "rollback"),
            (good.clone(), Some(NOW + 5), "rollback"),
            (
                token(&pair, "statuslist+jwt", NOW - 7_200, serde_json::json!({})),
                None,
                "expired",
            ),
            ("x".repeat(MAX_LIST_TOKEN_BYTES + 1), None, "size"),
        ] {
            let refused =
                verify_list(&offered, &keys, ISSUER, "default", held, NOW).expect_err("refused");
            assert_eq!(refused.signal(), reason, "{refused}");
        }
    }

    /// The held list is replaced only by a fresher one, kept on the volume, and restored at start
    /// verified again; an expired or unverifiable kept file is dropped.
    #[test]
    fn a_held_list_is_replaced_by_a_fresher_one_kept_and_restored() {
        let root = std::env::temp_dir().join(format!(
            "pg-token-status-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch directory");
        let dir = || crate::storage::Dir::open(&root).expect("the directory");
        let pair = pair(1);
        let keys = pinned(&pair);
        let verify = |token: &str| verify_list(token, &keys, ISSUER, "default", None, NOW);
        let lists = HeldLists::kept_in(dir());
        let first = verify(&token(
            &pair,
            "statuslist+jwt",
            NOW - 10,
            serde_json::json!({}),
        ))
        .expect("verified");
        lists.accept(first.clone()).expect("held");
        assert!(matches!(
            lists.accept(first),
            Err(ListRefusal::Rollback { .. })
        ));
        let fresher =
            verify(&token(&pair, "statuslist+jwt", NOW, serde_json::json!({}))).expect("verified");
        lists.accept(fresher).expect("replaced");
        assert_eq!(lists.iat_of(URI), Some(NOW));
        // A file nobody signed beside it is dropped at restore.
        std::fs::write(root.join("forged.jwt"), b"not.a.token").expect("written");
        let restored = HeldLists::kept_in(dir());
        assert_eq!(restored.restore(|token| verify(token).ok()), 1);
        assert_eq!(restored.iat_of(URI), Some(NOW));
        assert!(!root.join("forged.jwt").exists());
        // Verified again later, past its expiry: dropped.
        let late = HeldLists::kept_in(dir());
        assert_eq!(
            late.restore(|token| {
                verify_list(token, &keys, ISSUER, "default", None, NOW + 7_200).ok()
            }),
            0
        );
    }

    #[test]
    fn the_requests_and_answers_read_back_and_nothing_else_does() {
        for request in [Request::Index, Request::List("abc".to_owned())] {
            assert_eq!(
                Request::decode(&request.encode().expect("encodes")).expect("decodes"),
                request
            );
        }
        assert!(Request::decode(&cbor::encode(&Value::Map(vec![])).expect("encodes")).is_err());
        let ids = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(
            decode_index(&encode_index(&ids).expect("encodes")).expect("decodes"),
            ids
        );
        assert_eq!(
            decode_list(&encode_list("t.o.k").expect("encodes")).expect("decodes"),
            "t.o.k"
        );
        assert!(decode_list(&encode_index(&ids).expect("encodes")).is_err());
    }
}
