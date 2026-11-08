// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The access token verifier of a member (iteration 02, WP-12.2, `2-security/8` On a member):
//! the IAM Host's `at+jwt` checked with nothing but what the member holds, in the spec's order,
//! the first failing step answering.
//!
//! | #   | Check                                                                              |
//! | --- | ---------------------------------------------------------------------------------- |
//! | 1   | a compact JWS of at most 8 KiB, strictly decoded                                   |
//! | 2   | `typ` `at+jwt`; `alg` the suite of `kid`; `kid` in a pinned `iam.tokens` set       |
//! | 3   | the signature verifies                                                             |
//! | 4   | `iss` and `permguard_tenant` the pinned issuer and tenant                          |
//! | 5   | `nbf` and `iat` not in the future, `exp` not passed, within 60 s of skew           |
//! | 6   | `aud` names this member or one of its groups (`*` is not served by this release)   |
//! | 7   | `status` present; the held list current; the index in range and `VALID`           |
//! | 8   | `cnf`, when present, is `x5t#S256` and matches the connection's certificate        |
//!
//! Step 9, the family, scope and target against the route, is the authorization's: the verified
//! token becomes an actor carrying its grant, which the Host's authorization decides with.
//! A member's `member_id` and groups come from its signed manifest, never from its configuration.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_core::authz::{Principal, Selector, TokenGrant};

use crate::membership::token_status::{HeldList, PinnedKey};

/// The most bytes an access token takes, checked before it is split.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// The clock skew a token's times are judged within.
pub const CLOCK_SKEW: u64 = 60;
/// A list's status for a token that may be used.
const VALID: u8 = 0;

/// What a member trusts tokens from: one IAM Host, as one membership pins it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// `urn:permguard:iam:<host_id>` of the coordinator.
    pub issuer: String,
    pub tenant: String,
    /// The pinned `iam.tokens` set: the current one, and the one retiring while it overlaps.
    pub keys: Vec<PinnedKey>,
    /// This member, `member:<member_id>`, as the manifest's record names it.
    pub member: String,
    /// `group:<name>` of each of its groups, from the same record.
    pub groups: Vec<String>,
    /// The coordinator's host id in lowercase hex without dashes, as its mirrors' directory is
    /// named: an application token reaches only ledgers mirrored from it. None on the IAM Host.
    pub authority: Option<String>,
    /// Whether an administration token must be bound to the client's certificate: `regulated`.
    pub bound_administration: bool,
}

/// Where a token's status is read: the lists the member holds, by issuer and `uri`.
pub trait StatusLists: Send + Sync {
    fn list(&self, issuer: &str, uri: &str) -> Option<Arc<HeldList>>;
}

impl StatusLists for crate::membership::token_status::HeldLists {
    fn list(&self, issuer: &str, uri: &str) -> Option<Arc<HeldList>> {
        self.get(issuer, uri)
    }
}

/// Why a token was refused: always `401 invalid_token` to the caller, which learns nothing more;
/// the step is for the log and the metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub step: u8,
    pub reason: &'static str,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "step {}: {}", self.step, self.reason)
    }
}

fn refused(step: u8, reason: &'static str) -> Refused {
    Refused { step, reason }
}

/// What a verified token says of its subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub subject: Principal,
    pub grant: TokenGrant,
}

/// The principal forms a token's `sub` may take: a service account, a local user, a provider
/// subject (`2-security/8` Principals).
const SUBJECT_FORMS: &[&str] = &["sa:", "user:", "oidc:"];

/// The claims of a compact JWS, read without verifying it: what routes a bearer, never what
/// decides it.
fn unverified_claims(token: &str) -> Option<serde_json::Value> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// Whether `token` reads as a compact JWS whose header says `at+jwt`: the first test a boundary
/// makes to send a bearer here rather than to another rule.
pub fn is_access_token(token: &str) -> bool {
    token.len() <= MAX_TOKEN_BYTES
        && token
            .split('.')
            .next()
            .and_then(|header| URL_SAFE_NO_PAD.decode(header).ok())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|header| header.get("typ")?.as_str().map(str::to_owned))
            .is_some_and(|typ| typ == permguard_core::domains::jwt::ACCESS_TOKEN)
}

/// Verifies `token` in the order of `2-security/8` On a member, under the anchor whose issuer it
/// names, its status read from `lists`, `certificate` the SHA-256 hex of the connection's client
/// certificate when there is one.
pub fn verify(
    token: &str,
    anchors: &[Anchor],
    lists: &dyn StatusLists,
    certificate: Option<&str>,
    now: u64,
) -> Result<Verified, Refused> {
    use permguard_core::authz::families;

    // 1. Shape and size.
    if token.len() > MAX_TOKEN_BYTES {
        return Err(refused(1, "larger than an access token may be"));
    }
    let mut parts = token.split('.');
    let (Some(protected), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(refused(1, "not a compact JWS"));
    };
    let decode = |part: &str| -> Option<serde_json::Value> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
    };
    let header = decode(protected).ok_or_else(|| refused(1, "the header does not read"))?;
    let claims = decode(payload).ok_or_else(|| refused(1, "the claims do not read"))?;
    if !claims.is_object() {
        return Err(refused(1, "the claims are not an object"));
    }
    let text = |value: &serde_json::Value, name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    // 2. Type and key, under the anchor of the issuer the token names. The issuer is read before
    // the signature only to choose the key set; it is checked again after it.
    if text(&header, "typ").as_deref() != Some(permguard_core::domains::jwt::ACCESS_TOKEN) {
        return Err(refused(2, "not an at+jwt"));
    }
    let issuer = text(&claims, "iss").unwrap_or_default();
    let anchor = anchors
        .iter()
        .find(|anchor| anchor.issuer == issuer)
        .ok_or_else(|| refused(2, "no pinned IAM Host issues it"))?;
    let (alg, kid) = (text(&header, "alg"), text(&header, "kid"));
    let key = anchor
        .keys
        .iter()
        .find(|key| {
            Some(key.kid.as_str()) == kid.as_deref() && Some(key.algorithm) == alg.as_deref()
        })
        .ok_or_else(|| refused(2, "its key is not in the pinned iam.tokens set"))?;
    // 3. The signature.
    let algorithm: &dyn ring::signature::VerificationAlgorithm = match key.algorithm {
        "EdDSA" => &ring::signature::ED25519,
        "ES256" => &ring::signature::ECDSA_P256_SHA256_FIXED,
        _ => return Err(refused(2, "an algorithm the set does not sign with")),
    };
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| refused(3, "the signature does not read"))?;
    ring::signature::UnparsedPublicKey::new(algorithm, &key.public_key)
        .verify(format!("{protected}.{payload}").as_bytes(), &signature)
        .map_err(|_| refused(3, "the signature does not verify"))?;
    // 4. Issuer, tenant and subject.
    if issuer != anchor.issuer
        || text(&claims, "permguard_tenant").as_deref() != Some(anchor.tenant.as_str())
    {
        return Err(refused(4, "another issuer or tenant"));
    }
    let subject = text(&claims, "sub")
        .filter(|sub| SUBJECT_FORMS.iter().any(|form| sub.starts_with(form)))
        .and_then(|sub| Principal::new(sub).ok())
        .ok_or_else(|| refused(4, "no subject of a form the IAM Host issues to"))?;
    // 5. Time, each claim an integer when present.
    let number = |name: &str| -> Result<Option<u64>, Refused> {
        match claims.get(name) {
            None => Ok(None),
            Some(value) => value
                .as_u64()
                .map(Some)
                .ok_or_else(|| refused(5, "a time that is not a number of seconds")),
        }
    };
    let (Some(iat), Some(exp)) = (number("iat")?, number("exp")?) else {
        return Err(refused(5, "no iat or exp"));
    };
    let nbf = number("nbf")?.unwrap_or(iat);
    let ahead = now.saturating_add(CLOCK_SKEW);
    if nbf > ahead || iat > ahead {
        return Err(refused(5, "not valid yet"));
    }
    if exp.saturating_add(CLOCK_SKEW) <= now {
        return Err(refused(5, "expired"));
    }
    // 6. Audience and family: this member or one of its groups, for a family it serves. `*` is
    // not served by this release (`2-security/8` Profiles): the endpoint never issues it, and a
    // member does not accept it either.
    let family = text(&claims, "permguard_family").unwrap_or_default();
    let audience: Vec<String> = match claims.get("aud") {
        Some(serde_json::Value::String(one)) => vec![one.clone()],
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .filter_map(|one| one.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    let scope: BTreeSet<String> = text(&claims, "scope")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let target_texts: Vec<&str> = claims
        .get("permguard_target")
        .and_then(serde_json::Value::as_array)
        .map(|targets| {
            targets
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect()
        })
        .unwrap_or_default();
    let mut targets = Vec::with_capacity(target_texts.len());
    for target in &target_texts {
        targets
            .push(Selector::parse(target).map_err(|_| refused(6, "a target is not a selector"))?);
    }
    if scope.is_empty() || !scope.iter().all(|op| families::serves(&family, op)) {
        return Err(refused(6, "a scope its family does not serve"));
    }
    match family.as_str() {
        families::APPLICATION => {
            let addressed = audience
                .iter()
                .any(|one| *one == anchor.member || anchor.groups.contains(one));
            if !addressed {
                return Err(refused(6, "not addressed to this member"));
            }
            if targets.is_empty()
                || targets.len() > crate::api::token_endpoint::MAX_TARGETS
                || targets
                    .iter()
                    .any(|target| target.prefix().plane_id().is_none())
            {
                return Err(refused(
                    6,
                    "an application token names its Planes' resources",
                ));
            }
        }
        families::ADMINISTRATION => {
            // Exactly this member's Host, by its own id: never a group, never another target.
            if audience != [anchor.member.clone()] {
                return Err(refused(
                    6,
                    "an administration token names exactly this member",
                ));
            }
            if target_texts != ["host"] {
                return Err(refused(
                    6,
                    "an administration token's target is its member's Host",
                ));
            }
        }
        _ => return Err(refused(6, "a family this release does not serve")),
    }
    // 7. Status, from the list this token's issuer signed for its uri.
    let status = claims
        .get("status")
        .and_then(|status| status.get("status_list"))
        .ok_or_else(|| refused(7, "no status"))?;
    let (Some(uri), Some(index)) = (
        status.get("uri").and_then(serde_json::Value::as_str),
        status.get("idx").and_then(serde_json::Value::as_u64),
    ) else {
        return Err(refused(7, "the status names no list or index"));
    };
    let list = lists
        .list(&anchor.issuer, uri)
        .ok_or_else(|| refused(7, "no list of that issuer and uri is held"))?;
    if list.exp <= now {
        return Err(refused(7, "the held list has expired"));
    }
    let entry = usize::try_from(index)
        .ok()
        .and_then(|index| list.list.get(index).ok())
        .ok_or_else(|| refused(7, "the index is out of the list's range"))?;
    if entry != VALID {
        return Err(refused(7, "revoked or suspended"));
    }
    // 8. Binding: a bound token is used only over the connection of its certificate. A
    // confirmation this member cannot check, a DPoP `jkt` among them, is refused, never ignored.
    let bound = match claims.get("cnf") {
        None => None,
        Some(cnf) => {
            let thumbprint = cnf
                .as_object()
                .filter(|members| members.len() == 1)
                .and_then(|members| members.get("x5t#S256"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| refused(8, "a confirmation this member does not check"))?;
            Some(thumbprint)
        }
    };
    if family == families::ADMINISTRATION && anchor.bound_administration && bound.is_none() {
        return Err(refused(
            8,
            "an administration token is bound under regulated",
        ));
    }
    if let Some(bound) = bound {
        let presented = certificate.and_then(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()
        });
        if presented
            .map(|digest| URL_SAFE_NO_PAD.encode(digest))
            .as_deref()
            != Some(bound)
        {
            return Err(refused(8, "bound to another certificate"));
        }
    }
    // What step 9 decides with: an application token only on ledgers its coordinator's.
    Ok(Verified {
        subject,
        grant: TokenGrant {
            family,
            scope,
            targets,
            jti: text(&claims, "jti").unwrap_or_default(),
            list_uri: uri.to_owned(),
            list_iat: list.iat,
            list_digest: list.digest,
            authority: anchor.authority.clone(),
        },
    })
}

/// What a Host trusts access tokens from and reads their status in.
pub trait Trust: Send + Sync {
    /// The anchors in force now.
    fn anchors(&self) -> Vec<Anchor>;
    /// The lists the status is read from.
    fn lists(&self) -> &dyn StatusLists;
}

/// How long the anchors a member computed from its manifests are used before they are read
/// again: a manifest revised is in force within this.
const ANCHORS_FOR: std::time::Duration = std::time::Duration::from_secs(2);

/// A member's trust: the pinned `iam.tokens` set and issuer of each active membership that grants
/// `token.status`, its own `member_id` and groups from the same manifest, and the lists it holds.
pub struct MemberTrust {
    pub store: Arc<crate::membership::Store>,
    pub lists: Arc<crate::membership::token_status::HeldLists>,
    bound_administration: bool,
    cached: std::sync::Mutex<Option<(std::time::Instant, Vec<Anchor>)>>,
}

impl MemberTrust {
    /// `bound_administration` under `regulated`: an administration token must carry `cnf`.
    pub fn new(
        store: Arc<crate::membership::Store>,
        lists: Arc<crate::membership::token_status::HeldLists>,
        bound_administration: bool,
    ) -> Self {
        Self {
            store,
            lists,
            bound_administration,
            cached: std::sync::Mutex::default(),
        }
    }

    fn computed(&self) -> Vec<Anchor> {
        use crate::membership::record::{Role, Status, TaskType};

        self.store
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
                // The current set, and the one a re-pin replaced while it is kept: a token it
                // signed stays valid until it expires.
                let statements = self.store.statements_held(&id, manifest.epoch);
                let mut current = false;
                let mut keys = Vec::new();
                for pin in manifest.ring_pins.iter().filter(|pin| {
                    pin.owner == Role::Coordinator && pin.ring == crate::keys::ring::IAM_TOKENS
                }) {
                    let Some(statement) = statements.iter().find(|statement| {
                        crate::membership::statement_matches(statement, pin).is_ok()
                    }) else {
                        continue;
                    };
                    current |= !pin.retiring;
                    keys.extend(crate::membership::token_status::pinned_keys(
                        &crate::composition::PinnedRing {
                            epoch: pin.epoch,
                            key_set_digest: pin.key_set_digest,
                            binding: pin.binding.clone(),
                            keys: statement.keys.clone(),
                        },
                    ));
                }
                if !current {
                    return None;
                }
                let host_id = manifest.coordinator.host_id;
                Some(Anchor {
                    issuer: format!(
                        "{}{}",
                        permguard_core::domains::subject::IAM_ISSUER_PREFIX,
                        crate::identity::record::uuid_text(&host_id)
                    ),
                    tenant: crate::api::tokens::TENANT.to_owned(),
                    keys,
                    member: format!(
                        "member:{}",
                        crate::identity::record::uuid_text(&manifest.member_record.member_id)
                    ),
                    groups: manifest
                        .member_record
                        .groups
                        .iter()
                        .map(|group| format!("group:{group}"))
                        .collect(),
                    authority: Some(host_id.iter().map(|byte| format!("{byte:02x}")).collect()),
                    bound_administration: self.bound_administration,
                })
            })
            .collect()
    }
}

impl Trust for MemberTrust {
    fn anchors(&self) -> Vec<Anchor> {
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, anchors)) = cached.as_ref()
            && at.elapsed() < ANCHORS_FOR
        {
            return anchors.clone();
        }
        let anchors = self.computed();
        *cached = Some((std::time::Instant::now(), anchors.clone()));
        anchors
    }

    fn lists(&self) -> &dyn StatusLists {
        self.lists.as_ref()
    }
}

/// The Host's authenticator with access tokens in front (WP-12.2): a bearer that is an `at+jwt`
/// of an IAM Host this Host pins is verified here and the request acts within its grant, `401`
/// when it fails, never handed on; every other credential is the inner authenticator's.
pub struct TokenAuthenticator {
    pub trust: Arc<dyn Trust>,
    pub inner: Arc<dyn permguard_core::authz::Authenticator>,
    pub time: Arc<crate::time::TimeGuard>,
}

impl permguard_core::authz::Authenticator for TokenAuthenticator {
    fn authenticate(
        &self,
        peer: Option<&permguard_core::PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<permguard_core::authz::Actor, permguard_core::AccessDenial> {
        // Only an `at+jwt` of an IAM Host this Host pins is decided here: a provider's own RFC 9068
        // access token stays the inner rules' to map or refuse.
        let anchors = self.trust.anchors();
        let Some(token) = bearer.filter(|token| {
            is_access_token(token)
                && unverified_claims(token)
                    .and_then(|claims| claims.get("iss")?.as_str().map(str::to_owned))
                    .is_some_and(|issuer| anchors.iter().any(|anchor| anchor.issuer == issuer))
        }) else {
            return self.inner.authenticate(peer, bearer);
        };
        match verify(
            token,
            &anchors,
            self.trust.lists(),
            peer.map(permguard_core::PeerIdentity::fingerprint),
            self.time.now_secs(),
        ) {
            Ok(verified) => Ok(permguard_core::authz::Actor::Authenticated(
                permguard_core::authz::ActorContext::of_token(verified.subject, verified.grant),
            )),
            Err(refused) => {
                tracing::info!(
                    event.name = "authz.token_refused",
                    component = "host",
                    step = refused.step,
                    reason = refused.reason,
                    "an access token was refused"
                );
                Err(permguard_core::AccessDenial::unauthenticated(
                    "the access token is not valid",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::membership::token_status::{HeldList, HeldLists};
    use permguard_core::authz::{Actor, Authenticator as _, Resource, operations};
    use permguard_objects::status_list::StatusList;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde_json::json;

    const ISSUER: &str = "urn:permguard:iam:0198f2aa-0000-7000-8000-000000000001";
    const OTHER_ISSUER: &str = "urn:permguard:iam:0198f2aa-0000-7000-8000-00000000000b";
    const MEMBER: &str = "member:0198f2aa-0000-7000-8000-000000000002";
    const URI: &str =
        "https://iam.example/iam/v1/status-lists/0198f2aa-0000-7000-8000-000000000003";
    const AUTHORITY: &str = "0198f2aa000070008000000000000001";
    const NOW: u64 = 1_800_000_000;

    fn pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[5; 32]).expect("a key")
    }

    fn anchor_of(pair: &Ed25519KeyPair, issuer: &str, member: &str) -> Anchor {
        Anchor {
            issuer: issuer.to_owned(),
            tenant: "default".to_owned(),
            keys: vec![PinnedKey {
                kid: "iam.tokens:k1".to_owned(),
                algorithm: "EdDSA",
                public_key: pair.public_key().as_ref().to_vec(),
            }],
            member: member.to_owned(),
            groups: vec!["group:eu".to_owned()],
            authority: Some(AUTHORITY.to_owned()),
            bound_administration: false,
        }
    }

    fn anchor(pair: &Ed25519KeyPair) -> Anchor {
        anchor_of(pair, ISSUER, MEMBER)
    }

    /// `issuer`'s list holding entry 1 revoked and entry 2 suspended, `exp` as given.
    fn list_of(issuer: &str, exp: u64) -> HeldList {
        let mut list = StatusList::new(2, permguard_objects::status_list::ENTRIES).expect("a list");
        list.set(1, 1).expect("revoked");
        list.set(2, 2).expect("suspended");
        HeldList {
            issuer: issuer.to_owned(),
            uri: URI.to_owned(),
            iat: NOW - 10,
            exp,
            ttl: 300,
            list,
            digest: [7; 32],
            token: String::new(),
        }
    }

    fn lists(exp: u64) -> HeldLists {
        let lists = HeldLists::in_memory();
        lists.accept(list_of(ISSUER, exp)).expect("held");
        lists
    }

    fn sign(pair: &Ed25519KeyPair, header: serde_json::Value, claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(header.to_string());
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signature = URL_SAFE_NO_PAD.encode(pair.sign(format!("{header}.{payload}").as_bytes()));
        format!("{header}.{payload}.{signature}")
    }

    fn claims(changes: serde_json::Value) -> serde_json::Value {
        let mut claims = json!({
            "iss": ISSUER, "permguard_tenant": "default", "sub": "sa:billing", "client_id": "c",
            "aud": [MEMBER], "permguard_family": "application", "scope": "decision.evaluate",
            "permguard_target": ["plane/data/zone/billing/*"], "iat": NOW, "nbf": NOW,
            "exp": NOW + 3_600, "jti": "j",
            "status": {"status_list": {"idx": 0, "uri": URI}},
        });
        for (name, value) in changes.as_object().expect("an object") {
            if value.is_null() {
                claims.as_object_mut().expect("an object").remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        claims
    }

    fn header() -> serde_json::Value {
        json!({"alg": "EdDSA", "kid": "iam.tokens:k1", "typ": "at+jwt"})
    }

    fn administration(changes: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
            "permguard_family": "administration", "scope": "keys.read backup.manage",
            "permguard_target": ["host"],
        });
        for (name, value) in changes.as_object().expect("an object") {
            base[name] = value.clone();
        }
        claims(base)
    }

    /// WP-12.2: a token of the pinned IAM Host, addressed to this member, current and `VALID`,
    /// becomes its subject acting within its grant, the list version and the coordinator with it.
    #[test]
    fn a_valid_token_verifies_into_its_grant() {
        let pair = pair();
        let token = sign(&pair, header(), claims(json!({})));
        assert!(is_access_token(&token));
        let verified =
            verify(&token, &[anchor(&pair)], &lists(NOW + 60), None, NOW).expect("verified");
        assert_eq!(verified.subject.as_str(), "sa:billing");
        assert_eq!(verified.grant.family, "application");
        assert!(verified.grant.permits(
            "decision.evaluate",
            &Resource::ledger("data", "billing", "l1")
        ));
        assert!(!verified.grant.permits(
            "decision.evaluate",
            &Resource::ledger("data", "payroll", "l1")
        ));
        assert!(
            !verified
                .grant
                .permits("event.submit", &Resource::ledger("data", "billing", "l1"))
        );
        assert_eq!(
            (verified.grant.list_iat, verified.grant.list_digest),
            (NOW - 10, [7; 32])
        );
        assert_eq!(verified.grant.authority.as_deref(), Some(AUTHORITY));
        // A group of the member addresses it too.
        let token = sign(&pair, header(), claims(json!({"aud": ["group:eu"]})));
        verify(&token, &[anchor(&pair)], &lists(NOW + 60), None, NOW).expect("addressed");
        // An administration token for exactly this member's Host.
        let token = sign(&pair, header(), administration(json!({})));
        let verified =
            verify(&token, &[anchor(&pair)], &lists(NOW + 60), None, NOW).expect("verified");
        assert!(
            verified
                .grant
                .permits(operations::KEYS_READ, &Resource::plane("data"))
        );
        // A bound token over its own certificate.
        let bound = sign(
            &pair,
            header(),
            claims(json!({"cnf": {"x5t#S256": URL_SAFE_NO_PAD.encode([1u8; 32])}})),
        );
        verify(
            &bound,
            &[anchor(&pair)],
            &lists(NOW + 60),
            Some(&"01".repeat(32)),
            NOW,
        )
        .expect("its own certificate");
    }

    /// WP-12.6, ring rotation: while a re-pin keeps the replaced `iam.tokens` set beside the
    /// current one, a token of either key verifies, so no token in flight is refused by the
    /// rotation; once the replaced pin retires, its key's tokens are refused at step 2, and a
    /// token naming the new `kid` under an old key's signature fails at step 3.
    #[test]
    fn a_rotation_keeps_the_retiring_keys_tokens_until_its_pin_retires() {
        let old = pair();
        let new = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).expect("a key");
        let key = |pair: &Ed25519KeyPair, kid: &str| PinnedKey {
            kid: kid.to_owned(),
            algorithm: "EdDSA",
            public_key: pair.public_key().as_ref().to_vec(),
        };
        let headed = |kid: &str| json!({"alg": "EdDSA", "kid": kid, "typ": "at+jwt"});
        let by_old = sign(&old, headed("iam.tokens:k1"), claims(json!({})));
        let by_new = sign(&new, headed("iam.tokens:k2"), claims(json!({})));
        let mut overlapping = anchor(&old);
        overlapping.keys = vec![key(&new, "iam.tokens:k2"), key(&old, "iam.tokens:k1")];
        let held = lists(NOW + 60);
        verify(&by_old, &[overlapping.clone()], &held, None, NOW).expect("the retiring key's");
        verify(&by_new, &[overlapping.clone()], &held, None, NOW).expect("the current key's");
        let mut retired = overlapping.clone();
        retired.keys.retain(|pinned| pinned.kid == "iam.tokens:k2");
        assert_eq!(
            verify(&by_old, &[retired.clone()], &held, None, NOW).map_err(|refused| refused.step),
            Err(2),
            "the retired key is no longer pinned"
        );
        verify(&by_new, &[retired.clone()], &held, None, NOW).expect("the current key's");
        let forged = sign(&old, headed("iam.tokens:k2"), claims(json!({})));
        assert_eq!(
            verify(&forged, &[retired], &held, None, NOW).map_err(|refused| refused.step),
            Err(3),
            "the new kid does not lend its name to the old key"
        );
    }

    /// Each step refuses what it is there for, and the first failing step answers.
    #[test]
    fn every_step_refuses_what_it_checks() {
        let pair = pair();
        let other = Ed25519KeyPair::from_seed_unchecked(&[6; 32]).expect("a key");
        let good = sign(&pair, header(), claims(json!({})));
        let mut tampered = good.clone();
        let last = tampered.pop().expect("a character");
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let with = |changes: serde_json::Value| sign(&pair, header(), claims(changes));
        let headed = |header: serde_json::Value| sign(&pair, header, claims(json!({})));
        let bound = json!({"cnf": {"x5t#S256": URL_SAFE_NO_PAD.encode([1u8; 32])}});
        let cases: Vec<(&str, String, u8, Option<String>)> = vec![
            ("oversized", "x".repeat(MAX_TOKEN_BYTES + 1), 1, None),
            ("not a JWS", "not.a".to_owned(), 1, None),
            (
                "claims not an object",
                sign(&pair, header(), json!([1])),
                1,
                None,
            ),
            (
                "typ",
                headed(json!({"alg": "EdDSA", "kid": "iam.tokens:k1", "typ": "JWT"})),
                2,
                None,
            ),
            (
                "kid",
                headed(json!({"alg": "EdDSA", "kid": "other", "typ": "at+jwt"})),
                2,
                None,
            ),
            (
                "alg of another suite",
                headed(json!({"alg": "ES256", "kid": "iam.tokens:k1", "typ": "at+jwt"})),
                2,
                None,
            ),
            (
                "issuer unpinned",
                with(json!({"iss": "urn:permguard:iam:elsewhere"})),
                2,
                None,
            ),
            (
                "another key",
                sign(&other, header(), claims(json!({}))),
                3,
                None,
            ),
            ("tampered", tampered, 3, None),
            ("tenant", with(json!({"permguard_tenant": "acme"})), 4, None),
            ("no sub", with(json!({"sub": null})), 4, None),
            (
                "sub of another form",
                with(json!({"sub": "role:admin"})),
                4,
                None,
            ),
            ("expired", with(json!({"exp": NOW - 61})), 5, None),
            ("not yet", with(json!({"nbf": NOW + 61})), 5, None),
            ("iat ahead", with(json!({"iat": NOW + 61})), 5, None),
            ("no iat", with(json!({"iat": null})), 5, None),
            ("no exp", with(json!({"exp": null})), 5, None),
            ("nbf not a number", with(json!({"nbf": "soon"})), 5, None),
            (
                "exp at the edge of u64",
                with(json!({"exp": u64::MAX, "iat": u64::MAX})),
                5,
                None,
            ),
            (
                "another member",
                with(json!({"aud": ["member:someone-else"]})),
                6,
                None,
            ),
            ("wildcard", with(json!({"aud": ["*"]})), 6, None),
            (
                "no family",
                with(json!({"permguard_family": null})),
                6,
                None,
            ),
            (
                "unknown family",
                with(json!({"permguard_family": "other"})),
                6,
                None,
            ),
            ("empty scope", with(json!({"scope": ""})), 6, None),
            (
                "scope off its family",
                with(json!({"scope": "decision.evaluate keys.read"})),
                6,
                None,
            ),
            ("no target", with(json!({"permguard_target": []})), 6, None),
            (
                "a target off the Planes",
                with(json!({"permguard_target": ["host"]})),
                6,
                None,
            ),
            (
                "a target not a selector",
                with(json!({"permguard_target": ["plane/data/x/y/z"]})),
                6,
                None,
            ),
            (
                "administration to a group",
                sign(
                    &pair,
                    header(),
                    administration(json!({"aud": ["group:eu"]})),
                ),
                6,
                None,
            ),
            (
                "administration elsewhere",
                sign(
                    &pair,
                    header(),
                    administration(json!({"permguard_target": ["plane/data/*"]})),
                ),
                6,
                None,
            ),
            (
                "administration evaluating",
                sign(
                    &pair,
                    header(),
                    administration(json!({"scope": "decision.evaluate"})),
                ),
                6,
                None,
            ),
            ("no status", with(json!({"status": null})), 7, None),
            (
                "revoked",
                with(json!({"status": {"status_list": {"idx": 1, "uri": URI}}})),
                7,
                None,
            ),
            (
                "suspended",
                with(json!({"status": {"status_list": {"idx": 2, "uri": URI}}})),
                7,
                None,
            ),
            (
                "index out of range",
                with(json!({"status": {"status_list": {"idx": 9_999_999, "uri": URI}}})),
                7,
                None,
            ),
            (
                "a list not held",
                with(json!({"status": {"status_list": {"idx": 0, "uri": "https://elsewhere/x"}}})),
                7,
                None,
            ),
            (
                "a DPoP key",
                with(json!({"cnf": {"jkt": "a-dpop-key"}})),
                8,
                None,
            ),
            (
                "cnf not a string",
                with(json!({"cnf": {"x5t#S256": 123}})),
                8,
                None,
            ),
            (
                "cnf with more",
                with(json!({"cnf": {"x5t#S256": "a", "jkt": "b"}})),
                8,
                None,
            ),
            ("bound, no certificate", with(bound.clone()), 8, None),
            (
                "bound, another certificate",
                with(bound),
                8,
                Some("02".repeat(32)),
            ),
        ];
        for (case, token, step, certificate) in cases {
            let refused = verify(
                &token,
                &[anchor(&pair)],
                &lists(NOW + 60),
                certificate.as_deref(),
                NOW,
            )
            .expect_err(case);
            assert_eq!(refused.step, step, "{case}: {refused}");
        }
        // An expired list refuses every token of it: the longest a revocation goes unseen.
        let refused = verify(&good, &[anchor(&pair)], &lists(NOW), None, NOW).expect_err("stale");
        assert_eq!(refused.step, 7);
        // Under `regulated` an administration token is bound.
        let mut regulated = anchor(&pair);
        regulated.bound_administration = true;
        let unbound = sign(&pair, header(), administration(json!({})));
        let refused = verify(&unbound, &[regulated], &lists(NOW + 60), None, NOW)
            .expect_err("unbound under regulated");
        assert_eq!(refused.step, 8);
    }

    /// The review's case: a member of two coordinators keeps their tokens and lists apart. A
    /// token of one is not addressed to the other's member id, and another issuer's list of the
    /// same `uri` neither stands for nor displaces the issuer's own.
    #[test]
    fn two_coordinators_never_stand_for_one_another() {
        let pair = pair();
        let mine = anchor(&pair);
        let theirs = anchor_of(
            &pair,
            OTHER_ISSUER,
            "member:0198f2aa-0000-7000-8000-00000000000c",
        );
        // A token of the other coordinator addressed to the member id this one knows it by.
        let crossed = sign(&pair, header(), claims(json!({"iss": OTHER_ISSUER})));
        let refused = verify(
            &crossed,
            &[mine.clone(), theirs.clone()],
            &lists(NOW + 60),
            None,
            NOW,
        )
        .expect_err("not addressed");
        assert_eq!(refused.step, 6);
        // The other coordinator's list of this `uri`, fresher and all `VALID`, is held beside it.
        let lists = lists(NOW + 60);
        let mut forged = list_of(OTHER_ISSUER, NOW + 60);
        forged.iat = NOW + 1_000;
        forged.list = StatusList::new(2, permguard_objects::status_list::ENTRIES).expect("a list");
        lists.accept(forged).expect("held as its own issuer's");
        let revoked = sign(
            &pair,
            header(),
            claims(json!({"status": {"status_list": {"idx": 1, "uri": URI}}})),
        );
        let refused = verify(&revoked, &[mine, theirs], &lists, None, NOW).expect_err("revoked");
        assert_eq!(refused.step, 7, "{refused}");
        assert_eq!(lists.iat_of(ISSUER, URI), Some(NOW - 10), "never displaced");
    }

    /// On a member the token decides alone; on the IAM Host it narrows the grants.
    #[test]
    fn a_token_decides_alone_on_a_member_and_within_the_grants_on_the_iam_host() {
        let pair = pair();
        let token = sign(&pair, header(), claims(json!({})));
        let verified =
            verify(&token, &[anchor(&pair)], &lists(NOW + 60), None, NOW).expect("verified");
        let actor = Actor::Authenticated(permguard_core::authz::ActorContext::of_token(
            verified.subject,
            verified.grant,
        ));
        let ledger = Resource::ledger("data", "billing", "l1");
        let member = super::super::Authorization::closed().with_tokens_alone(true);
        assert!(
            member
                .authorize(&actor, operations::DECISION_EVALUATE, &ledger)
                .is_ok()
        );
        assert!(
            member
                .authorize(
                    &actor,
                    operations::DECISION_EVALUATE,
                    &Resource::ledger("data", "payroll", "l1")
                )
                .is_err()
        );
        assert!(
            member
                .authorize(&actor, operations::CATALOG_READ, &ledger)
                .is_err()
        );
        assert!(
            member
                .may_act_under(
                    &actor,
                    operations::DECISION_EVALUATE,
                    &Resource::plane("data")
                )
                .is_ok()
        );
        assert!(member.covers_whole(
            &actor,
            operations::DECISION_EVALUATE,
            &Resource::zone("data", "billing")
        ));
        assert!(!member.covers_whole(
            &actor,
            operations::DECISION_EVALUATE,
            &Resource::plane("data")
        ));
        // The IAM Host holds no grant for the subject here: the token alone allows nothing.
        let iam = super::super::Authorization::closed();
        assert!(
            iam.authorize(&actor, operations::DECISION_EVALUATE, &ledger)
                .is_err()
        );
        // And a token never widens what the grants allow.
        let open = super::super::Authorization::permissive();
        assert!(
            open.authorize(&actor, operations::DECISION_EVALUATE, &ledger)
                .is_ok()
        );
        assert!(
            open.authorize(&actor, operations::CATALOG_READ, &ledger)
                .is_err()
        );
    }

    struct Fixed(Vec<Anchor>, HeldLists);

    impl Trust for Fixed {
        fn anchors(&self) -> Vec<Anchor> {
            self.0.clone()
        }

        fn lists(&self) -> &dyn StatusLists {
            &self.1
        }
    }

    /// Answers `inner` for every bearer it is handed: what reached it shows.
    struct Inner;

    impl permguard_core::authz::Authenticator for Inner {
        fn authenticate(
            &self,
            _peer: Option<&permguard_core::PeerIdentity>,
            _bearer: Option<&str>,
        ) -> Result<Actor, permguard_core::AccessDenial> {
            Ok(Actor::Unmapped {
                reason: "inner".to_owned(),
            })
        }
    }

    /// Only an `at+jwt` of a pinned issuer is decided here, and a failing one never falls through
    /// to the other rules; a provider's own access token, or any other bearer, is theirs.
    #[test]
    fn the_authenticator_decides_only_the_tokens_of_a_pinned_issuer() {
        let pair = pair();
        let authenticator = TokenAuthenticator {
            trust: Arc::new(Fixed(vec![anchor(&pair)], lists(NOW + 60))),
            inner: Arc::new(Inner),
            time: Arc::new(crate::time::TimeGuard::system(
                std::time::Duration::from_secs(30),
            )),
        };
        let inner =
            |actor: &Actor| matches!(actor, Actor::Unmapped { reason } if reason == "inner");
        // Valid now, by the system clock the guard reads.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        let good = sign(
            &pair,
            header(),
            claims(json!({"iat": now, "nbf": now, "exp": now + 600})),
        );
        let lists_now = HeldLists::in_memory();
        lists_now.accept(list_of(ISSUER, now + 600)).expect("held");
        let authenticator = TokenAuthenticator {
            trust: Arc::new(Fixed(vec![anchor(&pair)], lists_now)),
            ..authenticator
        };
        let actor = authenticator
            .authenticate(None, Some(&good))
            .expect("verified");
        assert!(matches!(&actor, Actor::Authenticated(context) if context.token().is_some()));
        // A failing token of a pinned issuer is refused here.
        let revoked = sign(
            &pair,
            header(),
            claims(json!({
                "iat": now, "nbf": now, "exp": now + 600,
                "status": {"status_list": {"idx": 1, "uri": URI}},
            })),
        );
        assert!(authenticator.authenticate(None, Some(&revoked)).is_err());
        // A provider's `at+jwt`, and an opaque bearer, are the inner rules'.
        let provider = sign(
            &pair,
            header(),
            claims(json!({"iss": "https://login.example"})),
        );
        assert!(inner(
            &authenticator
                .authenticate(None, Some(&provider))
                .expect("handed on")
        ));
        assert!(inner(
            &authenticator
                .authenticate(None, Some("opaque"))
                .expect("handed on")
        ));
    }
}
