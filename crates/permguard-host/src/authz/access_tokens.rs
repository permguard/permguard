// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The access token verifier (`2-security/8` Verifying a token): the Authority Plane's `at+jwt`
//! checked with nothing but what the Host holds, in the spec's order, the first failing step
//! answering.
//!
//! | #   | Check                                                                               |
//! | --- | ----------------------------------------------------------------------------------- |
//! | 1   | a compact JWS of at most 8 KiB, strictly decoded                                    |
//! | 2   | `typ` `at+jwt`; `alg` the suite of `kid`; `kid` in the held `authority.tokens` set  |
//! | 3   | the signature verifies                                                              |
//! | 4   | `iss` the issuer, `aud` the audience, `sub` a `sa:` principal, `permguard_scopes` read |
//! | 5   | `nbf` and `iat` not in the future, `exp` not passed, within 60 s of skew            |
//! | 6   | `status` present; the held list current; the index in range and `VALID`            |
//!
//! Step 7, the route's operation on its resource within the token's scopes, is the
//! authorization's: the verified token becomes an actor carrying its grant.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_core::authz::{MAX_TOKEN_SCOPES, Principal, Selector, TokenGrant, TokenScope};

use super::status_lists::{HeldList, HeldLists, PinnedKey};

/// The most bytes an access token takes, checked before it is split.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// The clock skew a token's times are judged within.
pub const CLOCK_SKEW: u64 = 60;
/// A list's status for a token that may be used.
const VALID: u8 = 0;
/// The only principal form a token's `sub` takes in the community edition.
pub const SUBJECT_PREFIX: &str = "sa:";

/// What a Host trusts tokens from: the one Authority Plane of its cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The Authority Plane's issuer URL, as `iss` names it.
    pub issuer: String,
    /// The cluster's audience, as `aud` must name it.
    pub audience: String,
    /// The held `authority.tokens` set: the current keys, and those retiring while they overlap.
    pub keys: Vec<PinnedKey>,
}

/// Where a token's status is read: the lists the Host holds, by issuer and `uri`.
pub trait StatusLists: Send + Sync {
    fn list(&self, issuer: &str, uri: &str) -> Option<Arc<HeldList>>;
}

impl StatusLists for HeldLists {
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
    /// The access key it was obtained with, `client_id`.
    pub client_id: String,
    pub grant: TokenGrant,
}

/// Whether `token` reads as a compact JWS whose header says `at+jwt`.
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

/// The claims a token carries, read without verifying anything: what a client shows of the token
/// it holds, never what a Plane decides by. `None` for anything that is not a compact JWS of at
/// most [`MAX_TOKEN_BYTES`] whose payload is an object.
pub fn claims_of(token: &str) -> Option<serde_json::Value> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let payload = token.trim().split('.').nth(1)?;
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    claims.is_object().then_some(claims)
}

/// The `kid` a token's header names, read without verifying anything: what tells a Host that the
/// Authority Plane rotated to a key it does not hold yet.
pub fn key_id_of(token: &str) -> Option<String> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let header = token.split('.').next()?;
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    header.get("kid")?.as_str().map(str::to_owned)
}

/// Reads `permguard_scopes`: at most [`MAX_TOKEN_SCOPES`] entries, each operations on a selector.
/// An operation outside the registry is kept: it matches no route, so it allows nothing.
pub fn scopes_of(value: Option<&serde_json::Value>) -> Option<Vec<TokenScope>> {
    let entries = value?.as_array()?;
    if entries.is_empty() || entries.len() > MAX_TOKEN_SCOPES {
        return None;
    }
    entries
        .iter()
        .map(|entry| {
            let entry = entry.as_object()?;
            if entry
                .keys()
                .any(|key| key != "operations" && key != "selector")
            {
                return None;
            }
            let operations: BTreeSet<String> = entry
                .get("operations")?
                .as_array()?
                .iter()
                .map(|operation| operation.as_str().map(str::to_owned))
                .collect::<Option<_>>()?;
            if operations.is_empty() {
                return None;
            }
            let selector = Selector::parse(entry.get("selector")?.as_str()?).ok()?;
            Some(TokenScope {
                operations,
                selector,
            })
        })
        .collect()
}

/// Verifies `token` in the order of `2-security/8` Verifying a token, under `anchor`, its status
/// read from `lists`.
pub fn verify(
    token: &str,
    anchor: &Anchor,
    lists: &dyn StatusLists,
    now: u64,
) -> Result<Verified, Refused> {
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
    // 2. Type and key.
    if text(&header, "typ").as_deref() != Some(permguard_core::domains::jwt::ACCESS_TOKEN) {
        return Err(refused(2, "not an at+jwt"));
    }
    let (alg, kid) = (text(&header, "alg"), text(&header, "kid"));
    let key = anchor
        .keys
        .iter()
        .find(|key| {
            Some(key.kid.as_str()) == kid.as_deref() && Some(key.algorithm) == alg.as_deref()
        })
        .ok_or_else(|| refused(2, "its key is not in the held authority.tokens set"))?;
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
    // 4. Issuer, audience, subject and scopes.
    if text(&claims, "iss").as_deref() != Some(anchor.issuer.as_str()) {
        return Err(refused(4, "another issuer"));
    }
    let addressed = match claims.get("aud") {
        Some(serde_json::Value::String(one)) => *one == anchor.audience,
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .any(|one| one.as_str() == Some(anchor.audience.as_str())),
        _ => false,
    };
    if !addressed {
        return Err(refused(4, "another audience"));
    }
    let subject = text(&claims, "sub")
        .filter(|sub| sub.starts_with(SUBJECT_PREFIX))
        .and_then(|sub| Principal::new(sub).ok())
        .ok_or_else(|| refused(4, "no service account as its subject"))?;
    let scopes = scopes_of(claims.get("permguard_scopes"))
        .ok_or_else(|| refused(4, "its permguard_scopes do not read"))?;
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
    // 6. Status, from the list the issuer signed for its uri.
    let status = claims
        .get("status")
        .and_then(|status| status.get("status_list"))
        .ok_or_else(|| refused(6, "no status"))?;
    let (Some(uri), Some(index)) = (
        status.get("uri").and_then(serde_json::Value::as_str),
        status.get("idx").and_then(serde_json::Value::as_u64),
    ) else {
        return Err(refused(6, "the status names no list or index"));
    };
    let list = lists
        .list(&anchor.issuer, uri)
        .ok_or_else(|| refused(6, "no list of that issuer and uri is held"))?;
    if list.exp <= now {
        return Err(refused(6, "the held list has expired"));
    }
    let entry = usize::try_from(index)
        .ok()
        .and_then(|index| list.list.get(index).ok())
        .ok_or_else(|| refused(6, "the index is out of the list's range"))?;
    if entry != VALID {
        return Err(refused(6, "revoked or suspended"));
    }
    Ok(Verified {
        subject,
        client_id: text(&claims, "client_id").unwrap_or_default(),
        grant: TokenGrant {
            scopes,
            jti: text(&claims, "jti").unwrap_or_default(),
            list_uri: uri.to_owned(),
            list_iat: list.iat,
            list_digest: list.digest,
        },
    })
}

/// What a Host trusts access tokens from and reads their status in.
pub trait Trust: Send + Sync {
    /// The anchor in force now; none while no key set is held, every token then refused.
    fn anchor(&self) -> Option<Anchor>;
    /// The lists the status is read from.
    fn lists(&self) -> &dyn StatusLists;
    /// A token named a key the held set lacks: the Authority Plane may have rotated, so the set is
    /// fetched again, at most once a minute (`2-security/8` Keys and lists on a Plane).
    fn unknown_key(&self, _kid: &str) {}
}

/// The Host's authenticator: a bearer is an access token of the Authority Plane, verified here,
/// the request acting within its grant, `401` when it fails, never handed on; a request without
/// one is the inner authenticator's, which knows the bootstrap certificate.
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
        let Some(token) = bearer else {
            return self.inner.authenticate(peer, None);
        };
        let outcome = match self.trust.anchor() {
            Some(anchor) => verify(token, &anchor, self.trust.lists(), self.time.now_secs())
                .inspect_err(|refused| {
                    if refused.step == 2
                        && let Some(kid) = key_id_of(token)
                    {
                        self.trust.unknown_key(&kid);
                    }
                }),
            None => Err(refused(2, "no key set of the Authority Plane is held yet")),
        };
        match outcome {
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
    use permguard_core::authz::{Actor, Authenticator as _, Resource, operations};
    use permguard_objects::status_list::StatusList;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde_json::json;

    const ISSUER: &str = "https://authority.example:8443";
    const URI: &str = "https://authority.example:8443/authority/v1/status-lists/0198f2aa-0000-7000-8000-000000000003";
    const NOW: u64 = 1_800_000_000;

    fn pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[5; 32]).expect("a key")
    }

    fn anchor(pair: &Ed25519KeyPair) -> Anchor {
        Anchor {
            issuer: ISSUER.to_owned(),
            audience: "permguard".to_owned(),
            keys: vec![PinnedKey {
                kid: "authority.tokens:k1".to_owned(),
                algorithm: "EdDSA",
                public_key: pair.public_key().as_ref().to_vec(),
            }],
        }
    }

    /// The issuer's list holding entry 1 revoked and entry 2 suspended, `exp` as given.
    fn list_of(exp: u64) -> HeldList {
        let mut list = StatusList::new(2, permguard_objects::status_list::ENTRIES).expect("a list");
        list.set(1, 1).expect("revoked");
        list.set(2, 2).expect("suspended");
        HeldList {
            issuer: ISSUER.to_owned(),
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
        lists.accept(list_of(exp)).expect("held");
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
            "iss": ISSUER, "sub": "sa:billing", "client_id": "pgak_AAAAAAAAAAAAAAAAAAAA",
            "aud": "permguard", "scope": "decision.evaluate",
            "permguard_scopes": [
                {"operations": ["decision.evaluate"], "selector": "plane/data/zone/billing/*"}
            ],
            "iat": NOW, "nbf": NOW, "exp": NOW + 3_600, "jti": "j",
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
        json!({"alg": "EdDSA", "kid": "authority.tokens:k1", "typ": "at+jwt"})
    }

    /// A token of the Authority Plane, for the cluster's audience, current and `VALID`, becomes
    /// its subject acting within its scopes, the list version with it.
    #[test]
    fn a_valid_token_verifies_into_its_scopes() {
        let pair = pair();
        let token = sign(&pair, header(), claims(json!({})));
        assert!(is_access_token(&token));
        assert_eq!(
            claims_of(&token).and_then(|claims| claims["sub"].as_str().map(str::to_owned)),
            Some("sa:billing".to_owned())
        );
        assert_eq!(claims_of("not.a.token"), None);
        assert_eq!(claims_of(&"x".repeat(MAX_TOKEN_BYTES + 1)), None);
        assert_eq!(key_id_of(&token).as_deref(), Some("authority.tokens:k1"));
        let verified = verify(&token, &anchor(&pair), &lists(NOW + 60), NOW).expect("verified");
        assert_eq!(verified.subject.as_str(), "sa:billing");
        assert_eq!(verified.client_id, "pgak_AAAAAAAAAAAAAAAAAAAA");
        let billing = Resource::ledger("data", "billing", "l1");
        assert!(
            verified
                .grant
                .permits(operations::DECISION_EVALUATE, &billing)
        );
        assert!(!verified.grant.permits(
            operations::DECISION_EVALUATE,
            &Resource::ledger("data", "payroll", "l1")
        ));
        assert!(!verified.grant.permits(operations::EVENT_SUBMIT, &billing));
        assert_eq!(
            (verified.grant.list_iat, verified.grant.list_digest),
            (NOW - 10, [7; 32])
        );
        // An audience given as an array names it too.
        let token = sign(
            &pair,
            header(),
            claims(json!({"aud": ["other", "permguard"]})),
        );
        verify(&token, &anchor(&pair), &lists(NOW + 60), NOW).expect("addressed");
    }

    #[test]
    fn every_step_refuses_what_it_checks() {
        let pair = pair();
        let other = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).expect("a key");
        let held = lists(NOW + 60);
        let step = |token: &str| {
            verify(token, &anchor(&pair), &held, NOW)
                .expect_err("refused")
                .step
        };
        // 1.
        assert_eq!(step(&"a".repeat(MAX_TOKEN_BYTES + 1)), 1);
        assert_eq!(step("a.b"), 1);
        assert_eq!(step("a.b.c.d"), 1);
        // 2.
        let jwt = json!({"alg": "EdDSA", "kid": "authority.tokens:k1", "typ": "JWT"});
        assert_eq!(step(&sign(&pair, jwt, claims(json!({})))), 2);
        let unknown = json!({"alg": "EdDSA", "kid": "authority.tokens:k9", "typ": "at+jwt"});
        assert_eq!(step(&sign(&pair, unknown, claims(json!({})))), 2);
        let es256 = json!({"alg": "ES256", "kid": "authority.tokens:k1", "typ": "at+jwt"});
        assert_eq!(step(&sign(&pair, es256, claims(json!({})))), 2);
        // 3.
        assert_eq!(step(&sign(&other, header(), claims(json!({})))), 3);
        // 4.
        for changes in [
            json!({"iss": "https://another.example"}),
            json!({"aud": "another"}),
            json!({"aud": null}),
            json!({"sub": "user:alice"}),
            json!({"sub": null}),
            json!({"permguard_scopes": null}),
            json!({"permguard_scopes": []}),
            json!({"permguard_scopes": [{"operations": [], "selector": "plane/data/*"}]}),
            json!({"permguard_scopes": [{"operations": ["x"], "selector": "nowhere/*"}]}),
            json!({"permguard_scopes": [{"operations": ["x"], "selector": "host", "y": 1}]}),
        ] {
            assert_eq!(
                step(&sign(&pair, header(), claims(changes.clone()))),
                4,
                "{changes}"
            );
        }
        let many: Vec<serde_json::Value> = (0..=MAX_TOKEN_SCOPES)
            .map(|_| json!({"operations": ["x"], "selector": "host"}))
            .collect();
        assert_eq!(
            step(&sign(
                &pair,
                header(),
                claims(json!({ "permguard_scopes": many }))
            )),
            4
        );
        // 5.
        for changes in [
            json!({"exp": NOW - CLOCK_SKEW}),
            json!({"nbf": NOW + CLOCK_SKEW + 1}),
            json!({"iat": NOW + CLOCK_SKEW + 1}),
            json!({"exp": null}),
            json!({"iat": "now"}),
        ] {
            assert_eq!(
                step(&sign(&pair, header(), claims(changes.clone()))),
                5,
                "{changes}"
            );
        }
        // 6.
        for (changes, why) in [
            (json!({"status": null}), "no status"),
            (
                json!({"status": {"status_list": {"idx": 1, "uri": URI}}}),
                "revoked",
            ),
            (
                json!({"status": {"status_list": {"idx": 2, "uri": URI}}}),
                "suspended",
            ),
            (
                json!({"status": {"status_list": {"idx": 0, "uri": "https://x/other"}}}),
                "no such list",
            ),
            (
                json!({"status": {"status_list": {"idx": 1_u64 << 21, "uri": URI}}}),
                "out of range",
            ),
        ] {
            assert_eq!(step(&sign(&pair, header(), claims(changes))), 6, "{why}");
        }
        let expired = lists(NOW);
        assert_eq!(
            verify(
                &sign(&pair, header(), claims(json!({}))),
                &anchor(&pair),
                &expired,
                NOW
            )
            .expect_err("an expired list")
            .step,
            6
        );
    }

    struct Fixed(Option<Anchor>, HeldLists, std::sync::Mutex<Vec<String>>);

    impl Trust for Fixed {
        fn anchor(&self) -> Option<Anchor> {
            self.0.clone()
        }

        fn lists(&self) -> &dyn StatusLists {
            &self.1
        }

        fn unknown_key(&self, kid: &str) {
            self.2.lock().expect("held").push(kid.to_owned());
        }
    }

    struct Inner;

    impl permguard_core::authz::Authenticator for Inner {
        fn authenticate(
            &self,
            _peer: Option<&permguard_core::PeerIdentity>,
            bearer: Option<&str>,
        ) -> Result<Actor, permguard_core::AccessDenial> {
            assert!(bearer.is_none(), "a bearer is never handed on");
            Ok(Actor::Anonymous)
        }
    }

    #[test]
    fn the_authenticator_decides_every_bearer_and_asks_for_a_key_it_lacks() {
        let pair = pair();
        let trust = Arc::new(Fixed(
            Some(anchor(&pair)),
            lists(NOW + 60),
            std::sync::Mutex::default(),
        ));
        let authenticator = TokenAuthenticator {
            trust: Arc::clone(&trust) as Arc<dyn Trust>,
            inner: Arc::new(Inner),
            time: Arc::new(crate::time::TimeGuard::fixed(NOW)),
        };
        let token = sign(&pair, header(), claims(json!({})));
        let actor = authenticator
            .authenticate(None, Some(&token))
            .expect("verified");
        assert_eq!(
            actor.principal().expect("a principal").as_str(),
            "sa:billing"
        );
        assert_eq!(
            authenticator.authenticate(None, None).expect("the inner's"),
            Actor::Anonymous
        );
        assert!(authenticator.authenticate(None, Some("opaque")).is_err());
        let rotated = sign(
            &pair,
            json!({"alg": "EdDSA", "kid": "authority.tokens:k2", "typ": "at+jwt"}),
            claims(json!({})),
        );
        assert!(authenticator.authenticate(None, Some(&rotated)).is_err());
        assert_eq!(
            *trust.2.lock().expect("held"),
            vec!["authority.tokens:k2".to_owned()]
        );
        // No key set held yet: every bearer refused.
        let empty = TokenAuthenticator {
            trust: Arc::new(Fixed(None, HeldLists::in_memory(), Default::default())),
            inner: Arc::new(Inner),
            time: Arc::new(crate::time::TimeGuard::fixed(NOW)),
        };
        assert!(empty.authenticate(None, Some(&token)).is_err());
    }
}
