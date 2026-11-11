// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A test Authority Plane: one Ed25519 key and one status list, the trust a Host verifies with
//! built from them, and access tokens minted for any subject and scopes. For the tests of every
//! crate that authorizes a token, behind the `test-support` feature; never in a release build.

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_objects::status_list::{ENTRIES, StatusList};
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use super::access_tokens::{TokenAuthenticator, Trust};
use super::authority::{AuthorityTrust, DEFAULT_AUDIENCE};

/// The issuer every test token names.
pub const ISSUER: &str = "https://authority.test:8443";
const KID: &str = "authority.tokens:test";

/// A test Authority Plane.
pub struct TestAuthority {
    pair: Ed25519KeyPair,
    trust: Arc<AuthorityTrust>,
    list: std::sync::Mutex<StatusList>,
    next: AtomicU64,
    iat: AtomicU64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl Default for TestAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl TestAuthority {
    /// A fresh authority whose key set and empty list a trust already holds.
    pub fn new() -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("a key");
        let trust = Arc::new(AuthorityTrust::in_memory(Some(ISSUER), DEFAULT_AUDIENCE));
        trust
            .accept_keys(&serde_json::json!({"keys": [{
                "kid": KID, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            }]}))
            .expect("the key set is held");
        let authority = Self {
            pair,
            trust,
            list: std::sync::Mutex::new(StatusList::new(2, ENTRIES).expect("a list")),
            next: AtomicU64::new(0),
            iat: AtomicU64::new(now().saturating_sub(10)),
        };
        authority.publish();
        authority
    }

    fn sign(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = URL_SAFE_NO_PAD.encode(self.pair.sign(input.as_bytes()));
        format!("{input}.{signature}")
    }

    fn uri() -> String {
        format!("{ISSUER}/authority/v1/status-lists/0198f2aa-0000-7000-8000-000000000001")
    }

    /// Signs the list as it stands and hands it to the trust.
    fn publish(&self) {
        let lst = self
            .list
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .encode()
            .expect("encoded");
        let iat = self.iat.fetch_add(1, Ordering::SeqCst) + 1;
        let token = self.sign(
            &serde_json::json!({"alg": "EdDSA", "kid": KID, "typ": permguard_core::domains::jwt::STATUS_LIST_TOKEN}),
            &serde_json::json!({
                "iss": ISSUER, "sub": Self::uri(), "iat": iat, "exp": iat + 24 * 3_600,
                "ttl": 30, "status_list": {"bits": 2, "lst": lst},
            }),
        );
        self.trust
            .accept_list(&token, now())
            .expect("the list is held");
    }

    /// The trust a Host verifies this authority's tokens with.
    pub fn trust(&self) -> Arc<AuthorityTrust> {
        Arc::clone(&self.trust)
    }

    /// An authenticator verifying this authority's tokens in front of `inner`.
    pub fn authenticator(
        &self,
        inner: Arc<dyn permguard_core::authz::Authenticator>,
    ) -> TokenAuthenticator {
        TokenAuthenticator {
            trust: Arc::clone(&self.trust) as Arc<dyn Trust>,
            inner,
            time: Arc::new(crate::time::TimeGuard::system(
                permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
            )),
        }
    }

    /// A token for `sa:<account>` holding `scopes`, each operations on a selector; its list index
    /// beside it, for [`Self::revoke`].
    pub fn token_with_index(&self, account: &str, scopes: &[(&[&str], &str)]) -> (String, u64) {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        let issued = now();
        let scopes: Vec<serde_json::Value> = scopes
            .iter()
            .map(|(operations, selector)| {
                serde_json::json!({"operations": operations, "selector": selector})
            })
            .collect();
        let token = self.sign(
            &serde_json::json!({"alg": "EdDSA", "kid": KID, "typ": permguard_core::domains::jwt::ACCESS_TOKEN}),
            &serde_json::json!({
                "iss": ISSUER, "sub": format!("sa:{account}"), "client_id": "pgak_TESTTESTTESTTESTTEST",
                "aud": DEFAULT_AUDIENCE, "scope": "", "permguard_scopes": scopes,
                "iat": issued, "nbf": issued, "exp": issued + 3_600,
                "jti": format!("test-{index}"),
                "status": {"status_list": {"idx": index, "uri": Self::uri()}},
            }),
        );
        (token, index)
    }

    /// A token for `sa:<account>` holding `scopes`.
    pub fn token(&self, account: &str, scopes: &[(&[&str], &str)]) -> String {
        self.token_with_index(account, scopes).0
    }

    /// Revokes the token of `index`: `INVALID` in the list, the trust holding the new list.
    pub fn revoke(&self, index: u64) {
        self.list
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set(usize::try_from(index).expect("an index"), 1)
            .expect("in range");
        self.publish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_core::authz::{Actor, Authenticator as _, Resource};

    #[test]
    fn a_minted_token_verifies_until_it_is_revoked() {
        let authority = TestAuthority::new();
        let authenticator =
            authority.authenticator(Arc::new(super::super::PrincipalMapper::empty()));
        let (token, index) =
            authority.token_with_index("billing", &[(&["decision.evaluate"], "plane/data/*")]);
        let Actor::Authenticated(context) = authenticator
            .authenticate(None, Some(&token))
            .expect("verified")
        else {
            panic!("authenticated");
        };
        assert!(
            context
                .token()
                .expect("a token")
                .permits("decision.evaluate", &Resource::ledger("data", "z", "l"))
        );
        authority.revoke(index);
        assert!(authenticator.authenticate(None, Some(&token)).is_err());
    }
}
