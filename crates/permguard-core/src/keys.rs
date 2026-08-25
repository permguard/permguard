// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signing keys Permguard publishes, and the lifecycle that lets them change without an outage.
//!
//! # Why a key cannot simply be replaced
//!
//! A verifier fetches the key set, caches it, and verifies what it is given against what it cached.
//! Swapping the signing key in one step therefore breaks everything holding a cache: the new
//! signatures name a key nobody has yet, and every verifier fails until it happens to refetch.
//!
//! The fix is to make the change take time on purpose. A key is **published** before it is used, so
//! every verifier has had a chance to see it while nothing depends on it. Only after that window
//! does it become **active** and start signing. The key it replaces becomes **retired** — still
//! published, so signatures made under it yesterday still verify, and no longer signing.
//!
//! ```text
//!            publish_ahead              rotate_every                 retain
//!   created ─────────────▶ signing ──────────────────▶ verifying ──────────▶ forgotten
//!   published              active                      retired
//! ```
//!
//! Three settings, three questions, and each is a real decision a deployment has to make: how long a
//! verifier may cache (`publish_ahead`), how long a key may sign (`rotate_every`), and how far back
//! a signature must still verify (`retain`).
//!
//! # What this crate does and does not decide
//!
//! It decides the shape: the states, the published form, and what a manager is asked. It decides no
//! algorithm and holds no key material — an implementation does that, and a build that keeps its
//! keys in an HSM implements the same contract without anything here changing.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::KeyError;

/// What a key manager answers with.
pub type Result<T> = std::result::Result<T, KeyError>;

/// How long a client is told it may cache the published key set.
///
/// It lives here rather than beside the endpoint that serves it because it is half of a pair: this
/// is how stale a verifier's copy may be, and `publish_ahead` is how long a key waits before anything
/// depends on it. A deployment whose `publish_ahead` is shorter than this has verifiers rejecting
/// good signatures for the difference — so the configuration refuses it rather than the operator
/// discovering it at the first rotation.
pub const KEY_SET_MAX_AGE: Duration = Duration::from_secs(300);

/// Where a key is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    /// In the key set, not signing yet. It exists so caches can learn it before anything depends on it.
    Published,
    /// Signing. Exactly one key is ever in this state.
    Active,
    /// In the key set, no longer signing. What makes yesterday's signatures still verify.
    Retired,
    /// In the key set for verification only: the private half has been deleted, so it can never sign
    /// again, but the public half stays published for as long as anything it signed must still verify.
    /// This is what lets a signature — an audit seal — keep verifying long after the key that made it
    /// stopped signing, without keeping the private half on disk that whole time.
    Archived,
}

impl KeyState {
    /// Returns the name this state is written as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Archived => "archived",
        }
    }

    /// Reports whether a key in this state appears in the published key set.
    ///
    /// All of them do, and that is the point of the design rather than an accident of it: a verifier
    /// must be able to find a key before it is used, while it is used, and after it stops being used —
    /// right up until nothing it signed is expected to verify any longer.
    pub fn is_published(&self) -> bool {
        true
    }
}

impl fmt::Display for KeyState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The name a signature carries so a verifier can find the key that made it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Names a key.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One public key in the form a client fetches it, as RFC 7517 defines it.
///
/// Only the public half is ever expressed here, and the type has no constructor that could carry the
/// other half by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Which key this is, matching the `kid` a signature names.
    pub kid: String,
    /// The key type — `OKP` for the Edwards curves, `EC` for the NIST ones.
    pub kty: String,
    /// The curve, when the key type has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// The public key itself, base64url without padding.
    pub x: String,
    /// The second coordinate, for the key types that have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// The algorithm this key is used with.
    pub alg: String,
    /// What the key is for. Always `sig` here: nothing Permguard publishes is an encryption key.
    #[serde(rename = "use")]
    pub usage: String,
}

impl Jwk {
    /// Describes an Edwards-curve public key.
    pub fn okp(kid: impl Into<String>, curve: &str, algorithm: &str, x: impl Into<String>) -> Self {
        Self {
            kid: kid.into(),
            kty: "OKP".to_owned(),
            crv: Some(curve.to_owned()),
            x: x.into(),
            y: None,
            alg: algorithm.to_owned(),
            usage: "sig".to_owned(),
        }
    }

    /// An elliptic-curve public key, the shape a NIST curve is published in.
    pub fn ec(
        kid: impl Into<String>,
        curve: &str,
        algorithm: &str,
        x: impl Into<String>,
        y: impl Into<String>,
    ) -> Self {
        Self {
            kid: kid.into(),
            kty: "EC".to_owned(),
            crv: Some(curve.to_owned()),
            x: x.into(),
            y: Some(y.into()),
            alg: algorithm.to_owned(),
            usage: "sig".to_owned(),
        }
    }
}

/// The document served at the key-set endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    /// Every key a client may need, in no particular order.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Builds the document out of the keys a manager published.
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }
}

/// A signature, and the name of the key a verifier needs to check it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    key_id: KeyId,
    algorithm: String,
    bytes: Vec<u8>,
}

impl Signature {
    /// Records a signature made under `key_id`.
    pub fn new(key_id: KeyId, algorithm: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            key_id,
            algorithm: algorithm.into(),
            bytes,
        }
    }

    /// Returns the key that made it.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Returns the algorithm it was made with.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the signature itself.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// What one pass of the lifecycle actually did, so it can be logged rather than guessed at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Maintenance {
    /// Keys created and put in the key set, not yet signing.
    pub published: usize,
    /// Keys that started signing.
    pub activated: usize,
    /// Keys that stopped signing and stayed in the key set.
    pub retired: usize,
    /// Keys whose private half was deleted, their public half kept in the key set for verification.
    pub archived: usize,
    /// Keys dropped from the key set because nothing they signed is still expected to verify.
    pub forgotten: usize,
}

impl Maintenance {
    /// Reports whether anything changed, which is what decides between a record and silence.
    pub fn is_empty(&self) -> bool {
        self.published == 0
            && self.activated == 0
            && self.retired == 0
            && self.archived == 0
            && self.forgotten == 0
    }
}

/// The keys a deployment signs with and publishes.
///
/// Implementations are shared across tasks, so they are `Send + Sync` and take `&self`.
pub trait KeyManager: Send + Sync {
    /// Returns the name of this implementation, for banners and diagnostics.
    fn name(&self) -> &'static str;

    /// Returns every key a client may need to verify with.
    ///
    /// Published, active and retired together — see the module documentation for why all three.
    fn public_keys(&self) -> Result<Vec<Jwk>>;

    /// Returns the key currently signing.
    ///
    /// Fails rather than inventing one: a deployment whose keys are not ready must refuse to sign,
    /// not sign under something nobody published.
    fn active_key_id(&self) -> Result<KeyId>;

    /// Signs `payload` under the active key.
    fn sign(&self, payload: &[u8]) -> Result<Signature>;

    /// Moves every key that is due to its next state, creating and forgetting keys as the policy says.
    ///
    /// Called at startup and on a timer. It is idempotent: calling it twice in a row does nothing the
    /// second time, which is what makes it safe to call from both.
    fn maintain(&self) -> Result<Maintenance>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_a_published_key_serialises_as_the_rfc_spells_it() {
        let jwk = Jwk::okp("2026-08-09", "Ed25519", "EdDSA", "AAAA");

        let value = serde_norway::to_value(&jwk).expect("it serialises");
        let published = value.as_mapping().expect("a key is a mapping");
        let field = |name: &str| published.get(name).and_then(serde_norway::Value::as_str);

        assert_eq!(field("kty"), Some("OKP"));
        assert_eq!(field("crv"), Some("Ed25519"));
        assert_eq!(field("alg"), Some("EdDSA"));
        assert_eq!(field("use"), Some("sig"));
        assert_eq!(field("kid"), Some("2026-08-09"));
        // A key type without a second coordinate must not publish a null one: a verifier that reads
        // `y` as present-and-empty is a verifier that fails on a key it could have used.
        assert!(published.get("y").is_none());
    }

    #[test]
    fn test_a_published_key_reads_back_as_what_was_published() {
        let jwk = Jwk::okp("k1", "Ed25519", "EdDSA", "AAAA");

        let written = serde_norway::to_string(&JwkSet::new(vec![jwk.clone()])).expect("written");
        let read: JwkSet = serde_norway::from_str(&written).expect("read back");

        assert_eq!(read.keys, vec![jwk]);
    }

    #[test]
    fn test_every_state_stays_in_the_key_set() {
        for state in [KeyState::Published, KeyState::Active, KeyState::Retired] {
            assert!(
                state.is_published(),
                "{state} disappeared from the key set, which breaks either new or old signatures"
            );
        }
    }

    #[test]
    fn test_a_pass_that_changed_nothing_says_so() {
        assert!(Maintenance::default().is_empty());
        assert!(
            !Maintenance {
                activated: 1,
                ..Maintenance::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn test_a_signature_names_the_key_that_made_it() {
        let signature = Signature::new(KeyId::new("k1"), "EdDSA", vec![1, 2, 3]);

        assert_eq!(signature.key_id().as_str(), "k1");
        assert_eq!(signature.algorithm(), "EdDSA");
        assert_eq!(signature.bytes(), &[1, 2, 3]);
    }
}
