// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Keyed commitments over caller-supplied inputs.
//!
//! # Why not a plain digest
//!
//! A bare `SHA-256` of a low-entropy value is not confidential. `department=HR`
//! has a few thousand plausible preimages and a dictionary recovers it in
//! milliseconds; the same is true of booleans, roles, small enumerations and
//! most identifiers. A decision log full of bare digests of caller attributes
//! is a decision log full of caller attributes.
//!
//! So a commitment is keyed:
//!
//! ```text
//! commitment(value) = HMAC-SHA256( key , "permguard.input.v1\n" || JCS(value) )
//! ```
//!
//! Equality within a deployment still works — which is what the commitment is
//! *for*: two decisions can be shown to have seen the same input without
//! either party keeping it. What stops working is enumeration by anyone who
//! does not hold the key.
//!
//! **What it does not promise**, stated because the difference matters: whoever
//! holds the key can confirm a guess, and the presence of a commitment for a
//! named field discloses that the field was part of the decision. The trade is
//! that commitments are not comparable across deployments, and rotating the
//! key changes them — the same crypto-shredding property the pseudonyms have,
//! and the reason the key version travels in the stream's marker.

use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::jcs::{self, CanonicalError};

/// The domain input commitments live in.
pub const COMMITMENT_DOMAIN: &str = permguard_core::domains::digest::INPUT_TAG;

/// The algorithm, as it is declared in a marker.
pub const COMMITMENT_ALGORITHM: &str = "HMAC-SHA256";

/// The commitment key, and which version of it.
///
/// Holding the key material here rather than reaching for the secret store on
/// every decision is deliberate: the decision path may not do I/O.
pub struct Commitment {
    mac: MacFn,
    version: String,
}

/// The zone and the ledger a tag is taken in, as their 16 UUID bytes: the key is the ledger's
/// (WP-3.3).
pub type Scope = ([u8; 16], [u8; 16]);

/// HMAC-SHA256 under the commitment key of a scope, over its arguments in order.
type MacFn = std::sync::Arc<dyn Fn(Option<&Scope>, &[&[u8]]) -> Option<[u8; 32]> + Send + Sync>;

impl Commitment {
    /// Builds a commitment scheme from key material and its version.
    pub fn new(key: impl Into<Vec<u8>>, version: impl Into<String>) -> Self {
        let key: Vec<u8> = key.into();
        Self::with_mac(version, move |parts: &[&[u8]]| {
            // HMAC accepts a key of any length; a refusal is rendered `unavailable`, never a tag.
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).ok()?;
            for part in parts {
                mac.update(part);
            }
            Some(mac.finalize().into_bytes().into())
        })
    }

    /// Builds a commitment scheme over an HMAC computed elsewhere — the Host's secret handle — so
    /// the key itself never reaches the code that commits.
    pub fn with_mac(
        version: impl Into<String>,
        mac: impl Fn(&[&[u8]]) -> Option<[u8; 32]> + Send + Sync + 'static,
    ) -> Self {
        Self {
            mac: std::sync::Arc::new(move |_: Option<&Scope>, parts: &[&[u8]]| mac(parts)),
            version: version.into(),
        }
    }

    /// Builds a commitment scheme whose key is chosen per scope, by a MAC computed elsewhere —
    /// the Host's zone key handle (WP-3.3). A value committed without a scope, or in a scope the
    /// handle holds no key for, is rendered `unavailable`, never tagged under another key.
    pub fn with_scoped_mac(
        version: impl Into<String>,
        mac: impl Fn(&Scope, &[&[u8]]) -> Option<[u8; 32]> + Send + Sync + 'static,
    ) -> Self {
        Self {
            mac: std::sync::Arc::new(move |scope: Option<&Scope>, parts: &[&[u8]]| {
                scope.and_then(|scope| mac(scope, parts))
            }),
            version: version.into(),
        }
    }

    /// Which version of the key this is — recorded in the governing marker.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Commits to `value`.
    ///
    /// The rendering carries the algorithm and the key version, so a reader
    /// holding two commitments can tell "different values" from "different
    /// keys" instead of concluding the first when it is the second.
    pub fn commit(&self, value: &Value) -> Result<String, CanonicalError> {
        self.commit_in(None, value)
    }

    /// Commits to `value` in `scope`: under that ledger's key for a scoped scheme.
    pub fn commit_in(
        &self,
        scope: Option<&Scope>,
        value: &Value,
    ) -> Result<String, CanonicalError> {
        let canonical = jcs::canonicalize(value)?;
        let Some(tag) = (self.mac)(scope, &[COMMITMENT_DOMAIN.as_bytes(), &canonical]) else {
            return Ok(format!("hmac-sha256:{}:unavailable", self.version));
        };

        let mut rendered = format!("hmac-sha256:{}:", self.version);
        for byte in tag {
            rendered.push_str(&format!("{byte:02x}"));
        }

        Ok(rendered)
    }
}

impl std::fmt::Debug for Commitment {
    /// Never prints the key. A commitment scheme that leaks into a log line is
    /// a commitment scheme that no longer commits.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Commitment")
            .field("version", &self.version)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn test_the_same_value_commits_the_same_way_under_one_key() {
        let scheme = Commitment::new(*b"a-key", "v1");
        let value = json!({ "department": "HR", "ip": "10.0.0.1" });

        assert_eq!(
            scheme.commit(&value).expect("it commits"),
            scheme
                .commit(&json!({ "ip": "10.0.0.1", "department": "HR" }))
                .expect("it commits"),
            "member order is not part of the value"
        );
    }

    #[test]
    fn test_a_bare_digest_of_the_same_value_is_not_the_commitment() {
        let scheme = Commitment::new(*b"a-key", "v1");
        let committed = scheme.commit(&json!("HR")).expect("it commits");

        let bare = {
            use sha2::Digest as _;
            Sha256::digest(br#""HR""#)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };

        assert!(
            !committed.ends_with(&bare),
            "an unkeyed digest is exactly what this exists to avoid"
        );
    }

    #[test]
    fn test_rotating_the_key_changes_every_commitment() {
        let value = json!("HR");
        let before = Commitment::new(*b"a-key", "v1")
            .commit(&value)
            .expect("it commits");
        let after = Commitment::new(*b"b-key", "v2")
            .commit(&value)
            .expect("it commits");

        assert_ne!(before, after, "crypto-shredding, deliberately");
    }

    #[test]
    fn test_the_rendering_says_which_key_version_produced_it() {
        let scheme = Commitment::new(*b"a-key", "v7");

        assert!(
            scheme
                .commit(&json!(1))
                .expect("it commits")
                .starts_with("hmac-sha256:v7:"),
            "a reader must tell a different value from a different key"
        );
    }

    #[test]
    fn test_the_key_never_reaches_a_debug_line() {
        let rendered = format!("{:?}", Commitment::new(*b"super-secret", "v1"));

        assert!(!rendered.contains("super-secret"), "{rendered}");
    }

    /// WP-3.3: a scoped scheme tags under the key of the scope it is given, and nothing without.
    #[test]
    fn test_a_scoped_scheme_tags_per_scope_and_never_without_one() {
        let scheme = Commitment::with_scoped_mac("v1", |(zone, ledger), parts| {
            let mut key = zone.to_vec();
            key.extend_from_slice(ledger);
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).ok()?;
            for part in parts {
                mac.update(part);
            }
            Some(mac.finalize().into_bytes().into())
        });
        let value = json!("HR");
        let one = scheme
            .commit_in(Some(&([1; 16], [2; 16])), &value)
            .expect("it commits");
        let other = scheme
            .commit_in(Some(&([1; 16], [3; 16])), &value)
            .expect("it commits");
        assert_ne!(one, other, "another ledger, another key");
        assert!(one.starts_with("hmac-sha256:v1:") && !one.ends_with("unavailable"));
        assert_eq!(
            scheme.commit(&value).expect("it commits"),
            "hmac-sha256:v1:unavailable",
            "no scope, no tag"
        );
    }
}
