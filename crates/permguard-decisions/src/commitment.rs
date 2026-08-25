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

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::jcs::{self, CanonicalError};

/// The domain input commitments live in.
pub const COMMITMENT_DOMAIN: &str = "permguard.input.v1\n";

/// The algorithm, as it is declared in a marker.
pub const COMMITMENT_ALGORITHM: &str = "HMAC-SHA256";

/// The commitment key, and which version of it.
///
/// Holding the key material here rather than reaching for the secret store on
/// every decision is deliberate: the decision path may not do I/O.
pub struct Commitment {
    key: Vec<u8>,
    version: String,
}

impl Commitment {
    /// Builds a commitment scheme from key material and its version.
    pub fn new(key: impl Into<Vec<u8>>, version: impl Into<String>) -> Self {
        Self {
            key: key.into(),
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
        let canonical = jcs::canonicalize(value)?;
        // HMAC accepts a key of any length, so this cannot fail for a real key.
        let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(&self.key) else {
            return Ok(format!("hmac-sha256:{}:unavailable", self.version));
        };
        mac.update(COMMITMENT_DOMAIN.as_bytes());
        mac.update(&canonical);

        let mut rendered = format!("hmac-sha256:{}:", self.version);
        for byte in mac.finalize().into_bytes() {
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
            format!("{:x}", Sha256::digest(br#""HR""#))
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
}
