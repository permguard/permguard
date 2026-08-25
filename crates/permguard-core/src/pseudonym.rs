// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Turning an identifier into something you can correlate but not read.
//!
//! Masking hides a person and loses the trail with them: two masked records are indistinguishable, so
//! "what did this account do" stops being answerable. A pseudonym keeps the trail and drops the
//! identity — the same input always yields the same token, and the token reveals nothing.
//!
//! Three properties make that true, and all three are part of the contract:
//!
//! * **Keyed.** A plain hash of an email is reversible with a dictionary in an afternoon; there are
//!   only so many plausible addresses. The secret has to be a key, not the cost of the computation.
//! * **Versioned.** Every token names the key that produced it. Without that, the first rotation makes
//!   two tokens for the same person indistinguishable from two different people, and nobody can answer
//!   "is this record about X?" because nobody knows which key to recompute with.
//! * **Rotatable.** Rotation severs correlation across the boundary — which is the point, because
//!   destroying a key is how records under it stop being attributable. It also means rotation cadence
//!   and audit retention are one decision, not two.
//!
//! A pseudonym is still personal data while the key exists: it lowers risk and gives an erasure lever,
//! it does not take a deployment out of scope.

/// Produces a stable, non-reversible token for an identifier.
///
/// Implementations are shared across tasks, so they are `Send + Sync` and take `&self`.
pub trait Pseudonymizer: Send + Sync {
    /// Returns the version of the key in use, which every token it produces names.
    fn key_version(&self) -> &str;

    /// Returns the token for `value`.
    ///
    /// The same value under the same key version always yields the same token, and no token discloses
    /// the value or its length.
    fn pseudonymize(&self, value: &str) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pseudonymiser written against the contract from outside any implementation crate.
    struct StubPseudonymizer;

    impl Pseudonymizer for StubPseudonymizer {
        fn key_version(&self) -> &str {
            "v0"
        }

        fn pseudonymize(&self, value: &str) -> String {
            format!("v0:{}", value.len())
        }
    }

    #[test]
    fn test_the_contract_is_implementable_from_outside_and_usable_as_a_trait_object() {
        let pseudonymizer: Box<dyn Pseudonymizer> = Box::new(StubPseudonymizer);

        assert_eq!(pseudonymizer.key_version(), "v0");
        assert_eq!(
            pseudonymizer.pseudonymize("a@b.c"),
            pseudonymizer.pseudonymize("a@b.c")
        );
    }
}
