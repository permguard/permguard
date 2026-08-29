// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Keyed, versioned pseudonyms for audit subjects.
//!
//! The token is `HMAC-SHA256(key, value)`, truncated to 128 bits, hex encoded, and prefixed with the
//! version of the key that produced it:
//!
//! ```text
//! v1:3f9a0c2e5b71d84a6c0f1e2d3a4b5c6d
//! ```
//!
//! **Keyed, not hashed.** A plain digest of an email is reversible with a dictionary — there are only
//! so many plausible addresses — so the secret has to be the key rather than the cost of computing.
//!
//! **Truncated on purpose.** 128 bits of a MAC is far beyond what a collision would need to be
//! implausible here, and a token that fits on a line is a token an operator will actually read.
//!
//! **Rotation is manual and deliberate.** Changing the key changes every token, which is exactly what
//! makes rotation an erasure lever: records written under a destroyed key stop being attributable. It
//! is also why nothing here rotates on its own — cadence belongs to the deployment's retention policy,
//! and the version in the prefix is what lets a later question find the right key.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use permguard_core::Pseudonymizer;

/// The number of MAC bytes a token keeps.
const TOKEN_BYTES: usize = 16;

/// Derives pseudonyms with HMAC-SHA256 under a named key version.
///
/// The key is held in a buffer that is erased when this is dropped. It is the same reduction —
/// and the same limits — as [`Secret`](permguard_core::Secret): it shortens the window in which the key
/// sits in a core dump to the time the process actually needed it, and claims nothing about copies
/// the allocator or the kernel may already have made.
pub struct HmacPseudonymizer {
    key: Zeroizing<Vec<u8>>,
    key_version: String,
}

impl HmacPseudonymizer {
    /// Builds a pseudonymiser over `key`, whose tokens name `key_version`.
    ///
    /// Nothing here validates the key: what counts as long enough is a question about the material,
    /// and it is answered where the material is resolved — before a build ever gets this far.
    pub fn new(key: &[u8], key_version: &str) -> Self {
        Self {
            key: Zeroizing::new(key.to_vec()),
            key_version: key_version.to_owned(),
        }
    }
}

impl Pseudonymizer for HmacPseudonymizer {
    fn key_version(&self) -> &str {
        &self.key_version
    }

    fn pseudonymize(&self, value: &str) -> String {
        // HMAC accepts a key of any length, so this cannot fail; the type still returns a Result.
        let mut mac = match Hmac::<Sha256>::new_from_slice(&self.key) {
            Ok(mac) => mac,
            Err(_) => return format!("{}:invalid-key", self.key_version),
        };

        mac.update(value.as_bytes());

        let digest = mac.finalize().into_bytes();
        let token: String = digest
            .iter()
            .take(TOKEN_BYTES)
            .map(|byte| format!("{byte:02x}"))
            .collect();

        format!("{}:{token}", self.key_version)
    }
}
