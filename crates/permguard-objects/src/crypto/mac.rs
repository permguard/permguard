// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! HMAC-SHA-256 with a domain prefix.
//!
//! Every keyed tag this product makes — a pseudonym, an input commitment, a cursor, a witness —
//! is `HMAC(key, domain || message)` where `domain` is a registered string ending in `\n`. The
//! terminal byte is what makes the concatenation unambiguous, and the registry is what makes two
//! artifacts never share a domain. Verification is constant-time, so a tag cannot be guessed one
//! byte at a time.

use std::fmt;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

/// The length of every tag.
pub const TAG_LEN: usize = 32;

/// The key was refused by the MAC.
///
/// HMAC accepts a key of any length, so this is reserved for a key the algorithm rejects; it exists
/// so that no path returns a tag made under a key that was not the one asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRefused;

impl fmt::Display for KeyRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the MAC refused the key")
    }
}

impl std::error::Error for KeyRefused {}

type HmacSha256 = Hmac<Sha256>;

/// `HMAC-SHA-256(key, message)`, the raw function the vectors exercise.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; TAG_LEN], KeyRefused> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| KeyRefused)?;
    mac.update(message);

    Ok(mac.finalize().into_bytes().into())
}

/// `HMAC-SHA-256(key, domain || message)`: the tag of one artifact under one registered domain.
pub fn tag(key: &[u8], domain: &str, message: &[u8]) -> Result<[u8; TAG_LEN], KeyRefused> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| KeyRefused)?;
    mac.update(domain.as_bytes());
    mac.update(message);

    Ok(mac.finalize().into_bytes().into())
}

/// Whether `candidate` is the tag of `message` under `key` and `domain`, compared in constant time.
pub fn verify(key: &[u8], domain: &str, message: &[u8], candidate: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(domain.as_bytes());
    mac.update(message);

    mac.verify_slice(candidate).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_domain_separates_tags_and_verification_is_exact() {
        let key = [9u8; 32];
        let one = tag(&key, "permguard.a.v1\n", b"m").unwrap();
        let two = tag(&key, "permguard.b.v1\n", b"m").unwrap();

        assert_ne!(one, two);
        assert!(verify(&key, "permguard.a.v1\n", b"m", &one));
        assert!(!verify(&key, "permguard.b.v1\n", b"m", &one));
        assert!(!verify(&key, "permguard.a.v1\n", b"n", &one));
        assert!(!verify(&key, "permguard.a.v1\n", b"m", &one[..31]));
        assert!(!verify(&[8u8; 32], "permguard.a.v1\n", b"m", &one));
    }
}
