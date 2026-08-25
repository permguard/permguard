// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Object identity: the OCI digest form `sha256:<64 lowercase hex>` of an
//! object's canonical bytes.

use std::fmt;

use sha2::{Digest as _, Sha256};

/// A parsed, validated object digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    raw: [u8; 32],
}

impl Digest {
    /// Compute the digest of a byte sequence.
    pub fn compute(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Digest {
            raw: hasher.finalize().into(),
        }
    }

    /// The 32 raw bytes.
    pub fn raw(&self) -> &[u8; 32] {
        &self.raw
    }

    /// Parse the exact grammar `sha256:` + 64 lowercase hex `[a-f0-9]`.
    /// Nothing else — no uppercase, no other algorithms, no whitespace.
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        let hex = text.strip_prefix("sha256:").ok_or(DigestError::Grammar)?;
        let bytes = hex.as_bytes();
        if bytes.len() != 64 {
            return Err(DigestError::Grammar);
        }
        let mut raw = [0u8; 32];
        for (i, chunk) in bytes.chunks_exact(2).enumerate() {
            raw[i] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
        }
        Ok(Digest { raw })
    }
}

fn hex_nibble(c: u8) -> Result<u8, DigestError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(DigestError::Grammar),
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:")?;
        for byte in self.raw {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Why a digest string was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    /// Not `sha256:` + exactly 64 lowercase hex characters.
    Grammar,
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "digest must be sha256: followed by 64 lowercase hex characters"
        )
    }
}

impl std::error::Error for DigestError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_text() {
        let digest = Digest::compute(b"hello");
        let text = digest.to_string();
        assert_eq!(Digest::parse(&text).unwrap(), digest);
    }

    #[test]
    fn known_vector() {
        // sha256("abc") is a published FIPS 180 test vector.
        assert_eq!(
            Digest::compute(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn grammar_is_exact() {
        let ok = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(Digest::parse(ok).is_ok());
        for bad in [
            "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "sha512:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha256:ba7816",
            "sha256:zz7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ] {
            assert!(Digest::parse(bad).is_err(), "accepted: {bad}");
        }
    }
}
