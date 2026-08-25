// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one implementation of "the fingerprint of these bytes".
//!
//! It is its own module because three things need it — a certificate's fingerprint, the value a
//! reload logs, and the chain an audit trail is built from — and two implementations of the same
//! digest eventually disagree about padding or case, at which point one of them is silently wrong.

use std::fmt::Write;

use sha2::{Digest, Sha256};

/// Returns the SHA-256 of some bytes, lowercase hex — the form every other tool prints.
pub fn digest(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

/// Renders bytes as lowercase hexadecimal.
///
/// The primitive under [`digest`], and used on its own for the things that are already short enough
/// to print whole — a certificate's serial number, for one.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        // Writing into a String cannot fail, and the alternative would be a fallible signature for
        // something that formats a number.
        let _ = write!(out, "{byte:02x}");

        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_digest_is_the_one_every_other_tool_prints() {
        // The SHA-256 of the empty input, which is the most published digest there is.
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_it_is_lowercase_and_two_characters_per_byte() {
        assert_eq!(digest(b"").len(), 64);
        assert!(digest(b"x").chars().all(|c| !c.is_ascii_uppercase()));
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }
}
