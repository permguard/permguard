// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Incarnation identifiers: UUIDv7, minted where a stream begins.
//!
//! Version 7 rather than 4 because the identifier is also an ordering hint:
//! its leading 48 bits are a millisecond timestamp, so a human reading two
//! instance ids of one plane can tell which came first without a lookup. The
//! remaining bits are random, which is what makes it an identifier rather than
//! a clock: two planes minting in the same millisecond do not collide.

use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom as _, SystemRandom};

/// Mints a fresh incarnation identifier.
///
/// Falls back to all-random bytes if the clock is before the epoch: an
/// identifier that sorts oddly is a nuisance, one that repeats is a bug.
pub fn mint() -> String {
    let mut bytes = [0u8; 16];
    let _ = SystemRandom::new().fill(&mut bytes);

    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default();
    for (index, shift) in [40, 32, 24, 16, 8, 0].into_iter().enumerate() {
        bytes[index] = ((millis >> shift) & 0xff) as u8;
    }
    // Version 7, variant RFC 4122.
    bytes[6] = 0x70 | (bytes[6] & 0x0f);
    bytes[8] = 0x80 | (bytes[8] & 0x3f);

    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_incarnations_are_never_the_same() {
        assert_ne!(mint(), mint());
    }

    #[test]
    fn test_it_is_shaped_like_a_version_seven_uuid() {
        let id = mint();

        assert_eq!(id.len(), 36, "{id}");
        assert_eq!(id.as_bytes()[14], b'7', "the version nibble: {id}");
        assert!(
            matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "the variant nibble: {id}"
        );
    }

    #[test]
    fn test_later_incarnations_sort_after_earlier_ones() {
        let first = mint();
        std::thread::sleep(std::time::Duration::from_millis(2));

        assert!(first < mint(), "the leading bits are a millisecond clock");
    }
}
