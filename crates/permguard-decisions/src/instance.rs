// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Incarnation identifiers: UUIDv7, minted where a stream begins.
//!
//! Version 7 rather than 4 because the identifier is also an ordering hint:
//! its leading 48 bits are a millisecond timestamp, so a human reading two
//! instance ids of one plane can tell which came first without a lookup. The
//! remaining bits are random, which is what makes it an identifier rather than
//! a clock: two planes minting in the same millisecond do not collide.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom as _, SystemRandom};

/// Distinguishes two identifiers minted in one process when the generator could not.
static MINTED: AtomicU64 = AtomicU64::new(0);

/// Mints a fresh incarnation identifier.
///
/// Falls back to all-random bytes if the clock is before the epoch: an
/// identifier that sorts oddly is a nuisance, one that repeats is a bug.
///
/// # When the generator cannot produce bytes
///
/// `fill` can fail, and discarding that error was a real defect: the buffer stays zero, the
/// timestamp overwrites the leading six bytes, and every identifier minted in the same millisecond
/// becomes the same identifier. These name journal incarnations, decision records and streams —
/// two of one is a stream the far end closes as forked, and an audit record nobody can tell from
/// another.
///
/// The failure is not propagated, and that is a choice rather than an omission. Two of the five
/// callers are infallible constructors, and making them fallible to carry an error that means "this
/// machine has no working entropy source" pushes a condition nobody can act on through code that
/// has nothing to do with it. What the failure must not do is produce *duplicates*, so it does not:
/// a process-wide counter is mixed into the bytes the generator was supposed to fill, and it is
/// monotonic whether or not the generator worked.
///
/// The result is weaker than a random identifier — predictable, in the worst case — and that is
/// sound here because these are names, not secrets: nothing authenticates by guessing one. What is
/// preserved is the property everything else depends on, which is that they are all different.
pub fn mint() -> String {
    let mut bytes = [0u8; 16];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        // Whatever else is true, these ten bytes will not repeat inside this process.
        let counted = MINTED.fetch_add(1, Ordering::Relaxed);
        let pid = u64::from(std::process::id());
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.subsec_nanos())
            .unwrap_or_default();
        for (index, shift) in (6..14).zip([56, 48, 40, 32, 24, 16, 8, 0]) {
            bytes[index] = ((counted ^ pid.rotate_left(17) ^ u64::from(nanos)) >> shift) as u8;
        }
        bytes[14] = (counted >> 8) as u8;
        bytes[15] = counted as u8;
    }

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
