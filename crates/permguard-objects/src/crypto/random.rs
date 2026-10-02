// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one source of randomness, and the one way it fails.
//!
//! Every key, identifier, nonce and token this product makes comes from the operating system's
//! cryptographically secure generator. When that generator cannot answer, nothing stands in for it:
//! no clock, no counter, no hash of the time, no "best effort" bytes. The caller receives
//! [`EntropyUnavailable`] and must treat it as fatal for whatever it was about to make — a Host that
//! cannot mint a key does not start, a session that cannot mint a nonce is not opened.
//!
//! The rule is the blueprint's; this module is where it cannot be broken by accident, because there
//! is no other function to call. [`Entropy`] is a trait so that a test can hand a failing source to
//! the code under test and prove that it stops rather than improvises.

use std::fmt;

use ring::rand::SecureRandom as _;
use zeroize::Zeroizing;

/// The operating system's generator did not answer.
///
/// Fatal for whatever was being made. There is deliberately no payload: nothing about the failure
/// is actionable by code, only by an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyUnavailable;

impl fmt::Display for EntropyUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "the operating system's source of randomness is unavailable: no key, identifier, nonce or token can be made",
        )
    }
}

impl std::error::Error for EntropyUnavailable {}

/// A source of cryptographically secure random bytes.
pub trait Entropy: Send + Sync {
    /// Fills `buffer` completely, or fails without writing anything a caller may use.
    fn fill(&self, buffer: &mut [u8]) -> Result<(), EntropyUnavailable>;
}

/// The operating system's generator.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), EntropyUnavailable> {
        ring::rand::SystemRandom::new()
            .fill(buffer)
            .map_err(|_| EntropyUnavailable)
    }
}

/// `N` fresh bytes, erased when dropped.
pub fn bytes<const N: usize>(
    entropy: &dyn Entropy,
) -> Result<Zeroizing<[u8; N]>, EntropyUnavailable> {
    let mut out = Zeroizing::new([0u8; N]);
    entropy.fill(&mut out[..])?;

    Ok(out)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A source that never answers, for proving that callers stop rather than improvise.
    pub struct Exhausted;

    impl Entropy for Exhausted {
        fn fill(&self, _buffer: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_system_source_fills_and_two_draws_differ() {
        let first = bytes::<32>(&SystemEntropy).unwrap();
        let second = bytes::<32>(&SystemEntropy).unwrap();

        assert_ne!(*first, *second);
        assert_ne!(*first, [0u8; 32]);
    }

    #[test]
    fn test_an_exhausted_source_is_an_error_and_nothing_else() {
        assert_eq!(
            bytes::<16>(&testing::Exhausted).err(),
            Some(EntropyUnavailable)
        );
    }
}
