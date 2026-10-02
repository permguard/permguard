// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The two signature suites, and nothing in between.
//!
//! | Suite                  | JWS `alg` | COSE `alg` | Key        | Public key encoding       |
//! | ---------------------- | --------- | ---------- | ---------- | ------------------------- |
//! | `pg-ed25519-sha256-v1` | `EdDSA`   | `-8`       | Ed25519    | 32 raw bytes              |
//! | `pg-p256-sha256-v1`    | `ES256`   | `-7`       | NIST P-256 | 65 bytes, uncompressed SEC1 |
//!
//! A ring fixes one suite for an epoch, a verifier is told which suite to expect, and a protected
//! header that names another algorithm is refused before any key is looked up. There is no
//! negotiation and no "accept either": the suite is a parameter the verifier already holds.
//!
//! # Low S
//!
//! An ECDSA signature `(r, s)` verifies equally with `s` replaced by `n − s`, so a third party can
//! mint a second valid encoding of any signature without the key. Two encodings of one signature
//! are two digests of one artifact, which is how a replay filter or an inclusion proof is slipped
//! past. P-256 signatures made here always carry `s ≤ n/2`, and a verifier refuses any that do not,
//! before the curve arithmetic runs — the rule Bitcoin adopted as BIP-62 after the malleability
//! incidents, applied to every P-256 signature this product checks.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ED25519, EcdsaKeyPair,
    Ed25519KeyPair, KeyPair as _, UnparsedPublicKey,
};
use zeroize::Zeroizing;

use super::random::EntropyUnavailable;

/// A signature suite: one key type, one hash, one encoding, one name on each wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Suite {
    /// Ed25519, the default for software and supported hardware.
    Ed25519Sha256V1,
    /// ECDSA over NIST P-256 with SHA-256, for FIPS and HSM oriented deployments.
    P256Sha256V1,
}

impl Suite {
    /// Every suite of the profile.
    pub const ALL: [Suite; 2] = [Self::Ed25519Sha256V1, Self::P256Sha256V1];

    /// The length of every signature of every suite: `r || s` for P-256, `R || S` for Ed25519.
    pub const SIGNATURE_LEN: usize = 64;

    /// The suite's registered name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519Sha256V1 => "pg-ed25519-sha256-v1",
            Self::P256Sha256V1 => "pg-p256-sha256-v1",
        }
    }

    /// The `alg` a JWS protected header carries.
    pub fn jws_alg(self) -> &'static str {
        match self {
            Self::Ed25519Sha256V1 => "EdDSA",
            Self::P256Sha256V1 => "ES256",
        }
    }

    /// The `alg` a COSE protected header carries (RFC 9053).
    pub fn cose_alg(self) -> i64 {
        match self {
            Self::Ed25519Sha256V1 => -8,
            Self::P256Sha256V1 => -7,
        }
    }

    /// The JWK key type.
    pub fn kty(self) -> &'static str {
        match self {
            Self::Ed25519Sha256V1 => "OKP",
            Self::P256Sha256V1 => "EC",
        }
    }

    /// The JWK curve.
    pub fn crv(self) -> &'static str {
        match self {
            Self::Ed25519Sha256V1 => "Ed25519",
            Self::P256Sha256V1 => "P-256",
        }
    }

    /// The length of a public key in the encoding this profile publishes and verifies with.
    pub fn public_key_len(self) -> usize {
        match self {
            Self::Ed25519Sha256V1 => 32,
            Self::P256Sha256V1 => 65,
        }
    }

    /// The suite with this registered name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|suite| suite.name() == name)
    }

    /// The suite a JWS `alg` names.
    pub fn from_jws_alg(alg: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|suite| suite.jws_alg() == alg)
    }

    /// The suite a COSE `alg` names.
    pub fn from_cose_alg(alg: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|suite| suite.cose_alg() == alg)
    }

    /// Verifies `signature` over `message` under `public_key`.
    ///
    /// The suite is this value, not anything read from the signature: a caller that let the
    /// artifact choose would be back to algorithm negotiation. For P-256 a high `s` is refused
    /// before the curve is consulted.
    pub fn verify(
        self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        if public_key.len() != self.public_key_len() {
            return Err(SignatureError::KeyLength {
                expected: self.public_key_len(),
                actual: public_key.len(),
            });
        }
        if signature.len() != Self::SIGNATURE_LEN {
            return Err(SignatureError::Length {
                expected: Self::SIGNATURE_LEN,
                actual: signature.len(),
            });
        }
        match self {
            Self::Ed25519Sha256V1 => UnparsedPublicKey::new(&ED25519, public_key)
                .verify(message, signature)
                .map_err(|_| SignatureError::Invalid),
            Self::P256Sha256V1 => {
                if public_key[0] != 0x04 {
                    return Err(SignatureError::KeyLength {
                        expected: self.public_key_len(),
                        actual: public_key.len(),
                    });
                }
                if !is_low_s(&signature[32..]) {
                    return Err(SignatureError::HighS);
                }
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
                    .verify(message, signature)
                    .map_err(|_| SignatureError::Invalid)
            }
        }
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Why a signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The signature is not 64 bytes.
    Length { expected: usize, actual: usize },
    /// The public key is not in the suite's encoding.
    KeyLength { expected: usize, actual: usize },
    /// A P-256 signature with `s > n/2`: valid arithmetic, refused encoding.
    HighS,
    /// The signature does not verify.
    Invalid,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => write!(
                formatter,
                "the signature is {actual} bytes; this profile's signatures are {expected}"
            ),
            Self::KeyLength { expected, actual } => write!(
                formatter,
                "the public key is {actual} bytes; this suite publishes {expected}"
            ),
            Self::HighS => formatter.write_str(
                "the signature carries a high s value: this profile accepts only the low-s encoding",
            ),
            Self::Invalid => formatter.write_str("the signature does not verify"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Why a key could not be made or used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The system's randomness failed; fatal, see [`super::random`].
    Entropy(EntropyUnavailable),
    /// The PKCS#8 document is not a key of this suite.
    Malformed,
    /// The signing operation itself failed.
    Signing,
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(error) => error.fmt(formatter),
            Self::Malformed => formatter.write_str("the key document is not a key of this suite"),
            Self::Signing => formatter.write_str("the signing operation failed"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A private key of one suite.
pub enum SigningKey {
    Ed25519(Ed25519KeyPair),
    P256(Box<EcdsaKeyPair>),
}

impl SigningKey {
    /// Mints a fresh key as a PKCS#8 document, erased when dropped.
    ///
    /// Randomness comes from the operating system through the signature library; a failure there
    /// is [`KeyError::Entropy`] and nothing is minted in its place.
    pub fn generate_pkcs8(suite: Suite) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let rng = SystemRandom::new();
        let document = match suite {
            Suite::Ed25519Sha256V1 => {
                Ed25519KeyPair::generate_pkcs8(&rng).map(|document| document.as_ref().to_vec())
            }
            Suite::P256Sha256V1 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map(|document| document.as_ref().to_vec())
            }
        }
        .map_err(|_| KeyError::Entropy(EntropyUnavailable))?;

        Ok(Zeroizing::new(document))
    }

    /// Reads a key of `suite` from its PKCS#8 document.
    pub fn from_pkcs8(suite: Suite, pkcs8: &[u8]) -> Result<Self, KeyError> {
        match suite {
            Suite::Ed25519Sha256V1 => Ed25519KeyPair::from_pkcs8(pkcs8)
                .map(Self::Ed25519)
                .map_err(|_| KeyError::Malformed),
            Suite::P256Sha256V1 => EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8,
                &SystemRandom::new(),
            )
            .map(|pair| Self::P256(Box::new(pair)))
            .map_err(|_| KeyError::Malformed),
        }
    }

    /// Reads an Ed25519 key from its 32-byte seed and the public key it must produce.
    ///
    /// For vectors and for stores that keep seeds; a mismatch between seed and public key is
    /// refused rather than trusted.
    pub fn ed25519_from_seed(seed: &[u8], public_key: &[u8]) -> Result<Self, KeyError> {
        Ed25519KeyPair::from_seed_and_public_key(seed, public_key)
            .map(Self::Ed25519)
            .map_err(|_| KeyError::Malformed)
    }

    /// The suite this key belongs to.
    pub fn suite(&self) -> Suite {
        match self {
            Self::Ed25519(_) => Suite::Ed25519Sha256V1,
            Self::P256(_) => Suite::P256Sha256V1,
        }
    }

    /// The public half, in the encoding the suite publishes.
    pub fn public_key(&self) -> &[u8] {
        match self {
            Self::Ed25519(pair) => pair.public_key().as_ref(),
            Self::P256(pair) => pair.public_key().as_ref(),
        }
    }

    /// Signs `message`; a P-256 signature is normalised to its low-s encoding.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; Suite::SIGNATURE_LEN], KeyError> {
        let mut out = [0u8; Suite::SIGNATURE_LEN];
        match self {
            Self::Ed25519(pair) => out.copy_from_slice(pair.sign(message).as_ref()),
            Self::P256(pair) => {
                let signature = pair
                    .sign(&SystemRandom::new(), message)
                    .map_err(|_| KeyError::Signing)?;
                out.copy_from_slice(signature.as_ref());
                if !is_low_s(&out[32..]) {
                    let negated = negate_s(&out[32..]);
                    out[32..].copy_from_slice(&negated);
                }
            }
        }

        Ok(out)
    }
}

/// The order `n` of the P-256 base point.
pub const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `n / 2`, rounded down: the largest `s` this profile accepts.
pub const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Whether a 32-byte big-endian `s` is at most `n / 2`.
pub fn is_low_s(s: &[u8]) -> bool {
    // Equal-length big-endian integers compare as their bytes do.
    s.len() == 32 && s <= &P256_HALF_ORDER[..]
}

/// `n − s` for a 32-byte big-endian `s < n`.
fn negate_s(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let difference = i16::from(P256_ORDER[index]) - i16::from(s[index]) - borrow;
        if difference < 0 {
            out[index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            out[index] = difference as u8;
            borrow = 0;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_names_round_trip_on_every_wire() {
        for suite in Suite::ALL {
            assert_eq!(Suite::from_name(suite.name()), Some(suite));
            assert_eq!(Suite::from_jws_alg(suite.jws_alg()), Some(suite));
            assert_eq!(Suite::from_cose_alg(suite.cose_alg()), Some(suite));
        }
        assert_eq!(Suite::from_jws_alg("none"), None);
        assert_eq!(Suite::from_jws_alg("HS256"), None);
        assert_eq!(Suite::from_cose_alg(-37), None);
    }

    #[test]
    fn test_each_suite_signs_and_verifies_and_refuses_the_other() {
        for suite in Suite::ALL {
            let key =
                SigningKey::from_pkcs8(suite, &SigningKey::generate_pkcs8(suite).unwrap()).unwrap();
            let signature = key.sign(b"message").unwrap();

            assert_eq!(
                suite.verify(key.public_key(), b"message", &signature),
                Ok(())
            );
            assert_eq!(
                suite.verify(key.public_key(), b"other", &signature),
                Err(SignatureError::Invalid)
            );
            let other = Suite::ALL.into_iter().find(|s| *s != suite).unwrap();
            assert!(
                other
                    .verify(key.public_key(), b"message", &signature)
                    .is_err()
            );
        }
    }

    #[test]
    fn test_p256_signatures_are_always_low_s_and_the_high_twin_is_refused() {
        let suite = Suite::P256Sha256V1;
        let key =
            SigningKey::from_pkcs8(suite, &SigningKey::generate_pkcs8(suite).unwrap()).unwrap();

        for round in 0..64u32 {
            let message = round.to_be_bytes();
            let signature = key.sign(&message).unwrap();
            assert!(
                is_low_s(&signature[32..]),
                "round {round} produced a high s"
            );
            assert_eq!(suite.verify(key.public_key(), &message, &signature), Ok(()));

            // The same signature with s replaced by n − s is arithmetically valid …
            let mut twin = signature;
            let negated = negate_s(&signature[32..]);
            twin[32..].copy_from_slice(&negated);
            assert!(
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key())
                    .verify(&message, &twin)
                    .is_ok(),
                "the curve accepts the twin, which is exactly why the profile must not"
            );
            // … and this profile refuses it before the curve is consulted.
            assert_eq!(
                suite.verify(key.public_key(), &message, &twin),
                Err(SignatureError::HighS)
            );
        }
    }

    #[test]
    fn test_negating_twice_is_the_identity_and_half_order_is_the_boundary() {
        let s = [7u8; 32];
        assert_eq!(negate_s(&negate_s(&s)), s);
        assert!(is_low_s(&P256_HALF_ORDER));
        let mut one_over = P256_HALF_ORDER;
        one_over[31] += 1;
        assert!(!is_low_s(&one_over));
        assert!(!is_low_s(&[0u8; 31]));
    }

    #[test]
    fn test_wrong_lengths_are_refused_before_any_arithmetic() {
        assert_eq!(
            Suite::Ed25519Sha256V1.verify(&[0u8; 32], b"m", &[0u8; 63]),
            Err(SignatureError::Length {
                expected: 64,
                actual: 63
            })
        );
        assert_eq!(
            Suite::P256Sha256V1.verify(&[0u8; 32], b"m", &[0u8; 64]),
            Err(SignatureError::KeyLength {
                expected: 65,
                actual: 32
            })
        );
    }
}
