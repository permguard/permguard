// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Envelope encryption of a private key at rest: one data key per blob, wrapped by a key the
//! Host never holds in the clear.
//!
//! ```text
//! dek         = 256 fresh random bits, made here, used once, erased
//! ciphertext  = AES-256-GCM(dek, nonce, private_key, aad = CBOR{format, host_id, ring, kid, suite})
//! wrapped_dek = provider.wrap(dek, context = that same aad)
//! on disk     = { v, kek_ref, kek_version, wrap_algorithm, wrapped_dek, content_algorithm, nonce, ciphertext }
//! ```
//!
//! # Why a key per blob
//!
//! AES-GCM fails catastrophically when a nonce repeats under one key. The usual answer is careful
//! nonce management; the answer here is to make repetition impossible: a [`Dek`] is minted inside
//! [`SealedKey::seal`], encrypts exactly one message, and is dropped. There is no API that accepts a
//! caller's DEK, so there is no way to encrypt twice under one.
//!
//! # Why the KEK is a provider, not bytes
//!
//! A key-encryption key in a KMS or an HSM is not exportable; it answers `wrap` and `unwrap` and
//! nothing else. [`KeyWrap`] is that interface. Rotating the KEK unwraps and rewraps the 32-byte
//! DEK and leaves the ciphertext untouched, so a rotation is cheap and the private key is never
//! re-encrypted. [`LocalKeyWrap`] is the one provider this crate ships: a KEK held in memory, for
//! development custody and for tests; a production provider lives with the Host's key custody.
//!
//! # The binding
//!
//! The associated data names the Host, the ring, the key id and the suite. A blob copied beside
//! another key, or onto another Host, fails to open, because the bytes were sealed to a context the
//! copy does not have.

use std::fmt;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

use super::random::{self, Entropy, EntropyUnavailable};
use super::suite::Suite;
use crate::cbor::{self, CborError, Value};
use permguard_core::domains;

/// The length of a data-encryption key.
pub const DEK_LEN: usize = 32;
/// The length of an AES-GCM nonce.
pub const NONCE_LEN: usize = 12;
/// The length of an AES-GCM tag.
pub const TAG_LEN: usize = 16;
/// The content algorithm, as JOSE names it.
pub const CONTENT_ALGORITHM: &str = "A256GCM";
/// The on-disk format version.
pub const FORMAT_VERSION: i64 = 1;

/// A fresh data-encryption key. Minted inside this module, used once, erased on drop.
pub struct Dek(Zeroizing<[u8; DEK_LEN]>);

impl Dek {
    fn generate(entropy: &dyn Entropy) -> Result<Self, EntropyUnavailable> {
        random::bytes::<DEK_LEN>(entropy).map(Self)
    }

    fn from_bytes(bytes: Zeroizing<[u8; DEK_LEN]>) -> Self {
        Self(bytes)
    }

    /// The key bytes, for a [`KeyWrap`] provider to wrap.
    pub fn expose(&self) -> &[u8; DEK_LEN] {
        &self.0
    }
}

/// What a sealed blob is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding<'a> {
    /// The owning Host, as its 16 UUID bytes.
    pub host_id: &'a [u8; 16],
    /// The ring the key belongs to.
    pub ring: &'a str,
    /// The key identifier.
    pub kid: &'a str,
    /// The key's suite.
    pub suite: Suite,
}

impl Binding<'_> {
    /// The associated data: a canonical CBOR map, so two implementations bind the same bytes.
    pub fn aad(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (
                Value::Text("format".into()),
                Value::Text(domains::format::SEALED_KEY_V1.to_owned()),
            ),
            (
                Value::Text("host_id".into()),
                Value::Bytes(self.host_id.to_vec()),
            ),
            (
                Value::Text("ring".into()),
                Value::Text(self.ring.to_owned()),
            ),
            (Value::Text("kid".into()), Value::Text(self.kid.to_owned())),
            (
                Value::Text("suite".into()),
                Value::Text(self.suite.name().to_owned()),
            ),
        ]))
    }
}

/// Why a wrap provider refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapError {
    /// The provider does not hold this KEK version.
    VersionUnknown(u64),
    /// The wrapped key does not unwrap under this KEK and context.
    Rejected,
    /// The provider could not be reached or answered with a failure.
    Unavailable(String),
}

impl fmt::Display for WrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionUnknown(version) => {
                write!(formatter, "the provider holds no KEK version {version}")
            }
            Self::Rejected => formatter.write_str("the wrapped key does not unwrap under this KEK"),
            Self::Unavailable(detail) => write!(formatter, "the wrap provider failed: {detail}"),
        }
    }
}

impl std::error::Error for WrapError {}

/// A key-encryption key that wraps and unwraps data keys without ever leaving its provider.
pub trait KeyWrap: Send + Sync {
    /// The `SecretRef` of the KEK, as configuration names it.
    fn kek_ref(&self) -> &str;
    /// The version of the KEK that wraps today.
    fn kek_version(&self) -> u64;
    /// The wrapping algorithm, as JOSE or the provider names it.
    fn wrap_algorithm(&self) -> &str;
    /// Wraps `dek` under the current version, bound to `context`.
    fn wrap(&self, dek: &Dek, context: &[u8]) -> Result<Vec<u8>, WrapError>;
    /// Unwraps `wrapped` made under `kek_version` and `context`.
    fn unwrap(&self, kek_version: u64, wrapped: &[u8], context: &[u8]) -> Result<Dek, WrapError>;
}

/// Why a blob could not be sealed, opened or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Randomness failed; fatal, nothing was sealed.
    Entropy(EntropyUnavailable),
    /// The wrap provider refused.
    Wrap(WrapError),
    /// The blob was wrapped under another KEK reference than the provider offered.
    KekMismatch { expected: String, actual: String },
    /// The blob names an algorithm this profile does not open.
    Algorithm(String),
    /// The ciphertext, the nonce or the binding do not match: the blob was altered or copied.
    Tamper,
    /// The on-disk bytes are not a sealed key.
    Encoding(String),
    /// A version does not fit the integer model of the canonical encoding.
    VersionRange(u64),
}

impl fmt::Display for SealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(error) => error.fmt(formatter),
            Self::Wrap(error) => error.fmt(formatter),
            Self::KekMismatch { expected, actual } => write!(
                formatter,
                "the blob was wrapped under `{actual}` and the provider offers `{expected}`"
            ),
            Self::Algorithm(name) => {
                write!(formatter, "`{name}` is not an algorithm this profile opens")
            }
            Self::Tamper => formatter.write_str(
                "the sealed key does not open under its binding: it was altered or copied",
            ),
            Self::Encoding(detail) => write!(formatter, "not a sealed key: {detail}"),
            Self::VersionRange(version) => {
                write!(formatter, "the version {version} cannot be encoded")
            }
        }
    }
}

impl std::error::Error for SealError {}

impl From<CborError> for SealError {
    fn from(error: CborError) -> Self {
        Self::Encoding(error.to_string())
    }
}

impl From<WrapError> for SealError {
    fn from(error: WrapError) -> Self {
        Self::Wrap(error)
    }
}

/// A private key at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedKey {
    pub kek_ref: String,
    pub kek_version: u64,
    pub wrap_algorithm: String,
    pub wrapped_dek: Vec<u8>,
    pub content_algorithm: String,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

// Integer labels of the on-disk map, normative.
const KEY_VERSION: i64 = 1;
const KEY_KEK_REF: i64 = 2;
const KEY_KEK_VERSION: i64 = 3;
const KEY_WRAP_ALGORITHM: i64 = 4;
const KEY_WRAPPED_DEK: i64 = 5;
const KEY_CONTENT_ALGORITHM: i64 = 6;
const KEY_NONCE: i64 = 7;
const KEY_CIPHERTEXT: i64 = 8;

impl SealedKey {
    /// Seals `private_key` to `binding` under a fresh DEK wrapped by `wrap`.
    pub fn seal(
        private_key: &[u8],
        binding: &Binding<'_>,
        wrap: &dyn KeyWrap,
        entropy: &dyn Entropy,
    ) -> Result<Self, SealError> {
        let dek = Dek::generate(entropy).map_err(SealError::Entropy)?;
        let nonce = random::bytes::<NONCE_LEN>(entropy).map_err(SealError::Entropy)?;
        let aad = binding.aad();
        let ciphertext = aes256gcm_seal(dek.expose(), &nonce, &aad, private_key)?;
        let wrapped_dek = wrap.wrap(&dek, &aad)?;

        Ok(Self {
            kek_ref: wrap.kek_ref().to_owned(),
            kek_version: wrap.kek_version(),
            wrap_algorithm: wrap.wrap_algorithm().to_owned(),
            wrapped_dek,
            content_algorithm: CONTENT_ALGORITHM.to_owned(),
            nonce: *nonce,
            ciphertext,
        })
    }

    /// Opens the blob under `binding`, returning the private key erased on drop.
    pub fn open(
        &self,
        binding: &Binding<'_>,
        wrap: &dyn KeyWrap,
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if self.content_algorithm != CONTENT_ALGORITHM {
            return Err(SealError::Algorithm(self.content_algorithm.clone()));
        }
        if self.kek_ref != wrap.kek_ref() {
            return Err(SealError::KekMismatch {
                expected: wrap.kek_ref().to_owned(),
                actual: self.kek_ref.clone(),
            });
        }
        let aad = binding.aad();
        let dek = wrap.unwrap(self.kek_version, &self.wrapped_dek, &aad)?;

        aes256gcm_open(dek.expose(), &self.nonce, &aad, &self.ciphertext)
    }

    /// Rewraps the DEK under `new`, leaving the ciphertext and the nonce exactly as they are.
    pub fn rewrap(
        &self,
        binding: &Binding<'_>,
        old: &dyn KeyWrap,
        new: &dyn KeyWrap,
    ) -> Result<Self, SealError> {
        if self.kek_ref != old.kek_ref() {
            return Err(SealError::KekMismatch {
                expected: old.kek_ref().to_owned(),
                actual: self.kek_ref.clone(),
            });
        }
        let aad = binding.aad();
        let dek = old.unwrap(self.kek_version, &self.wrapped_dek, &aad)?;
        let wrapped_dek = new.wrap(&dek, &aad)?;

        Ok(Self {
            kek_ref: new.kek_ref().to_owned(),
            kek_version: new.kek_version(),
            wrap_algorithm: new.wrap_algorithm().to_owned(),
            wrapped_dek,
            content_algorithm: self.content_algorithm.clone(),
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
        })
    }

    /// The on-disk bytes: a canonical CBOR map with integer labels.
    pub fn encode(&self) -> Result<Vec<u8>, SealError> {
        let kek_version = i64::try_from(self.kek_version)
            .map_err(|_| SealError::VersionRange(self.kek_version))?;

        Ok(cbor::encode(&Value::Map(vec![
            (Value::Int(KEY_VERSION), Value::Int(FORMAT_VERSION)),
            (Value::Int(KEY_KEK_REF), Value::Text(self.kek_ref.clone())),
            (Value::Int(KEY_KEK_VERSION), Value::Int(kek_version)),
            (
                Value::Int(KEY_WRAP_ALGORITHM),
                Value::Text(self.wrap_algorithm.clone()),
            ),
            (
                Value::Int(KEY_WRAPPED_DEK),
                Value::Bytes(self.wrapped_dek.clone()),
            ),
            (
                Value::Int(KEY_CONTENT_ALGORITHM),
                Value::Text(self.content_algorithm.clone()),
            ),
            (Value::Int(KEY_NONCE), Value::Bytes(self.nonce.to_vec())),
            (
                Value::Int(KEY_CIPHERTEXT),
                Value::Bytes(self.ciphertext.clone()),
            ),
        ])))
    }

    /// Reads the on-disk bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, SealError> {
        let Value::Map(map) = cbor::decode_canonical(bytes)? else {
            return Err(SealError::Encoding("a sealed key is a map".into()));
        };
        if map.len() != 8 {
            return Err(SealError::Encoding("a sealed key has eight members".into()));
        }
        let text = |label: i64| match map.iter().find(|(key, _)| *key == Value::Int(label)) {
            Some((_, Value::Text(text))) => Ok(text.clone()),
            _ => Err(SealError::Encoding(format!("member {label} is not text"))),
        };
        let int = |label: i64| match map.iter().find(|(key, _)| *key == Value::Int(label)) {
            Some((_, Value::Int(value))) => Ok(*value),
            _ => Err(SealError::Encoding(format!(
                "member {label} is not an integer"
            ))),
        };
        let bytes = |label: i64| match map.iter().find(|(key, _)| *key == Value::Int(label)) {
            Some((_, Value::Bytes(bytes))) => Ok(bytes.clone()),
            _ => Err(SealError::Encoding(format!("member {label} is not bytes"))),
        };
        if int(KEY_VERSION)? != FORMAT_VERSION {
            return Err(SealError::Encoding(
                "unknown sealed-key format version".into(),
            ));
        }
        let nonce: [u8; NONCE_LEN] = bytes(KEY_NONCE)?
            .try_into()
            .map_err(|_| SealError::Encoding("the nonce is not 96 bits".into()))?;
        let kek_version = u64::try_from(int(KEY_KEK_VERSION)?)
            .map_err(|_| SealError::Encoding("the KEK version is negative".into()))?;
        let ciphertext = bytes(KEY_CIPHERTEXT)?;
        if ciphertext.len() < TAG_LEN {
            return Err(SealError::Encoding(
                "the ciphertext is shorter than a tag".into(),
            ));
        }

        Ok(Self {
            kek_ref: text(KEY_KEK_REF)?,
            kek_version,
            wrap_algorithm: text(KEY_WRAP_ALGORITHM)?,
            wrapped_dek: bytes(KEY_WRAPPED_DEK)?,
            content_algorithm: text(KEY_CONTENT_ALGORITHM)?,
            nonce,
            ciphertext,
        })
    }
}

/// `AES-256-GCM(key, nonce, plaintext, aad)`, the ciphertext followed by the tag.
///
/// Exposed for the vectors; production code reaches it only through [`SealedKey`], where the key
/// is a fresh DEK that encrypts once.
pub fn aes256gcm_seal(
    key: &[u8; DEK_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| SealError::Algorithm(CONTENT_ALGORITHM.into()))?,
    );
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::from(aad),
        &mut in_out,
    )
    .map_err(|_| SealError::Algorithm(CONTENT_ALGORITHM.into()))?;

    Ok(in_out)
}

/// The inverse of [`aes256gcm_seal`]; a wrong key, nonce, tag or `aad` is [`SealError::Tamper`].
pub fn aes256gcm_open(
    key: &[u8; DEK_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| SealError::Algorithm(CONTENT_ALGORITHM.into()))?,
    );
    let mut in_out = Zeroizing::new(ciphertext.to_vec());
    let length = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| SealError::Tamper)?
        .len();
    in_out.truncate(length);

    Ok(in_out)
}

/// A KEK held in memory: development custody and tests. A production provider is a KMS or an HSM.
///
/// Wraps with AES-256-GCM under a fresh nonce, `nonce || ciphertext || tag`, the context as
/// associated data: the JOSE `A256GCMKW` construction.
pub struct LocalKeyWrap {
    kek_ref: String,
    kek_version: u64,
    kek: Zeroizing<[u8; DEK_LEN]>,
    entropy: Box<dyn Entropy>,
}

impl LocalKeyWrap {
    /// The algorithm name this provider writes.
    pub const ALGORITHM: &'static str = "A256GCMKW";

    /// Holds `kek` as `kek_ref` at `kek_version`.
    pub fn new(
        kek_ref: impl Into<String>,
        kek_version: u64,
        kek: Zeroizing<[u8; DEK_LEN]>,
        entropy: Box<dyn Entropy>,
    ) -> Self {
        Self {
            kek_ref: kek_ref.into(),
            kek_version,
            kek,
            entropy,
        }
    }

    /// Mints a fresh KEK; fails, and holds nothing, when randomness does.
    pub fn generate(
        kek_ref: impl Into<String>,
        kek_version: u64,
        entropy: Box<dyn Entropy>,
    ) -> Result<Self, EntropyUnavailable> {
        let kek = random::bytes::<DEK_LEN>(entropy.as_ref())?;

        Ok(Self::new(kek_ref, kek_version, kek, entropy))
    }
}

impl KeyWrap for LocalKeyWrap {
    fn kek_ref(&self) -> &str {
        &self.kek_ref
    }

    fn kek_version(&self) -> u64 {
        self.kek_version
    }

    fn wrap_algorithm(&self) -> &str {
        Self::ALGORITHM
    }

    fn wrap(&self, dek: &Dek, context: &[u8]) -> Result<Vec<u8>, WrapError> {
        let nonce = random::bytes::<NONCE_LEN>(self.entropy.as_ref())
            .map_err(|error| WrapError::Unavailable(error.to_string()))?;
        let mut out = nonce.to_vec();
        let sealed = aes256gcm_seal(&self.kek, &nonce, context, dek.expose())
            .map_err(|error| WrapError::Unavailable(error.to_string()))?;
        out.extend_from_slice(&sealed);

        Ok(out)
    }

    fn unwrap(&self, kek_version: u64, wrapped: &[u8], context: &[u8]) -> Result<Dek, WrapError> {
        if kek_version != self.kek_version {
            return Err(WrapError::VersionUnknown(kek_version));
        }
        if wrapped.len() != NONCE_LEN + DEK_LEN + TAG_LEN {
            return Err(WrapError::Rejected);
        }
        let nonce: [u8; NONCE_LEN] = wrapped[..NONCE_LEN]
            .try_into()
            .map_err(|_| WrapError::Rejected)?;
        let dek = aes256gcm_open(&self.kek, &nonce, context, &wrapped[NONCE_LEN..])
            .map_err(|_| WrapError::Rejected)?;
        let mut bytes = Zeroizing::new([0u8; DEK_LEN]);
        bytes.copy_from_slice(&dek);

        Ok(Dek::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::{SystemEntropy, testing::Exhausted};

    const HOST: [u8; 16] = [7; 16];

    fn binding<'a>(host: &'a [u8; 16], kid: &'a str) -> Binding<'a> {
        Binding {
            host_id: host,
            ring: "host.identity",
            kid,
            suite: Suite::Ed25519Sha256V1,
        }
    }

    fn provider(kek_ref: &str, version: u64) -> LocalKeyWrap {
        LocalKeyWrap::generate(kek_ref, version, Box::new(SystemEntropy)).unwrap()
    }

    #[test]
    fn test_a_sealed_key_opens_under_its_binding_and_nowhere_else() {
        let kek = provider("kms://kek", 1);
        let bound = binding(&HOST, "host.identity:abc");
        let sealed = SealedKey::seal(b"private bytes", &bound, &kek, &SystemEntropy).unwrap();

        assert_eq!(&*sealed.open(&bound, &kek).unwrap(), b"private bytes");

        let other_host = [8u8; 16];
        assert_eq!(
            sealed.open(&binding(&other_host, "host.identity:abc"), &kek),
            Err(SealError::Wrap(WrapError::Rejected)),
            "a blob copied to another Host does not even unwrap"
        );
        assert_eq!(
            sealed.open(&binding(&HOST, "host.identity:other"), &kek),
            Err(SealError::Wrap(WrapError::Rejected))
        );

        let mut altered = sealed.clone();
        altered.ciphertext[0] ^= 1;
        assert_eq!(altered.open(&bound, &kek), Err(SealError::Tamper));
        let mut altered = sealed.clone();
        altered.nonce[0] ^= 1;
        assert_eq!(altered.open(&bound, &kek), Err(SealError::Tamper));
    }

    #[test]
    fn test_every_seal_uses_a_fresh_dek_and_nonce() {
        let kek = provider("kms://kek", 1);
        let bound = binding(&HOST, "k");
        let one = SealedKey::seal(b"same", &bound, &kek, &SystemEntropy).unwrap();
        let two = SealedKey::seal(b"same", &bound, &kek, &SystemEntropy).unwrap();

        assert_ne!(one.nonce, two.nonce);
        assert_ne!(one.ciphertext, two.ciphertext);
        assert_ne!(one.wrapped_dek, two.wrapped_dek);
    }

    #[test]
    fn test_rewrap_changes_only_the_wrapped_dek_and_the_old_kek_stops_working() {
        let old = provider("kms://kek", 1);
        let new = provider("kms://kek", 2);
        let bound = binding(&HOST, "k");
        let sealed = SealedKey::seal(b"private", &bound, &old, &SystemEntropy).unwrap();
        let rewrapped = sealed.rewrap(&bound, &old, &new).unwrap();

        assert_eq!(rewrapped.ciphertext, sealed.ciphertext);
        assert_eq!(rewrapped.nonce, sealed.nonce);
        assert_eq!(rewrapped.kek_version, 2);
        assert_ne!(rewrapped.wrapped_dek, sealed.wrapped_dek);
        assert_eq!(&*rewrapped.open(&bound, &new).unwrap(), b"private");
        assert_eq!(
            rewrapped.open(&bound, &old),
            Err(SealError::Wrap(WrapError::VersionUnknown(2)))
        );
    }

    #[test]
    fn test_the_on_disk_form_round_trips_and_refuses_alterations() {
        let kek = provider("kms://kek", 1);
        let bound = binding(&HOST, "k");
        let sealed = SealedKey::seal(b"private", &bound, &kek, &SystemEntropy).unwrap();
        let bytes = sealed.encode().unwrap();

        assert_eq!(SealedKey::decode(&bytes).unwrap(), sealed);
        assert!(SealedKey::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(SealedKey::decode(&[0xa0]).is_err());
        let wrong_algorithm = SealedKey {
            content_algorithm: "A128GCM".into(),
            ..sealed.clone()
        };
        assert_eq!(
            wrong_algorithm.open(&bound, &kek),
            Err(SealError::Algorithm("A128GCM".into()))
        );
        let other_ref = SealedKey {
            kek_ref: "kms://other".into(),
            ..sealed
        };
        assert!(matches!(
            other_ref.open(&bound, &kek),
            Err(SealError::KekMismatch { .. })
        ));
    }

    #[test]
    fn test_without_randomness_nothing_is_sealed_and_no_provider_is_minted() {
        let kek = provider("kms://kek", 1);
        let bound = binding(&HOST, "k");

        assert_eq!(
            SealedKey::seal(b"private", &bound, &kek, &Exhausted).err(),
            Some(SealError::Entropy(EntropyUnavailable))
        );
        assert!(LocalKeyWrap::generate("kms://kek", 1, Box::new(Exhausted)).is_err());
    }
}
