// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Envelope encryption of a private key at rest: one data key per blob, wrapped by a key the
//! Host never holds in the clear.
//!
//! ```text
//! dek             = 256 fresh random bits, made here, used once, erased
//! content_context = CBOR{format, v, host_id, ring, kid, suite, content_algorithm, unique_nonce}
//! wrap_context    = CBOR{format, v, host_id, ring, kid, suite, kek_ref, kek_version,
//!                        wrap_algorithm, content_algorithm, unique_nonce}
//! ciphertext      = AES-256-GCM(dek, unique_nonce, private_key, aad = content_context)
//! wrapped_dek     = provider.wrap(dek, context = wrap_context)
//! on disk         = {1: v, 2: kek_ref, 3: kek_version, 4: wrap_algorithm, 5: wrapped_dek,
//!                    6: content_algorithm, 7: unique_nonce, 8: ciphertext}
//! ```
//!
//! # Why a key per blob
//!
//! AES-GCM fails catastrophically when a nonce repeats under one key. The usual answer is careful
//! nonce management; the answer here is to make repetition impossible: a [`Dek`] is minted inside
//! [`SealedKey::seal`], encrypts exactly one message, and is dropped. No path of [`SealedKey`]
//! accepts a caller's DEK, so a sealed key is never encrypted twice under one.
//!
//! # Why two contexts
//!
//! The content context binds the ciphertext to this Host, ring, key, suite and nonce, and to
//! nothing about the KEK. The wrap context binds the same facts plus the KEK reference, version
//! and wrapping algorithm. Rotating the KEK therefore rewraps the 32-byte DEK under a new wrap
//! context and leaves the ciphertext untouched, while a blob whose KEK metadata was edited no
//! longer unwraps: the provider authenticated the metadata it wrapped under.
//!
//! # Why the KEK is a provider, not bytes
//!
//! A key-encryption key in a KMS or an HSM is not exportable; it answers `wrap` and `unwrap` and
//! nothing else. [`KeyWrap`] is that interface, and a conformant provider authenticates the exact
//! context it is given. [`LocalKeyWrap`] is the one provider this crate ships, for tests: a KEK held
//! in memory. Its wrapped-DEK layout is its own and is not a registered format; a production
//! provider lives with the Host's key custody.
//!
//! # What is checked after opening
//!
//! A blob that decrypts has proved only that it was sealed under this context. Before the key is
//! handed out it must also be a PKCS#8 document of the binding's suite, its RFC 7638 thumbprint
//! must name the binding's `kid`, and its public half must be the one the ring stores.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

use super::random::{self, Entropy, EntropyUnavailable};
use super::suite::{SigningKey, Suite};
use super::thumbprint;
use crate::cbor::{self, CborError, Value};
use permguard_core::domains;

/// The length of a data-encryption key.
pub const DEK_LEN: usize = 32;
/// The length of an AES-GCM nonce.
pub const NONCE_LEN: usize = 12;
/// The length of an AES-GCM tag.
pub const TAG_LEN: usize = 16;
/// The content algorithm, exactly as the sealed-key format names it.
pub const CONTENT_ALGORITHM: &str = "AES-256-GCM";
/// The sealed-key format version, `v` in both contexts and in the on-disk map.
pub const FORMAT_VERSION: i64 = 1;

/// A fresh data-encryption key. Minted inside this module, used once, erased on drop.
pub struct Dek(Zeroizing<[u8; DEK_LEN]>);

impl Dek {
    fn generate(entropy: &dyn Entropy) -> Result<Self, EntropyUnavailable> {
        random::bytes::<DEK_LEN>(entropy).map(Self)
    }

    /// A data key a [`KeyWrap`] provider recovered from its wrapped form.
    pub fn from_unwrapped(bytes: Zeroizing<[u8; DEK_LEN]>) -> Self {
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
    /// The key identifier, `<ring>:<thumbprint>`.
    pub kid: &'a str,
    /// The ring's suite.
    pub suite: Suite,
}

impl Binding<'_> {
    fn members(&self) -> Vec<(Value, Value)> {
        vec![
            (
                text("format"),
                Value::Text(domains::format::SEALED_KEY_V1.to_owned()),
            ),
            (text("v"), Value::Int(FORMAT_VERSION)),
            (text("host_id"), Value::Bytes(self.host_id.to_vec())),
            (text("ring"), Value::Text(self.ring.to_owned())),
            (text("kid"), Value::Text(self.kid.to_owned())),
            (text("suite"), Value::Text(self.suite.name().to_owned())),
        ]
    }

    /// The associated data of the content encryption: a closed deterministic-CBOR map.
    pub fn content_context(
        &self,
        content_algorithm: &str,
        unique_nonce: &[u8; NONCE_LEN],
    ) -> Vec<u8> {
        let mut members = self.members();
        members.push((
            text("content_algorithm"),
            Value::Text(content_algorithm.to_owned()),
        ));
        members.push((text("unique_nonce"), Value::Bytes(unique_nonce.to_vec())));

        cbor::encode(&Value::Map(members))
    }

    /// The context the wrap provider binds the DEK to: the content facts plus the KEK metadata.
    pub fn wrap_context(
        &self,
        kek_ref: &str,
        kek_version: u64,
        wrap_algorithm: &str,
        content_algorithm: &str,
        unique_nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, SealError> {
        let kek_version_value =
            i64::try_from(kek_version).map_err(|_| SealError::VersionRange(kek_version))?;
        let mut members = self.members();
        members.push((text("kek_ref"), Value::Text(kek_ref.to_owned())));
        members.push((text("kek_version"), Value::Int(kek_version_value)));
        members.push((
            text("wrap_algorithm"),
            Value::Text(wrap_algorithm.to_owned()),
        ));
        members.push((
            text("content_algorithm"),
            Value::Text(content_algorithm.to_owned()),
        ));
        members.push((text("unique_nonce"), Value::Bytes(unique_nonce.to_vec())));

        Ok(cbor::encode(&Value::Map(members)))
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

/// Why a wrap provider refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapError {
    /// The provider does not hold this KEK version.
    VersionUnknown(u64),
    /// The wrapped key does not unwrap under this KEK and context.
    Rejected,
    /// The KEK has wrapped as many keys as its algorithm allows; it must be rotated.
    UsageLimit,
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
            Self::UsageLimit => {
                formatter.write_str("the KEK reached its usage limit and must be rotated")
            }
            Self::Unavailable(detail) => write!(formatter, "the wrap provider failed: {detail}"),
        }
    }
}

impl std::error::Error for WrapError {}

/// A key-encryption key that wraps and unwraps data keys without ever leaving its provider.
///
/// A conformant provider authenticates the exact `context` bytes: an unwrap under any other
/// context fails. A provider that ignored the context would let a blob's KEK metadata be
/// substituted, and is not conformant.
pub trait KeyWrap: Send + Sync {
    /// The `SecretRef` of the KEK, as configuration names it.
    fn kek_ref(&self) -> &str;
    /// The version of the KEK that wraps today.
    fn kek_version(&self) -> u64;
    /// The wrapping algorithm, as the provider names it.
    fn wrap_algorithm(&self) -> &str;
    /// Wraps `dek` under the current version, bound to `context`.
    fn wrap(&self, dek: &Dek, context: &[u8]) -> Result<Vec<u8>, WrapError>;
    /// Unwraps `wrapped` made under `kek_version` and `context`.
    fn unwrap(&self, kek_version: u64, wrapped: &[u8], context: &[u8]) -> Result<Dek, WrapError>;
}

/// Why a decrypted private key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMismatch {
    /// The document is not a PKCS#8 key of the binding's suite.
    Suite,
    /// The key's RFC 7638 thumbprint does not name the binding's `kid`.
    Kid,
    /// The key's public half is not the one the ring stores.
    PublicKey,
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
    /// The blob names another wrapping algorithm than the configured provider uses.
    WrapAlgorithm { expected: String, actual: String },
    /// The blob names a content algorithm this profile does not open.
    Algorithm(String),
    /// The ciphertext, the nonce or the binding do not match: the blob was altered or copied.
    Tamper,
    /// The private key does not belong to the binding.
    Key(KeyMismatch),
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
            Self::WrapAlgorithm { expected, actual } => write!(
                formatter,
                "the blob names the wrapping algorithm `{actual}` and the provider uses `{expected}`"
            ),
            Self::Algorithm(name) => {
                write!(formatter, "`{name}` is not an algorithm this profile opens")
            }
            Self::Tamper => formatter.write_str(
                "the sealed key does not open under its binding: it was altered or copied",
            ),
            Self::Key(KeyMismatch::Suite) => {
                formatter.write_str("the sealed key is not a key of the ring's suite")
            }
            Self::Key(KeyMismatch::Kid) => {
                formatter.write_str("the sealed key's thumbprint does not name its kid")
            }
            Self::Key(KeyMismatch::PublicKey) => {
                formatter.write_str("the sealed key is not the key the ring publishes")
            }
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

/// A private key at rest, as `private/<kid>.key` holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedKey {
    pub kek_ref: String,
    pub kek_version: u64,
    pub wrap_algorithm: String,
    pub wrapped_dek: Vec<u8>,
    pub content_algorithm: String,
    pub unique_nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// A sealed key that opened and proved it belongs to its binding.
pub struct Unsealed {
    /// The PKCS#8 document, erased on drop.
    pub pkcs8: Zeroizing<Vec<u8>>,
    /// The key, ready to sign.
    pub key: SigningKey,
}

// Integer labels of the on-disk map, normative.
const LABEL_V: i64 = 1;
const LABEL_KEK_REF: i64 = 2;
const LABEL_KEK_VERSION: i64 = 3;
const LABEL_WRAP_ALGORITHM: i64 = 4;
const LABEL_WRAPPED_DEK: i64 = 5;
const LABEL_CONTENT_ALGORITHM: i64 = 6;
const LABEL_UNIQUE_NONCE: i64 = 7;
const LABEL_CIPHERTEXT: i64 = 8;

/// Reads `pkcs8` as a key of the binding's suite and checks that its thumbprint names the
/// binding's `kid` and, when given, that its public half is the stored one.
fn bound_key(
    binding: &Binding<'_>,
    pkcs8: &[u8],
    stored_public_key: Option<&[u8]>,
) -> Result<SigningKey, SealError> {
    let key = SigningKey::from_pkcs8(binding.suite, pkcs8)
        .map_err(|_| SealError::Key(KeyMismatch::Suite))?;
    let thumbprint = thumbprint::jwk_thumbprint(binding.suite, key.public_key())
        .map_err(|_| SealError::Key(KeyMismatch::Suite))?;
    if thumbprint::kid(binding.ring, &thumbprint) != binding.kid {
        return Err(SealError::Key(KeyMismatch::Kid));
    }
    if stored_public_key.is_some_and(|stored| stored != key.public_key()) {
        return Err(SealError::Key(KeyMismatch::PublicKey));
    }

    Ok(key)
}

impl SealedKey {
    /// Seals the PKCS#8 `private_key` to `binding` under a fresh DEK wrapped by `wrap`.
    ///
    /// A key that does not belong to the binding — another suite, another `kid` — is refused
    /// before anything is encrypted.
    pub fn seal(
        private_key: &[u8],
        binding: &Binding<'_>,
        wrap: &dyn KeyWrap,
        entropy: &dyn Entropy,
    ) -> Result<Self, SealError> {
        bound_key(binding, private_key, None)?;
        let dek = Dek::generate(entropy).map_err(SealError::Entropy)?;
        let unique_nonce = random::bytes::<NONCE_LEN>(entropy).map_err(SealError::Entropy)?;
        let content_context = binding.content_context(CONTENT_ALGORITHM, &unique_nonce);
        let ciphertext =
            aes256gcm_seal(dek.expose(), &unique_nonce, &content_context, private_key)?;
        let wrap_context = binding.wrap_context(
            wrap.kek_ref(),
            wrap.kek_version(),
            wrap.wrap_algorithm(),
            CONTENT_ALGORITHM,
            &unique_nonce,
        )?;
        let wrapped_dek = wrap.wrap(&dek, &wrap_context)?;

        Ok(Self {
            kek_ref: wrap.kek_ref().to_owned(),
            kek_version: wrap.kek_version(),
            wrap_algorithm: wrap.wrap_algorithm().to_owned(),
            wrapped_dek,
            content_algorithm: CONTENT_ALGORITHM.to_owned(),
            unique_nonce: *unique_nonce,
            ciphertext,
        })
    }

    /// Opens the blob under `binding` with the configured provider `wrap`, and refuses a key that
    /// is not of the binding's suite, whose thumbprint does not name its `kid`, or whose public
    /// half is not `stored_public_key`.
    pub fn open(
        &self,
        binding: &Binding<'_>,
        wrap: &dyn KeyWrap,
        stored_public_key: &[u8],
    ) -> Result<Unsealed, SealError> {
        self.check_provider(wrap)?;
        let dek = wrap.unwrap(
            self.kek_version,
            &self.wrapped_dek,
            &self.wrap_context(binding)?,
        )?;
        let content_context = binding.content_context(&self.content_algorithm, &self.unique_nonce);
        let pkcs8 = aes256gcm_open(
            dek.expose(),
            &self.unique_nonce,
            &content_context,
            &self.ciphertext,
        )?;
        let key = bound_key(binding, &pkcs8, Some(stored_public_key))?;

        Ok(Unsealed { pkcs8, key })
    }

    /// Rewraps the DEK under `new`, leaving the ciphertext and the nonce exactly as they are.
    pub fn rewrap(
        &self,
        binding: &Binding<'_>,
        old: &dyn KeyWrap,
        new: &dyn KeyWrap,
    ) -> Result<Self, SealError> {
        self.check_provider(old)?;
        let dek = old.unwrap(
            self.kek_version,
            &self.wrapped_dek,
            &self.wrap_context(binding)?,
        )?;
        let wrap_context = binding.wrap_context(
            new.kek_ref(),
            new.kek_version(),
            new.wrap_algorithm(),
            &self.content_algorithm,
            &self.unique_nonce,
        )?;
        let wrapped_dek = new.wrap(&dek, &wrap_context)?;

        Ok(Self {
            kek_ref: new.kek_ref().to_owned(),
            kek_version: new.kek_version(),
            wrap_algorithm: new.wrap_algorithm().to_owned(),
            wrapped_dek,
            content_algorithm: self.content_algorithm.clone(),
            unique_nonce: self.unique_nonce,
            ciphertext: self.ciphertext.clone(),
        })
    }

    /// The wrap context this blob's metadata names under `binding`.
    pub fn wrap_context(&self, binding: &Binding<'_>) -> Result<Vec<u8>, SealError> {
        binding.wrap_context(
            &self.kek_ref,
            self.kek_version,
            &self.wrap_algorithm,
            &self.content_algorithm,
            &self.unique_nonce,
        )
    }

    /// The algorithms are the profile's and the configured provider's, never the blob's choice.
    fn check_provider(&self, wrap: &dyn KeyWrap) -> Result<(), SealError> {
        if self.content_algorithm != CONTENT_ALGORITHM {
            return Err(SealError::Algorithm(self.content_algorithm.clone()));
        }
        if self.kek_ref != wrap.kek_ref() {
            return Err(SealError::KekMismatch {
                expected: wrap.kek_ref().to_owned(),
                actual: self.kek_ref.clone(),
            });
        }
        if self.wrap_algorithm != wrap.wrap_algorithm() {
            return Err(SealError::WrapAlgorithm {
                expected: wrap.wrap_algorithm().to_owned(),
                actual: self.wrap_algorithm.clone(),
            });
        }

        Ok(())
    }

    /// The on-disk bytes: a canonical CBOR map with the eight integer labels.
    pub fn encode(&self) -> Result<Vec<u8>, SealError> {
        let kek_version = i64::try_from(self.kek_version)
            .map_err(|_| SealError::VersionRange(self.kek_version))?;

        Ok(cbor::encode(&Value::Map(vec![
            (Value::Int(LABEL_V), Value::Int(FORMAT_VERSION)),
            (Value::Int(LABEL_KEK_REF), Value::Text(self.kek_ref.clone())),
            (Value::Int(LABEL_KEK_VERSION), Value::Int(kek_version)),
            (
                Value::Int(LABEL_WRAP_ALGORITHM),
                Value::Text(self.wrap_algorithm.clone()),
            ),
            (
                Value::Int(LABEL_WRAPPED_DEK),
                Value::Bytes(self.wrapped_dek.clone()),
            ),
            (
                Value::Int(LABEL_CONTENT_ALGORITHM),
                Value::Text(self.content_algorithm.clone()),
            ),
            (
                Value::Int(LABEL_UNIQUE_NONCE),
                Value::Bytes(self.unique_nonce.to_vec()),
            ),
            (
                Value::Int(LABEL_CIPHERTEXT),
                Value::Bytes(self.ciphertext.clone()),
            ),
        ])))
    }

    /// Reads the on-disk bytes strictly: canonical CBOR, exactly the eight labels once each with
    /// their exact types, `v` 1, `AES-256-GCM` and a 12-byte nonce.
    pub fn decode(bytes: &[u8]) -> Result<Self, SealError> {
        let Value::Map(map) = cbor::decode_canonical(bytes)? else {
            return Err(SealError::Encoding("a sealed key is a map".into()));
        };
        // Eight members, each of the eight labels found below, and no duplicates (the canonical
        // decoder refuses them): the map is exactly the closed version 1 form.
        if map.len() != 8 {
            return Err(SealError::Encoding(
                "a sealed key has exactly eight members".into(),
            ));
        }
        let member = |label: i64| {
            map.iter()
                .find(|(key, _)| *key == Value::Int(label))
                .map(|(_, value)| value)
                .ok_or_else(|| SealError::Encoding(format!("member {label} is missing")))
        };
        let text = |label: i64| match member(label)? {
            Value::Text(text) => Ok(text.clone()),
            _ => Err(SealError::Encoding(format!("member {label} is not text"))),
        };
        let unsigned = |label: i64| match member(label)? {
            Value::Int(value) => u64::try_from(*value).map_err(|_| {
                SealError::Encoding(format!("member {label} is not an unsigned integer"))
            }),
            _ => Err(SealError::Encoding(format!(
                "member {label} is not an unsigned integer"
            ))),
        };
        let bytes = |label: i64| match member(label)? {
            Value::Bytes(bytes) => Ok(bytes.clone()),
            _ => Err(SealError::Encoding(format!(
                "member {label} is not a byte string"
            ))),
        };
        if unsigned(LABEL_V)? != FORMAT_VERSION.unsigned_abs() {
            return Err(SealError::Encoding(
                "unknown sealed-key format version".into(),
            ));
        }
        let content_algorithm = text(LABEL_CONTENT_ALGORITHM)?;
        if content_algorithm != CONTENT_ALGORITHM {
            return Err(SealError::Algorithm(content_algorithm));
        }
        let unique_nonce: [u8; NONCE_LEN] = bytes(LABEL_UNIQUE_NONCE)?
            .try_into()
            .map_err(|_| SealError::Encoding("the nonce is not exactly 12 bytes".into()))?;
        let ciphertext = bytes(LABEL_CIPHERTEXT)?;
        if ciphertext.len() < TAG_LEN {
            return Err(SealError::Encoding(
                "the ciphertext is shorter than a tag".into(),
            ));
        }

        Ok(Self {
            kek_ref: text(LABEL_KEK_REF)?,
            kek_version: unsigned(LABEL_KEK_VERSION)?,
            wrap_algorithm: text(LABEL_WRAP_ALGORITHM)?,
            wrapped_dek: bytes(LABEL_WRAPPED_DEK)?,
            content_algorithm,
            unique_nonce,
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

/// The most DEKs one KEK wraps under random 96-bit nonces: NIST SP 800-38D, section 8.3.
pub const KEK_WRAP_LIMIT: u64 = 1 << 32;

/// A KEK held in memory, for tests. A production provider is a KMS, an HSM or the Host's custody.
///
/// Wraps with AES-256-GCM under a fresh nonce, `nonce || ciphertext || tag`, the context as
/// associated data, and refuses to wrap more than [`KEK_WRAP_LIMIT`] keys. The layout is this
/// provider's own and is not a registered persisted format.
pub struct LocalKeyWrap {
    kek_ref: String,
    kek_version: u64,
    kek: Zeroizing<[u8; DEK_LEN]>,
    entropy: Box<dyn Entropy>,
    wraps: AtomicU64,
    limit: u64,
}

impl LocalKeyWrap {
    /// The algorithm name this provider writes: deliberately not a JOSE name, because the layout
    /// is not JOSE `A256GCMKW` and a test provider must not pass for a registered one.
    pub const ALGORITHM: &'static str = "pg-test-a256gcm";

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
            wraps: AtomicU64::new(0),
            limit: KEK_WRAP_LIMIT,
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
        // Counted before the nonce is drawn, so a refused wrap still spends its slot.
        if self.wraps.fetch_add(1, Ordering::SeqCst) >= self.limit {
            return Err(WrapError::UsageLimit);
        }
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

        Ok(Dek::from_unwrapped(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::{SystemEntropy, testing::Exhausted};

    const HOST: [u8; 16] = [7; 16];
    const RING: &str = "host.identity";

    /// A fresh key of `suite`, its PKCS#8 document and the `kid` it binds to.
    fn key(suite: Suite) -> (Zeroizing<Vec<u8>>, Vec<u8>, String) {
        let pkcs8 = SigningKey::generate_pkcs8(suite).unwrap();
        let public = SigningKey::from_pkcs8(suite, &pkcs8)
            .unwrap()
            .public_key()
            .to_vec();
        let kid = thumbprint::kid(RING, &thumbprint::jwk_thumbprint(suite, &public).unwrap());

        (pkcs8, public, kid)
    }

    fn binding<'a>(host: &'a [u8; 16], kid: &'a str, suite: Suite) -> Binding<'a> {
        Binding {
            host_id: host,
            ring: RING,
            kid,
            suite,
        }
    }

    fn provider(kek_ref: &str, version: u64) -> LocalKeyWrap {
        LocalKeyWrap::generate(kek_ref, version, Box::new(SystemEntropy)).unwrap()
    }

    /// A blob sealed around `plaintext` with the real contexts but without the pre-seal key
    /// check, to prove that `open` checks the key itself.
    fn forge(plaintext: &[u8], binding: &Binding<'_>, wrap: &dyn KeyWrap) -> SealedKey {
        let dek = Dek::generate(&SystemEntropy).unwrap();
        let nonce = [5u8; NONCE_LEN];
        let content = binding.content_context(CONTENT_ALGORITHM, &nonce);
        let wrap_context = binding
            .wrap_context(
                wrap.kek_ref(),
                wrap.kek_version(),
                wrap.wrap_algorithm(),
                CONTENT_ALGORITHM,
                &nonce,
            )
            .unwrap();

        SealedKey {
            kek_ref: wrap.kek_ref().to_owned(),
            kek_version: wrap.kek_version(),
            wrap_algorithm: wrap.wrap_algorithm().to_owned(),
            wrapped_dek: wrap.wrap(&dek, &wrap_context).unwrap(),
            content_algorithm: CONTENT_ALGORITHM.to_owned(),
            unique_nonce: nonce,
            ciphertext: aes256gcm_seal(dek.expose(), &nonce, &content, plaintext).unwrap(),
        }
    }

    #[test]
    fn test_a_sealed_key_of_each_suite_opens_and_signs_under_its_binding() {
        for suite in Suite::ALL {
            let kek = provider("secret://kek", 1);
            let (pkcs8, public, kid) = key(suite);
            let bound = binding(&HOST, &kid, suite);
            let sealed = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();
            let opened = sealed.open(&bound, &kek, &public).unwrap();

            assert_eq!(*opened.pkcs8, *pkcs8);
            let signature = opened.key.sign(b"m").unwrap();
            assert_eq!(suite.verify(&public, b"m", &signature), Ok(()));
        }
    }

    #[test]
    fn test_a_blob_opens_under_its_own_binding_and_no_other() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, public, kid) = key(Suite::Ed25519Sha256V1);
        let (_, _, other_kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);
        let sealed = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();

        let other_host = [8u8; 16];
        let elsewhere = [
            binding(&other_host, &kid, Suite::Ed25519Sha256V1),
            binding(&HOST, &other_kid, Suite::Ed25519Sha256V1),
            binding(&HOST, &kid, Suite::P256Sha256V1),
            Binding {
                ring: "host.operations",
                ..bound
            },
        ];
        for copy in elsewhere {
            assert_eq!(
                sealed.open(&copy, &kek, &public).err(),
                Some(SealError::Wrap(WrapError::Rejected)),
                "{copy:?}"
            );
        }
    }

    #[test]
    fn test_every_on_disk_member_is_bound_or_checked() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, public, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);
        let sealed = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();

        let mut kek_ref = sealed.clone();
        kek_ref.kek_ref = "secret://other".into();
        let mut kek_version = sealed.clone();
        kek_version.kek_version = 2;
        let mut wrap_algorithm = sealed.clone();
        wrap_algorithm.wrap_algorithm = "A128GCMKW".into();
        let mut wrapped_dek = sealed.clone();
        wrapped_dek.wrapped_dek[20] ^= 1;
        let mut content_algorithm = sealed.clone();
        content_algorithm.content_algorithm = "A256GCM".into();
        let mut nonce = sealed.clone();
        nonce.unique_nonce[0] ^= 1;
        let mut ciphertext = sealed.clone();
        ciphertext.ciphertext[0] ^= 1;

        let cases = [
            (kek_ref, "kek_ref"),
            (kek_version, "kek_version"),
            (wrap_algorithm, "wrap_algorithm"),
            (wrapped_dek, "wrapped_dek"),
            (content_algorithm, "content_algorithm"),
            (nonce, "unique_nonce"),
            (ciphertext, "ciphertext"),
        ];
        for (altered, member) in cases {
            let refused = altered.open(&bound, &kek, &public).err();
            assert!(refused.is_some(), "an altered `{member}` still opened");
        }
        assert_eq!(
            sealed.open(&bound, &kek, &public).err(),
            None,
            "the unaltered blob opens"
        );
    }

    /// The wrap context with one member replaced, encoded the way the format encodes it.
    fn wrap_context_with(base: &[(Value, Value)], name: &str, value: Value) -> Vec<u8> {
        let mut members = base.to_vec();
        let slot = members
            .iter_mut()
            .find(|(key, _)| *key == text(name))
            .unwrap();
        slot.1 = value;
        cbor::encode(&Value::Map(members))
    }

    #[test]
    fn test_the_provider_binds_every_member_of_the_wrap_context_and_the_cipher_every_member_of_the_content_context()
     {
        let kek = provider("secret://kek", 1);
        let (pkcs8, _, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);
        let sealed = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();
        let context = sealed.wrap_context(&bound).unwrap();
        let Value::Map(wrap_members) = cbor::decode_canonical(&context).unwrap() else {
            panic!("a wrap context is a map");
        };
        assert_eq!(wrap_members.len(), 11, "the wrap context is closed");
        let dek = kek
            .unwrap(sealed.kek_version, &sealed.wrapped_dek, &context)
            .unwrap();

        for (name, value) in [
            ("format", text("permguard.sealed-key.v2")),
            ("v", Value::Int(2)),
            ("host_id", Value::Bytes(vec![8; 16])),
            ("ring", text("host.operations")),
            ("kid", text("host.identity:x")),
            ("suite", text("pg-p256-sha256-v1")),
            ("kek_ref", text("secret://other")),
            ("kek_version", Value::Int(2)),
            ("wrap_algorithm", text("A128GCMKW")),
            ("content_algorithm", text("A256GCM")),
            ("unique_nonce", Value::Bytes(vec![0; 12])),
        ] {
            let altered = wrap_context_with(&wrap_members, name, value);
            assert_eq!(
                kek.unwrap(sealed.kek_version, &sealed.wrapped_dek, &altered)
                    .err(),
                Some(WrapError::Rejected),
                "the provider unwrapped under an altered `{name}`"
            );
        }

        let content = bound.content_context(CONTENT_ALGORITHM, &sealed.unique_nonce);
        let Value::Map(content_members) = cbor::decode_canonical(&content).unwrap() else {
            panic!("a content context is a map");
        };
        assert_eq!(content_members.len(), 8, "the content context is closed");
        let names: Vec<&Value> = content_members.iter().map(|(key, _)| key).collect();
        for absent in ["kek_ref", "kek_version", "wrap_algorithm"] {
            assert!(
                !names.contains(&&text(absent)),
                "`{absent}` belongs to the wrap context only"
            );
        }
        assert!(
            aes256gcm_open(
                dek.expose(),
                &sealed.unique_nonce,
                &content,
                &sealed.ciphertext
            )
            .is_ok()
        );
        for (name, value) in [
            ("format", text("permguard.sealed-key.v2")),
            ("v", Value::Int(2)),
            ("host_id", Value::Bytes(vec![8; 16])),
            ("ring", text("host.operations")),
            ("kid", text("host.identity:x")),
            ("suite", text("pg-p256-sha256-v1")),
            ("content_algorithm", text("A256GCM")),
            ("unique_nonce", Value::Bytes(vec![0; 12])),
        ] {
            let altered = wrap_context_with(&content_members, name, value);
            assert_eq!(
                aes256gcm_open(
                    dek.expose(),
                    &sealed.unique_nonce,
                    &altered,
                    &sealed.ciphertext
                )
                .err(),
                Some(SealError::Tamper),
                "the content opened under an altered `{name}`"
            );
        }
    }

    #[test]
    fn test_a_decrypted_key_that_is_not_the_bindings_key_is_refused() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, public, kid) = key(Suite::Ed25519Sha256V1);
        let (other_pkcs8, other_public, _) = key(Suite::Ed25519Sha256V1);
        let (p256_pkcs8, _, _) = key(Suite::P256Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);

        // Another key of the same suite: its thumbprint does not name the kid.
        assert_eq!(
            forge(&other_pkcs8, &bound, &kek)
                .open(&bound, &kek, &other_public)
                .err(),
            Some(SealError::Key(KeyMismatch::Kid))
        );
        // A key of another suite sealed under an Ed25519 binding.
        assert_eq!(
            forge(&p256_pkcs8, &bound, &kek)
                .open(&bound, &kek, &public)
                .err(),
            Some(SealError::Key(KeyMismatch::Suite))
        );
        // Bytes that are no key at all.
        assert_eq!(
            forge(b"not a key", &bound, &kek)
                .open(&bound, &kek, &public)
                .err(),
            Some(SealError::Key(KeyMismatch::Suite))
        );
        // The right key, but the ring stores another public key under this kid.
        assert_eq!(
            forge(&pkcs8, &bound, &kek)
                .open(&bound, &kek, &other_public)
                .err(),
            Some(SealError::Key(KeyMismatch::PublicKey))
        );
        assert!(
            forge(&pkcs8, &bound, &kek)
                .open(&bound, &kek, &public)
                .is_ok()
        );
    }

    #[test]
    fn test_a_key_that_is_not_the_bindings_key_is_never_sealed() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, _, kid) = key(Suite::Ed25519Sha256V1);
        let (other_pkcs8, _, _) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);

        assert_eq!(
            SealedKey::seal(&other_pkcs8, &bound, &kek, &SystemEntropy).err(),
            Some(SealError::Key(KeyMismatch::Kid))
        );
        assert_eq!(
            SealedKey::seal(
                &pkcs8,
                &binding(&HOST, &kid, Suite::P256Sha256V1),
                &kek,
                &SystemEntropy
            )
            .err(),
            Some(SealError::Key(KeyMismatch::Suite))
        );
    }

    #[test]
    fn test_every_seal_uses_a_fresh_dek_and_nonce() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, _, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);
        let one = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();
        let two = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();

        assert_ne!(one.unique_nonce, two.unique_nonce);
        assert_ne!(one.ciphertext, two.ciphertext);
        assert_ne!(one.wrapped_dek, two.wrapped_dek);
    }

    #[test]
    fn test_rewrap_changes_only_the_kek_metadata_and_the_wrapped_dek() {
        let old = provider("secret://kek", 1);
        let new = provider("secret://kek", 2);
        let (pkcs8, public, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);
        let sealed = SealedKey::seal(&pkcs8, &bound, &old, &SystemEntropy).unwrap();
        let rewrapped = sealed.rewrap(&bound, &old, &new).unwrap();

        assert_eq!(rewrapped.ciphertext, sealed.ciphertext);
        assert_eq!(rewrapped.unique_nonce, sealed.unique_nonce);
        assert_eq!(rewrapped.kek_version, 2);
        assert_ne!(rewrapped.wrapped_dek, sealed.wrapped_dek);
        assert_eq!(
            *rewrapped.open(&bound, &new, &public).unwrap().pkcs8,
            *pkcs8
        );
        assert_eq!(
            rewrapped.open(&bound, &old, &public).err(),
            Some(SealError::Wrap(WrapError::VersionUnknown(2)))
        );

        // The new wrapped DEK under the old version number: the provider bound the version.
        let substituted = SealedKey {
            kek_version: 1,
            ..rewrapped.clone()
        };
        assert!(substituted.open(&bound, &new, &public).is_err());
        assert!(substituted.open(&bound, &old, &public).is_err());
    }

    #[test]
    fn test_the_algorithms_are_never_chosen_by_the_blob() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, public, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);
        let sealed = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();

        let content = SealedKey {
            content_algorithm: "A128GCM".into(),
            ..sealed.clone()
        };
        assert_eq!(
            content.open(&bound, &kek, &public).err(),
            Some(SealError::Algorithm("A128GCM".into()))
        );
        let wrapping = SealedKey {
            wrap_algorithm: "A128GCMKW".into(),
            ..sealed.clone()
        };
        assert!(matches!(
            wrapping.open(&bound, &kek, &public),
            Err(SealError::WrapAlgorithm { .. })
        ));
        let reference = SealedKey {
            kek_ref: "secret://other".into(),
            ..sealed
        };
        assert!(matches!(
            reference.open(&bound, &kek, &public),
            Err(SealError::KekMismatch { .. })
        ));
    }

    #[test]
    fn test_the_on_disk_form_round_trips_and_only_the_closed_version_1_decodes() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, _, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);
        let sealed = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();
        let bytes = sealed.encode().unwrap();
        assert_eq!(SealedKey::decode(&bytes).unwrap(), sealed);

        let Value::Map(members) = cbor::decode_canonical(&bytes).unwrap() else {
            panic!("a sealed key is a map");
        };
        let with = |label: i64, value: Option<Value>| {
            let mut altered: Vec<(Value, Value)> = members
                .iter()
                .filter(|(key, _)| *key != Value::Int(label))
                .cloned()
                .collect();
            if let Some(value) = value {
                altered.push((Value::Int(label), value));
            }
            cbor::encode(&Value::Map(altered))
        };
        let refused = [
            ("a ninth label", with(9, Some(Value::Int(0)))),
            ("label 0", with(0, Some(Value::Int(0)))),
            ("a missing label", with(LABEL_CIPHERTEXT, None)),
            ("v 2", with(LABEL_V, Some(Value::Int(2)))),
            ("v as text", with(LABEL_V, Some(text("1")))),
            (
                "a negative KEK version",
                with(LABEL_KEK_VERSION, Some(Value::Int(-1))),
            ),
            (
                "a KEK reference as bytes",
                with(LABEL_KEK_REF, Some(Value::Bytes(b"x".to_vec()))),
            ),
            (
                "a wrapped DEK as text",
                with(LABEL_WRAPPED_DEK, Some(text("x"))),
            ),
            (
                "another content algorithm",
                with(LABEL_CONTENT_ALGORITHM, Some(text("A256GCM"))),
            ),
            (
                "an 11-byte nonce",
                with(LABEL_UNIQUE_NONCE, Some(Value::Bytes(vec![0; 11]))),
            ),
            (
                "a 13-byte nonce",
                with(LABEL_UNIQUE_NONCE, Some(Value::Bytes(vec![0; 13]))),
            ),
            (
                "a ciphertext shorter than a tag",
                with(LABEL_CIPHERTEXT, Some(Value::Bytes(vec![0; 15]))),
            ),
            ("a text label", {
                let mut altered = members.clone();
                altered[0].0 = text("v");
                cbor::encode(&Value::Map(altered))
            }),
        ];
        for (name, bytes) in refused {
            assert!(SealedKey::decode(&bytes).is_err(), "{name} was accepted");
        }

        // Non-preferred encodings and duplicate labels never reach the member checks.
        let mut long_v = bytes.clone();
        assert_eq!(&long_v[..3], &[0xa8, 0x01, 0x01], "v is the first member");
        long_v.splice(2..3, [0x18, 0x01]);
        assert!(
            SealedKey::decode(&long_v).is_err(),
            "a non-preferred integer was accepted"
        );
        let mut duplicate = bytes.clone();
        duplicate[0] = 0xa9;
        duplicate.splice(3..3, [0x01, 0x01]);
        assert!(
            SealedKey::decode(&duplicate).is_err(),
            "a duplicate label was accepted"
        );
        assert!(SealedKey::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn test_without_randomness_nothing_is_sealed_and_no_provider_is_minted() {
        let kek = provider("secret://kek", 1);
        let (pkcs8, _, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);

        assert_eq!(
            SealedKey::seal(&pkcs8, &bound, &kek, &Exhausted).err(),
            Some(SealError::Entropy(EntropyUnavailable))
        );
        assert!(LocalKeyWrap::generate("secret://kek", 1, Box::new(Exhausted)).is_err());
        let starved = LocalKeyWrap::new(
            "secret://kek",
            1,
            Zeroizing::new([1; DEK_LEN]),
            Box::new(Exhausted),
        );
        assert!(matches!(
            SealedKey::seal(&pkcs8, &bound, &starved, &SystemEntropy),
            Err(SealError::Wrap(WrapError::Unavailable(_)))
        ));
    }

    #[test]
    fn test_a_kek_stops_wrapping_at_its_usage_limit() {
        let mut kek = provider("secret://kek", 1);
        kek.limit = 2;
        let (pkcs8, public, kid) = key(Suite::Ed25519Sha256V1);
        let bound = binding(&HOST, &kid, Suite::Ed25519Sha256V1);

        let first = SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();
        SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).unwrap();
        assert_eq!(
            SealedKey::seal(&pkcs8, &bound, &kek, &SystemEntropy).err(),
            Some(SealError::Wrap(WrapError::UsageLimit))
        );
        assert!(
            first.open(&bound, &kek, &public).is_ok(),
            "a KEK at its limit still unwraps what it wrapped"
        );
    }
}
