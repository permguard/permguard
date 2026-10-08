// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PKCS#11 custody (WP-3.2, owner decisions of 2026-10-08), behind the `pkcs11` feature.
//!
//! | Object        | In the token                                                         |
//! | ------------- | -------------------------------------------------------------------- |
//! | a ring's key  | an EC or EdDSA key pair, private half sensitive and non-extractable, labelled `<ring>:<thumbprint>` |
//! | the KEK       | an AES key, non-extractable, labelled with `operations.keys.kek_ref`  |
//!
//! The ring keeps each key's label in `private/<slot>.ref`. A DEK is wrapped by AES-GCM in the
//! token with a fresh 96-bit IV and the exact wrap context as associated data, `iv ‖ ciphertext ‖
//! tag`. The module is the operator's (`operations.keys.pkcs11.module`), the token found by its
//! label and the PIN resolved from the secret store.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::Context as _;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::{AuthPin, Ulong};
use zeroize::Zeroizing;

use permguard_host::identity::Suite;
use permguard_host::keys::custody::{Dek, Remote, Wrap, WrapError};
use permguard_host::keys::{Custody, KeyError, KeyProvider, PublicKey};
use permguard_host::storage::Dir;
use permguard_host::storage::write::{Published, publish_immutable};

/// The wrapping algorithm a PKCS#11 KEK writes.
pub const WRAP_PKCS11: &str = permguard_core::domains::format::PKCS11_KEK_WRAP_V1;

/// DER of the Ed25519 curve OID, 1.3.101.112.
const ED25519_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER of the P-256 curve OID, 1.2.840.10045.3.1.7.
const P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Where the token is.
pub struct Token {
    pub module: std::path::PathBuf,
    pub label: String,
    pub pin: Zeroizing<String>,
}

/// An open, logged-in session on the token.
pub struct Hsm {
    // Kept for the life of the session: the module stays loaded while the session is used.
    _context: Pkcs11,
    session: Mutex<Session>,
}

impl fmt::Debug for Hsm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hsm").finish_non_exhaustive()
    }
}

fn hsm_error(error: impl fmt::Display) -> KeyError {
    KeyError::Malformed(format!("the PKCS#11 token: {error}"))
}

impl Hsm {
    /// Loads the module, finds the token by its label and logs in with the PIN.
    pub fn open(token: Token) -> anyhow::Result<Arc<Self>> {
        let context = Pkcs11::new(&token.module)
            .with_context(|| format!("loading the PKCS#11 module {}", token.module.display()))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("initializing the PKCS#11 module")?;
        let slot = context
            .get_slots_with_token()
            .context("listing the PKCS#11 slots")?
            .into_iter()
            .find(|slot| {
                context
                    .get_token_info(*slot)
                    .is_ok_and(|info| info.label().trim() == token.label)
            })
            .with_context(|| format!("no PKCS#11 token is labelled `{}`", token.label))?;
        let session = context
            .open_rw_session(slot)
            .context("opening a PKCS#11 session")?;
        session
            .login(UserType::User, Some(&AuthPin::from(token.pin.as_str())))
            .context("logging in to the PKCS#11 token")?;
        Ok(Arc::new(Self {
            _context: context,
            session: Mutex::new(session),
        }))
    }

    fn session(&self) -> std::sync::MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The one object of `class` labelled `label`.
    fn find(&self, class: ObjectClass, label: &str) -> Result<ObjectHandle, KeyError> {
        let found = self
            .session()
            .find_objects(&[
                Attribute::Class(class),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(hsm_error)?;
        match found.as_slice() {
            [one] => Ok(*one),
            [] => Err(KeyError::Absent(label.to_owned())),
            _ => Err(hsm_error(format!("`{label}` names several objects"))),
        }
    }
}

/// A ring's keys in the token, their labels in `<slot>.ref` below `dir`.
pub struct HsmKeys {
    hsm: Arc<Hsm>,
    dir: Dir,
    ring: &'static str,
}

impl fmt::Debug for HsmKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmKeys")
            .field("ring", &self.ring)
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

/// The raw point of a `CKA_EC_POINT`: the DER OCTET STRING PKCS#11 specifies, or the bare point
/// some tokens answer, each recognised by its exact length.
fn point_of(bytes: &[u8], suite: Suite) -> Result<Vec<u8>, KeyError> {
    let length = suite.public_key_len();
    let raw = match bytes {
        [0x04, wrapped, rest @ ..] if usize::from(*wrapped) == length && rest.len() == length => {
            rest
        }
        bare if bare.len() == length => bare,
        _ => {
            return Err(hsm_error(format!(
                "the token's public key is not a {suite} key"
            )));
        }
    };
    if suite == Suite::P256Sha256V1 && raw.first() != Some(&0x04) {
        return Err(hsm_error("the token's P-256 point is not uncompressed"));
    }
    Ok(raw.to_vec())
}

impl HsmKeys {
    fn reference(slot: &str) -> String {
        format!("{slot}.ref")
    }

    /// The label `<slot>.ref` names: `<ring>:<thumbprint>`, never another ring's key or the KEK's
    /// label copied in. A ring's slot is its key's thumbprint, so the label is exactly
    /// `<ring>:<slot>`; the identity's slot is its epoch, and its open compares the key it finds
    /// with its signed document.
    fn label_of(&self, slot: &str) -> Result<String, KeyError> {
        let bytes = self
            .dir
            .read(&Self::reference(slot))?
            .ok_or_else(|| KeyError::Absent(slot.to_owned()))?;
        let refused = || KeyError::Malformed(format!("`{slot}.ref` names no key of this ring"));
        let label = String::from_utf8(bytes).map_err(|_| refused())?;
        let thumbprint = label
            .strip_prefix(self.ring)
            .and_then(|rest| rest.strip_prefix(':'))
            .ok_or_else(refused)?;
        let named = if self.ring == permguard_host::keys::ring::HOST_IDENTITY {
            permguard_host::keys::is_thumbprint(thumbprint)
        } else {
            thumbprint == slot
        };
        if !named {
            return Err(refused());
        }
        Ok(label)
    }

    /// Generates a key pair in the token, private half sensitive and non-extractable, labelled
    /// `<ring>:<thumbprint>`.
    fn create(&self, suite: Suite) -> Result<(String, PublicKey), KeyError> {
        let (mechanism, params, key_type) = match suite {
            Suite::Ed25519Sha256V1 => (
                Mechanism::EccEdwardsKeyPairGen,
                ED25519_PARAMS,
                KeyType::EC_EDWARDS,
            ),
            Suite::P256Sha256V1 => (Mechanism::EccKeyPairGen, P256_PARAMS, KeyType::EC),
        };
        let session = self.hsm.session();
        let (public, private) = session
            .generate_key_pair(
                &mechanism,
                &[
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::KeyType(key_type),
                    Attribute::EcParams(params.to_vec()),
                ],
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Sign(true),
                    Attribute::KeyType(key_type),
                ],
            )
            .map_err(hsm_error)?;
        let point = session
            .get_attributes(public, &[AttributeType::EcPoint])
            .map_err(hsm_error)?
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::EcPoint(point) => Some(point),
                _ => None,
            })
            .ok_or_else(|| hsm_error("the token showed no public point"))?;
        let public_key = PublicKey {
            suite,
            bytes: point_of(&point, suite)?,
        };
        let thumbprint = permguard_host::keys::thumbprint_of(&public_key)?;
        let label = format!("{}:{thumbprint}", self.ring).into_bytes();
        for handle in [public, private] {
            session
                .update_attributes(handle, &[Attribute::Label(label.clone())])
                .map_err(hsm_error)?;
        }
        Ok((format!("{}:{thumbprint}", self.ring), public_key))
    }

    fn remember(&self, slot: &str, label: &str) -> Result<(), KeyError> {
        let reference = Self::reference(slot);
        let readable = |bytes: &[u8]| std::str::from_utf8(bytes).is_ok();
        let same = |bytes: &[u8]| bytes == label.as_bytes();
        match publish_immutable(&self.dir, &reference, label.as_bytes(), &readable, &same)? {
            Published::Written => Ok(()),
            Published::AlreadyThere => Err(KeyError::Exists(slot.to_owned())),
        }
    }
}

impl KeyProvider for HsmKeys {
    fn name(&self) -> &'static str {
        "pkcs11"
    }

    fn custody(&self) -> Custody {
        Custody::Hsm
    }

    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        if self.dir.read(&Self::reference(slot))?.is_some() {
            return Err(KeyError::Exists(slot.to_owned()));
        }
        let (label, public) = self.create(suite)?;
        self.remember(slot, &label)?;
        Ok(public)
    }

    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), KeyError> {
        let (label, public) = self.create(suite)?;
        let slot = permguard_host::keys::thumbprint_of(&public)?;
        self.remember(&slot, &label)?;
        Ok((slot, public))
    }

    fn slots(&self) -> Result<Vec<String>, KeyError> {
        Ok(self
            .dir
            .names()?
            .into_iter()
            .filter_map(|name| name.strip_suffix(".ref").map(str::to_owned))
            .collect())
    }

    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        let label = self.label_of(slot)?;
        let handle = self.hsm.find(ObjectClass::PUBLIC_KEY, &label)?;
        let point = self
            .hsm
            .session()
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(hsm_error)?
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::EcPoint(point) => Some(point),
                _ => None,
            })
            .ok_or_else(|| hsm_error("the token showed no public point"))?;
        Ok(PublicKey {
            suite,
            bytes: point_of(&point, suite)?,
        })
    }

    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let label = self.label_of(slot)?;
        let handle = self.hsm.find(ObjectClass::PRIVATE_KEY, &label)?;
        let mechanism = match suite {
            Suite::Ed25519Sha256V1 => {
                Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))
            }
            Suite::P256Sha256V1 => Mechanism::EcdsaSha256,
        };
        let signature = self
            .hsm
            .session()
            .sign(&mechanism, handle, message)
            .map_err(hsm_error)?;
        // A token does not choose the low-s twin of a P-256 signature: this profile does.
        suite
            .canonical_signature(&signature)
            .map(|signature| signature.to_vec())
            .map_err(hsm_error)
    }

    fn destroy(&self, slot: &str) -> Result<(), KeyError> {
        let label = self.label_of(slot)?;
        for class in [ObjectClass::PRIVATE_KEY, ObjectClass::PUBLIC_KEY] {
            match self.hsm.find(class, &label) {
                Ok(handle) => self
                    .hsm
                    .session()
                    .destroy_object(handle)
                    .map_err(hsm_error)?,
                Err(KeyError::Absent(_)) => {}
                Err(error) => return Err(error),
            }
        }
        permguard_host::storage::tombstone::delete(&self.dir, &Self::reference(slot))?;
        Ok(())
    }
}

/// The token shared by every ring that keeps its keys there.
#[derive(Debug, Clone)]
pub struct SharedHsm(pub Arc<Hsm>);

impl Remote for SharedHsm {
    fn provider(&self, ring: &'static str, dir: Dir) -> Result<Arc<dyn KeyProvider>, KeyError> {
        Ok(Arc::new(HsmKeys {
            hsm: Arc::clone(&self.0),
            dir,
            ring,
        }))
    }
}

/// A KEK in the token: an AES key labelled with `operations.keys.kek_ref`.
pub struct HsmKek {
    hsm: Arc<Hsm>,
    label: String,
    version: u64,
}

impl fmt::Debug for HsmKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmKek")
            .field("label", &self.label)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl HsmKek {
    /// The token's AES key labelled `label`, checked to be what a KEK must be: a 256-bit AES key,
    /// sensitive, not extractable, able to encrypt and decrypt.
    pub fn open(hsm: Arc<Hsm>, label: &str, version: u64) -> anyhow::Result<Self> {
        let handle = hsm
            .find(ObjectClass::SECRET_KEY, label)
            .map_err(|error| anyhow::anyhow!("the KEK `{label}` in the token: {error}"))?;
        let attributes = hsm
            .session()
            .get_attributes(
                handle,
                &[
                    AttributeType::KeyType,
                    AttributeType::ValueLen,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::AlwaysSensitive,
                    AttributeType::NeverExtractable,
                ],
            )
            .map_err(|error| anyhow::anyhow!("the KEK `{label}` in the token: {error}"))?;
        let held = |wanted: &Attribute| attributes.iter().any(|attribute| attribute == wanted);
        if !(held(&Attribute::KeyType(KeyType::AES))
            && held(&Attribute::ValueLen(32.into()))
            && held(&Attribute::Sensitive(true))
            && held(&Attribute::Extractable(false))
            && held(&Attribute::Encrypt(true))
            && held(&Attribute::Decrypt(true))
            && held(&Attribute::AlwaysSensitive(true))
            && held(&Attribute::NeverExtractable(true)))
        {
            anyhow::bail!(
                "the KEK `{label}` in the token is a 256-bit AES key, always sensitive and never \
                 extractable, that encrypts and decrypts"
            );
        }
        Ok(Self {
            hsm,
            label: label.to_owned(),
            version,
        })
    }
}

const TAG_BITS: std::os::raw::c_ulong = 128;

impl Wrap for HsmKek {
    fn kek_ref(&self) -> &str {
        &self.label
    }

    fn kek_version(&self) -> u64 {
        self.version
    }

    fn wrap_algorithm(&self) -> &str {
        WRAP_PKCS11
    }

    fn wrap(&self, dek: &Dek, context: &[u8]) -> Result<Vec<u8>, WrapError> {
        let key = self
            .hsm
            .find(ObjectClass::SECRET_KEY, &self.label)
            .map_err(|error| WrapError::Unavailable(error.to_string()))?;
        let mut iv = [0u8; 12];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut iv)
            .map_err(|_| WrapError::Unavailable("the random source refused".to_owned()))?;
        let mut out = iv.to_vec();
        let params = GcmParams::new(&mut iv, context, Ulong::from(TAG_BITS))
            .map_err(|error| WrapError::Unavailable(error.to_string()))?;
        out.extend(
            self.hsm
                .session()
                .encrypt(&Mechanism::AesGcm(params), key, dek.expose())
                .map_err(|error| WrapError::Unavailable(error.to_string()))?,
        );
        Ok(out)
    }

    fn unwrap(&self, kek_version: u64, wrapped: &[u8], context: &[u8]) -> Result<Dek, WrapError> {
        if kek_version != self.version {
            return Err(WrapError::VersionUnknown(kek_version));
        }
        if wrapped.len() != 12 + 32 + 16 {
            return Err(WrapError::Rejected);
        }
        let key = self
            .hsm
            .find(ObjectClass::SECRET_KEY, &self.label)
            .map_err(|error| WrapError::Unavailable(error.to_string()))?;
        let mut iv: [u8; 12] = wrapped[..12].try_into().map_err(|_| WrapError::Rejected)?;
        let params = GcmParams::new(&mut iv, context, Ulong::from(TAG_BITS))
            .map_err(|_| WrapError::Rejected)?;
        // A failed tag is a rejection; the token failing is not, and the start says so.
        let plaintext = Zeroizing::new(
            self.hsm
                .session()
                .decrypt(&Mechanism::AesGcm(params), key, &wrapped[12..])
                .map_err(|error| match error {
                    cryptoki::error::Error::Pkcs11(
                        cryptoki::error::RvError::EncryptedDataInvalid
                        | cryptoki::error::RvError::EncryptedDataLenRange,
                        _,
                    ) => WrapError::Rejected,
                    other => WrapError::Unavailable(format!("the PKCS#11 token: {other}")),
                })?,
        );
        let mut bytes = Zeroizing::new([0u8; 32]);
        if plaintext.len() != bytes.len() {
            return Err(WrapError::Rejected);
        }
        bytes.copy_from_slice(&plaintext);
        Ok(Dek::from_unwrapped(bytes))
    }
}
