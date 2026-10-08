// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where the Host's private keys are held (WP-3.2).
//!
//! | Custody       | Provider                | At rest                                                     |
//! | ------------- | ----------------------- | ----------------------------------------------------------- |
//! | `development` | [`super::FileKeyProvider`] | PKCS#8 in the clear: the `custody.plaintext` relaxation  |
//! | `file`        | [`SealedFileKeyProvider`]  | `permguard.sealed-key.v1`: one DEK per blob, wrapped by the KEK |
//! | `pkcs11`      | the PKCS#11 provider    | a non-extractable handle in the token                       |
//! | `kms`         | the Vault Transit provider | a non-exportable key in the KMS                          |
//!
//! The `file` custody seals each private key under a fresh DEK, AES-256-GCM with the content
//! context as associated data, and wraps the DEK through a [`KeyWrap`] bound to the exact wrap
//! context (`permguard_objects::crypto::seal`). Keys are unsealed into zeroized memory when they
//! are first used, which a ring and the identity do at Bootstrap. At Bootstrap a key still held in
//! plaintext is sealed in place, and a blob under the previous KEK is rewrapped under the current
//! one: the DEK only, the ciphertext unchanged (owner decisions of 2026-10-08).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroizing;

use permguard_objects::crypto::random::{self, SystemEntropy};
use permguard_objects::crypto::seal::{
    self, Binding, DEK_LEN, KEK_WRAP_LIMIT, KeyWrap, NONCE_LEN, SealedKey, TAG_LEN,
};
use permguard_objects::crypto::suite::{SigningKey, Suite};
use permguard_objects::crypto::thumbprint;

pub use permguard_objects::crypto::seal::{Dek, KeyWrap as Wrap, SealedKey as Sealed, WrapError};

use permguard_core::config::KeyCustody;

use super::{Custody, FileKeyProvider, KeyError, KeyProvider, PublicKey};
use crate::secrets::Root;
use crate::storage::write::{Published, publish_immutable, replace_bytes};
use crate::storage::{Dir, tombstone};

/// The wrapping algorithm of a KEK held in the secret store (owner decision of 2026-10-08):
/// AES-256-GCM under a fresh nonce, the wrap context as associated data, `nonce ‖ ciphertext ‖
/// tag`.
pub const WRAP_SECRET: &str = permguard_core::domains::format::SECRET_KEK_WRAP_V1;

/// A key-encryption key held as a 32-byte root of the secret store.
pub struct SecretKek {
    kek_ref: String,
    version: u64,
    key: Zeroizing<[u8; DEK_LEN]>,
    wraps: AtomicU64,
}

impl fmt::Debug for SecretKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKek")
            .field("kek_ref", &self.kek_ref)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl SecretKek {
    /// The KEK `kek_ref` at the version `root` was resolved at: exactly 32 bytes.
    pub fn from_root(kek_ref: &str, root: &Root) -> Result<Self, KeyError> {
        let material = root.material();
        let key: [u8; DEK_LEN] = material.try_into().map_err(|_| {
            KeyError::Malformed(format!(
                "the key-encryption key `{kek_ref}` is {} bytes, and a KEK is exactly {DEK_LEN}",
                material.len()
            ))
        })?;
        Ok(Self {
            kek_ref: kek_ref.to_owned(),
            version: root.version().get(),
            key: Zeroizing::new(key),
            wraps: AtomicU64::new(0),
        })
    }
}

impl KeyWrap for SecretKek {
    fn kek_ref(&self) -> &str {
        &self.kek_ref
    }

    fn kek_version(&self) -> u64 {
        self.version
    }

    fn wrap_algorithm(&self) -> &str {
        WRAP_SECRET
    }

    fn wrap(&self, dek: &Dek, context: &[u8]) -> Result<Vec<u8>, WrapError> {
        // Counted before the nonce is drawn: random 96-bit nonces under one key are bounded.
        if self.wraps.fetch_add(1, Ordering::SeqCst) >= KEK_WRAP_LIMIT {
            return Err(WrapError::UsageLimit);
        }
        let nonce = random::bytes::<NONCE_LEN>(&SystemEntropy)
            .map_err(|error| WrapError::Unavailable(error.to_string()))?;
        let mut out = nonce.to_vec();
        out.extend(
            seal::aes256gcm_seal(&self.key, &nonce, context, dek.expose())
                .map_err(|error| WrapError::Unavailable(error.to_string()))?,
        );
        Ok(out)
    }

    fn unwrap(&self, kek_version: u64, wrapped: &[u8], context: &[u8]) -> Result<Dek, WrapError> {
        if kek_version != self.version {
            return Err(WrapError::VersionUnknown(kek_version));
        }
        if wrapped.len() != NONCE_LEN + DEK_LEN + TAG_LEN {
            return Err(WrapError::Rejected);
        }
        let nonce: [u8; NONCE_LEN] = wrapped[..NONCE_LEN]
            .try_into()
            .map_err(|_| WrapError::Rejected)?;
        let dek = seal::aes256gcm_open(&self.key, &nonce, context, &wrapped[NONCE_LEN..])
            .map_err(|_| WrapError::Rejected)?;
        let mut bytes = Zeroizing::new([0u8; DEK_LEN]);
        bytes.copy_from_slice(&dek);
        Ok(Dek::from_unwrapped(bytes))
    }
}

/// The KEK that wraps today, and the one a rotation left behind, whose blobs are rewrapped.
#[derive(Clone)]
pub struct Keks {
    pub current: Arc<dyn KeyWrap>,
    pub previous: Option<Arc<dyn KeyWrap>>,
}

impl fmt::Debug for Keks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keks")
            .field(
                "current",
                &(self.current.kek_ref(), self.current.kek_version()),
            )
            .field(
                "previous",
                &self
                    .previous
                    .as_ref()
                    .map(|kek| (kek.kek_ref().to_owned(), kek.kek_version())),
            )
            .finish()
    }
}

/// Where a slot's stored public key is read: the ring's `public/<thumbprint>.jwk`, the identity's
/// `<epoch>.pub`. A sealed key opens only as the key stored there.
pub type StoredPublic = Box<dyn Fn(&str, Suite) -> Result<Option<Vec<u8>>, KeyError> + Send + Sync>;

/// What [`SealedFileKeyProvider::prepare`] did at Bootstrap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prepared {
    /// Slots whose plaintext key was sealed in place.
    pub sealed: Vec<String>,
    /// Slots whose DEK was rewrapped under the current KEK.
    pub rewrapped: Vec<String>,
}

/// Whether `bytes` are a plaintext PKCS#8 document rather than a sealed key: DER starts with a
/// SEQUENCE, a sealed key with an eight-member CBOR map.
fn is_plaintext(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x30)
}

/// Private keys sealed in files below one directory, `0600` below `0700`.
pub struct SealedFileKeyProvider {
    dir: Dir,
    host_id: [u8; 16],
    ring: &'static str,
    keks: Keks,
    stored: StoredPublic,
    /// Keys unsealed once, held for signing; their PKCS#8 was erased when they were opened.
    unsealed: Mutex<BTreeMap<String, Arc<SigningKey>>>,
}

impl fmt::Debug for SealedFileKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedFileKeyProvider")
            .field("dir", &self.dir.path())
            .field("ring", &self.ring)
            .field("keks", &self.keks)
            .finish_non_exhaustive()
    }
}

impl SealedFileKeyProvider {
    /// Over `dir`, which the caller created `0700`, for `ring` of `host_id`.
    pub fn new(
        dir: Dir,
        host_id: [u8; 16],
        ring: &'static str,
        keks: Keks,
        stored: StoredPublic,
    ) -> Self {
        Self {
            dir,
            host_id,
            ring,
            keks,
            stored,
            unsealed: Mutex::new(BTreeMap::new()),
        }
    }

    fn kid_of(&self, suite: Suite, public: &[u8]) -> Result<String, KeyError> {
        thumbprint::jwk_thumbprint(suite, public)
            .map(|thumbprint| thumbprint::kid(self.ring, &thumbprint))
            .map_err(|error| KeyError::Malformed(error.to_string()))
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Arc<SigningKey>>> {
        self.unsealed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn file(slot: &str) -> Result<String, KeyError> {
        FileKeyProvider::name_of(slot)
    }

    /// Seals `pkcs8` for `slot` under the current KEK.
    fn seal(&self, suite: Suite, pkcs8: &[u8], public: &[u8]) -> Result<Vec<u8>, KeyError> {
        let kid = self.kid_of(suite, public)?;
        let binding = Binding {
            host_id: &self.host_id,
            ring: self.ring,
            kid: &kid,
            suite,
        };
        SealedKey::seal(pkcs8, &binding, self.keks.current.as_ref(), &SystemEntropy)
            .and_then(|sealed| sealed.encode())
            .map_err(|error| KeyError::Malformed(format!("sealing `{kid}`: {error}")))
    }

    /// Generates a key, seals it and publishes it in `slot`, which must be empty.
    fn generate_in(
        &self,
        slot: Option<&str>,
        suite: Suite,
    ) -> Result<(String, PublicKey), KeyError> {
        let pkcs8 = Zeroizing::new(SigningKey::generate_pkcs8(suite).map_err(|error| {
            KeyError::Malformed(format!("generating a {suite} key: {error:?}"))
        })?);
        let key = SigningKey::from_pkcs8(suite, &pkcs8)
            .map_err(|error| KeyError::Malformed(format!("reading a {suite} key: {error:?}")))?;
        let public = key.public_key().to_vec();
        let slot = match slot {
            Some(slot) => slot.to_owned(),
            None => thumbprint::jwk_thumbprint(suite, &public)
                .map_err(|error| KeyError::Malformed(error.to_string()))?,
        };
        let name = Self::file(&slot)?;
        if self.dir.read(&name)?.is_some() {
            return Err(KeyError::Exists(slot));
        }
        let sealed = self.seal(suite, &pkcs8, &public)?;
        let readable = |bytes: &[u8]| SealedKey::decode(bytes).is_ok();
        let same = |bytes: &[u8]| bytes == sealed.as_slice();
        match publish_immutable(&self.dir, &name, &sealed, &readable, &same)? {
            Published::Written => {}
            Published::AlreadyThere => return Err(KeyError::Exists(slot)),
        }
        self.cache().insert(slot.clone(), Arc::new(key));
        Ok((
            slot,
            PublicKey {
                suite,
                bytes: public,
            },
        ))
    }

    /// The stored public key of `slot`, which a sealed key must open as.
    fn stored_public(&self, slot: &str, suite: Suite) -> Result<Vec<u8>, KeyError> {
        (self.stored)(slot, suite)?.ok_or_else(|| {
            KeyError::Malformed(format!(
                "no public key is stored for `{slot}`: a sealed key opens only as its stored one"
            ))
        })
    }

    /// The KEK a blob was wrapped under: the current one, or the previous one a rotation left.
    fn kek_for(&self, sealed: &SealedKey) -> Result<&Arc<dyn KeyWrap>, KeyError> {
        let matches = |kek: &Arc<dyn KeyWrap>| {
            kek.kek_ref() == sealed.kek_ref && kek.kek_version() == sealed.kek_version
        };
        if matches(&self.keks.current) {
            return Ok(&self.keks.current);
        }
        self.keks
            .previous
            .as_ref()
            .filter(|kek| matches(kek))
            .ok_or_else(|| {
                KeyError::Malformed(format!(
                    "a sealed key is wrapped under `{}` v{}, which is neither the configured \
                     key-encryption key nor the previous one",
                    sealed.kek_ref, sealed.kek_version
                ))
            })
    }

    /// Unseals `slot` into memory, once: the binding is this Host, ring, kid and suite, and the
    /// key must be the one stored.
    fn open(&self, slot: &str, suite: Suite) -> Result<Arc<SigningKey>, KeyError> {
        if let Some(key) = self.cache().get(slot) {
            return Ok(Arc::clone(key));
        }
        let name = Self::file(slot)?;
        let bytes = self
            .dir
            .read(&name)?
            .ok_or_else(|| KeyError::Absent(slot.to_owned()))?;
        if is_plaintext(&bytes) {
            return Err(KeyError::Malformed(format!(
                "`{slot}` is held in plaintext, and the `file` custody opens sealed keys only: \
                 the start seals it"
            )));
        }
        let sealed = SealedKey::decode(&bytes)
            .map_err(|error| KeyError::Malformed(format!("`{slot}`: {error}")))?;
        let stored = self.stored_public(slot, suite)?;
        let kid = self.kid_of(suite, &stored)?;
        let binding = Binding {
            host_id: &self.host_id,
            ring: self.ring,
            kid: &kid,
            suite,
        };
        let unsealed = sealed
            .open(&binding, self.kek_for(&sealed)?.as_ref(), &stored)
            .map_err(|error| KeyError::Malformed(format!("opening `{kid}`: {error}")))?;
        // The PKCS#8 buffer is erased here; the key the provider keeps signs and nothing else.
        let key = Arc::new(unsealed.key);
        drop(unsealed.pkcs8);
        self.cache().insert(slot.to_owned(), Arc::clone(&key));
        Ok(key)
    }

    /// At Bootstrap: seals every key still in plaintext in place, and rewraps every blob under
    /// the previous KEK under the current one; a blob under any other KEK fails. Each key is
    /// checked against its stored public key first, and unsealed after.
    pub fn prepare(&self, suite: Suite) -> Result<Prepared, KeyError> {
        self.walk(suite, true)
    }

    /// What [`Self::prepare`] would do, every key checked and nothing written: the ring journals
    /// it before it is done, so a crash between the two leaves an entry and a key to seal again,
    /// never a sealed key without its entry.
    pub fn plan(&self, suite: Suite) -> Result<Prepared, KeyError> {
        self.walk(suite, false)
    }

    fn walk(&self, suite: Suite, write: bool) -> Result<Prepared, KeyError> {
        let mut prepared = Prepared::default();
        for slot in self.slots()? {
            let name = Self::file(&slot)?;
            let Some(bytes) = self.dir.read(&name)? else {
                continue;
            };
            let bytes = Zeroizing::new(bytes);
            if is_plaintext(&bytes) {
                let key = SigningKey::from_pkcs8(suite, &bytes).map_err(|error| {
                    KeyError::Malformed(format!(
                        "`{slot}` is not a {suite} PKCS#8 document carrying its public key: \
                         {error:?}"
                    ))
                })?;
                let public = key.public_key().to_vec();
                if let Some(stored) = (self.stored)(&slot, suite)?
                    && stored != public
                {
                    return Err(KeyError::Malformed(format!(
                        "`{slot}` holds another key than the one stored"
                    )));
                }
                if write {
                    let sealed = self.seal(suite, &bytes, &public)?;
                    replace_bytes(&self.dir, &name, &sealed)?;
                }
                prepared.sealed.push(slot.clone());
            } else {
                // A sealed key whose public half was never stored — generated before a crash,
                // before the ring published it — is no key of the ring's: maintenance removes it,
                // and it neither blocks a rotation nor needs the KEK it was sealed under.
                if (self.stored)(&slot, suite)?.is_none() {
                    continue;
                }
                let sealed = SealedKey::decode(&bytes)
                    .map_err(|error| KeyError::Malformed(format!("`{slot}`: {error}")))?;
                let kek = self.kek_for(&sealed)?;
                if !Arc::ptr_eq(kek, &self.keks.current) {
                    let stored = self.stored_public(&slot, suite)?;
                    let kid = self.kid_of(suite, &stored)?;
                    let binding = Binding {
                        host_id: &self.host_id,
                        ring: self.ring,
                        kid: &kid,
                        suite,
                    };
                    let rewrapped = sealed
                        .rewrap(&binding, kek.as_ref(), self.keks.current.as_ref())
                        .and_then(|rewrapped| rewrapped.encode())
                        .map_err(|error| {
                            KeyError::Malformed(format!("rewrapping `{kid}`: {error}"))
                        })?;
                    if write {
                        replace_bytes(&self.dir, &name, &rewrapped)?;
                    }
                    prepared.rewrapped.push(slot.clone());
                }
            }
        }
        Ok(prepared)
    }
}

impl KeyProvider for SealedFileKeyProvider {
    fn name(&self) -> &'static str {
        "file"
    }

    fn custody(&self) -> Custody {
        Custody::Encrypted
    }

    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        self.generate_in(Some(slot), suite)
            .map(|(_, public)| public)
    }

    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), KeyError> {
        self.generate_in(None, suite)
    }

    fn slots(&self) -> Result<Vec<String>, KeyError> {
        Ok(self
            .dir
            .names()?
            .into_iter()
            .filter_map(|name| name.strip_suffix(".key").map(str::to_owned))
            .filter(|slot| Self::file(slot).is_ok())
            .collect())
    }

    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        let key = self.open(slot, suite)?;
        Ok(PublicKey {
            suite,
            bytes: key.public_key().to_vec(),
        })
    }

    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let key = self.open(slot, suite)?;
        key.sign(message)
            .map(|signature| signature.to_vec())
            .map_err(|error| KeyError::Malformed(format!("signing with `{slot}`: {error:?}")))
    }

    fn destroy(&self, slot: &str) -> Result<(), KeyError> {
        let name = Self::file(slot)?;
        self.cache().remove(slot);
        tombstone::delete(&self.dir, &name)?;
        Ok(())
    }
}

/// A provider of non-exportable keys a custody brings: the PKCS#11 token, the KMS.
pub trait Remote: Send + Sync {
    /// The provider holding `ring`'s keys, their references kept below `dir`.
    fn provider(&self, ring: &'static str, dir: Dir) -> Result<Arc<dyn KeyProvider>, KeyError>;
}

/// Chooses each ring's provider from its custody (WP-3.2, owner decisions of 2026-10-08).
/// Refuses a remote custody over a directory that still holds key files: keys a `development` or
/// `file` custody wrote — a volume provisioned without the server's configuration, a custody
/// changed in place — which no token or KMS holds, and which would otherwise read as lost.
fn no_files_left(dir: &Dir, ring: &str, custody: &str) -> Result<(), KeyError> {
    if let Some(file) = dir.names()?.into_iter().find(|name| name.ends_with(".key")) {
        return Err(KeyError::Malformed(format!(
            "`{ring}` is on the `{custody}` custody and holds the key file `{file}`: it was \
             written by the `development` or `file` custody (a volume provisioned without the \
             server's configuration, or a custody changed in place), and a key is never moved \
             into a token or a KMS"
        )));
    }
    Ok(())
}

/// A ring's provider, with what its custody will do to the keys it found.
pub struct Custodied {
    pub provider: Arc<dyn KeyProvider>,
    /// The keys to seal and to rewrap.
    pub plan: Prepared,
    sealer: Option<(Arc<SealedFileKeyProvider>, Suite)>,
}

impl Custodied {
    fn held(provider: Arc<dyn KeyProvider>) -> Self {
        Self {
            provider,
            plan: Prepared::default(),
            sealer: None,
        }
    }

    /// Seals and rewraps what the plan names; what a crash already did is not done twice.
    pub fn apply(&self) -> Result<(), KeyError> {
        match &self.sealer {
            Some((sealer, suite)) => sealer.prepare(*suite).map(drop),
            None => Ok(()),
        }
    }
}

pub struct Custodian {
    custody_of: Box<dyn Fn(&str) -> KeyCustody + Send + Sync>,
    /// The KEKs, or why they could not be resolved: reported only when a `file` provider is
    /// asked for, so a start refused for another reason says that reason first.
    keks: Result<Option<Keks>, String>,
    hsm: Option<Arc<dyn Remote>>,
    kms: Option<Arc<dyn Remote>>,
}

impl fmt::Debug for Custodian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Custodian")
            .field("keks", &self.keks.as_ref().ok())
            .field("hsm", &self.hsm.is_some())
            .field("kms", &self.kms.is_some())
            .finish_non_exhaustive()
    }
}

impl Custodian {
    /// Each ring's custody from `custody_of`; `keks` for the `file` custody.
    pub fn new(
        custody_of: impl Fn(&str) -> KeyCustody + Send + Sync + 'static,
        keks: Result<Option<Keks>, String>,
    ) -> Self {
        Self {
            custody_of: Box::new(custody_of),
            keks,
            hsm: None,
            kms: None,
        }
    }

    /// Every ring in plaintext files: development, and the tests.
    pub fn development() -> Self {
        Self::new(|_| KeyCustody::Development, Ok(None))
    }

    /// The PKCS#11 token the `pkcs11` custody uses.
    pub fn with_hsm(mut self, hsm: Arc<dyn Remote>) -> Self {
        self.hsm = Some(hsm);
        self
    }

    /// The KMS the `kms` custody uses.
    pub fn with_kms(mut self, kms: Arc<dyn Remote>) -> Self {
        self.kms = Some(kms);
        self
    }

    /// The custody of `ring`.
    pub fn custody_of(&self, ring: &str) -> KeyCustody {
        (self.custody_of)(ring)
    }

    /// The provider of `ring` of `host_id`, over `dir`: a `file` custody seals what it finds in
    /// plaintext and rewraps what the previous KEK wrapped before the provider is handed out.
    pub fn provider(
        &self,
        ring: &'static str,
        host_id: [u8; 16],
        dir: Dir,
        stored: StoredPublic,
        suite: Suite,
    ) -> Result<(Arc<dyn KeyProvider>, Prepared), KeyError> {
        let custodied = self.plan(ring, host_id, dir, stored, suite)?;
        custodied.apply()?;
        Ok((custodied.provider, custodied.plan))
    }

    /// `ring`'s provider and what its custody will do to the keys found, not done yet:
    /// [`Custodied::apply`] does it, after the ring journaled it.
    pub fn plan(
        &self,
        ring: &'static str,
        host_id: [u8; 16],
        dir: Dir,
        stored: StoredPublic,
        suite: Suite,
    ) -> Result<Custodied, KeyError> {
        let remote = |held: &Option<Arc<dyn Remote>>, what: &str| {
            held.clone().ok_or_else(|| {
                KeyError::Malformed(format!(
                    "the `{what}` custody of `{ring}` has no provider in this process"
                ))
            })
        };
        match self.custody_of(ring) {
            KeyCustody::Development => Ok(Custodied::held(Arc::new(FileKeyProvider::new(dir)))),
            KeyCustody::File => {
                let keks = self
                    .keks
                    .clone()
                    .map_err(KeyError::Malformed)?
                    .ok_or_else(|| {
                        KeyError::Malformed(format!(
                            "the `file` custody of `{ring}` seals under a key-encryption key, \
                             and none is configured: set `operations.keys.kek_ref`"
                        ))
                    })?;
                let sealed = Arc::new(SealedFileKeyProvider::new(dir, host_id, ring, keks, stored));
                let plan = sealed.plan(suite)?;
                Ok(Custodied {
                    provider: Arc::clone(&sealed) as Arc<dyn KeyProvider>,
                    plan,
                    sealer: Some((sealed, suite)),
                })
            }
            KeyCustody::Pkcs11 => {
                no_files_left(&dir, ring, "pkcs11")?;
                Ok(Custodied::held(
                    remote(&self.hsm, "pkcs11")?.provider(ring, dir)?,
                ))
            }
            KeyCustody::Kms => {
                no_files_left(&dir, ring, "kms")?;
                Ok(Custodied::held(
                    remote(&self.kms, "kms")?.provider(ring, dir)?,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests;
