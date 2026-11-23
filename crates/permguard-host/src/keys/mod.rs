// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The common key provider port (WP-2.2): every private key the Host holds is generated, used
//! and destroyed through a [`KeyProvider`], so no part of the server or a Plane keeps a key
//! store of its own. The Host identity is its first user; the [`ring`] registry (WP-3.1) its
//! second; the custody providers (WP-3.2) follow.
//!
//! | Provider            | Custody                                                              |
//! | ------------------- | -------------------------------------------------------------------- |
//! | [`FileKeyProvider`] | PKCS#8 in the clear, a key a slot of its [`slots`]: plaintext custody |
//!
//! A slot names one key; the private bytes never leave the provider, and a slot once generated
//! is never generated again: a lost key is not silently replaced. A ring's slot is the key's own
//! RFC 7638 thumbprint ([`KeyProvider::generate_addressed`]), so the slot cannot name other
//! material.

pub mod bundle;
pub mod custody;
pub mod migration;
pub mod record;
pub mod registry;
pub mod ring;
pub mod slots;

use std::fmt;
use std::sync::Arc;

use permguard_objects::crypto::suite::{SigningKey, Suite};
use permguard_objects::crypto::thumbprint;
use permguard_objects::digest::Digest;

pub use permguard_objects::crypto::thumbprint::{is_thumbprint, selects};

use slots::{Kind, SlotStore};

/// How a provider keeps the private keys it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// The private bytes are on the volume in the clear: the `custody.plaintext` relaxation.
    Plaintext,
    /// Envelope-encrypted on the volume, one DEK per blob under a key-encryption key (WP-3.2).
    Encrypted,
    /// Non-exportable keys in a PKCS#11 token (WP-3.2).
    Hsm,
    /// Non-exportable keys in a remote KMS (WP-3.2).
    Kms,
}

/// A public key and its suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub suite: Suite,
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// `sha256:` over the canonical public key, the suite's raw encoding: the value an operator
    /// pins out of band.
    pub fn fingerprint(&self) -> String {
        Digest::compute(&self.bytes).to_string()
    }
}

/// Why a provider refused.
#[derive(Debug)]
pub enum KeyError {
    /// No key is held in the slot.
    Absent(String),
    /// The slot already holds a key: a key is generated once.
    Exists(String),
    /// The key held does not read as the suite asked.
    Malformed(String),
    /// What keeps the provider's keys could not be read or written.
    Unavailable(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent(slot) => write!(f, "no key is held in `{slot}`"),
            Self::Exists(slot) => {
                write!(f, "`{slot}` already holds a key; a key is generated once")
            }
            Self::Malformed(detail) => f.write_str(detail),
            Self::Unavailable(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The RFC 7638 thumbprint of `public`: the slot a ring's key is named by.
pub fn thumbprint_of(public: &PublicKey) -> Result<String, KeyError> {
    thumbprint::jwk_thumbprint(public.suite, &public.bytes)
        .map_err(|error| KeyError::Malformed(error.to_string()))
}

/// Where a Host's private keys live.
pub trait KeyProvider: Send + Sync {
    /// The provider's name, for the log and the status.
    fn name(&self) -> &'static str;
    /// How it keeps keys.
    fn custody(&self) -> Custody;
    /// Generates a key of `suite` in `slot`, which must be empty, and answers its public half.
    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError>;
    /// Generates a key of `suite` in the slot named by its RFC 7638 thumbprint, and answers the
    /// slot and the public half: a ring's key (WP-3.1).
    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), KeyError>;
    /// The slots the provider holds a key in.
    fn slots(&self) -> Result<Vec<String>, KeyError>;
    /// The public half of the key in `slot`, read as `suite`.
    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError>;
    /// Signs `message` with the key in `slot`, read as `suite`.
    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, KeyError>;
    /// Destroys the key in `slot`.
    fn destroy(&self, slot: &str) -> Result<(), KeyError>;

    /// Forgets what this process holds of the key in `slot`, so the next use reads the slot
    /// again: a key another instance put there, or one an undone attempt made, is never used
    /// from memory (iteration 03, WP-28.5). A provider that holds nothing in memory forgets
    /// nothing.
    fn forget(&self, _slot: &str) {}
}

/// Keys as PKCS#8 in the clear, each the key of its slot.
pub struct FileKeyProvider {
    slots: Arc<dyn SlotStore>,
}

impl fmt::Debug for FileKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKeyProvider").finish_non_exhaustive()
    }
}

impl FileKeyProvider {
    /// Over the slots `slots` keeps.
    pub fn over(slots: Arc<dyn SlotStore>) -> Self {
        Self { slots }
    }

    /// Takes over a key held before the rings (WP-3.1): `pkcs8` of `suite` lands in the slot named
    /// by its thumbprint, which is answered with the public half. The migration of a legacy ring
    /// is its only caller; a key is still never generated twice.
    pub fn import(&self, suite: Suite, pkcs8: &[u8]) -> Result<(String, PublicKey), KeyError> {
        let key = SigningKey::from_pkcs8(suite, pkcs8)
            .map_err(|error| KeyError::Malformed(format!("reading a {suite} key: {error:?}")))?;
        let slot = thumbprint::jwk_thumbprint(suite, key.public_key())
            .map_err(|error| KeyError::Malformed(error.to_string()))?;
        self.publish(&slot, suite, pkcs8)?;
        let public = self.public(&slot, suite)?;
        Ok((slot, public))
    }

    /// Publishes `pkcs8` as `slot`, which must hold nothing yet.
    fn publish(&self, slot: &str, suite: Suite, pkcs8: &[u8]) -> Result<(), KeyError> {
        // Read as its suite before it is kept: what does not read is never a slot's key.
        SigningKey::from_pkcs8(suite, pkcs8)
            .map_err(|error| KeyError::Malformed(format!("reading a {suite} key: {error:?}")))?;
        self.slots.fill(Kind::Key, slot, pkcs8)
    }

    fn load(&self, slot: &str, suite: Suite) -> Result<SigningKey, KeyError> {
        let pkcs8 = zeroize::Zeroizing::new(
            self.slots
                .read(Kind::Key, slot)?
                .ok_or_else(|| KeyError::Absent(slot.to_owned()))?,
        );
        SigningKey::from_pkcs8(suite, &pkcs8).map_err(|error| {
            KeyError::Malformed(format!(
                "{} does not read as a {suite} key: {error:?}",
                self.slots.place(Kind::Key, slot)
            ))
        })
    }
}

impl KeyProvider for FileKeyProvider {
    fn name(&self) -> &'static str {
        "file"
    }

    fn custody(&self) -> Custody {
        Custody::Plaintext
    }

    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        slots::check(slot)?;
        let pkcs8 =
            zeroize::Zeroizing::new(SigningKey::generate_pkcs8(suite).map_err(|error| {
                KeyError::Malformed(format!("generating a {suite} key: {error:?}"))
            })?);
        self.publish(slot, suite, &pkcs8)?;
        self.public(slot, suite)
    }

    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), KeyError> {
        let pkcs8 =
            zeroize::Zeroizing::new(SigningKey::generate_pkcs8(suite).map_err(|error| {
                KeyError::Malformed(format!("generating a {suite} key: {error:?}"))
            })?);
        let key = SigningKey::from_pkcs8(suite, &pkcs8)
            .map_err(|error| KeyError::Malformed(format!("reading a {suite} key: {error:?}")))?;
        let slot = thumbprint::jwk_thumbprint(suite, key.public_key())
            .map_err(|error| KeyError::Malformed(error.to_string()))?;
        self.publish(&slot, suite, &pkcs8)?;
        let public = self.public(&slot, suite)?;
        Ok((slot, public))
    }

    fn slots(&self) -> Result<Vec<String>, KeyError> {
        self.slots.slots(Kind::Key)
    }

    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        let key = self.load(slot, suite)?;
        Ok(PublicKey {
            suite,
            bytes: key.public_key().to_vec(),
        })
    }

    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let key = self.load(slot, suite)?;
        key.sign(message)
            .map(|signature| signature.to_vec())
            .map_err(|error| KeyError::Malformed(format!("signing with `{slot}`: {error:?}")))
    }

    fn destroy(&self, slot: &str) -> Result<(), KeyError> {
        self.slots.empty(Kind::Key, slot)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::storage::Dir;

    fn scratch(tag: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-keys-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Dir::open(&path).expect("opens")
    }

    /// The file backend of the slots passes the contract's suite, each case in a directory of
    /// its own.
    #[test]
    fn the_file_backend_of_the_slots_keeps_the_contract() {
        let made = std::sync::atomic::AtomicUsize::new(0);
        slots::suite::run(&|| {
            let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Arc::new(slots::files::FileSlots::new(scratch(&format!(
                "suite-{case}"
            ))))
        });
    }

    /// What only the file backend can prove: a slot is one file named for it, a key `.key` and a
    /// reference `.ref`, read back by a later process; a file that is no slot's is not listed.
    #[test]
    fn the_file_backend_keeps_a_slot_in_one_file_named_for_it() {
        let dir = scratch("slot-files");
        let store = slots::files::FileSlots::new(Dir::open(dir.path()).expect("opens"));
        store.fill(Kind::Key, "7", b"a key").expect("filled");
        store
            .fill(Kind::Reference, "7", b"a label")
            .expect("filled");
        assert_eq!(
            std::fs::read(dir.path().join("7.key")).expect("the file"),
            b"a key"
        );
        assert_eq!(
            std::fs::read(dir.path().join("7.ref")).expect("the file"),
            b"a label"
        );
        std::fs::write(dir.path().join("not a slot.key"), b"x").expect("written");
        std::fs::write(dir.path().join("7.pub"), b"x").expect("written");
        drop(store);
        let reopened = slots::files::FileSlots::new(Dir::open(dir.path()).expect("opens"));
        assert_eq!(reopened.slots(Kind::Key).expect("reads"), vec!["7"]);
        assert_eq!(reopened.slots(Kind::Reference).expect("reads"), vec!["7"]);
        assert_eq!(
            reopened.read(Kind::Key, "7").expect("reads").as_deref(),
            Some(&b"a key"[..])
        );
        assert!(reopened.place(Kind::Key, "7").ends_with("7.key"));
    }

    #[test]
    fn a_key_is_generated_once_signs_and_is_destroyed() {
        let dir = scratch("file");
        let provider = FileKeyProvider::new(Dir::open(dir.path()).expect("opens"));
        for (slot, suite) in [("1", Suite::Ed25519Sha256V1), ("2", Suite::P256Sha256V1)] {
            let public = provider.generate(slot, suite).expect("generated");
            assert!(public.fingerprint().starts_with("sha256:"));
            assert_eq!(provider.public(slot, suite).expect("read"), public);
            let signature = provider.sign(slot, suite, b"message").expect("signed");
            suite
                .verify(&public.bytes, b"message", &signature)
                .expect("verifies");
            assert!(matches!(
                provider.generate(slot, suite),
                Err(KeyError::Exists(_))
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.child_path("1.key"))
                .expect("held")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "owner only");
        }
        let (slot, public) = provider
            .generate_addressed(Suite::Ed25519Sha256V1)
            .expect("generated under its thumbprint");
        assert_eq!(
            slot,
            thumbprint::jwk_thumbprint(Suite::Ed25519Sha256V1, &public.bytes).expect("thumbprint")
        );
        let mut slots = provider.slots().expect("listed");
        slots.sort();
        let mut expected = vec!["1".to_owned(), "2".to_owned(), slot];
        expected.sort();
        assert_eq!(slots, expected);
        provider.destroy("1").expect("destroyed");
        assert!(matches!(
            provider.sign("1", Suite::Ed25519Sha256V1, b"m"),
            Err(KeyError::Absent(_))
        ));
        assert!(matches!(
            provider.generate("../x", Suite::Ed25519Sha256V1),
            Err(KeyError::Malformed(_))
        ));
        let _ = std::fs::remove_dir_all(dir.path());
    }
}
