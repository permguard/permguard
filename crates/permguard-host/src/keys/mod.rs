// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The common key provider port (WP-2.2): every private key the Host holds is generated, used
//! and destroyed through a [`KeyProvider`], so no part of the server or a Plane keeps a key
//! store of its own. The Host identity is its first user; the [`ring`] registry (WP-3.1) its
//! second; the custody providers (WP-3.2) follow.
//!
//! | Provider            | Custody                                                                      |
//! | ------------------- | ---------------------------------------------------------------------------- |
//! | [`FileKeyProvider`] | PKCS#8 in `<slot>.key`, `0600`, below a `0700` directory: plaintext custody  |
//!
//! A slot names one key; the private bytes never leave the provider, and a slot once generated
//! is never generated again: a lost key is not silently replaced. A ring's slot is the key's own
//! RFC 7638 thumbprint ([`KeyProvider::generate_addressed`]), so the slot cannot name other
//! material.

pub mod migration;
pub mod record;
pub mod registry;
pub mod ring;

use std::fmt;

use permguard_objects::crypto::suite::{SigningKey, Suite};
use permguard_objects::crypto::thumbprint;
use permguard_objects::digest::Digest;

pub use permguard_objects::crypto::thumbprint::selects;

use crate::storage::write::{Published, publish_immutable};
use crate::storage::{Dir, StorageError, tombstone};

/// How a provider keeps the private keys it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// The private bytes are on the volume in the clear: the `custody.plaintext` relaxation.
    Plaintext,
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
    /// The storage below the provider failed.
    Storage(StorageError),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent(slot) => write!(f, "no key is held in `{slot}`"),
            Self::Exists(slot) => {
                write!(f, "`{slot}` already holds a key; a key is generated once")
            }
            Self::Malformed(detail) => f.write_str(detail),
            Self::Storage(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<StorageError> for KeyError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
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
}

/// Keys as PKCS#8 files below one directory.
pub struct FileKeyProvider {
    dir: Dir,
}

impl fmt::Debug for FileKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKeyProvider")
            .field("dir", &self.dir.path())
            .finish()
    }
}

impl FileKeyProvider {
    /// Over `dir`, which the caller created `0700`.
    pub fn new(dir: Dir) -> Self {
        Self { dir }
    }

    /// A slot is letters, digits, `-` and `_`: an identity epoch, a ring key's base64url
    /// thumbprint (owner decision of 2026-10-08).
    fn name_of(slot: &str) -> Result<String, KeyError> {
        if slot.is_empty()
            || !slot
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(KeyError::Malformed(format!(
                "`{slot}` is not a key slot: letters, digits, `-` and `_`"
            )));
        }
        Ok(format!("{slot}.key"))
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
        let name = Self::name_of(slot)?;
        if self.dir.read(&name)?.is_some() {
            return Err(KeyError::Exists(slot.to_owned()));
        }
        let readable = |bytes: &[u8]| SigningKey::from_pkcs8(suite, bytes).is_ok();
        let same = |bytes: &[u8]| bytes == pkcs8;
        match publish_immutable(&self.dir, &name, pkcs8, &readable, &same)? {
            Published::Written => Ok(()),
            Published::AlreadyThere => Err(KeyError::Exists(slot.to_owned())),
        }
    }

    fn load(&self, slot: &str, suite: Suite) -> Result<SigningKey, KeyError> {
        let name = Self::name_of(slot)?;
        let pkcs8 = zeroize::Zeroizing::new(
            self.dir
                .read(&name)?
                .ok_or_else(|| KeyError::Absent(slot.to_owned()))?,
        );
        SigningKey::from_pkcs8(suite, &pkcs8).map_err(|error| {
            KeyError::Malformed(format!(
                "{} does not read as a {suite} key: {error:?}",
                self.dir.child_path(&name).display()
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
        Self::name_of(slot)?;
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
        Ok(self
            .dir
            .names()?
            .into_iter()
            .filter_map(|name| name.strip_suffix(".key").map(str::to_owned))
            .filter(|slot| Self::name_of(slot).is_ok())
            .collect())
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
        let name = Self::name_of(slot)?;
        tombstone::delete(&self.dir, &name)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

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
