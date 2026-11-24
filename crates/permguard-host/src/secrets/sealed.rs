// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A 256-bit secret sealed at rest (iteration 03, WP-27.5): what a store that every instance
//! reads keeps of a delivered zone key or of a cursor root, so that no secret is ever in the
//! clear there.
//!
//! The secret is wrapped by the key-encryption key of the `file` custody, held outside the store
//! (the secret store's root, a PKCS#11 token's or a KMS's key), bound to a closed
//! deterministic-CBOR context: the format, the Host, what the secret is for, its name, and the
//! key-encryption key that wrapped it. A sealed secret read under another Host, purpose or name,
//! or edited, does not open. A secret wrapped by the key-encryption key a rotation left behind
//! opens, and is answered to be wrapped again under the current one.

use zeroize::Zeroizing;

use permguard_objects::cbor::{self, Value};
use permguard_objects::crypto::seal::{DEK_LEN, Dek};

use crate::keys::custody::Keks;

/// What a store keeps of a sealed secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub kek_ref: String,
    pub kek_version: u64,
    pub wrap_algorithm: String,
    pub wrapped: Vec<u8>,
}

/// A secret opened: its bytes, and whether it was wrapped by a key-encryption key a rotation
/// left behind, so its store wraps it again.
pub struct Opened {
    pub secret: Zeroizing<[u8; DEK_LEN]>,
    pub stale: bool,
}

/// What seals the secrets of one Host.
pub struct Sealer {
    keks: Keks,
    host_id: [u8; 16],
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("keks", &self.keks)
            .finish_non_exhaustive()
    }
}

impl Sealer {
    /// What seals the secrets of `host_id` under `keks`.
    pub fn new(keks: Keks, host_id: [u8; 16]) -> Self {
        Self { keks, host_id }
    }

    /// The context a secret is bound to.
    fn context(
        &self,
        purpose: &str,
        name: &str,
        kek_ref: &str,
        kek_version: u64,
        wrap_algorithm: &str,
    ) -> Result<Vec<u8>, String> {
        let text = |text: &str| Value::Text(text.to_owned());
        let version = i64::try_from(kek_version)
            .map_err(|_| "a key-encryption key version past its range".to_owned())?;
        cbor::encode(&Value::Map(vec![
            (
                text("format"),
                text(permguard_core::domains::format::SEALED_SECRET_V1),
            ),
            (text("v"), Value::Int(1)),
            (text("host_id"), Value::Bytes(self.host_id.to_vec())),
            (text("purpose"), text(purpose)),
            (text("name"), text(name)),
            (text("kek_ref"), text(kek_ref)),
            (text("kek_version"), Value::Int(version)),
            (text("wrap_algorithm"), text(wrap_algorithm)),
        ]))
        .map_err(|error| error.to_string())
    }

    /// Seals `secret`, what `purpose` names `name`, under the current key-encryption key.
    pub fn seal(
        &self,
        purpose: &str,
        name: &str,
        secret: &[u8; DEK_LEN],
    ) -> Result<Sealed, String> {
        let kek = &self.keks.current;
        let context = self.context(
            purpose,
            name,
            kek.kek_ref(),
            kek.kek_version(),
            kek.wrap_algorithm(),
        )?;
        let wrapped = kek
            .wrap(&Dek::from_unwrapped(Zeroizing::new(*secret)), &context)
            .map_err(|error| format!("sealing a secret: {error}"))?;
        Ok(Sealed {
            kek_ref: kek.kek_ref().to_owned(),
            kek_version: kek.kek_version(),
            wrap_algorithm: kek.wrap_algorithm().to_owned(),
            wrapped,
        })
    }

    /// Opens `sealed`, what `purpose` names `name`: refused when it was sealed for anything
    /// else, edited, or wrapped by a key-encryption key this Host does not hold.
    pub fn open(&self, purpose: &str, name: &str, sealed: &Sealed) -> Result<Opened, String> {
        let current = &self.keks.current;
        let (kek, stale) = if sealed.kek_ref == current.kek_ref()
            && sealed.kek_version == current.kek_version()
        {
            (current, false)
        } else {
            match &self.keks.previous {
                Some(previous)
                    if sealed.kek_ref == previous.kek_ref()
                        && sealed.kek_version == previous.kek_version() =>
                {
                    (previous, true)
                }
                _ => {
                    return Err(format!(
                        "the secret `{name}` was sealed by the key-encryption key `{}` version {}, \
                         which this Host does not hold",
                        sealed.kek_ref, sealed.kek_version
                    ));
                }
            }
        };
        if sealed.wrap_algorithm != kek.wrap_algorithm() {
            return Err(format!(
                "the secret `{name}` was sealed by another algorithm"
            ));
        }
        let context = self.context(
            purpose,
            name,
            &sealed.kek_ref,
            sealed.kek_version,
            &sealed.wrap_algorithm,
        )?;
        let dek = kek
            .unwrap(sealed.kek_version, &sealed.wrapped, &context)
            .map_err(|_| format!("the secret `{name}` does not open: it is not the one sealed"))?;
        Ok(Opened {
            secret: Zeroizing::new(*dek.expose()),
            stale,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use super::*;
    use crate::keys::custody::SecretKek;
    use crate::secrets::{KeyVersion, Root};

    fn kek(byte: u8, version: u64) -> Arc<dyn permguard_objects::crypto::seal::KeyWrap> {
        let root = Root::from_material(&[byte; 32], KeyVersion::new(version).expect("a version"))
            .expect("a root");
        Arc::new(SecretKek::from_root("kek", &root).expect("a KEK"))
    }

    fn sealer(current: (u8, u64), previous: Option<(u8, u64)>, host: u8) -> Sealer {
        Sealer::new(
            Keks {
                current: kek(current.0, current.1),
                previous: previous.map(|(byte, version)| kek(byte, version)),
            },
            [host; 16],
        )
    }

    #[test]
    fn a_secret_opens_only_as_what_it_was_sealed_for() {
        let sealer = sealer((1, 1), None, 7);
        let sealed = sealer
            .seal("stream.cursor", "decisions", &[9; 32])
            .expect("sealed");
        assert_ne!(
            sealed.wrapped.as_slice(),
            &[9u8; 32][..],
            "never in the clear"
        );
        let opened = sealer
            .open("stream.cursor", "decisions", &sealed)
            .expect("opened");
        assert_eq!(*opened.secret, [9; 32]);
        assert!(!opened.stale);
        // Another name, purpose or Host, or an edited wrap: it does not open.
        assert!(sealer.open("stream.cursor", "events", &sealed).is_err());
        assert!(sealer.open("zone.key", "decisions", &sealed).is_err());
        assert!(
            super::Sealer::new(sealer.keks.clone(), [8; 16])
                .open("stream.cursor", "decisions", &sealed)
                .is_err()
        );
        let mut edited = sealed.clone();
        edited.wrapped[20] ^= 1;
        assert!(sealer.open("stream.cursor", "decisions", &edited).is_err());
    }

    #[test]
    fn a_secret_of_the_previous_kek_opens_and_is_wrapped_again() {
        let before = sealer((1, 1), None, 7);
        let sealed = before.seal("zone.key", "a", &[5; 32]).expect("sealed");
        let after = sealer((2, 2), Some((1, 1)), 7);
        let opened = after.open("zone.key", "a", &sealed).expect("opened");
        assert_eq!((*opened.secret, opened.stale), ([5; 32], true));
        let again = after
            .seal("zone.key", "a", &opened.secret)
            .expect("wrapped again");
        assert_eq!(again.kek_version, 2);
        assert!(!after.open("zone.key", "a", &again).expect("opened").stale);
        // A KEK this Host does not hold: refused, never treated as absent.
        assert!(
            sealer((3, 3), None, 7)
                .open("zone.key", "a", &sealed)
                .is_err()
        );
    }
}
