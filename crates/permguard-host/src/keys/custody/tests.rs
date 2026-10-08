// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Mutex;

use super::*;
use crate::secrets::KeyVersion;

const HOST: [u8; 16] = [7; 16];
const RING: &str = "data.attest";

fn scratch(tag: &str) -> Dir {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-custody-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("created");
    Dir::open(&path).expect("opens")
}

fn kek(name: &str, version: u64, byte: u8) -> Arc<dyn KeyWrap> {
    let root = Root::from_material(&[byte; 32], KeyVersion::new(version).expect("a version"))
        .expect("a root");
    Arc::new(SecretKek::from_root(name, &root).expect("a KEK"))
}

/// The stored public keys of a test, as a ring's `public/` would hold them.
#[derive(Clone, Default)]
struct Stored(Arc<Mutex<BTreeMap<String, Vec<u8>>>>);

impl Stored {
    fn reader(&self) -> StoredPublic {
        let held = Arc::clone(&self.0);
        Box::new(move |slot, _| Ok(held.lock().expect("lock").get(slot).cloned()))
    }

    fn put(&self, slot: &str, public: &[u8]) {
        self.0
            .lock()
            .expect("lock")
            .insert(slot.to_owned(), public.to_vec());
    }
}

fn provider(dir: &Dir, host: [u8; 16], keks: Keks, stored: &Stored) -> SealedFileKeyProvider {
    SealedFileKeyProvider::new(
        Dir::open(dir.path()).expect("opens"),
        host,
        RING,
        keks,
        stored.reader(),
    )
}

fn current(byte: u8) -> Keks {
    Keks {
        current: kek("kek", 1, byte),
        previous: None,
    }
}

#[test]
fn a_secret_kek_binds_its_context_and_its_version() {
    let kek = kek("kek", 2, 1);
    let dek = Dek::from_unwrapped(Zeroizing::new([9; DEK_LEN]));
    let wrapped = kek.wrap(&dek, b"context").expect("wrapped");
    assert_eq!(wrapped.len(), NONCE_LEN + DEK_LEN + TAG_LEN);
    assert_eq!(
        kek.unwrap(2, &wrapped, b"context")
            .expect("unwrapped")
            .expose(),
        &[9; DEK_LEN]
    );
    assert!(matches!(
        kek.unwrap(2, &wrapped, b"other"),
        Err(WrapError::Rejected)
    ));
    assert!(matches!(
        kek.unwrap(1, &wrapped, b"context"),
        Err(WrapError::VersionUnknown(1))
    ));
    assert_eq!(kek.wrap_algorithm(), WRAP_SECRET);
    let long = Root::from_material(&[1; 33], KeyVersion::new(1).expect("v1")).expect("a root");
    assert!(
        SecretKek::from_root("kek", &long).is_err(),
        "exactly 32 bytes"
    );
}

#[test]
fn a_key_is_sealed_at_rest_and_signs_once_unsealed() {
    let dir = scratch("sealed");
    let stored = Stored::default();
    let held = provider(&dir, HOST, current(1), &stored);
    let (slot, public) = held
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("generated");
    stored.put(&slot, &public.bytes);
    let bytes = std::fs::read(dir.path().join(format!("{slot}.key"))).expect("held");
    assert!(!is_plaintext(&bytes), "never PKCS#8 at rest");
    SealedKey::decode(&bytes).expect("a sealed key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.path().join(format!("{slot}.key")))
            .expect("held")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A fresh provider, as after a restart, unseals it and signs.
    let reopened = provider(&dir, HOST, current(1), &stored);
    let signature = reopened
        .sign(&slot, Suite::Ed25519Sha256V1, b"message")
        .expect("signs");
    Suite::Ed25519Sha256V1
        .verify(&public.bytes, b"message", &signature)
        .expect("verifies");
    // A wrong KEK fails, and nothing is minted in its place.
    let wrong = provider(&dir, HOST, current(2), &stored);
    assert!(wrong.sign(&slot, Suite::Ed25519Sha256V1, b"m").is_err());
    assert_eq!(wrong.slots().expect("listed"), vec![slot]);
}

#[test]
fn a_copied_blob_fails_under_another_kid_or_another_host() {
    let dir = scratch("copied");
    let stored = Stored::default();
    let held = provider(&dir, HOST, current(1), &stored);
    let (a, public_a) = held.generate_addressed(Suite::Ed25519Sha256V1).expect("a");
    let (b, public_b) = held.generate_addressed(Suite::Ed25519Sha256V1).expect("b");
    stored.put(&a, &public_a.bytes);
    stored.put(&b, &public_b.bytes);
    // A's blob presented as B's.
    std::fs::copy(
        dir.path().join(format!("{a}.key")),
        dir.path().join(format!("{b}.key")),
    )
    .expect("copied");
    let reopened = provider(&dir, HOST, current(1), &stored);
    assert!(reopened.sign(&b, Suite::Ed25519Sha256V1, b"m").is_err());
    reopened
        .sign(&a, Suite::Ed25519Sha256V1, b"m")
        .expect("A still opens as itself");
    // The same blob on another Host's volume.
    let elsewhere = provider(&dir, [8; 16], current(1), &stored);
    assert!(elsewhere.sign(&a, Suite::Ed25519Sha256V1, b"m").is_err());
}

#[test]
fn a_plaintext_key_is_sealed_in_place_at_bootstrap() {
    let dir = scratch("seal-plaintext");
    let plain = FileKeyProvider::new(Dir::open(dir.path()).expect("opens"));
    let (slot, public) = plain
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("generated");
    let stored = Stored::default();
    stored.put(&slot, &public.bytes);
    let held = provider(&dir, HOST, current(1), &stored);
    assert!(
        held.sign(&slot, Suite::Ed25519Sha256V1, b"m").is_err(),
        "a plaintext key is not opened as sealed"
    );
    let prepared = held.prepare(Suite::Ed25519Sha256V1).expect("prepared");
    assert_eq!(prepared.sealed, vec![slot.clone()]);
    let bytes = std::fs::read(dir.path().join(format!("{slot}.key"))).expect("held");
    assert!(!is_plaintext(&bytes));
    let signature = held
        .sign(&slot, Suite::Ed25519Sha256V1, b"m")
        .expect("the same key signs");
    Suite::Ed25519Sha256V1
        .verify(&public.bytes, b"m", &signature)
        .expect("verifies under the stored key");
    assert_eq!(
        held.prepare(Suite::Ed25519Sha256V1).expect("again"),
        Prepared::default(),
        "idempotent"
    );

    // A plaintext key that is not the stored one is refused, not sealed.
    let other_dir = scratch("seal-mismatch");
    let plain = FileKeyProvider::new(Dir::open(other_dir.path()).expect("opens"));
    let (slot, _) = plain
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("generated");
    let stored = Stored::default();
    stored.put(&slot, &[1; 32]);
    assert!(
        provider(&other_dir, HOST, current(1), &stored)
            .prepare(Suite::Ed25519Sha256V1)
            .is_err()
    );
}

#[test]
fn a_kek_rotation_rewraps_the_dek_and_leaves_the_ciphertext_unchanged() {
    let dir = scratch("rotation");
    let stored = Stored::default();
    let old = kek("kek-a", 1, 1);
    let held = provider(
        &dir,
        HOST,
        Keks {
            current: Arc::clone(&old),
            previous: None,
        },
        &stored,
    );
    let (slot, public) = held
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("generated");
    stored.put(&slot, &public.bytes);
    let before =
        SealedKey::decode(&std::fs::read(dir.path().join(format!("{slot}.key"))).expect("held"))
            .expect("sealed");

    let rotated = provider(
        &dir,
        HOST,
        Keks {
            current: kek("kek-b", 2, 2),
            previous: Some(old),
        },
        &stored,
    );
    let prepared = rotated.prepare(Suite::Ed25519Sha256V1).expect("rewrapped");
    assert_eq!(prepared.rewrapped, vec![slot.clone()]);
    let after =
        SealedKey::decode(&std::fs::read(dir.path().join(format!("{slot}.key"))).expect("held"))
            .expect("sealed");
    assert_eq!(
        after.ciphertext, before.ciphertext,
        "the ciphertext is unchanged"
    );
    assert_eq!(after.unique_nonce, before.unique_nonce);
    assert_ne!(after.wrapped_dek, before.wrapped_dek);
    assert_eq!((after.kek_ref.as_str(), after.kek_version), ("kek-b", 2));

    // The previous KEK is no longer needed; a third one, with no previous, fails the open.
    let settled = provider(&dir, HOST, current_named("kek-b", 2, 2), &stored);
    settled
        .sign(&slot, Suite::Ed25519Sha256V1, b"m")
        .expect("opens under the new KEK alone");
    let unknown = provider(&dir, HOST, current_named("kek-c", 3, 3), &stored);
    assert!(unknown.prepare(Suite::Ed25519Sha256V1).is_err());
    assert!(unknown.sign(&slot, Suite::Ed25519Sha256V1, b"m").is_err());
}

fn current_named(name: &str, version: u64, byte: u8) -> Keks {
    Keks {
        current: kek(name, version, byte),
        previous: None,
    }
}

#[test]
fn the_plaintext_of_an_unsealed_key_is_a_zeroizing_buffer() {
    // H-03: what holds a key's PKCS#8 after unsealing erases itself on drop.
    fn erased<T: zeroize::Zeroize>(_: &zeroize::Zeroizing<T>) {}
    let pkcs8 = SigningKey::generate_pkcs8(Suite::Ed25519Sha256V1).expect("generated");
    let key = SigningKey::from_pkcs8(Suite::Ed25519Sha256V1, &pkcs8).expect("reads");
    let public = key.public_key().to_vec();
    let kid = thumbprint::kid(
        RING,
        &thumbprint::jwk_thumbprint(Suite::Ed25519Sha256V1, &public).expect("tp"),
    );
    let binding = Binding {
        host_id: &HOST,
        ring: RING,
        kid: &kid,
        suite: Suite::Ed25519Sha256V1,
    };
    let kek = kek("kek", 1, 1);
    let sealed = SealedKey::seal(&pkcs8, &binding, kek.as_ref(), &SystemEntropy).expect("sealed");
    let unsealed = sealed
        .open(&binding, kek.as_ref(), &public)
        .expect("opened");
    erased(&unsealed.pkcs8);
}

/// WP-3.2 re-review: a token or a KMS never inherits key files; the custody names them.
#[test]
fn a_remote_custody_over_key_files_is_refused_and_names_them() {
    let dir = scratch("remote-files");
    FileKeyProvider::new(Dir::open(dir.path()).expect("opens"))
        .generate("1", Suite::Ed25519Sha256V1)
        .expect("a development key");
    for custody in [KeyCustody::Pkcs11, KeyCustody::Kms] {
        let refused = Custodian::new(move |_| custody, Ok(None))
            .plan(
                "host.identity",
                HOST,
                Dir::open(dir.path()).expect("opens"),
                Stored::default().reader(),
                Suite::Ed25519Sha256V1,
            )
            .err()
            .expect("refused");
        assert!(
            refused.to_string().contains("holds the key file `1.key`"),
            "{refused}"
        );
    }
}
