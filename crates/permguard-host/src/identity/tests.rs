// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_core::assurance::AssuranceProfile;

use super::*;
use crate::keys::FileKeyProvider;

const NOW: u64 = 1_800_000_000;

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-identity-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn provider(volume: &Volume) -> Arc<dyn KeyProvider> {
    let (_, keys) = directories(volume).expect("the directories");
    Arc::new(FileKeyProvider::new(keys))
}

fn provisioned(root: &std::path::Path) -> (Volume, Identity) {
    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let identity = Identity::provision(
        &volume,
        provider(&volume),
        Suite::Ed25519Sha256V1,
        NOW,
        NOW * 1000,
    )
    .expect("provisioned");
    (volume, identity)
}

#[test]
fn a_provisioned_identity_opens_again_as_itself_with_a_new_boot_id() {
    let root = scratch("open");
    let (host_id, witness, boot) = {
        let (_volume, identity) = provisioned(&root);
        assert!(record::is_uuid_v7(&identity.host_id()));
        assert_eq!(
            identity.subject(),
            format!(
                "{}{}",
                permguard_core::domains::subject::HOST_V1_PREFIX,
                identity.host_id_text()
            )
        );
        assert_eq!(identity.epoch(), 1);
        assert_eq!(identity.fingerprint(), identity.first_fingerprint());
        assert!(identity.successions().is_empty());
        (identity.host_id(), identity.witness(), identity.boot_id())
    };
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let identity = Identity::open(&volume, provider(&volume)).expect("opens");
    assert_eq!(identity.host_id(), host_id, "the same Host");
    assert_eq!(identity.witness(), witness, "the same witness");
    assert_ne!(identity.boot_id(), boot, "a new incarnation");
    let held =
        Boot::decode(&std::fs::read(root.join("host").join(DIRECTORY).join(BOOT)).expect("BOOT"))
            .expect("reads");
    assert_eq!(held.boot_id, identity.boot_id());
    assert_eq!(held.generation, volume.generation());
    // The document verifies under the key it names, as a peer would check it.
    let envelope = Sign1::decode(&identity.document()).expect("decodes");
    let payload = envelope
        .verify(
            Suite::Ed25519Sha256V1,
            identity.first_public_key(),
            protected::HOST_IDENTITY,
        )
        .expect("verifies");
    let document = Document::decode(payload).expect("reads");
    assert_eq!(document.protocols, vec![protected::HOST_SESSION.to_owned()]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for (path, mode) in [
            (root.join("host").join(DIRECTORY), 0o700),
            (root.join("host").join(DIRECTORY).join(KEYS), 0o700),
            (
                root.join("host").join(DIRECTORY).join(KEYS).join("1.key"),
                0o600,
            ),
        ] {
            let held = std::fs::metadata(&path).expect("held").permissions().mode();
            assert_eq!(held & 0o777, mode, "{}", path.display());
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_copied_volume_is_the_same_host_with_a_new_boot_id() {
    let root = scratch("copied");
    let copy = scratch("copied-to");
    let (host_id, boot) = {
        let (_volume, identity) = provisioned(&root);
        (identity.host_id(), identity.boot_id())
    };
    let status = std::process::Command::new("cp")
        .args(["-Rp"])
        .arg(&root)
        .arg(&copy)
        .status()
        .expect("cp runs");
    assert!(status.success());
    let volume = Volume::claim(&copy, AssuranceProfile::Development).expect("claimed");
    let identity = Identity::open(&volume, provider(&volume)).expect("opens");
    assert_eq!(identity.host_id(), host_id);
    assert_ne!(identity.boot_id(), boot);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(copy);
}

#[test]
fn without_init_nothing_is_minted_and_provisioning_happens_once() {
    let root = scratch("init");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert!(matches!(
        Identity::open(&volume, provider(&volume)),
        Err(IdentityError::NotProvisioned)
    ));
    assert!(
        directories(&volume)
            .expect("dirs")
            .1
            .names()
            .expect("listed")
            .is_empty(),
        "no key minted by an open"
    );
    Identity::provision(
        &volume,
        provider(&volume),
        Suite::Ed25519Sha256V1,
        NOW,
        NOW * 1000,
    )
    .expect("provisioned");
    assert!(matches!(
        Identity::provision(
            &volume,
            provider(&volume),
            Suite::Ed25519Sha256V1,
            NOW,
            NOW * 1000
        ),
        Err(IdentityError::Provisioned)
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_interrupted_provisioning_starts_over_from_nothing() {
    let root = scratch("interrupted");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (dir, keys) = directories(&volume).expect("dirs");
    // A provisioning that stopped before INIT: a key and a document, no INIT.
    provider(&volume)
        .generate("1", Suite::Ed25519Sha256V1)
        .expect("a leftover key");
    write::replace_bytes(&dir, DOCUMENT, b"leftover").expect("a leftover document");
    let identity = Identity::provision(
        &volume,
        provider(&volume),
        Suite::Ed25519Sha256V1,
        NOW,
        NOW * 1000,
    )
    .expect("provisioned anew");
    assert_eq!(identity.epoch(), 1);
    assert!(keys.read("1.pub").expect("read").is_some());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn damaged_state_after_init_refuses_and_never_regenerates_a_key() {
    let root = scratch("damaged");
    let identity_dir = root.join("host").join(DIRECTORY);
    drop(provisioned(&root));
    let key = identity_dir.join(KEYS).join("1.key");
    let held = std::fs::read(&key).expect("the key");
    std::fs::remove_file(&key).expect("removed");
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        assert!(matches!(
            Identity::open(&volume, provider(&volume)),
            Err(IdentityError::Key(KeyError::Absent(_)))
        ));
    }
    assert!(!key.exists(), "no replacement key");
    std::fs::write(&key, held).expect("restored");
    std::fs::remove_file(identity_dir.join(DOCUMENT)).expect("removed");
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        assert!(matches!(
            Identity::open(&volume, provider(&volume)),
            Err(IdentityError::Corrupt(_))
        ));
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn init_of_another_volume_is_refused() {
    let root = scratch("other-volume");
    drop(provisioned(&root));
    let other = scratch("other-volume-2");
    {
        let _ = Volume::claim(&other, AssuranceProfile::Development).expect("claimed");
    }
    let from = root.join("host").join(DIRECTORY);
    let status = std::process::Command::new("cp")
        .args(["-Rp"])
        .arg(&from)
        .arg(other.join("host").join(DIRECTORY))
        .status()
        .expect("cp runs");
    assert!(status.success());
    let volume = Volume::claim(&other, AssuranceProfile::Development).expect("claimed");
    let refused = Identity::open(&volume, provider(&volume)).expect_err("another volume");
    assert!(refused.to_string().contains("another volume"), "{refused}");
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(other);
}

#[test]
fn a_rotation_extends_a_chain_that_verifies_from_the_first_fingerprint() {
    let root = scratch("rotate");
    let (first, witness) = {
        let (_volume, identity) = provisioned(&root);
        let first = identity.fingerprint();
        let refused = identity
            .rotate(&Applying::for_tests(1), Some(7), NOW + 1)
            .expect_err("a stale epoch");
        assert!(matches!(
            refused,
            IdentityError::Conflict {
                expected: 7,
                current: 1
            }
        ));
        let second = identity
            .rotate(&Applying::for_tests(2), Some(1), NOW + 1)
            .expect("rotated");
        assert_eq!(second.epoch, 2);
        let third = identity
            .rotate(&Applying::for_tests(3), None, NOW + 2)
            .expect("rotated");
        assert_eq!(third.epoch, 3);
        assert_eq!(identity.successions().len(), 2);
        assert_eq!(identity.first_fingerprint(), first);
        (first, identity.witness())
    };
    let keys = root.join("host").join(DIRECTORY).join(KEYS);
    assert!(
        !keys.join("1.key").exists(),
        "epoch 1's private key destroyed"
    );
    assert!(keys.join("2.key").exists(), "epoch 2's kept for the grace");
    assert!(keys.join("1.pub").exists(), "the public evidence kept");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let identity = Identity::open(&volume, provider(&volume)).expect("the chain verifies");
    assert_eq!(identity.epoch(), 3);
    assert_eq!(identity.first_fingerprint(), first);
    assert_eq!(identity.witness(), witness, "rotation keeps the witness");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_tampered_succession_breaks_the_chain() {
    let root = scratch("tampered");
    {
        let (_volume, identity) = provisioned(&root);
        identity
            .rotate(&Applying::for_tests(1), None, NOW + 1)
            .expect("rotated");
    }
    let path = root.join("host").join(DIRECTORY).join(SUCCESSION);
    let mut bytes = std::fs::read(&path).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, bytes).expect("tampered");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert!(matches!(
        Identity::open(&volume, provider(&volume)),
        Err(IdentityError::Corrupt(_))
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_interrupted_rotation_is_completed_at_open_and_a_stray_key_replaced_by_the_next() {
    let root = scratch("half-rotated");
    let old_document = {
        let (_volume, identity) = provisioned(&root);
        let old = identity.document();
        identity
            .rotate(&Applying::for_tests(1), None, NOW + 1)
            .expect("rotated");
        old
    };
    let dir = root.join("host").join(DIRECTORY);
    // Stopped after the succession, before the document.
    std::fs::write(dir.join(DOCUMENT), &old_document).expect("the old document back");
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let identity = Identity::open(&volume, provider(&volume)).expect("completed");
        assert_eq!(identity.epoch(), 2);
    }
    // Stopped after generating the next key, before the succession.
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        provider(&volume)
            .generate("3", Suite::Ed25519Sha256V1)
            .expect("a stray key");
    }
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let stray = std::fs::read(dir.join(KEYS).join("3.key")).expect("the stray key");
    let identity = Identity::open(&volume, provider(&volume)).expect("opens");
    assert_eq!(identity.epoch(), 2);
    assert!(
        dir.join(KEYS).join("3.key").exists(),
        "an open removes nothing: the key may be what a rollback hides"
    );
    let rotated = identity
        .rotate(&Applying::for_tests(2), Some(2), NOW + 2)
        .expect("the next rotation replaces it under its own operation");
    assert_eq!(rotated.epoch, 3);
    assert_ne!(
        std::fs::read(dir.join(KEYS).join("3.key")).expect("the new key"),
        stray,
        "a fresh key"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_identity_key_signs_proofs_and_bindings_and_nothing_else() {
    let root = scratch("sign");
    let (_volume, identity) = provisioned(&root);
    for allowed in [protected::HOST_PROOF, protected::HOST_RING_BINDING] {
        let envelope = identity.sign(allowed, b"x".to_vec()).expect("signs");
        Sign1::decode(&envelope)
            .expect("decodes")
            .verify(Suite::Ed25519Sha256V1, identity.first_public_key(), allowed)
            .expect("verifies");
    }
    for refused in [
        protected::HOST_IDENTITY,
        protected::HOST_SUCCESSION,
        protected::HOST_GRANT,
        "anything",
    ] {
        assert!(matches!(
            identity.sign(refused, b"x".to_vec()),
            Err(IdentityError::Refused(_))
        ));
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn recovery_observes_a_rotation_by_the_epoch_it_produced() {
    let root = scratch("observe");
    let (_volume, identity) = provisioned(&root);
    let domain = Identities(&identity);
    let id = OperationId::from_bytes([1; 16]);
    assert_eq!(domain.observe(&id, Some("epoch:2")), None);
    identity
        .rotate(&Applying::for_tests(1), None, NOW + 1)
        .expect("rotated");
    assert_eq!(
        domain.observe(&id, Some("epoch:2")),
        Some(Observed {
            revision: 2,
            target: Some("epoch:2".to_owned())
        })
    );
    assert_eq!(domain.observe(&id, None), None);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_previous_document_that_does_not_verify_is_never_re_signed() {
    let root = scratch("forged-previous");
    let (first_key, first_fingerprint) = {
        let (_volume, identity) = provisioned(&root);
        let first = (
            identity.first_public_key().to_vec(),
            identity.first_fingerprint().to_owned(),
        );
        identity
            .rotate(&Applying::for_tests(1), None, NOW + 1)
            .expect("rotated");
        first
    };
    // An epoch-1 document naming this Host and its real epoch-1 key, with chosen members, signed
    // by a stranger's key, put where the interrupted rotation's document would be.
    let stranger = crate::keys::FileKeyProvider::new(
        Dir::open(&{
            let path = scratch("forged-previous-keys");
            std::fs::create_dir_all(&path).expect("dir");
            path
        })
        .expect("opens"),
    );
    stranger
        .generate("1", Suite::Ed25519Sha256V1)
        .expect("a stranger's key");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let held = Sign1::decode(
        &std::fs::read(root.join("host").join(DIRECTORY).join(DOCUMENT)).expect("read"),
    )
    .expect("decodes");
    let mut forged = Document::decode(held.payload_unverified()).expect("reads");
    forged.epoch = 1;
    forged.public_key = first_key;
    forged.fingerprint = first_fingerprint;
    forged.last_succession = None;
    forged.protocols = vec!["forged".to_owned()];
    let envelope = sign(
        &stranger,
        1,
        Suite::Ed25519Sha256V1,
        protected::HOST_IDENTITY,
        forged.encode().expect("encodes"),
    )
    .expect("signed");
    std::fs::write(root.join("host").join(DIRECTORY).join(DOCUMENT), envelope).expect("put");
    assert!(matches!(
        Identity::open(&volume, provider(&volume)),
        Err(IdentityError::Corrupt(_))
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_envelope_whose_kid_is_not_its_epoch_is_refused() {
    let root = scratch("kid");
    drop(provisioned(&root));
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let path = root.join("host").join(DIRECTORY).join(DOCUMENT);
    let held = Sign1::decode(&std::fs::read(&path).expect("read")).expect("decodes");
    let payload = held.payload_unverified().to_vec();
    let keys = provider(&volume);
    let relabelled = Sign1::sign_with(
        Suite::Ed25519Sha256V1,
        protected::HOST_IDENTITY,
        b"9",
        payload,
        |bytes| {
            keys.sign("1", Suite::Ed25519Sha256V1, bytes)
                .map_err(|error| error.to_string())
        },
    )
    .expect("signed")
    .encode()
    .expect("encoded");
    std::fs::write(&path, relabelled).expect("put");
    assert!(matches!(
        Identity::open(&volume, provider(&volume)),
        Err(IdentityError::Corrupt(_))
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_identity_that_lost_its_init_is_never_provisioned_over() {
    let root = scratch("init-lost");
    {
        let (_volume, identity) = provisioned(&root);
        identity
            .rotate(&Applying::for_tests(1), None, NOW + 1)
            .expect("rotated");
    }
    std::fs::remove_file(root.join("host").join(DIRECTORY).join(INIT)).expect("INIT lost");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let refused = Identity::provision(
        &volume,
        provider(&volume),
        Suite::Ed25519Sha256V1,
        NOW,
        NOW * 1000,
    )
    .expect_err("an identity existed");
    assert!(matches!(refused, IdentityError::Corrupt(_)), "{refused}");
    assert!(
        root.join("host")
            .join(DIRECTORY)
            .join(KEYS)
            .join("2.key")
            .exists(),
        "nothing destroyed"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// A provider whose signatures with one slot fail.
struct Failing {
    inner: FileKeyProvider,
    slot: &'static str,
}

impl KeyProvider for Failing {
    fn name(&self) -> &'static str {
        "failing"
    }
    fn custody(&self) -> Custody {
        Custody::Plaintext
    }
    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        self.inner.generate(slot, suite)
    }
    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), KeyError> {
        self.inner.generate_addressed(suite)
    }
    fn slots(&self) -> Result<Vec<String>, KeyError> {
        self.inner.slots()
    }
    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, KeyError> {
        self.inner.public(slot, suite)
    }
    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        if slot == self.slot {
            return Err(KeyError::Malformed("the HSM is gone".to_owned()));
        }
        self.inner.sign(slot, suite, message)
    }
    fn destroy(&self, slot: &str) -> Result<(), KeyError> {
        self.inner.destroy(slot)
    }
}

#[test]
fn a_rotation_that_fails_after_its_succession_is_uncertain_and_completed_at_open() {
    let root = scratch("uncertain");
    drop(provisioned(&root));
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let keys = directories(&volume).expect("dirs").1;
        let identity = Identity::open(
            &volume,
            Arc::new(Failing {
                inner: FileKeyProvider::new(keys),
                slot: "2",
            }),
        )
        .expect("opens");
        let failed = identity
            .rotate(&Applying::for_tests(1), Some(1), NOW + 1)
            .expect_err("the new key does not sign");
        assert!(
            matches!(failed, IdentityError::Indeterminate(_)),
            "{failed}"
        );
    }
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let identity = Identity::open(&volume, provider(&volume)).expect("completed");
    assert_eq!(identity.epoch(), 2, "the durable rotation landed");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_swapped_first_public_key_is_refused() {
    let root = scratch("swapped-first");
    drop(provisioned(&root));
    let stranger = FileKeyProvider::new(
        Dir::open(&{
            let path = scratch("swapped-first-keys");
            std::fs::create_dir_all(&path).expect("dir");
            path
        })
        .expect("opens"),
    );
    let other = stranger
        .generate("1", Suite::Ed25519Sha256V1)
        .expect("a stranger's key");
    std::fs::write(
        root.join("host").join(DIRECTORY).join(KEYS).join("1.pub"),
        &other.bytes,
    )
    .expect("swapped");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let refused = Identity::open(&volume, provider(&volume)).expect_err("not INIT's key");
    assert!(refused.to_string().contains("INIT pins"), "{refused}");
    let _ = std::fs::remove_dir_all(root);
}
