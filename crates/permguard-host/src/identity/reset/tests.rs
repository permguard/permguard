// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_core::assurance::AssuranceProfile;

use super::*;
use crate::identity::Identities;
use crate::keys::FileKeyProvider;
use crate::operations::mutation::Domain as _;

const NOW: u64 = 1_800_000_000;

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-identity-reset-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn provisioner(volume: &Volume) -> Provisioner {
    let (_, keys) = directories(volume).expect("the directories");
    let path = keys.path().to_path_buf();
    Arc::new(move |_| Ok(Arc::new(FileKeyProvider::new(Dir::open(&path)?)) as Arc<dyn KeyProvider>))
}

fn provisioned(root: &std::path::Path) -> (Volume, Identity) {
    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let provision = provisioner(&volume);
    let identity = Identity::provision_with(
        &volume,
        |host_id| provision(host_id),
        Suite::Ed25519Sha256V1,
        NOW,
        NOW * 1000,
    )
    .expect("provisioned")
    .with_provisioner(provisioner(&volume));
    (volume, identity)
}

/// Every file below `root`, relative.
fn files(root: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(
                    path.strip_prefix(root)
                        .expect("below")
                        .display()
                        .to_string(),
                );
            }
        }
    }
    found.sort();
    found
}

#[test]
fn a_reset_retires_the_identity_keeps_its_public_evidence_and_provisions_another() {
    let root = scratch("whole");
    let (volume, identity) = provisioned(&root);
    let old = identity.host_id();
    let old_fingerprint = identity.first_fingerprint().to_owned();
    let applying = Applying::for_tests(7);
    let reset = identity
        .reset(
            &applying,
            &[],
            Suite::Ed25519Sha256V1,
            NOW + 10,
            (NOW + 10) * 1000,
        )
        .expect("reset");
    // Once only: a second reset of the retired identity is refused.
    assert!(matches!(
        identity.reset(
            &Applying::for_tests(9),
            &[],
            Suite::Ed25519Sha256V1,
            NOW,
            NOW * 1000
        ),
        Err(IdentityError::Retired)
    ));
    assert_eq!(reset.old_host_id, old);
    assert_ne!(reset.host_id, old, "a new host_id, never the old one");
    assert_ne!(reset.fingerprint, old_fingerprint);

    // The old identity signs nothing more in this process.
    assert!(identity.is_retired());
    assert!(matches!(
        identity.sign(
            permguard_core::domains::protected::HOST_PROOF,
            b"x".to_vec()
        ),
        Err(IdentityError::Retired)
    ));

    // Its public records are kept apart, and nothing private of it is left anywhere: `keys/`
    // holds the new identity's epoch 1 alone.
    let identity_dir = root.join("host/identity");
    let retired = format!("{RETIRED}/{}", record::uuid_text(&old));
    let held = files(&identity_dir);
    let kept: Vec<String> = held
        .iter()
        .filter_map(|file| file.strip_prefix(&format!("{retired}/")).map(str::to_owned))
        .collect();
    assert_eq!(kept, [INIT, RESET, DOCUMENT, "keys-1.pub"], "{held:?}");
    let keys: Vec<&String> = held
        .iter()
        .filter(|file| file.starts_with("keys/"))
        .collect();
    assert_eq!(keys, ["keys/1.key", "keys/1.pub"]);
    assert_ne!(
        std::fs::read(identity_dir.join("keys/1.pub")).expect("the new key"),
        std::fs::read(identity_dir.join(format!("{retired}/keys-1.pub"))).expect("the old key")
    );
    assert!(!held.contains(&RESETTING.to_owned()), "the marker is gone");

    // The volume opens as the new Host, and recovery reads the reset as done.
    drop(identity);
    let provider: Arc<dyn KeyProvider> = Arc::new(FileKeyProvider::new(
        directories(&volume).expect("directories").1,
    ));
    let reopened = Identity::open(&volume, provider).expect("the new identity opens");
    assert_eq!(reopened.host_id(), reset.host_id);
    assert_eq!(reopened.epoch(), 1);
    assert_eq!(reopened.witness(), reset.witness);
    let observed = Identities(&reopened)
        .observe(
            &applying.operation_id(),
            Some(&format!("reset:{}", record::uuid_text(&old))),
        )
        .expect("observed");
    assert_eq!(
        observed.target,
        Some(format!("host:{}", reopened.host_id_text()))
    );
    assert!(
        Identities(&reopened)
            .observe(
                &Applying::for_tests(8).operation_id(),
                Some(&format!("reset:{}", record::uuid_text(&old)))
            )
            .is_none(),
        "another operation did not reset it"
    );
}

#[test]
fn an_interrupted_reset_refuses_the_open_and_completes_when_run_again() {
    let root = scratch("interrupted");
    let (volume, identity) = provisioned(&root);
    let old = identity.host_id();
    drop(identity);
    let (dir, keys) = directories(&volume).expect("directories");
    let resume_now = || {
        resume(
            &Applying::for_tests(3),
            &volume,
            &provisioner(&volume),
            &[],
            Suite::Ed25519Sha256V1,
            NOW,
            NOW * 1000,
        )
    };
    // A marker with no kept evidence completes nothing: it would destroy a live identity.
    write::replace_bytes(&dir, RESETTING, &old).expect("marked");
    assert!(matches!(resume_now(), Err(IdentityError::Corrupt(_))));
    assert!(
        dir.read(INIT).expect("readable").is_some(),
        "nothing was removed"
    );
    // A reset that kept its evidence, wrote its marker and stopped.
    let retired = dir
        .subdir(RETIRED, true)
        .expect("retired")
        .subdir(&record::uuid_text(&old), true)
        .expect("its directory");
    keep_evidence(&dir, &keys, &retired).expect("kept");
    write::replace_bytes(
        &retired,
        RESET,
        &reset_record(&old, NOW, None).expect("a record"),
    )
    .expect("recorded");
    let provider: Arc<dyn KeyProvider> = Arc::new(FileKeyProvider::new(
        directories(&volume).expect("directories").1,
    ));
    assert!(matches!(
        Identity::open(&volume, Arc::clone(&provider)),
        Err(IdentityError::ResetIncomplete)
    ));
    let reset = resume_now()
        .expect("resumed")
        .expect("a reset was under way");
    assert_eq!(reset.old_host_id, old);
    let reopened = Identity::open(&volume, provider).expect("opens");
    assert_eq!(reopened.host_id(), reset.host_id);
    assert!(resume_now().expect("nothing to resume").is_none());
}

#[test]
fn a_reset_without_a_provisioner_is_refused_and_retires_nothing() {
    let root = scratch("unprovisioned");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let provider: Arc<dyn KeyProvider> = Arc::new(FileKeyProvider::new(
        directories(&volume).expect("directories").1,
    ));
    let identity = Identity::provision(&volume, provider, Suite::Ed25519Sha256V1, NOW, NOW * 1000)
        .expect("provisioned");
    assert!(matches!(
        identity.reset(
            &Applying::for_tests(1),
            &[],
            Suite::Ed25519Sha256V1,
            NOW,
            NOW * 1000
        ),
        Err(IdentityError::Refused(_))
    ));
    assert!(!identity.is_retired());
}

#[test]
fn a_reset_that_published_its_identity_and_kept_its_marker_is_completed_by_resume() {
    let root = scratch("published");
    let (volume, identity) = provisioned(&root);
    let old = identity.host_id();
    let reset = identity
        .reset(
            &Applying::for_tests(4),
            &[],
            Suite::Ed25519Sha256V1,
            NOW,
            NOW * 1000,
        )
        .expect("reset");
    drop(identity);
    // A crash between the new INIT and the marker's removal leaves the marker behind.
    let (dir, _) = directories(&volume).expect("directories");
    write::replace_bytes(&dir, RESETTING, &old).expect("marked again");
    let provider: Arc<dyn KeyProvider> = Arc::new(FileKeyProvider::new(
        directories(&volume).expect("directories").1,
    ));
    assert!(matches!(
        Identity::open(&volume, Arc::clone(&provider)),
        Err(IdentityError::ResetIncomplete)
    ));
    let resumed = resume(
        &Applying::for_tests(5),
        &volume,
        &provisioner(&volume),
        &[],
        Suite::Ed25519Sha256V1,
        NOW,
        NOW * 1000,
    )
    .expect("completed")
    .expect("a reset was under way");
    assert_eq!(resumed.old_host_id, old);
    assert_eq!(
        resumed.host_id, reset.host_id,
        "the identity already published"
    );
    assert_eq!(resumed.witness, reset.witness);
    let reopened = Identity::open(&volume, provider).expect("opens");
    assert_eq!(reopened.host_id(), reset.host_id);
}
