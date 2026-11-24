// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use permguard_core::assurance::AssuranceProfile;

use super::files::FileBootstrap;
use super::*;
use crate::operations::grants::{AUDIT_COMMITTED, BOOTSTRAP, DOMAIN};
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Begin, Failure, Mutations};
use crate::storage::volume::Volume;

fn scratch(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "pg-authz-bootstrap-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch");
    root
}

/// The file backend passes the contract's suite, each case on a volume of its own and every
/// commitment inside an operation the engine built.
#[test]
fn the_file_backend_keeps_the_contract() {
    let made = std::sync::atomic::AtomicUsize::new(0);
    let engine_volume =
        Volume::claim(&scratch("suite-engine"), AssuranceProfile::Development).expect("a volume");
    let mutations = Mutations::open_offline(&engine_volume, "suite").expect("the engine opens");
    let next = std::sync::atomic::AtomicU64::new(1);
    // The volumes stay claimed while their stores are used.
    let volumes = Mutex::new(Vec::new());
    suite::run(
        &|| {
            let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let volume = Volume::claim(
                &scratch(&format!("suite-{case}")),
                AssuranceProfile::Development,
            )
            .expect("a volume");
            let store = Arc::new(FileBootstrap::open(&volume).expect("the store opens"));
            volumes.lock().expect("lock").push(volume);
            store
        },
        &|work| {
            let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            mutations
                .run(
                    Begin {
                        domain: DOMAIN,
                        operation: BOOTSTRAP,
                        action: AUDIT_COMMITTED,
                        initiator: Initiator::System("suite".to_owned()),
                        request: None,
                        target: Some(format!("suite-{at}")),
                    },
                    |applying| {
                        work(applying);
                        Ok::<_, Failure<String>>(Applied {
                            revision: at,
                            target: None,
                            value: (),
                        })
                    },
                )
                .expect("the operation ran");
        },
    );
}

/// What only the file backend can prove: the commitment is read back by a later open, and a file
/// that does not read as one refuses the open instead of reading as no commitment.
#[test]
fn the_commitment_survives_a_restart_and_a_damaged_one_is_not_taken_for_none() {
    let root = scratch("restart");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let store = FileBootstrap::open(&volume).expect("opens");
    let (commitment, written) = store
        .commit(&Applying::for_tests(1), &"ab".repeat(32), 10)
        .expect("committed");
    assert!(written);
    drop(store);
    let reopened = FileBootstrap::open(&volume).expect("reopens");
    assert_eq!(
        reopened.bootstrap().expect("reads"),
        Some(commitment.clone())
    );
    drop(reopened);

    let file = root
        .join(crate::storage::volume::HOST)
        .join(DIRECTORY)
        .join("bootstrap.cbor");
    let whole = std::fs::read(&file).expect("the file");
    let mut permissions = std::fs::metadata(&file).expect("metadata").permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(&file, permissions).expect("writable");
    std::fs::write(&file, &whole[..whole.len() / 2]).expect("damaged");
    let refused = FileBootstrap::open(&volume).expect_err("a damaged commitment");
    assert!(matches!(refused, AuthzError::Record(_)), "{refused}");
    assert!(refused.to_string().contains("does not read"), "{refused}");
}
