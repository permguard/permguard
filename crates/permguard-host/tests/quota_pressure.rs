// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Storage pressure, with a disk that fills (WP-1.5): a required journal refuses before the volume
//! is exhausted, and a deletion's tombstone, anchor and audit record still land under the same
//! pressure, from the maintenance reserve.

#![allow(clippy::expect_used)]

use permguard_core::fault::{self, Fault};
use permguard_core::volume::{Floors, Limit};
use permguard_host::storage::journal::{Journal, Options};
use permguard_host::storage::quota::{Class, Quota};
use permguard_host::storage::write::{Published, publish_immutable_in, replace_view_in};
use permguard_host::storage::{Dir, StorageError, format, tombstone};

const FLOOR: u64 = 64 * 1024;
const RESERVE: u64 = 8 * 1024;
const FRAME: usize = 4096;

fn volume(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-pressure-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    Dir::create_root(&path).expect("a volume");
    path
}

#[test]
fn a_required_journal_refuses_before_exhaustion_and_maintenance_still_lands() {
    let root = volume("full");
    let quota = Quota::open(
        Dir::open(&root).expect("root"),
        Floors {
            free_bytes: FLOOR,
            free_inodes: 1,
            maintenance_bytes: RESERVE,
            maintenance_inodes: 1,
        },
        Limit::default(),
    )
    .expect("the quota opens");
    let host = quota.host(Class::Ordinary);
    let data = Dir::open(&root)
        .expect("root")
        .subdir("data", true)
        .expect("data");
    let data_scope = host.child("data", &data, Limit::default()).expect("scope");

    // Written before the disk fills: what retention deletes later.
    let expired = b"an expired record batch".repeat(64);
    let published = publish_immutable_in(
        &data_scope,
        &data,
        "batch-0001",
        &expired,
        &|held| held == expired.as_slice(),
        &|held| held == expired.as_slice(),
    )
    .expect("published");
    assert_eq!(published, Published::Written);

    // From here on the disk holds 200 KiB more, and no more.
    let _full = fault::inject(
        &root,
        Fault::DiskFull {
            remaining_bytes: 200 * 1024,
        },
    );
    quota.refresh().expect("measured");
    let readiness = quota.readiness();
    assert!(
        readiness.is_ready(),
        "200 KiB free: ready before the first write"
    );

    let decisions = data.subdir("decisions", true).expect("decisions");
    let decisions_scope = data_scope
        .child("decisions", &decisions, Limit::default())
        .expect("scope");
    let (mut journal, _) = Journal::open(
        decisions,
        Options {
            max_frame: FRAME as u32,
            ..Options::default()
        },
    )
    .expect("the required journal opens");
    journal.charge(decisions_scope).expect("charged");

    let (refused, ready_at_refusal) = loop {
        let ready = readiness.is_ready();
        if let Err(error) = journal.append(1, &[7u8; FRAME]) {
            break (error, ready);
        }
    };
    assert!(
        matches!(refused, StorageError::BelowFloor(_)),
        "refused by the floor, not by the disk: {refused}"
    );
    assert!(
        !ready_at_refusal,
        "readiness had already fallen when the refused write was asked for"
    );
    assert!(
        journal.readiness().is_ready(),
        "nothing was written: the journal is whole and may append once space returns"
    );
    let left = fault::free_bytes(&root).expect("the fault is armed");
    assert!(
        left >= FLOOR,
        "the disk was never exhausted: {left} bytes left, the floor is {FLOOR}"
    );

    // The disk now leaves 50 bytes above the floor: less than an anchor needs.
    let _fuller = fault::inject(
        &root,
        Fault::DiskFull {
            remaining_bytes: FLOOR + 50,
        },
    );
    let refused = replace_view_in(
        &data_scope,
        &data,
        "ANCHOR",
        format::VIEW,
        b"deleted batch-0001",
    )
    .expect_err("an ordinary writer may not write into the floor");
    assert!(matches!(refused, StorageError::BelowFloor(_)), "{refused}");
    assert!(!data.child_path("ANCHOR").exists(), "nothing was written");

    // Retention deletes the expired batch, writes its anchor and audits its own action, all from
    // the floor an ordinary writer may not touch.
    let maintenance = data_scope.maintenance();
    tombstone::delete_in(&maintenance, &data, "batch-0001").expect("the deletion lands");
    replace_view_in(
        &maintenance,
        &data,
        "ANCHOR",
        format::VIEW,
        b"deleted batch-0001",
    )
    .expect("the anchor lands");
    let audit = Dir::open(&root)
        .expect("root")
        .subdir("audit", true)
        .expect("audit");
    let audit_scope = quota
        .host(Class::Maintenance)
        .child("audit", &audit, Limit::default())
        .expect("scope");
    let (mut trail, _) = Journal::open(audit, Options::default()).expect("the trail opens");
    trail.charge(audit_scope).expect("charged");
    trail
        .append(2, b"retention deleted batch-0001")
        .expect("the audit record lands");

    // An ordinary writer is still refused: the maintenance writes did not open the floor to it.
    let refused = journal
        .append(1, &[7u8; FRAME])
        .expect_err("still below the floor");
    assert!(matches!(refused, StorageError::BelowFloor(_)), "{refused}");
    assert!(fault::free_bytes(&root).expect("armed") >= RESERVE);
    assert!(
        fault::free_bytes(&root).expect("armed") < FLOOR,
        "the maintenance writes did use the floor"
    );
}

#[test]
fn a_quota_refuses_the_write_that_would_pass_it_and_nothing_is_written() {
    let root = volume("quota");
    // Small floors: the test is about the quota, not about how full the disk running it is.
    let quota = Quota::open(
        Dir::open(&root).expect("root"),
        Floors {
            free_bytes: 4096,
            free_inodes: 1,
            maintenance_bytes: 1024,
            maintenance_inodes: 1,
        },
        Limit::default(),
    )
    .expect("the quota opens");
    let plane = Dir::open(&root)
        .expect("root")
        .subdir("control", true)
        .expect("plane");
    let scope = quota
        .host(Class::Ordinary)
        .child(
            "control",
            &plane,
            Limit {
                bytes: Some(10 * 1024),
                inodes: None,
            },
        )
        .expect("scope");
    let (mut journal, _) = Journal::open(
        plane,
        Options {
            max_frame: FRAME as u32,
            ..Options::default()
        },
    )
    .expect("opens");
    journal.charge(scope).expect("charged");

    journal.append(1, &[1u8; FRAME]).expect("within the quota");
    journal.append(1, &[1u8; FRAME]).expect("within the quota");
    let frames = journal.next_index();
    let refused = journal
        .append(1, &[1u8; FRAME])
        .expect_err("the third frame passes 10 KiB");
    assert!(
        matches!(refused, StorageError::QuotaExceeded(_)),
        "{refused}"
    );
    assert_eq!(journal.next_index(), frames, "nothing was appended");
    assert_eq!(journal.frames().expect("read").len() as u64, frames);

    let usage = quota.usage().expect("usage");
    let control = usage
        .scopes
        .iter()
        .find(|scope| scope.scope == "control")
        .expect("reported");
    assert_eq!(control.limit.bytes, Some(10 * 1024));
    assert!(control.used_bytes > 2 * FRAME as u64 && control.used_bytes <= 10 * 1024);
    assert_eq!(
        control.reserved_bytes, 0,
        "the refused reservation was released"
    );
}

/// BUG-0062: once a volume's quota is installed in the gate, every write the storage primitives
/// make below it is charged, whichever crate makes it and without a scope of its own: an
/// immutable file, a view and a journal frame past `storage.quotas.host` are refused
/// `QuotaExceeded` and write nothing; what a replacement frees is given back.
#[test]
fn every_primitive_writing_below_an_installed_volume_is_held_to_its_quota() {
    use permguard_host::storage::gate;
    use permguard_host::storage::write::{publish_immutable, replace_view};

    let root = volume("gate");
    let dir = Dir::open(&root).expect("opens");
    let quota = Quota::open(
        Dir::open(&root).expect("opens"),
        Floors {
            free_bytes: 0,
            free_inodes: 0,
            maintenance_bytes: 0,
            maintenance_inodes: 0,
        },
        Limit {
            bytes: Some(16 * 1024),
            inodes: None,
        },
    )
    .expect("the quota");
    gate::install(&root, quota.clone());

    let any = |_: &[u8]| true;
    assert_eq!(
        publish_immutable(&dir, "first", &[1u8; 6 * 1024], &any, &any).expect("within"),
        Published::Written
    );
    let refused = publish_immutable(&dir, "second", &[2u8; 12 * 1024], &any, &any)
        .expect_err("past the quota");
    assert!(
        matches!(refused, StorageError::QuotaExceeded(_)),
        "{refused}"
    );
    assert!(!root.join("second").exists(), "nothing was written");

    replace_view(&dir, "view", format::VIEW, &[3u8; 4 * 1024]).expect("within");
    let refused =
        replace_view(&dir, "big", format::VIEW, &[4u8; 8 * 1024]).expect_err("past the quota");
    assert!(
        matches!(refused, StorageError::QuotaExceeded(_)),
        "{refused}"
    );
    // Replacing the view with a smaller one gives its bytes back.
    replace_view(&dir, "view", format::VIEW, &[3u8; 512]).expect("smaller");

    let plane = dir.subdir("data", true).expect("a directory");
    let (mut journal, _) = Journal::open(
        plane,
        Options {
            max_frame: 8 * 1024,
            ..Options::default()
        },
    )
    .expect("opens");
    journal
        .append(1, &[5u8; 4 * 1024])
        .expect("within the quota");
    let frames = journal.next_index();
    let refused = journal
        .append(1, &[5u8; 8 * 1024])
        .expect_err("past the quota");
    assert!(
        matches!(refused, StorageError::QuotaExceeded(_)),
        "{refused}"
    );
    assert_eq!(journal.next_index(), frames, "nothing was appended");

    gate::uninstall(&root);
    publish_immutable(&dir, "after", &[6u8; 12 * 1024], &any, &any)
        .expect("uninstalled: nothing is charged");
}
