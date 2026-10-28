// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use permguard_core::assurance::AssuranceProfile;
use permguard_host::storage::migrate::Layout;
use permguard_host::storage::volume::Volume;
use serde_json::json;

use super::*;
use crate::record::GENESIS;

const NOW: u64 = 1_800_000_000;

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-decision-archive-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("created");
    root
}

fn spool_of(root: &Path) -> PathBuf {
    root.join("data/decisions/spool")
}

/// A spool of `records` records, the first `acked` of them acknowledged, with a zone key witness.
fn written(directory: &Path, records: u64, acked: u64) {
    let mut spool = Spool::open(directory, Bounds::default()).expect("opened");
    let mut prev = GENESIS.to_owned();
    let mut digests = Vec::new();
    for seq in 1..=records {
        let appended = spool
            .append(&json!({"v": 1, "seq": seq, "prev": prev, "kind": "decision"}))
            .expect("appended");
        prev = appended.digest.clone();
        digests.push(appended.digest);
    }
    if acked > 0 {
        spool
            .acknowledge(acked, digests[usize::try_from(acked).unwrap() - 1].clone())
            .expect("acknowledged");
    }
    std::fs::write(directory.join(ZONE_KEYS), "v1\tabcd\n").expect("a witness");
}

fn files(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let mut found: Vec<(String, Vec<u8>)> = std::fs::read_dir(directory)
        .expect("listed")
        .map(|entry| {
            let entry = entry.expect("an entry");
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).expect("read"),
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn a_drained_spool_is_archived_byte_for_byte() {
    let root = scratch("drained");
    let spool = spool_of(&root);
    written(&spool, 3, 3);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Drained);

    archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect("archived");

    let before: Vec<(String, Vec<u8>)> = files(&spool)
        .into_iter()
        .filter(|(name, _)| name != LOCK_FILE)
        .collect();
    assert!(
        before.iter().any(|(name, _)| segment_seq(name).is_some())
            && before.iter().any(|(name, _)| name == ZONE_KEYS),
        "{before:?}"
    );
    assert_eq!(files(&root.join(TARGET)), before, "every file but the lock");
    let manifest = Layout::open(&volume, SUBSYSTEM)
        .unwrap()
        .manifest()
        .unwrap()
        .expect("laid out");
    assert_eq!(manifest.active.version, TARGET_VERSION);
    assert_eq!(manifest.active.directory, TARGET);
    // The old generation stays until `migrate finalize`: archived, not an orphan.
    assert!(spool.exists());
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Archived);
    let again =
        archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect_err("not twice");
    assert!(format!("{again}").contains("archived already"), "{again}");
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_undrained_spool_is_not_archived() {
    let root = scratch("undrained");
    let spool = spool_of(&root);
    written(&spool, 3, 2);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Undrained);
    let refused = archive(&volume, &spool, AssuranceProfile::Development, None, NOW)
        .expect_err("a record unshipped");
    assert!(
        format!("{refused}").contains("not yet shipped"),
        "{refused}"
    );
    assert!(!root.join(TARGET).exists(), "nothing carried");
    assert!(
        Layout::open(&volume, SUBSYSTEM)
            .unwrap()
            .manifest()
            .unwrap()
            .is_none(),
        "nothing declared"
    );
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_waiting_terminal_record_is_not_drained() {
    let root = scratch("terminal");
    let spool = spool_of(&root);
    written(&spool, 2, 2);
    {
        let mut open = Spool::open(&spool, Bounds::default()).expect("opened");
        open.discontinue(permguard_core::codes::stream::SPOOL_FULL, |terminal| {
            Ok(json!({
                "v": 1,
                "seq": terminal.seq,
                "prev": terminal.prev,
                "kind": "discontinuity",
                "successor": terminal.successor,
            }))
        })
        .expect("ended");
    }
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Undrained);
    drop(volume);
    {
        let mut open = Spool::open(&spool, Bounds::default()).expect("opened");
        open.close_finished().expect("the terminal shipped");
    }
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Drained);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_spool_holding_a_foreign_file_is_not_archived() {
    let root = scratch("foreign");
    let spool = spool_of(&root);
    written(&spool, 1, 1);
    std::fs::write(spool.join("notes.txt"), "mine").expect("a foreign file");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let refused = archive(&volume, &spool, AssuranceProfile::Development, None, NOW)
        .expect_err("a foreign file");
    assert!(format!("{refused}").contains("notes.txt"), "{refused}");
    assert!(!root.join(TARGET).exists(), "nothing carried");
    assert!(
        Layout::open(&volume, SUBSYSTEM)
            .unwrap()
            .manifest()
            .unwrap()
            .is_none(),
        "refused before anything is declared, so no migration is left to recover"
    );
    std::fs::create_dir(spool.join("nested")).expect("a directory");
    std::fs::remove_file(spool.join("notes.txt")).expect("moved out");
    let refused = obstacle(&volume, &spool).unwrap().expect("a directory");
    assert!(format!("{refused}").contains("nested/"), "{refused}");
    std::fs::remove_dir(spool.join("nested")).expect("moved out");
    assert!(obstacle(&volume, &spool).unwrap().is_none());
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Drained);
    archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect("archived");
    assert!(root.join(TARGET).join(ZONE_KEYS).exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_spool_outside_the_volume_is_refused() {
    let root = scratch("outside-volume");
    let elsewhere = scratch("outside-spool");
    written(&elsewhere, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let refused = archive(
        &volume,
        &elsewhere,
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect_err("outside the volume");
    assert!(
        format!("{refused}").contains("outside the volume"),
        "{refused}"
    );
    assert!(!root.join(TARGET).exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(elsewhere);
}

#[test]
fn a_production_archive_declares_a_backup() {
    let root = scratch("production");
    let spool = spool_of(&root);
    written(&spool, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let refused =
        archive(&volume, &spool, AssuranceProfile::Production, None, NOW).expect_err("no backup");
    assert!(format!("{refused}").contains("backup"), "{refused}");
    // Declared at version 1 and refused by the preflight: the retry archives the spool it names,
    // once drained.
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Drained);
    {
        let mut open = Spool::open(&spool, Bounds::default()).expect("opened");
        let prev = open.head().to_owned();
        open.append(&json!({"v": 1, "seq": 2, "prev": prev, "kind": "decision"}))
            .expect("an older release wrote again");
    }
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Undrained);
    {
        let mut open = Spool::open(&spool, Bounds::default()).expect("opened");
        let head = open.head().to_owned();
        open.acknowledge(2, head).expect("shipped");
    }
    archive(
        &volume,
        &spool,
        AssuranceProfile::Production,
        Some("snapshot-1".to_owned()),
        NOW,
    )
    .expect("archived with its backup");
    assert!(root.join(TARGET).exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn no_spool_or_a_witness_alone_is_absent_and_a_spool_with_no_record_is_drained() {
    let root = scratch("absent");
    let spool = spool_of(&root);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Absent);
    // What a release that witnessed its zone key and wrote no spool left: no layout for it.
    std::fs::create_dir_all(&spool).expect("created");
    std::fs::write(spool.join(ZONE_KEYS), "v1\t-\n").expect("a witness");
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Absent);
    assert!(!spool.join(STATE_FILE).exists(), "nothing opened");
    // A spool opened and never written: drained, and archived whole.
    drop(Spool::open(&spool, Bounds::default()).expect("opened"));
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Drained);
    archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect("archived");
    let carried: Vec<String> = files(&root.join(TARGET))
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(carried, [RESERVE_FILE, STATE_FILE, ZONE_KEYS]);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_declared_spool_gone_is_refused_by_name() {
    let root = scratch("declared-gone");
    let spool = spool_of(&root);
    written(&spool, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive(&volume, &spool, AssuranceProfile::Production, None, NOW).expect_err("no backup");
    assert_eq!(waiting(&volume).unwrap().as_deref(), Some(SPOOL));
    std::fs::remove_dir_all(&spool).expect("removed by hand");
    let refused = obstacle(&volume, &spool).unwrap().expect("gone");
    assert!(format!("{refused}").contains("which is gone"), "{refused}");
    let refused =
        archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect_err("gone");
    assert!(format!("{refused}").contains("which is gone"), "{refused}");
    std::fs::create_dir_all(&spool).expect("put back empty");
    archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect("archived");
    assert!(
        files(&root.join(TARGET)).is_empty(),
        "an empty directory is not opened as a spool"
    );
    assert_eq!(waiting(&volume).unwrap(), None);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_spool_at_the_volume_root_or_the_archive_is_refused_before_it_is_declared() {
    let root = scratch("around-target");
    let at_target = root.join(TARGET);
    written(&at_target, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let refused = archive(
        &volume,
        &at_target,
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect_err("where the archive goes");
    assert!(
        format!("{refused}").contains("where its archive"),
        "{refused}"
    );
    let refused = obstacle(&volume, &root.join("data/decisions"))
        .unwrap()
        .expect("around the archive");
    assert!(
        format!("{refused}").contains("where its archive"),
        "{refused}"
    );
    let refused = obstacle(&volume, &root).unwrap().expect("the root");
    assert!(
        format!("{refused}").contains("outside the volume"),
        "{refused}"
    );
    assert_eq!(waiting(&volume).unwrap(), None, "nothing declared");
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_spool_elsewhere_while_the_old_generation_is_kept_is_an_orphan() {
    let root = scratch("orphan-kept");
    let spool = spool_of(&root);
    written(&spool, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect("archived");
    let moved = root.join("custom/spool");
    written(&moved, 1, 1);
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Archived);
    assert_eq!(standing(&volume, &moved).unwrap(), Standing::Orphan);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_spool_back_after_finalize_is_an_orphan() {
    let root = scratch("orphan");
    let spool = spool_of(&root);
    written(&spool, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive(&volume, &spool, AssuranceProfile::Development, None, NOW).expect("archived");
    Layout::open(&volume, SUBSYSTEM)
        .unwrap()
        .finalize(NOW)
        .expect("finalized");
    assert!(!spool.exists(), "the old generation went");
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Archived);
    // An older release wrote the spool again.
    written(&spool, 1, 0);
    assert_eq!(standing(&volume, &spool).unwrap(), Standing::Orphan);
    let refused = archive(&volume, &spool, AssuranceProfile::Development, None, NOW)
        .expect_err("never twice");
    assert!(
        format!("{refused}").contains("not archived twice"),
        "{refused}"
    );
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_declared_layouts_include_the_decision_archive() {
    let declared = layouts();
    assert_eq!(declared.len(), 1);
    assert_eq!(declared[0].0, SUBSYSTEM);
    let reads = &declared[0].1;
    assert_eq!(
        format!("{reads:?}"),
        format!("{:?}", Reads::from(SOURCE_VERSION, TARGET_VERSION))
    );
}
