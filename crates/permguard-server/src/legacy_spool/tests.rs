// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use clap::Parser as _;
use permguard_decisions::record::GENESIS;
use permguard_decisions::spool::{Bounds, Spool};
use permguard_host::storage::migrate::Layout;
use serde_json::json;

use super::*;

const NOW: u64 = 1_800_000_000;

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-server-legacy-spool-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("created");
    root
}

/// A spool at the default place below `root`, of `records` records, `acked` of them acknowledged.
fn written(root: &Path, records: u64, acked: u64) -> PathBuf {
    let directory = root.join(SPOOL);
    let mut spool = Spool::open(&directory, Bounds::default()).expect("opened");
    let mut prev = GENESIS.to_owned();
    for seq in 1..=records {
        let appended = spool
            .append(&json!({"v": 1, "seq": seq, "prev": prev, "kind": "decision"}))
            .expect("appended");
        prev = appended.digest;
        if seq == acked {
            spool
                .acknowledge(acked, prev.clone())
                .expect("acknowledged");
        }
    }
    directory
}

fn laid_out(volume: &Volume) -> Option<u16> {
    Layout::open(volume, SUBSYSTEM)
        .unwrap()
        .manifest()
        .unwrap()
        .map(|manifest| manifest.active.version)
}

#[test]
fn a_drained_spool_is_archived_at_start_below_production() {
    let root = scratch("start-development");
    written(&root, 2, 2);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(&volume, &root, SPOOL, AssuranceProfile::Development, NOW);
    assert_eq!(laid_out(&volume), Some(2));
    assert!(root.join(TARGET).join("STATE").exists());
    // Archived: the next start does nothing more.
    archive_at_start(&volume, &root, SPOOL, AssuranceProfile::Development, NOW);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_production_start_leaves_a_drained_spool_in_place() {
    let root = scratch("start-production");
    written(&root, 2, 2);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(&volume, &root, SPOOL, AssuranceProfile::Production, NOW);
    assert_eq!(laid_out(&volume), None, "nothing declared");
    assert!(!root.join(TARGET).exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_start_leaves_an_undrained_or_obstructed_spool_and_still_starts() {
    let root = scratch("start-undrained");
    let spool = written(&root, 2, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(&volume, &root, SPOOL, AssuranceProfile::Development, NOW);
    assert_eq!(laid_out(&volume), None, "its shipper sends it first");
    drop(volume);

    let root = scratch("start-obstructed");
    let spool_drained = written(&root, 1, 1);
    std::fs::write(spool_drained.join("notes.txt"), "mine").expect("a foreign file");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(&volume, &root, SPOOL, AssuranceProfile::Development, NOW);
    assert_eq!(
        laid_out(&volume),
        None,
        "nothing declared, no migration left to recover"
    );
    assert!(!root.join(TARGET).exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(spool.parent().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn migrate_decisions_refuses_an_undrained_spool_and_archives_a_drained_one() {
    let root = scratch("command");
    let spool = written(&root, 3, 2);
    drop(Volume::claim(&root, AssuranceProfile::Development).expect("claimed"));
    let mut out = Vec::new();

    let refused =
        migrate_decisions(&root, "snapshot-1", None, &mut out).expect_err("a record unshipped");
    assert!(
        format!("{refused:#}").contains("not yet shipped"),
        "{refused:#}"
    );
    let refused = migrate_decisions(&root, " ", None, &mut out).expect_err("no backup");
    assert!(format!("{refused:#}").contains("--backup"), "{refused:#}");

    {
        let mut opened = Spool::open(&spool, Bounds::default()).expect("opened");
        let head = opened.head().to_owned();
        opened.acknowledge(3, head).expect("shipped");
    }
    migrate_decisions(&root, "snapshot-1", Some(Path::new(SPOOL)), &mut out).expect("archived");
    migrate_decisions(&root, "snapshot-1", None, &mut out).expect("archived already");
    let said = String::from_utf8(out).expect("text");
    assert!(
        said.contains("carried from") && said.contains("archived already"),
        "{said}"
    );
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let commit = Layout::open(&volume, SUBSYSTEM)
        .unwrap()
        .status()
        .unwrap()
        .expect("laid out")
        .commit
        .expect("committed");
    assert_eq!(commit.backup.as_deref(), Some("snapshot-1"));
    drop(volume);

    let empty = scratch("command-empty");
    drop(Volume::claim(&empty, AssuranceProfile::Development).expect("claimed"));
    let mut out = Vec::new();
    migrate_decisions(&empty, "snapshot-1", None, &mut out).expect("nothing to archive");
    assert!(
        String::from_utf8(out)
            .expect("text")
            .contains("nothing to archive"),
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(empty);
}

#[test]
fn the_command_line_names_the_decision_archive() {
    let parsed = crate::command::Cli::try_parse_from([
        "permguard",
        "migrate",
        "decisions",
        "--volume",
        "/volume",
        "--backup",
        "snapshot-1",
        "--legacy",
        "custom/spool",
    ])
    .expect("parsed");
    assert_eq!(
        parsed.command,
        Some(crate::command::Command::Migrate {
            what: crate::command::MigrateCommand::Decisions {
                volume: PathBuf::from("/volume"),
                backup: "snapshot-1".to_owned(),
                legacy: Some(PathBuf::from("custom/spool")),
            },
        })
    );
}

#[test]
fn an_unreadable_spool_does_not_stop_a_start() {
    let root = scratch("start-unreadable");
    let spool = root.join(SPOOL);
    std::fs::create_dir_all(&spool).expect("created");
    std::fs::write(spool.join("STATE"), b"not a state").expect("a broken state");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert!(
        permguard_decisions::archive::standing(&volume, &spool).is_err(),
        "the spool cannot be read"
    );
    archive_at_start(&volume, &root, SPOOL, AssuranceProfile::Development, NOW);
    assert_eq!(laid_out(&volume), None);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_start_archives_the_spool_a_version_1_declared() {
    let root = scratch("start-declared");
    let spool = written(&root, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    permguard_decisions::archive::archive(&volume, &spool, AssuranceProfile::Production, None, NOW)
        .expect_err("no backup, declared at version 1");
    assert_eq!(laid_out(&volume), Some(1));
    // `log.spool_directory` changed since: the declared spool is the one archived.
    archive_at_start(
        &volume,
        &root,
        "elsewhere",
        AssuranceProfile::Development,
        NOW,
    );
    assert_eq!(laid_out(&volume), Some(2));
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_production_warning_names_the_command_and_the_spool() {
    let said = command(Path::new("/volume"), "data/decisions/spool");
    assert!(
        said.contains(
            "permguard migrate decisions --volume /volume --backup <reference> --legacy \
             data/decisions/spool"
        ),
        "{said}"
    );
}

#[test]
fn migrate_decisions_refuses_a_spool_outside_the_volume() {
    let root = scratch("command-outside");
    let elsewhere = scratch("command-outside-spool");
    let spool = written(&elsewhere, 1, 1);
    drop(Volume::claim(&root, AssuranceProfile::Development).expect("claimed"));
    let refused = migrate_decisions(&root, "snapshot-1", Some(&spool), &mut Vec::new())
        .expect_err("outside the volume");
    assert!(
        format!("{refused:#}").contains("outside the volume"),
        "{refused:#}"
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(elsewhere);
}
