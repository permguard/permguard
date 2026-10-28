// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use clap::Parser as _;
use permguard_events::journal::Journal;
use permguard_events::record::{GENESIS, Producer, Stream, occurrence_digest_of};
use permguard_host::storage::migrate::Layout;
use serde_json::json;

use super::*;

/// When every record below occurred: 2026-10-01T00:00:00Z.
const OCCURRED: &str = "2026-10-01T00:00:00Z";

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-server-legacy-events-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("created");
    root
}

/// A moment long after every record and every bound: a drained history is drained then.
fn later() -> u64 {
    u64::try_from(permguard_events::index::epoch_seconds(OCCURRED).unwrap()).unwrap()
        + 365 * 24 * 3600
}

/// A moment just after the records: a window still reads them.
fn soon() -> u64 {
    u64::try_from(permguard_events::index::epoch_seconds(OCCURRED).unwrap()).unwrap() + 60
}

/// A legacy journal of `acme/main` below `root/data/events`, of `records` records, `acked` of them
/// acknowledged.
fn written(root: &Path, records: u64, acked: u64) -> PathBuf {
    let history = root.join("data/events");
    let stream = Stream::new(Producer::data_plane("pdp-a", "inst-1"), "acme", "main");
    let mut journal =
        Journal::open(history.join("acme/main"), stream, Bounds::default()).expect("opened");
    let mut prev = GENESIS.to_owned();
    for seq in 1..=records {
        let event = json!({ "event_id": format!("evt-{seq}"), "kind": "request" });
        let record = json!({
            "v": 1,
            "record_type": permguard_core::domains::record::EVENT_V1,
            "stream": {
                "producer": {
                    "class": permguard_core::domains::producer::DATA_PLANE_V1,
                    "id": "pdp-a",
                    "instance": "inst-1"
                },
                "zone": "acme",
                "ledger": "main"
            },
            "seq": seq,
            "prev": prev,
            "event_type": permguard_core::domains::event::DOGWOOD_V1,
            "event_id": format!("evt-{seq}"),
            "occurrence_digest": occurrence_digest_of(&event).unwrap(),
            "kind": "request",
            "profile": "default",
            "policy_partitions": ["governance"],
            "commit": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "occurred_at": OCCURRED,
            "observed_at": OCCURRED,
            "event": event
        });
        prev = journal.append(&record).expect("appended").digest;
    }
    journal.mark_signed(records).expect("signed");
    journal.acknowledge(acked).expect("acknowledged");
    history
}

fn laid_out(volume: &Volume) -> Option<u16> {
    Layout::open(volume, SUBSYSTEM)
        .unwrap()
        .manifest()
        .unwrap()
        .map(|manifest| manifest.active.version)
}

fn config_file() -> &'static Path {
    Path::new("/etc/permguard/server.yml")
}

#[test]
fn a_drained_legacy_is_archived_at_start_below_production() {
    let root = scratch("start-development");
    let history = written(&root, 2, 2);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        later(),
    );
    assert_eq!(laid_out(&volume), Some(2));
    assert!(root.join(TARGET).join("acme/main/STATE").exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_production_start_leaves_a_drained_legacy_in_place_and_names_the_command() {
    let root = scratch("start-production");
    let history = written(&root, 2, 2);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Production,
        later(),
    );
    assert_eq!(laid_out(&volume), None);
    assert!(!root.join(TARGET).exists());
    let said = command(Path::new("/volume"), config_file());
    assert!(
        said.contains(
            "permguard migrate events --volume /volume --backup <reference> --config \
             /etc/permguard/server.yml"
        ),
        "{said}"
    );
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_start_leaves_an_undrained_or_obstructed_legacy_and_still_starts() {
    // Unshipped.
    let root = scratch("start-unshipped");
    let history = written(&root, 2, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        later(),
    );
    assert_eq!(laid_out(&volume), None);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);

    // Shipped, and a window still reads it.
    let root = scratch("start-recent");
    let history = written(&root, 2, 2);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        soon(),
    );
    assert_eq!(laid_out(&volume), None);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);

    // Drained, with a file beside it that is not the history's.
    let root = scratch("start-foreign");
    let history = written(&root, 2, 2);
    std::fs::write(history.join("notes.txt"), b"mine").unwrap();
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        later(),
    );
    assert_eq!(laid_out(&volume), None, "nothing declared");
    assert!(!root.join(TARGET).exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);

    // Unreadable.
    let root = scratch("start-unreadable");
    let history = root.join("data/events");
    std::fs::create_dir_all(history.join("acme/main")).unwrap();
    std::fs::write(history.join("acme/main/STATE"), b"not a state").unwrap();
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        later(),
    );
    assert_eq!(laid_out(&volume), None);
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_start_archives_the_history_a_version_1_declared() {
    let root = scratch("start-declared");
    let history = written(&root, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let now = later();
    permguard_events::archive::archive(
        &volume,
        &history,
        Bounds::default(),
        horizon(Bounds::default(), i64::try_from(now).unwrap()),
        AssuranceProfile::Production,
        None,
        now,
    )
    .expect_err("no backup, declared at version 1");
    assert_eq!(laid_out(&volume), Some(1));
    // `events.directory` changed since: the declared history is the one archived.
    archive_at_start(
        &volume,
        &root.join("elsewhere"),
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        now,
    );
    assert_eq!(laid_out(&volume), Some(2));
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_declared_history_is_not_archived_while_the_configured_one_holds_history() {
    let root = scratch("start-moved");
    let history = written(&root, 1, 1);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let now = later();
    permguard_events::archive::archive(
        &volume,
        &history,
        Bounds::default(),
        horizon(Bounds::default(), i64::try_from(now).unwrap()),
        AssuranceProfile::Production,
        None,
        now,
    )
    .expect_err("no backup, declared at version 1");
    // `events.directory` now names another directory, holding a journal a window still reads.
    let configured = written(&root.join("moved"), 2, 1);
    archive_at_start(
        &volume,
        &configured,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        now,
    );
    assert_eq!(laid_out(&volume), Some(1), "not archived");
    let refused = obstacle(&volume, &configured)
        .unwrap()
        .expect("the configured history");
    assert!(
        refused.to_string().contains("holds history too"),
        "{refused}"
    );
    drop(volume);
    let refused = migrate_events(
        &root,
        "snapshot-1",
        &root,
        &configured,
        Bounds::default(),
        &mut Vec::new(),
    )
    .expect_err("the configured history");
    assert!(
        format!("{refused:#}").contains("holds history too"),
        "{refused:#}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn migrate_events_refuses_an_undrained_legacy_and_archives_a_drained_one() {
    let root = scratch("command");
    let history = written(&root, 2, 1);
    drop(Volume::claim(&root, AssuranceProfile::Development).expect("claimed"));
    let mut out = Vec::new();

    // The command measures against now: a retention longer than the records' age keeps them.
    let long = Bounds {
        retention_minimum: std::time::Duration::from_secs(100 * 365 * 24 * 3600),
        ..Bounds::default()
    };
    let refused = migrate_events(&root, "snapshot-1", &root, &history, long, &mut out)
        .expect_err("a record unshipped");
    assert!(
        format!("{refused:#}").contains("not yet shipped"),
        "{refused:#}"
    );
    let refused = migrate_events(&root, " ", &root, &history, Bounds::default(), &mut out)
        .expect_err("no backup");
    assert!(format!("{refused:#}").contains("--backup"), "{refused:#}");

    {
        let stream = permguard_events::journal::stream_of(history.join("acme/main")).unwrap();
        let mut journal =
            Journal::open(history.join("acme/main"), stream, Bounds::default()).expect("opened");
        journal.acknowledge(2).expect("shipped");
    }
    // Shipped whole, and still inside a window under the long retention.
    migrate_events(&root, "snapshot-1", &root, &history, long, &mut out)
        .expect_err("a window still reads it");
    migrate_events(
        &root,
        "snapshot-1",
        &root,
        &history,
        Bounds::default(),
        &mut out,
    )
    .expect("archived");
    migrate_events(
        &root,
        "snapshot-1",
        &root,
        &history,
        Bounds::default(),
        &mut out,
    )
    .expect("archived already");
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
    migrate_events(
        &empty,
        "snapshot-1",
        &empty,
        &empty.join("data/events"),
        Bounds::default(),
        &mut out,
    )
    .expect("nothing to archive");
    assert!(
        String::from_utf8(out)
            .expect("text")
            .contains("nothing to archive")
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(empty);
}

#[test]
fn migrate_events_refuses_another_volume_than_the_configuration_s() {
    let root = scratch("command-volume");
    let other = scratch("command-volume-other");
    let history = written(&root, 1, 1);
    drop(Volume::claim(&root, AssuranceProfile::Development).expect("claimed"));
    let refused = migrate_events(
        &root,
        "snapshot-1",
        &other,
        &history,
        Bounds::default(),
        &mut Vec::new(),
    )
    .expect_err("another working directory");
    assert!(
        format!("{refused:#}").contains("is not the working directory"),
        "{refused:#}"
    );
    assert!(!root.join(TARGET).exists());
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(other);
}

#[test]
fn the_command_line_names_the_event_archive() {
    let parsed = crate::command::Cli::try_parse_from([
        "permguard",
        "migrate",
        "events",
        "--volume",
        "/volume",
        "--backup",
        "snapshot-1",
        "--config",
        "/etc/permguard/server.yml",
    ])
    .expect("parsed");
    assert_eq!(
        parsed.command,
        Some(crate::command::Command::Migrate {
            what: crate::command::MigrateCommand::Events {
                volume: PathBuf::from("/volume"),
                backup: "snapshot-1".to_owned(),
                config: PathBuf::from("/etc/permguard/server.yml"),
            },
        })
    );
    // The configuration is required: the history is measured against it.
    assert!(
        crate::command::Cli::try_parse_from([
            "permguard",
            "migrate",
            "events",
            "--volume",
            "/volume",
            "--backup",
            "snapshot-1",
        ])
        .is_err()
    );
}

#[test]
fn the_bounds_are_the_configuration_s() {
    let config = permguard_core::Config::default();
    let bounds = bounds_of(&config);
    assert_eq!(bounds.retention_minimum, config.events_retention_minimum());
    assert_eq!(bounds.allowed_lateness, config.events_allowed_lateness());
    assert_eq!(bounds.clock_skew, config.events_clock_skew());
}
