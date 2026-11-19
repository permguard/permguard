// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

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

/// BUG-0126: from `production` upward, a drained history that a foreign file keeps from being
/// archived is reported with that refusal; the command is named only for one it would archive.
#[test]
fn a_production_start_names_the_obstacle_rather_than_a_command_that_refuses() {
    let root = scratch("start-production-obstacle");
    let history = written(&root, 2, 2);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert!(production_reason(&volume, &history, config_file()).contains("migrate events"));
    std::fs::write(history.join("README"), "not the history's").expect("a foreign file");
    let said = production_reason(&volume, &history, config_file());
    assert!(said.contains("README"), "{said}");
    assert!(!said.contains("migrate events"), "{said}");
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Production,
        later(),
    );
    assert_eq!(laid_out(&volume), None, "left in place, the start goes on");
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

/// BUG-0122: the default store is not inside the default history any more, and a store releases
/// before kept there is moved out at start: a volume with no legacy history then reads as having
/// none, and a real one beside the store layout is archived. Two stores are left as they are.
#[test]
fn the_event_store_moves_out_of_the_legacy_history_and_a_volume_without_one_has_none() {
    use permguard_core::config::{
        DEFAULT_EVENT_STORE_DIRECTORY, DEFAULT_EVENTS_DIRECTORY, LEGACY_EVENT_STORE_DIRECTORY,
    };
    assert!(
        !DEFAULT_EVENT_STORE_DIRECTORY.starts_with(&format!("{DEFAULT_EVENTS_DIRECTORY}/")),
        "the defaults do not nest"
    );
    let root = scratch("store-relocated");
    let legacy = root.join(LEGACY_EVENT_STORE_DIRECTORY);
    let configured = root.join(DEFAULT_EVENT_STORE_DIRECTORY);
    std::fs::create_dir_all(legacy.join("streams")).expect("a store");
    for name in ["CURSOR_KEY", "CURSOR_KEY.witness", "LOCK"] {
        std::fs::write(legacy.join(name), name).expect("a store file");
    }
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let history = root.join(DEFAULT_EVENTS_DIRECTORY);
    let horizon = horizon(Bounds::default(), i64::try_from(later()).unwrap());
    assert_eq!(
        standing(&volume, &history, Bounds::default(), horizon).expect("read"),
        Standing::Drained,
        "the store taken for a history: the bug"
    );
    assert!(relocate_event_store(&legacy, &configured).expect("moved"));
    assert!(!legacy.exists());
    assert_eq!(
        std::fs::read(configured.join("CURSOR_KEY")).expect("moved whole"),
        b"CURSOR_KEY"
    );
    assert_eq!(
        standing(&volume, &history, Bounds::default(), horizon).expect("read"),
        Standing::Absent
    );
    assert!(!relocate_event_store(&legacy, &configured).expect("nothing to move"));

    // A real drained history beside the store layout is archived.
    let history = written(&root, 2, 2);
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        later(),
    );
    assert_eq!(laid_out(&volume), Some(2));
    assert!(
        configured.join("CURSOR_KEY").is_file(),
        "the store untouched"
    );

    // Two stores: neither moves.
    std::fs::create_dir_all(&legacy).expect("another");
    std::fs::write(legacy.join("LOCK"), "x").expect("written");
    assert!(!relocate_event_store(&legacy, &configured).expect("left"));
    assert!(legacy.join("LOCK").is_file() && configured.join("LOCK").is_file());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

/// BUG-0124: a file written under the archived history's old directory is not the history's:
/// the start names it, and `migrate finalize` refuses and leaves it.
#[test]
fn finalize_never_removes_a_file_written_under_the_old_directory_after_the_archive() {
    let root = scratch("finalize-store");
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
    std::fs::create_dir_all(history.join("store")).expect("a store turned on later");
    std::fs::write(history.join("store/LOCK"), "live").expect("written");
    let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
    assert_eq!(
        layout.unrecorded().expect("read"),
        vec!["store/LOCK".to_owned()]
    );
    // The start says so, and goes on.
    archive_at_start(
        &volume,
        &history,
        Bounds::default(),
        config_file(),
        AssuranceProfile::Development,
        later(),
    );
    let refused = layout.finalize(later()).expect_err("an unrecorded file");
    assert!(refused.to_string().contains("store/LOCK"), "{refused}");
    assert!(history.join("store/LOCK").is_file(), "never removed");
    drop(volume);
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
fn the_bounds_are_the_configuration_s() {
    let config = permguard_core::Config::default();
    let bounds = bounds_of(&config);
    assert_eq!(bounds.retention_minimum, config.events_retention_minimum());
    assert_eq!(bounds.allowed_lateness, config.events_allowed_lateness());
    assert_eq!(bounds.clock_skew, config.events_clock_skew());
}
