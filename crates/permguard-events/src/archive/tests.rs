// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use crate::journal::Journal;
use crate::record::{GENESIS, Producer, Stream, occurrence_digest_of};
use permguard_core::assurance::AssuranceProfile;
use permguard_host::storage::migrate::Layout;
use permguard_host::storage::volume::Volume;
use serde_json::{Value, json};

use super::*;

const NOW: u64 = 1_800_000_000;
/// When every record below occurred.
const OCCURRED: &str = "2026-10-01T00:00:00Z";

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-event-archive-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("created");
    root
}

fn epoch(instant: &str) -> i64 {
    crate::index::epoch_seconds(instant).expect("an instant")
}

/// A horizon after every record: nothing a loaded window reads.
fn after() -> i64 {
    epoch(OCCURRED) + 1
}

/// A horizon at the records: a window still reads them.
fn at() -> i64 {
    epoch(OCCURRED)
}

fn history_of(root: &Path) -> PathBuf {
    root.join("data/events")
}

fn stream() -> Stream {
    Stream::new(Producer::data_plane("pdp-a", "inst-1"), "acme", "main")
}

fn record(seq: u64, prev: &str, occurred_at: &str) -> Value {
    let event = json!({ "event_id": format!("evt-{seq}"), "kind": "request" });
    json!({
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
        "occurrence_digest": occurrence_digest_of(&event).expect("digested"),
        "kind": "request",
        "profile": "default",
        "policy_partitions": ["governance"],
        "commit": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        "occurred_at": occurred_at,
        "observed_at": occurred_at,
        "event": event
    })
}

/// A legacy journal of `acme/main` holding `records` records occurred at `occurred_at`, the first
/// `acked` of them acknowledged by the control plane.
fn journal(history: &Path, records: u64, acked: u64, occurred_at: &str) {
    let directory = history.join("acme/main");
    let mut journal = Journal::open(&directory, stream(), Bounds::default()).expect("opened");
    let mut prev = GENESIS.to_owned();
    for seq in 1..=records {
        prev = journal
            .append(&record(seq, &prev, occurred_at))
            .expect("appended")
            .digest;
    }
    journal.mark_signed(records).expect("signed");
    journal.acknowledge(acked).expect("acknowledged");
}

/// The retired pull's store of `acme/main`: one imported record occurred at `occurred_at`, and
/// `gaps` as its cursor kept them.
fn store(history: &Path, occurred_at: &str, gaps: Value) {
    let directory = history.join("pull/acme/main");
    std::fs::create_dir_all(&directory).expect("created");
    let imported = json!({ "observe": true, "record": record(1, GENESIS, occurred_at) });
    std::fs::write(directory.join(STORE_RECORDS), format!("{imported}\n")).expect("written");
    std::fs::write(
        directory.join(STORE_STATE),
        serde_json::to_vec(&json!({ "offset": "o-1", "gaps": gaps })).unwrap(),
    )
    .expect("written");
    std::fs::write(directory.join(crate::index::INDEX_FILE), b"derived\n").expect("written");
}

fn gap(at: &str, resolved: bool) -> Value {
    json!({
        "zone": "acme",
        "ledger": "main",
        "from_sequence": 3,
        "to_sequence": 9,
        "at": at,
        "consistency": "shared-bounded",
        "resolved": resolved
    })
}

/// Every file below `directory`, by its `/`-separated path, with its bytes.
fn files(directory: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(directory: &Path, prefix: &str, into: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(directory).expect("listed") {
            let entry = entry.expect("an entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().expect("a type").is_dir() {
                walk(&entry.path(), &format!("{prefix}{name}/"), into);
            } else {
                into.push((
                    format!("{prefix}{name}"),
                    std::fs::read(entry.path()).expect("read"),
                ));
            }
        }
    }
    let mut found = Vec::new();
    walk(directory, "", &mut found);
    found.sort();
    found
}

fn claimed(root: &Path) -> Volume {
    Volume::claim(root, AssuranceProfile::Development).expect("claimed")
}

fn bounds() -> Bounds {
    Bounds::default()
}

#[test]
fn a_drained_legacy_is_archived_byte_for_byte() {
    let root = scratch("drained");
    let history = history_of(&root);
    journal(&history, 3, 3, OCCURRED);
    store(
        &history,
        OCCURRED,
        json!([gap("2026-09-30T00:00:00Z", false)]),
    );
    let volume = claimed(&root);
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Drained
    );

    archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect("archived");

    let before: Vec<(String, Vec<u8>)> = files(&history)
        .into_iter()
        .filter(|(path, _)| !path.ends_with("/LOCK"))
        .collect();
    let carried = files(&root.join(TARGET));
    assert_eq!(carried, before, "every file but the locks, byte for byte");
    for expected in [
        "acme/main/STATE",
        "acme/main/RESERVE",
        "acme/main/INDEX",
        "acme/main/seg-00000000000000000001.events",
        "pull/acme/main/STATE",
        "pull/acme/main/imported.events",
        "pull/acme/main/INDEX",
    ] {
        assert!(
            carried.iter().any(|(path, _)| path == expected),
            "{expected} is carried"
        );
    }
    assert!(!carried.iter().any(|(path, _)| path.ends_with("LOCK")));
    let manifest = Layout::open(&volume, SUBSYSTEM)
        .unwrap()
        .manifest()
        .unwrap()
        .expect("laid out");
    assert_eq!(manifest.active.version, TARGET_VERSION);
    assert_eq!(manifest.active.directory, TARGET);
    // The old generation is kept until `migrate finalize`, and is what the commit names.
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Archived
    );
    assert!(archived(Some(TARGET_VERSION)));
    assert!(!archived(Some(SOURCE_VERSION)));
    assert!(!archived(None));
}

#[test]
fn an_unshipped_journal_is_not_archived() {
    let root = scratch("unshipped");
    let history = history_of(&root);
    journal(&history, 3, 2, OCCURRED);
    let volume = claimed(&root);
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Undrained
    );
    let refused = archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect_err("one record unshipped");
    assert!(refused.to_string().contains("not yet shipped"), "{refused}");
    assert!(!root.join(TARGET).exists());
    assert!(
        Layout::open(&volume, SUBSYSTEM)
            .unwrap()
            .manifest()
            .unwrap()
            .is_none(),
        "nothing declared"
    );
}

#[test]
fn a_record_inside_the_horizon_keeps_the_journal() {
    let root = scratch("inside");
    let history = history_of(&root);
    journal(&history, 2, 2, OCCURRED);
    let volume = claimed(&root);
    // A record at the horizon is one a window may still read.
    assert_eq!(
        standing(&volume, &history, bounds(), at()).unwrap(),
        Standing::Undrained
    );
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Drained
    );
    // A record whose time cannot be read keeps it, whatever the horizon.
    let unreadable = scratch("unreadable-time");
    let history = history_of(&unreadable);
    journal(&history, 1, 1, "not an instant");
    let volume = claimed(&unreadable);
    assert_eq!(
        standing(&volume, &history, bounds(), i64::MAX).unwrap(),
        Standing::Undrained
    );
}

#[test]
fn an_imported_record_or_gap_inside_the_horizon_keeps_the_store() {
    let cases = [
        // An imported record a window may still read.
        ("record", "2026-10-02T00:00:00Z", json!([])),
        // An unresolved gap noticed at or after the horizon: what it lost may be inside.
        ("gap", OCCURRED, json!([gap("2026-10-02T00:00:00Z", false)])),
        // A gap whose time cannot be read.
        ("gap-time", OCCURRED, json!([gap("whenever", false)])),
    ];
    for (tag, occurred, gaps) in cases {
        let root = scratch(tag);
        let history = history_of(&root);
        store(&history, occurred, gaps);
        let volume = claimed(&root);
        assert_eq!(
            standing(&volume, &history, bounds(), after()).unwrap(),
            Standing::Undrained,
            "{tag}"
        );
    }
    // A resolved gap, however recent, keeps nothing.
    let root = scratch("resolved");
    let history = history_of(&root);
    store(
        &history,
        OCCURRED,
        json!([gap("2026-10-02T00:00:00Z", true)]),
    );
    let volume = claimed(&root);
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Drained
    );
}

#[test]
fn no_events_directory_or_an_empty_one_is_absent() {
    let root = scratch("absent");
    let history = history_of(&root);
    let volume = claimed(&root);
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Absent
    );
    // Directories alone, as a reading store or an older release left them, hold no history.
    std::fs::create_dir_all(history.join("pull/acme/main")).unwrap();
    std::fs::create_dir_all(history.join("acme/main")).unwrap();
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Absent
    );
    let refused = archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect_err("nothing to archive");
    assert!(
        refused.to_string().contains("nothing to archive"),
        "{refused}"
    );
}

#[test]
fn a_foreign_file_stops_the_archive() {
    for (tag, foreign) in [
        ("root", "notes.txt"),
        ("zone", "acme/notes.txt"),
        ("journal", "acme/main/notes.txt"),
        ("journal-dir", "acme/main/extra/x"),
        ("store", "pull/acme/main/notes.txt"),
        ("store-dir", "pull/acme/main/extra/x"),
        ("occurrence", "acme/main/occurrences/zz/x.json"),
    ] {
        let root = scratch(&format!("foreign-{tag}"));
        let history = history_of(&root);
        journal(&history, 1, 1, OCCURRED);
        store(&history, OCCURRED, json!([]));
        let path = history.join(foreign);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"mine").unwrap();
        let volume = claimed(&root);
        let obstacle = obstacle(&volume, &history)
            .unwrap()
            .expect("a foreign file");
        assert!(
            obstacle
                .to_string()
                .contains("beside the legacy event history"),
            "{tag}"
        );
        archive(
            &volume,
            &history,
            bounds(),
            after(),
            AssuranceProfile::Development,
            None,
            NOW,
        )
        .expect_err(tag);
        assert!(!root.join(TARGET).exists(), "{tag}");
    }
    // A journal's own occurrence entries are its files.
    assert!(of_history("acme/main/occurrences/"));
    assert!(of_history("acme/main/occurrences/ab/"));
    assert!(of_history("acme/main/occurrences/ab/0123.json"));
    assert!(of_history("acme/main/checkpoint-00000000000000000001.jws"));
    assert!(of_history("acme/main/signers.json"));
    assert!(of_history("acme/main/OCCURRENCES_STATE"));
    assert!(!of_history("acme/main/seg-x.events"));
    assert!(!of_history("pull/acme/main/LOCK"));
}

#[test]
fn an_events_directory_outside_the_volume_or_around_the_target_is_refused() {
    let root = scratch("outside");
    let elsewhere = scratch("outside-elsewhere");
    journal(&elsewhere, 1, 1, OCCURRED);
    let volume = claimed(&root);
    let refused = archive(
        &volume,
        &elsewhere,
        bounds(),
        after(),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect_err("outside the volume");
    assert!(
        refused.to_string().contains("outside the volume"),
        "{refused}"
    );
    for (tag, relative) in [("target", TARGET), ("parent", "data")] {
        let root = scratch(&format!("around-{tag}"));
        let history = root.join(relative);
        journal(&history, 1, 1, OCCURRED);
        let volume = claimed(&root);
        let refused = archive(
            &volume,
            &history,
            bounds(),
            after(),
            AssuranceProfile::Development,
            None,
            NOW,
        )
        .expect_err(tag);
        assert!(
            refused.to_string().contains("at or around"),
            "{tag}: {refused}"
        );
        assert!(
            Layout::open(&volume, SUBSYSTEM)
                .unwrap()
                .manifest()
                .unwrap()
                .is_none(),
            "{tag}: nothing declared"
        );
    }
}

#[test]
fn a_legacy_back_after_the_archive_is_an_orphan() {
    let root = scratch("orphan");
    let history = history_of(&root);
    journal(&history, 1, 1, OCCURRED);
    let volume = claimed(&root);
    archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect("archived");
    Layout::open(&volume, SUBSYSTEM)
        .unwrap()
        .finalize(NOW + 1)
        .expect("finalized");
    assert!(!history.exists(), "the old generation went with finalize");
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Archived
    );
    // A history found there again is never archived twice.
    journal(&history, 1, 1, OCCURRED);
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Orphan
    );
    archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect_err("an orphan");
}

#[test]
fn a_production_archive_declares_a_backup() {
    let root = scratch("production");
    let history = history_of(&root);
    journal(&history, 1, 1, OCCURRED);
    let volume = claimed(&root);
    let refused = archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Production,
        None,
        NOW,
    )
    .expect_err("no backup declared");
    assert!(refused.to_string().contains("backup"), "{refused}");
    assert!(!root.join(TARGET).exists());
    // Declared at version 1 and refused by the preflight: the retry reads the history it names.
    assert_eq!(waiting(&volume).unwrap().as_deref(), Some("data/events"));
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Drained
    );
    archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Production,
        Some("snapshot-1".to_owned()),
        NOW,
    )
    .expect("archived with its backup");
    assert!(root.join(TARGET).join("acme/main/STATE").exists());
}

#[test]
fn a_declared_history_gone_is_refused_by_name() {
    let root = scratch("gone");
    let history = history_of(&root);
    journal(&history, 1, 1, OCCURRED);
    let volume = claimed(&root);
    archive(
        &volume,
        &history,
        bounds(),
        after(),
        AssuranceProfile::Production,
        None,
        NOW,
    )
    .expect_err("declared, then refused for its backup");
    std::fs::remove_dir_all(&history).unwrap();
    let obstacle = obstacle(&volume, &history)
        .unwrap()
        .expect("the declared directory is gone");
    assert!(obstacle.to_string().contains("which is gone"), "{obstacle}");
}

#[test]
fn the_horizon_is_the_evictions() {
    let bounds = Bounds::default();
    let required = bounds.required_retention(bounds.retention_minimum);
    assert_eq!(
        horizon(bounds, 1_000_000_000),
        1_000_000_000 - i64::try_from(required.as_secs()).unwrap()
    );
}

#[test]
fn the_declared_layouts_include_the_event_archive() {
    let declared = layouts();
    assert_eq!(declared.len(), 1);
    assert_eq!(declared[0].0, SUBSYSTEM);
    assert_eq!(
        format!("{:?}", declared[0].1),
        format!("{:?}", Reads::from(SOURCE_VERSION, TARGET_VERSION))
    );
}

#[test]
fn an_imported_record_or_gap_at_the_horizon_keeps_the_store() {
    // A record occurred exactly at the horizon: a window still reads it.
    let root = scratch("store-at-record");
    let history = history_of(&root);
    store(&history, OCCURRED, json!([]));
    let volume = claimed(&root);
    assert_eq!(
        standing(&volume, &history, bounds(), at()).unwrap(),
        Standing::Undrained
    );
    // An unresolved gap noticed exactly at the horizon, over older records.
    let root = scratch("store-at-gap");
    let history = history_of(&root);
    store(
        &history,
        "2026-09-01T00:00:00Z",
        json!([gap(OCCURRED, false)]),
    );
    let volume = claimed(&root);
    assert_eq!(
        standing(&volume, &history, bounds(), at()).unwrap(),
        Standing::Undrained
    );
    assert_eq!(
        standing(&volume, &history, bounds(), after()).unwrap(),
        Standing::Drained
    );
}

#[test]
fn a_history_inside_the_target_or_holding_a_link_is_refused() {
    let root = scratch("inside-target");
    let history = root.join(TARGET).join("events");
    journal(&history, 1, 1, OCCURRED);
    let volume = claimed(&root);
    let refused = obstacle(&volume, &history)
        .unwrap()
        .expect("inside the target");
    assert!(refused.to_string().contains("at or around"), "{refused}");

    #[cfg(unix)]
    {
        let root = scratch("link");
        let history = history_of(&root);
        journal(&history, 1, 1, OCCURRED);
        std::os::unix::fs::symlink(
            history.join("acme/main/STATE"),
            history.join("acme/main/INDEX.link"),
        )
        .unwrap();
        std::os::unix::fs::symlink(history.join("acme/main"), history.join("acme/other")).unwrap();
        let volume = claimed(&root);
        let refused = obstacle(&volume, &history)
            .unwrap()
            .expect("links are foreign");
        let said = refused.to_string();
        assert!(
            said.contains("INDEX.link") && said.contains("acme/other"),
            "{said}"
        );
    }
}
