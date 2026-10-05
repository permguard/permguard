// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every crash point of every protocol, one at a time (P4).
//!
//! The parent test prepares a directory, runs one of the `child_*` tests in a child process told
//! to abort at one named point (`PERMGUARD_CRASH_AT`), and then checks what recovery makes of what
//! the child left: published or absent, never partial; the old view or the new, never a mixture;
//! the journal opening with every flushed frame and nothing torn; the deletion completed. The
//! child tests are ignored in a normal run and only ever started by their parent.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use permguard_host::storage::crash::{CRASH_AT, POINTS};
use permguard_host::storage::journal::{Journal, Options};
use permguard_host::storage::write::{Published, publish_immutable, read_view, replace_view};
use permguard_host::storage::{Dir, format, tombstone, volume};

const DIRECTORY: &str = "PERMGUARD_CRASH_DIRECTORY";

fn scratch(tag: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("permguard-host-crash-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// Runs the child test `child` in a process told to abort at `point`; answers whether it died of
/// that abort — a panic or an early exit is not a crash at the point.
fn crash(child: &str, point: &str, directory: &Path) -> bool {
    let status = Command::new(std::env::current_exe().expect("this binary names itself"))
        .args([
            "--ignored",
            "--exact",
            child,
            "--test-threads",
            "1",
            "--nocapture",
        ])
        .env(CRASH_AT, point)
        .env(DIRECTORY, directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the child runs");
    aborted(status)
}

#[cfg(unix)]
fn aborted(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal() == Some(6)
}

#[cfg(not(unix))]
fn aborted(status: std::process::ExitStatus) -> bool {
    // `abort` ends a Windows process with `STATUS_STACK_BUFFER_OVERRUN` (the `__fastfail` it
    // uses), or with exit code 3 where the C runtime's own `abort` runs.
    matches!(status.code(), Some(3) | Some(-1_073_740_791))
}

fn directory() -> Dir {
    Dir::open(Path::new(
        &std::env::var(DIRECTORY).expect("the parent names the directory"),
    ))
    .expect("the directory opens")
}

fn exact(content: &'static [u8]) -> impl Fn(&[u8]) -> bool {
    move |held: &[u8]| held == content
}

fn journal_options() -> Options {
    // Small enough that the child's first append fills the segment and its second rolls it.
    Options {
        max_frame: 1024,
        segment_bytes: 120,
        ..Options::default()
    }
}

#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_immutable() {
    publish_immutable(
        &directory(),
        "obj",
        b"content",
        &exact(b"content"),
        &exact(b"content"),
    )
    .expect("published");
}

#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_volume() {
    volume::Volume::claim(
        Path::new(&std::env::var(DIRECTORY).expect("the parent names the directory")),
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("claimed");
}

#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_view() {
    replace_view(&directory(), "state", format::VIEW, b"new").expect("replaced");
}

#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_journal() {
    let (mut journal, _) = Journal::open(directory(), journal_options()).expect("opened");
    journal.append(1, &[7u8; 40]).expect("appended");
    journal.append(1, &[8u8; 40]).expect("rolled and appended");
}

#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_failed_flush() {
    let (mut journal, _) = Journal::open(directory(), Options::default()).expect("opened");
    journal.append(1, &[7u8; 40]).expect("appended");
    let segment = directory().child_path(&journal.segments()[0]);
    let _guard = permguard_core::fault::inject_exact(segment, permguard_core::fault::Fault::Fsync);
    let _ = journal.append(1, &[8u8; 40]);
}

/// A failed flush whose record cannot be written either: the whole directory's flushes fail. The
/// process then ends, as a restart would end it.
#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_unrecorded_failure() {
    let (mut journal, _) = Journal::open(directory(), Options::default()).expect("opened");
    journal.append(1, &[7u8; 40]).expect("appended");
    let _guard =
        permguard_core::fault::inject(directory().path(), permguard_core::fault::Fault::Fsync);
    assert!(journal.append(1, &[8u8; 40]).is_err(), "the flush failed");
}

#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_recovery() {
    drop(Journal::open(directory(), failure_options()).expect("opened"));
}

#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_tombstone() {
    tombstone::delete(&directory(), "obj").expect("deleted");
}

/// Two 20-byte frames per segment.
fn failure_options() -> Options {
    Options {
        max_frame: 64,
        segment_bytes: 120,
        ..Options::default()
    }
}

fn points(prefix: &str) -> Vec<&'static str> {
    POINTS
        .iter()
        .copied()
        .filter(|point| point.starts_with(prefix))
        .collect()
}

/// Immutable publish: after a crash at any step the name is absent or holds exactly the content,
/// no temporary survives the sweep, and publishing again succeeds.
#[test]
fn every_crash_point_of_an_immutable_publish_recovers() {
    for point in points("immutable.") {
        let path = scratch(point);
        assert!(
            crash("child_immutable", point, &path),
            "the child aborted at {point}"
        );

        let dir = Dir::open(&path).expect("opened");
        dir.sweep_temps().expect("swept");
        let linked = !matches!(
            point,
            "immutable.temp_created" | "immutable.temp_written" | "immutable.temp_flushed"
        );
        match dir.read("obj").expect("read") {
            Some(held) => assert_eq!(held, b"content", "{point}: never partial"),
            None => assert!(
                !linked,
                "{point}: the content was published before the crash"
            ),
        }
        assert!(
            dir.names()
                .expect("listed")
                .iter()
                .all(|name| !name.starts_with(".tmp-")),
            "{point}: no temporary survives"
        );
        let again = publish_immutable(
            &dir,
            "obj",
            b"content",
            &exact(b"content"),
            &exact(b"content"),
        )
        .expect("published again");
        assert_eq!(again == Published::AlreadyThere, linked, "{point}");
    }
}

/// Replaceable view: after a crash at any step the view is the old one or the new one.
#[test]
fn every_crash_point_of_a_view_replacement_recovers() {
    for point in points("view.") {
        let path = scratch(point);
        replace_view(
            &Dir::open(&path).expect("opened"),
            "state",
            format::VIEW,
            b"old",
        )
        .expect("the old view");
        assert!(
            crash("child_view", point, &path),
            "the child aborted at {point}"
        );

        let dir = Dir::open(&path).expect("opened");
        dir.sweep_temps().expect("swept");
        let held = read_view(&dir, "state", format::VIEW).expect("a whole view, never a mixture");
        let renamed = matches!(point, "view.renamed" | "view.parent_flushed");
        let expected: &[u8] = if renamed { b"new" } else { b"old" };
        assert_eq!(held.as_deref(), Some(expected), "{point}");
    }
}

/// Journal append and segment roll: after a crash at any step the journal opens, every flushed
/// frame is there, and appends continue at the right index.
#[test]
fn every_crash_point_of_a_journal_append_and_roll_recovers() {
    for point in points("journal.") {
        let path = scratch(point);
        drop(Journal::open(Dir::open(&path).expect("opened"), journal_options()).expect("created"));
        assert!(
            crash("child_journal", point, &path),
            "the child aborted at {point}"
        );

        let (mut journal, _) = Journal::open(Dir::open(&path).expect("opened"), journal_options())
            .expect("the journal opens after the crash");
        let frames = journal.frames().expect("read");
        let flushed = point != "journal.frame_written";
        if flushed {
            assert_eq!(frames.len(), 1, "{point}: the flushed frame survives");
        }
        assert!(frames.len() <= 1, "{point}");
        assert!(
            frames.iter().all(|frame| frame.payload == [7u8; 40]),
            "{point}: never partial"
        );
        let next = journal.append(2, b"after").expect("appends continue");
        assert_eq!(next, frames.len() as u64, "{point}");
    }
}

/// A failed flush (WP-1.2): after a crash once the failure is recorded, the frame that failed is
/// cut when the journal opens and appends continue at its index.
#[test]
fn a_crash_after_a_failure_is_recorded_recovers_without_the_failed_frame() {
    let path = scratch("failure.recorded");
    drop(Journal::open(Dir::open(&path).expect("opened"), Options::default()).expect("created"));
    assert!(
        crash("child_failed_flush", "failure.recorded", &path),
        "the child aborted"
    );

    let (mut journal, recovery) =
        Journal::open(Dir::open(&path).expect("opened"), Options::default())
            .expect("the journal opens after the crash");
    assert_eq!(recovery.cut_from, Some(1));
    let frames = journal.frames().expect("read");
    assert_eq!(frames.len(), 1, "only the acknowledged frame");
    assert_eq!(frames[0].payload, [7u8; 40]);
    assert_eq!(journal.append(2, b"after").expect("appends continue"), 1);
}

/// The residual rule of WP-1.2, pinned: after a restart without a failure record, a frame whose
/// flush failed cannot be told from a write that crashed before its acknowledgement, and is kept
/// as one. Its writer was answered an error, never a success.
#[test]
fn after_a_restart_without_a_record_a_failed_frame_is_kept_like_an_unacknowledged_write() {
    let path = scratch("unrecorded");
    let status = Command::new(std::env::current_exe().expect("this binary names itself"))
        .args([
            "--ignored",
            "--exact",
            "child_unrecorded_failure",
            "--test-threads",
            "1",
        ])
        .env(DIRECTORY, &path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the child runs");
    assert!(status.success(), "the child saw its append fail and ended");
    assert!(!path.join("FAILED").exists(), "no record could be written");

    let (journal, recovery) = Journal::open(Dir::open(&path).expect("opened"), Options::default())
        .expect("a new process opens it");
    assert_eq!(recovery.cut_from, None, "nothing says the frame failed");
    let payloads: Vec<u8> = journal
        .frames()
        .expect("read")
        .iter()
        .map(|frame| frame.payload[0])
        .collect();
    assert_eq!(
        payloads,
        [7, 8],
        "the failed frame is kept, like an unacknowledged write"
    );
}

/// Recovery from a failure record: after a crash at any step of the cut, the journal opens with
/// exactly the acknowledged frames, no gap and no record.
#[test]
fn every_crash_point_of_a_cut_recovers() {
    for point in [
        "failure.cut_segments_removed",
        "failure.cut_flushed",
        "failure.record_removed",
    ] {
        let path = scratch(point);
        let (mut journal, _) =
            Journal::open(Dir::open(&path).expect("opened"), failure_options()).expect("created");
        for index in 0..6u8 {
            journal.append(1, &[index; 20]).expect("appended");
        }
        drop(journal);
        replace_view(
            &Dir::open(&path).expect("opened"),
            "FAILED",
            format::VIEW,
            &3u64.to_be_bytes(),
        )
        .expect("a record");
        assert!(
            crash("child_recovery", point, &path),
            "the child aborted at {point}"
        );

        let (journal, _) = Journal::open(Dir::open(&path).expect("opened"), failure_options())
            .expect("the journal opens after the crash");
        let frames = journal.frames().expect("read");
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.payload[0])
                .collect::<Vec<_>>(),
            [0, 1, 2],
            "{point}"
        );
        assert!(!path.join("FAILED").exists(), "{point}");
    }
}

/// Deletion: after a crash at any step, completing the deletions leaves the file gone whenever the
/// tombstone became durable, and no tombstone behind.
#[test]
fn every_crash_point_of_a_deletion_recovers() {
    for point in points("tombstone.") {
        let path = scratch(point);
        std::fs::write(path.join("obj"), b"x").expect("the file");
        assert!(
            crash("child_tombstone", point, &path),
            "the child aborted at {point}"
        );

        let dir = Dir::open(&path).expect("opened");
        dir.sweep_temps().expect("swept");
        tombstone::complete(&dir).expect("completed");
        assert!(
            !tombstone::is_pending(&dir, "obj").expect("asked"),
            "{point}: no tombstone outlives its deletion"
        );
        assert!(
            !dir.exists("obj").expect("asked"),
            "{point}: the file is gone"
        );
    }
}

/// Volume creation: after a crash at any step, the next claim completes the volume, keeping a
/// `VOLUME_ID` already written, and every later claim reads the same identity.
#[test]
fn every_crash_point_of_a_volume_creation_recovers() {
    for point in points("volume.") {
        let path = scratch(point);
        assert!(
            crash("child_volume", point, &path),
            "the child aborted at {point}"
        );
        let host = path.join(volume::HOST);
        let written = std::fs::read(host.join(volume::VOLUME_ID)).expect("VOLUME_ID was written");
        assert_eq!(
            host.join(volume::FORMAT).exists(),
            point == "volume.format_written",
            "{point}: FORMAT is written last"
        );

        let claimed = volume::Volume::claim(
            &path,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("the next claim completes the volume");
        assert_eq!(
            std::fs::read(host.join(volume::VOLUME_ID)).expect("VOLUME_ID"),
            written,
            "{point}: the identity is kept"
        );
        let id = claimed.id();
        drop(claimed);
        let again = volume::Volume::claim(
            &path,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed again");
        assert_eq!(again.id(), id, "{point}");
    }
}

/// Every crash point the library names belongs to one of the protocols tested above; each round
/// there proves its point was reached, by requiring the child to die of the abort at it.
#[test]
fn every_named_crash_point_belongs_to_a_tested_protocol() {
    let visited: Vec<&str> = [
        "immutable.",
        "view.",
        "journal.",
        "tombstone.",
        "failure.",
        "volume.",
    ]
        .iter()
        .flat_map(|prefix| points(prefix))
        .collect();
    assert_eq!(visited.len(), POINTS.len());
}
