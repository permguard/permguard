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
use permguard_host::storage::{Dir, format, tombstone};

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
fn child_tombstone() {
    tombstone::delete(&directory(), "obj").expect("deleted");
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

/// Every crash point the library names belongs to one of the protocols tested above; each round
/// there proves its point was reached, by requiring the child to die of the abort at it.
#[test]
fn every_named_crash_point_belongs_to_a_tested_protocol() {
    let visited: Vec<&str> = ["immutable.", "view.", "journal.", "tombstone."]
        .iter()
        .flat_map(|prefix| points(prefix))
        .collect();
    assert_eq!(visited.len(), POINTS.len());
}
