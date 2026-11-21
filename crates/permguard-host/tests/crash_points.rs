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

use permguard_host::storage::crash::{CRASH_AT, CRASH_HIT, POINTS};
use permguard_host::storage::journal::{Journal, Options};
use permguard_host::storage::write::{Published, publish_immutable, read_view, replace_view};
use permguard_host::storage::{Dir, format, tombstone, volume};

const DIRECTORY: &str = "PERMGUARD_CRASH_DIRECTORY";

/// Claims the volume at `root`, waiting out a lock another test's child shares for an instant.
///
/// A child process another test thread spawns holds a copy of every descriptor of this process
/// between its fork and its exec — the volume's `LOCK` among them, close-on-exec or not — so a lock
/// this thread has just released can read as held by another process for that instant. Waited
/// out, and bounded: a lock really held elsewhere is still refused.
fn claim_volume(root: &Path) -> volume::Volume {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match volume::Volume::claim(
            root,
            permguard_core::assurance::AssuranceProfile::Development,
        ) {
            Err(permguard_host::storage::StorageError::Held(_))
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            claimed => return claimed.expect("claimed"),
        }
    }
}

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
    crash_at_hit(child, point, 1, directory)
}

/// [`crash`] at the `hit`-th pass through `point`.
fn crash_at_hit(child: &str, point: &str, hit: u64, directory: &Path) -> bool {
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
        .env(CRASH_HIT, hit.to_string())
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
    claim_volume(Path::new(
        &std::env::var(DIRECTORY).expect("the parent names the directory"),
    ));
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

/// A prefix deletion (WP-5.6a) of a journal its parent filled: seven frames, one per segment.
#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_prefix() {
    let (mut journal, _) = Journal::open(directory(), journal_options()).expect("opened");
    journal.drop_prefix(5, None).expect("dropped");
}

/// An open that finishes a prefix deletion its parent left: `BASE` written, nothing removed.
#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_open() {
    drop(Journal::open(directory(), journal_options()).expect("opened"));
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

/// Prefix deletion (WP-5.6a): after a crash at any step — writing `BASE`, any of the segment
/// deletions, or after them — the journal opens holding exactly the frames the step decides: every
/// frame while `BASE` is not yet in place, the frames from 5 once it is, each at its index, with no
/// segment below `BASE` and no tombstone left, and appends continue at the next index.
#[test]
fn every_crash_point_of_a_prefix_deletion_recovers() {
    // The frame the journal starts at after a crash at each step: `BASE`'s temporary is not yet
    // the view until its rename.
    let mut rounds: Vec<(&str, u64, u64)> = Vec::new();
    for point in points("view.") {
        let first = if matches!(point, "view.temp_written" | "view.temp_flushed") {
            0
        } else {
            5
        };
        rounds.push((point, 1, first));
    }
    rounds.push(("prefix.base_written", 1, 5));
    rounds.push(("prefix.segments_removed", 1, 5));
    // One frame per segment, so five segments go: each tombstone step is crashed at the first
    // deletion and the last.
    for point in points("tombstone.") {
        rounds.extend([(point, 1, 5), (point, 5, 5)]);
    }
    for (point, hit, expected) in rounds {
        let path = scratch(&format!("prefix-{point}-{hit}"));
        let (mut journal, _) =
            Journal::open(Dir::open(&path).expect("opened"), journal_options()).expect("created");
        for index in 0..7u8 {
            journal.append(1, &[index; 40]).expect("appended");
        }
        drop(journal);
        assert!(
            crash_at_hit("child_prefix", point, hit, &path),
            "the child aborted at {point} ({hit})"
        );
        assert_recovered(&path, expected, &format!("{point} ({hit})"));
    }

    // The open that finishes the deletion, crashed after its removals.
    let path = scratch("prefix-recovered");
    let (mut journal, _) =
        Journal::open(Dir::open(&path).expect("opened"), journal_options()).expect("created");
    for index in 0..7u8 {
        journal.append(1, &[index; 40]).expect("appended");
    }
    drop(journal);
    replace_view(
        &Dir::open(&path).expect("opened"),
        permguard_host::storage::journal::BASE,
        format::VIEW,
        &permguard_host::storage::journal::encode_base(5, 0).expect("encoded"),
    )
    .expect("BASE written");
    assert!(
        crash("child_open", "prefix.recovered", &path),
        "the child aborted at prefix.recovered"
    );
    assert_recovered(&path, 5, "prefix.recovered");
}

/// The journal at `path` holds the frames from `first` through 6, each its index repeated, starts
/// with the segment at `first`, keeps no tombstone, `BASE` says `first` (absent when 0), and the
/// next append is frame 7.
fn assert_recovered(path: &Path, first: u64, case: &str) {
    let (mut journal, _) = Journal::open(Dir::open(path).expect("opened"), journal_options())
        .expect("the journal opens after the crash");
    assert_eq!(journal.first_index(), first, "{case}");
    let frames = journal.frames().expect("read");
    assert_eq!(frames.len() as u64, 7 - first, "{case}");
    for frame in &frames {
        assert_eq!(frame.payload, [frame.index as u8; 40], "{case}");
    }
    let names: Vec<String> = std::fs::read_dir(path)
        .expect("listed")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        !names.iter().any(|name| name.ends_with(".tomb")),
        "{case}: {names:?}"
    );
    assert_eq!(
        journal.segments().first().map(String::as_str),
        Some(format!("seg-{first:020}.pgj").as_str()),
        "{case}"
    );
    let base = read_view(
        &Dir::open(path).expect("opened"),
        permguard_host::storage::journal::BASE,
        format::VIEW,
    )
    .expect("read")
    .map(|body| {
        permguard_host::storage::journal::decode_base(&body)
            .expect("decoded")
            .0
    });
    assert_eq!(base, (first > 0).then_some(first), "{case}");
    assert_eq!(
        journal.append(2, b"after").expect("appends continue"),
        7,
        "{case}"
    );
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

        // The next claim completes the volume.
        let claimed = claim_volume(&path);
        assert_eq!(
            std::fs::read(host.join(volume::VOLUME_ID)).expect("VOLUME_ID"),
            written,
            "{point}: the identity is kept"
        );
        let id = claimed.id();
        drop(claimed);
        let again = claim_volume(&path);
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
        "prefix.",
        "volume.",
        "migrate.",
        "mutation.",
        "audit.",
        "holds.",
    ]
    .iter()
    .flat_map(|prefix| points(prefix))
    .collect();
    assert_eq!(visited.len(), POINTS.len());
}

// ---------------------------------------------------------------------------------------------
// Migration (WP-1.9): the synthetic `notes` subsystem, version 1 to 2.

mod migrating {
    use super::*;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_host::storage::migrate::testing::{NotesV2, SUBSYSTEM, write_note};
    use permguard_host::storage::migrate::{Layout, Phase, Preflight, Reads};

    const NOW: u64 = 1_800_000_000;

    fn preflight() -> Preflight {
        Preflight::new(AssuranceProfile::Development, "data/notes/g2", None, NOW)
    }

    fn migration() -> NotesV2 {
        NotesV2 {
            tamper: false,
            write_old: false,
            omit: false,
        }
    }

    fn root() -> PathBuf {
        PathBuf::from(std::env::var(DIRECTORY).expect("the parent names the directory"))
    }

    /// Lays `notes` out at version 1 with two notes on a fresh volume at `root`.
    fn lay_out(root: &Path) {
        let volume = claim_volume(root);
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        layout.declare(1, "data/notes/g1", NOW).expect("declared");
        let old = layout.active(&Reads::only(1)).expect("active");
        write_note(&old, "alpha", b"first note");
        write_note(&old, "beta", b"second note");
    }

    fn migrated(root: &Path) {
        lay_out(root);
        let volume = claim_volume(root);
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .migrate(&migration(), preflight())
            .expect("migrated");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_migrate() {
        let volume = claim_volume(&root());
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .migrate(&migration(), preflight())
            .expect("migrated");
    }

    /// A build refused before the switch leaves the intent; `recover` abandons it.
    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_abandon() {
        let volume = claim_volume(&root());
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        layout
            .migrate(
                &NotesV2 {
                    tamper: true,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect_err("refused before the switch");
        layout.recover(NOW + 1).expect("abandoned");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_finalize() {
        let volume = claim_volume(&root());
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .finalize(NOW + 1)
            .expect("finalized");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_rollback() {
        let volume = claim_volume(&root());
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .rollback(NOW + 1)
            .expect("rolled back");
    }

    /// What a volume must look like on one side or the other, whatever step the crash hit.
    fn assert_on_one_side(root: &Path, point: &str, expect_new: bool) {
        let volume = claim_volume(root);
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        // Opening already completed a finalize or a rollback in progress; a migration between
        // its intent and its commit waits for this.
        let _ = layout.recover(NOW + 2).expect("recovers");
        let status = layout.status().expect("status").expect("laid out");
        assert!(
            status.phase.serves(),
            "{point}: landed on one side, found {:?}",
            status.phase
        );
        assert_eq!(
            status.manifest.active.version,
            if expect_new { 2 } else { 1 },
            "{point}: the side the protocol had reached"
        );
        let old_alpha = root.join("data/notes/g1/alpha");
        let new_alpha = root.join("data/notes/g2/a/alpha");
        if expect_new {
            assert!(new_alpha.is_file(), "{point}: the new generation serves");
            assert_eq!(
                std::fs::read(&new_alpha).expect("read"),
                b"first note",
                "{point}: evidence carried byte for byte"
            );
            assert!(root.join("data/notes/g2/INDEX").is_file(), "{point}");
        } else {
            assert!(old_alpha.is_file(), "{point}: the old generation serves");
            assert_eq!(
                std::fs::read(&old_alpha).expect("read"),
                b"first note",
                "{point}"
            );
            assert!(
                !root.join("data/notes/g2").exists(),
                "{point}: nothing half-built remains"
            );
        }
        // Whatever side, the old generation's evidence was never rewritten while it existed.
        if old_alpha.exists() {
            assert_eq!(
                std::fs::read(&old_alpha).expect("read"),
                b"first note",
                "{point}"
            );
        }
        // Serving is possible again: the next command finds nothing pending.
        layout
            .active(&Reads::from(1, 2))
            .expect("the active generation opens");
    }

    /// Migration: a crash at any step before the switch lands on the old side, at any step from
    /// the switch on lands on the new one; evidence is byte for byte on either.
    #[test]
    fn every_crash_point_of_a_migration_recovers_to_one_side() {
        for point in points("migrate.").into_iter().filter(|point| {
            !point.contains("finalize") && !point.contains("rollback") && !point.contains("abandon")
        }) {
            let path = scratch(point);
            lay_out(&path);
            assert!(
                crash("migrating::child_migrate", point, &path),
                "the child aborted at {point}"
            );
            let switched = matches!(point, "migrate.switched" | "migrate.committed");
            assert_on_one_side(&path, point, switched);
        }
    }

    /// Abandon: a crash at any step of removing a refused build still ends on the old side with
    /// nothing half-built and nothing pending.
    #[test]
    fn every_crash_point_of_an_abandon_recovers_to_the_old_generation() {
        for point in points("migrate.abandon") {
            let path = scratch(point);
            lay_out(&path);
            assert!(
                crash("migrating::child_abandon", point, &path),
                "the child aborted at {point}"
            );
            assert_on_one_side(&path, point, false);
        }
    }

    /// Finalize: a crash at any step still ends with the new generation alone and nothing pending.
    #[test]
    fn every_crash_point_of_a_finalize_recovers_to_the_new_generation() {
        for point in points("migrate.finalize") {
            let path = scratch(point);
            migrated(&path);
            assert!(
                crash("migrating::child_finalize", point, &path),
                "the child aborted at {point}"
            );
            assert_on_one_side(&path, point, true);
            let volume = claim_volume(&path);
            let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
            // Every finalize point is past the manifest's replacement, so opening the layout
            // completed what the crash left.
            let status = layout.status().expect("status").expect("laid out");
            assert_eq!(status.phase, Phase::Idle, "{point}");
            assert!(status.manifest.previous.is_none(), "{point}");
            assert!(
                !path.join("data/notes/g1").exists(),
                "{point}: the old generation is gone"
            );
        }
    }

    /// Rollback: a crash at any step still ends with the old generation alone and nothing pending.
    #[test]
    fn every_crash_point_of_a_rollback_recovers_to_the_old_generation() {
        for point in points("migrate.rollback") {
            let path = scratch(point);
            migrated(&path);
            assert!(
                crash("migrating::child_rollback", point, &path),
                "the child aborted at {point}"
            );
            let volume = claim_volume(&path);
            let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
            // Every rollback point is past the manifest's return, so opening the layout
            // completed what the crash left.
            let status = layout.status().expect("status").expect("laid out");
            assert_eq!(status.phase, Phase::Idle, "{point}");
            assert_eq!(status.manifest.active.version, 1, "{point}");
            assert!(
                !path.join("data/notes/g2").exists(),
                "{point}: the new generation is gone"
            );
            assert_eq!(
                std::fs::read(path.join("data/notes/g1/alpha")).expect("read"),
                b"first note",
                "{point}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The security-mutation transaction (WP-3.6): a record written through the engine, by a domain
// of this test's own that writes one file per operation.

mod mutating {
    use super::*;
    use permguard_host::audit::{Class, HOST, trail};
    use permguard_host::operations::journal::{Initiator, OperationId, RequestKey};
    use permguard_host::operations::mutation::{
        Applied, Applying, Begin, Domain, Failure, MutationError, Mutations, Observed, Outcome,
    };
    use permguard_host::storage::volume::Volume;

    const DOMAIN: &str = "notes";

    fn root() -> PathBuf {
        PathBuf::from(std::env::var(DIRECTORY).expect("the parent names the directory"))
    }

    /// A domain writing one note per operation, named by the operation: what recovery observes.
    struct Notes(Dir);

    impl Notes {
        fn open(volume: &Volume) -> Self {
            Self(volume.host().subdir("notes", true).expect("the notes"))
        }

        fn records(&self) -> Vec<String> {
            let mut names = self.0.names().expect("listed");
            names.sort();
            names
        }

        fn write(&self, applying: &Applying<'_>) -> Result<String, String> {
            let name = format!("note-{}", applying.operation_id());
            publish_immutable(&self.0, &name, b"a note", &|_| true, &|held| {
                held == b"a note"
            })
            .map_err(|error| error.to_string())?;
            Ok(name)
        }
    }

    impl Domain for Notes {
        fn name(&self) -> &'static str {
            DOMAIN
        }

        fn observe(
            &self,
            operation_id: &OperationId,
            _target: Option<&str>,
        ) -> Result<Option<Observed>, String> {
            let name = format!("note-{operation_id}");
            let held = self.records().contains(&name);
            Ok(held.then_some(Observed {
                revision: 1,
                target: Some(name),
            }))
        }
    }

    fn begin() -> Begin {
        Begin {
            domain: DOMAIN,
            operation: "notes.write",
            // A registered security action: the engine records every phase under it.
            action: permguard_host::operations::grants::AUDIT_COMMITTED,
            initiator: Initiator::Principal("sa:admin".to_owned()),
            request: Some(RequestKey {
                request_id: "r-1".to_owned(),
                digest: "d".to_owned(),
            }),
            target: None,
        }
    }

    /// Writes the note as the operation of request `r-1`, answering its name.
    fn create(
        mutations: &Mutations,
        store: &Notes,
    ) -> Result<Outcome<String>, MutationError<String>> {
        mutations.run(begin(), |applying| {
            let name = store.write(applying).map_err(Failure::Indeterminate)?;
            Ok(Applied {
                revision: 1,
                target: Some(name.clone()),
                value: name,
            })
        })
    }

    fn reopen(path: &Path) -> (Volume, Notes, Mutations) {
        let volume = claim_volume(path);
        let store = Notes::open(&volume);
        let mutations = Mutations::open_offline(&volume, "test").expect("the journal opens");
        (volume, store, mutations)
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_issue() {
        let (_volume, store, mutations) = reopen(&root());
        create(&mutations, &store).expect("issued");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_open() {
        // Opening folds the journal into the snapshot.
        let (_volume, _store, _mutations) = reopen(&root());
    }

    /// The phases the Host trail recorded, in order.
    fn phases(volume: &Volume) -> Vec<String> {
        let trails = volume
            .host()
            .subdir(permguard_host::audit::DIRECTORY, false)
            .and_then(|dir| dir.subdir(permguard_host::audit::TRAILS, false))
            .expect("the trails");
        let Ok(dir) = trail::directory(&trails, Class::Security, HOST, false) else {
            return Vec::new();
        };
        trail::verify(&dir).expect("the trail verifies");
        trail::days(&dir)
            .expect("listed")
            .iter()
            .flat_map(|day| trail::read_day(&dir, day).expect("read"))
            .filter_map(|record| record.phase)
            .collect()
    }

    /// A crash at any step leaves either no note and a failed operation, or the note and an
    /// operation committed; every outcome is recorded once the journal is recovered, at least
    /// once (owner decision); and a retry of the request learns the durable result.
    #[test]
    fn every_crash_point_of_a_mutation_recovers_to_one_outcome() {
        for point in points("mutation.")
            .into_iter()
            .filter(|point| *point != "mutation.snapshot_written")
        {
            let path = scratch(point);
            assert!(
                crash("mutating::child_issue", point, &path),
                "{point}: the child died of the abort there"
            );
            let (volume, store, mutations) = reopen(&path);
            let recovered = mutations.recover(&store).expect("recovers");
            assert!(mutations.open_intents().is_empty(), "{point}");
            assert_eq!(mutations.pending(), 0, "{point}: every outcome recorded");
            let applied = !matches!(point, "mutation.intent_written" | "mutation.intent_audited");
            assert_eq!(store.records().len(), usize::from(applied), "{point}");
            match point {
                "mutation.intent_written" | "mutation.intent_audited" => {
                    assert_eq!(recovered.failed.len(), 1, "{point}");
                }
                "mutation.applied" => assert_eq!(recovered.reconciled.len(), 1, "{point}"),
                _ => assert!(
                    recovered.failed.is_empty() && recovered.reconciled.is_empty(),
                    "{point}: committed before the crash"
                ),
            }
            let expected: &[&str] = match point {
                "mutation.intent_written" => &["failed"],
                "mutation.intent_audited" => &["intent", "failed"],
                "mutation.applied" => &["intent", "reconciled"],
                // Written to the trail and not yet marked: written again, at least once.
                "mutation.applied_audited" => &["intent", "applied", "applied"],
                _ => &["intent", "applied"],
            };
            assert_eq!(phases(&volume), expected, "{point}");
            // The caller lost the answer: a retry of the same request learns the result.
            let retried = create(&mutations, &store).expect("the retry answers");
            match (point, retried) {
                ("mutation.intent_written" | "mutation.intent_audited", Outcome::Applied(_)) => {
                    assert_eq!(store.records().len(), 1, "{point}: applied anew, once")
                }
                ("mutation.applied", Outcome::Reconciled { target, .. }) => {
                    assert_eq!(target, Some(store.records()[0].clone()), "{point}")
                }
                (_, Outcome::Replayed(name)) if applied && point != "mutation.applied" => {
                    assert_eq!(name, store.records()[0], "{point}")
                }
                (_, other) => panic!("{point}: {other:?}"),
            }
            assert_eq!(store.records().len(), 1, "{point}: never two notes");
            drop(mutations);
            drop(store);
            drop(volume);
            let _ = std::fs::remove_dir_all(path);
        }
    }

    /// A crash between the snapshot and the journal's rewrite folds to the same state: the
    /// answer a retry needs is still there.
    #[test]
    fn a_crash_mid_fold_keeps_every_answer() {
        let point = "mutation.snapshot_written";
        let path = scratch(point);
        {
            let (_volume, store, mutations) = reopen(&path);
            create(&mutations, &store).expect("issued");
        }
        assert!(
            crash("mutating::child_open", point, &path),
            "{point}: the child died of the abort there"
        );
        let (_volume, store, mutations) = reopen(&path);
        mutations.recover(&store).expect("recovers");
        let retried = create(&mutations, &store).expect("the retry answers");
        assert!(matches!(retried, Outcome::Replayed(_)), "{retried:?}");
        assert_eq!(store.records().len(), 1);
        let _ = std::fs::remove_dir_all(path);
    }
}

// ---------------------------------------------------------------------------------------------
// The audit trail (iteration 03, WP-26.2): a trail's directory and its name in the index.

mod auditing {
    use super::*;
    use std::sync::Arc;

    use permguard_core::AuditEvent;
    use permguard_host::audit::{self, Class, Engine, HOST, Stamp, index, trail};
    use permguard_host::time::TimeGuard;
    use permguard_objects::Digest;

    fn root() -> PathBuf {
        PathBuf::from(std::env::var(DIRECTORY).expect("the parent names the volume"))
    }

    fn engine(volume: &volume::Volume) -> Engine {
        Engine::open(
            volume,
            Stamp {
                host_id: [1; 16],
                boot_id: [2; 16],
                build: "9.9.9".to_owned(),
                config_revision: Digest::compute(b"settings"),
            },
            Arc::new(TimeGuard::system(
                permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
            )),
            None,
        )
        .expect("the engine opens")
    }

    /// One record of `security:host`, the first of which makes its trail.
    fn record(engine: &Engine) {
        engine
            .append(
                &AuditEvent::system(audit::AUDIT_TRAIL_LOST, "permguard").on("security:none"),
                None,
            )
            .expect("recorded");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_first_record() {
        let volume = claim_volume(&root());
        record(&engine(&volume));
    }

    /// A Host that stops after a trail's directory exists and before the index names it has
    /// lost nothing: no record was written, the next start finds no trail lost, and the trail
    /// goes on from its first record.
    #[test]
    fn a_crash_between_a_trails_directory_and_its_name_loses_no_trail() {
        let point = "audit.trail_created";
        let path = scratch(point);
        assert!(
            crash("auditing::child_first_record", point, &path),
            "{point}: the child died of the abort there"
        );
        let volume = claim_volume(&path);
        let restarted = engine(&volume);
        let audit_dir = volume
            .host()
            .subdir(audit::DIRECTORY, false)
            .expect("the audit directory");
        let index_dir = audit_dir
            .subdir(index::DIRECTORY, false)
            .expect("the index");
        let entries = index::entries(&index_dir).expect("the index reads");
        assert!(
            entries.iter().all(|entry| entry.lost.is_none()),
            "a trail that never held a record was recorded lost: {entries:?}"
        );
        record(&restarted);
        let trails = audit_dir.subdir(audit::TRAILS, false).expect("the trails");
        let dir = trail::directory(&trails, Class::Security, HOST, false).expect("security:host");
        assert_eq!(
            trail::verify(&dir).expect("the trail verifies"),
            1,
            "the record of this start is the trail's first"
        );
        let entries = index::entries(&index_dir).expect("the index reads");
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert!(entries[0].lost.is_none());
        drop(restarted);
        drop(volume);
        let _ = std::fs::remove_dir_all(path);
    }
}

// ---------------------------------------------------------------------------------------------
// Store contracts (iteration 03, WP-26.2, E30): an operation of a store killed before and after
// its domain write.

mod stores {
    use super::*;
    use std::sync::Arc;

    use permguard_core::authz::Principal;
    use permguard_host::api::Replay;
    use permguard_host::api::plans::{AUDIT_APPROVED, consume_plan};
    use permguard_host::api::replay::files::FileReplay;
    use permguard_host::api::replay::{self, Plan, PlanApproval};
    use permguard_host::holds::files::FileHolds;
    use permguard_host::holds::{self, Deadline, HoldStore as _, Holds, NewHold};
    use permguard_host::operations::journal::Initiator;
    use permguard_host::operations::mutation::{Applied, Begin, Failure, Mutations};
    use permguard_host::storage::volume::Volume;

    const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";
    const LEDGER: &str = "01a00000-0000-7000-8000-00000000000b";
    const PLAN: &str = "p1";

    /// The two points that tell an operation killed before its domain write from one killed
    /// after it, before its commit.
    const POINTS_OF_A_WRITE: [&str; 2] = ["mutation.intent_audited", "mutation.applied"];

    fn root() -> PathBuf {
        PathBuf::from(std::env::var(DIRECTORY).expect("the parent names the volume"))
    }

    fn now() -> u64 {
        permguard_core::time::unix_now()
    }

    fn open_holds(path: &Path) -> (Volume, FileHolds, Mutations) {
        let volume = claim_volume(path);
        let store = FileHolds::open(&volume).expect("the holds open");
        let mutations = Mutations::open_offline(&volume, "test").expect("the journal opens");
        (volume, store, mutations)
    }

    fn add_hold(store: &FileHolds, mutations: &Mutations) -> holds::Hold {
        holds::add(
            mutations,
            store,
            Initiator::System("test".to_owned()),
            NewHold {
                resource: format!("plane/control/zone/{ZONE}/ledger/{LEDGER}"),
                owner: "legal@acme".to_owned(),
                reason: "litigation 2026-17".to_owned(),
                deadline: Deadline::Review(now() + 86_400),
            },
            now(),
        )
        .expect("added")
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_hold_add() {
        let (_volume, store, mutations) = open_holds(&root());
        add_hold(&store, &mutations);
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_hold_release() {
        let (_volume, store, mutations) = open_holds(&root());
        let held = store.list().expect("the holds read");
        holds::release(
            &mutations,
            &store,
            Initiator::System("test".to_owned()),
            &held[0].id,
        )
        .expect("released");
    }

    /// An add killed before its write leaves no hold and a failed operation; killed after it,
    /// the hold with its record and an operation recovery commits.
    #[test]
    fn a_hold_add_killed_midway_is_whole_or_absent() {
        for point in POINTS_OF_A_WRITE {
            let path = scratch(&format!("hold-add-{point}"));
            assert!(
                crash("stores::child_hold_add", point, &path),
                "{point}: the child died of the abort there"
            );
            let (volume, store, mutations) = open_holds(&path);
            let recovered = mutations.recover(&Holds(&store)).expect("recovers");
            assert!(mutations.open_intents().is_empty(), "{point}");
            let held = store.list().expect("the holds read");
            if point == "mutation.applied" {
                assert_eq!(recovered.reconciled.len(), 1, "{point}");
                assert_eq!(held.len(), 1, "{point}: the hold is held");
                assert!(store.keeps(ZONE, LEDGER, now()).expect("read"), "{point}");
            } else {
                assert_eq!(recovered.failed.len(), 1, "{point}");
                assert!(held.is_empty(), "{point}: nothing was written");
            }
            assert!(
                store.verify().expect("the holds read").is_empty(),
                "{point}: every hold has its record"
            );
            drop((mutations, store, volume));
            let _ = std::fs::remove_dir_all(path);
        }
    }

    /// A release killed before its write leaves the hold keeping; killed after it, no hold and
    /// an operation recovery commits.
    #[test]
    fn a_hold_release_killed_midway_keeps_or_ends_the_hold() {
        for point in POINTS_OF_A_WRITE {
            let path = scratch(&format!("hold-release-{point}"));
            {
                let (_volume, store, mutations) = open_holds(&path);
                add_hold(&store, &mutations);
            }
            assert!(
                crash("stores::child_hold_release", point, &path),
                "{point}: the child died of the abort there"
            );
            let (volume, store, mutations) = open_holds(&path);
            let recovered = mutations.recover(&Holds(&store)).expect("recovers");
            assert!(mutations.open_intents().is_empty(), "{point}");
            let held = store.list().expect("the holds read");
            if point == "mutation.applied" {
                assert_eq!(recovered.reconciled.len(), 1, "{point}");
                assert!(held.is_empty(), "{point}: the hold is released");
            } else {
                assert_eq!(recovered.failed.len(), 1, "{point}");
                assert_eq!(held.len(), 1, "{point}: the hold still keeps");
                assert!(store.keeps(ZONE, LEDGER, now()).expect("read"), "{point}");
            }
            assert!(
                store.verify().expect("the holds read").is_empty(),
                "{point}"
            );
            drop((mutations, store, volume));
            let _ = std::fs::remove_dir_all(path);
        }
    }

    /// What `verify` names a hold by whose file the index does not record.
    const UNRECORDED: &str = "has a file the index does not record";

    /// An add killed between its file and its entry in the index: the hold is held and keeps,
    /// recovery commits the operation its file names, the hold is named unrecorded, and the
    /// next operation records it. The index never names a hold whose file is not there.
    #[test]
    fn a_hold_add_killed_between_its_file_and_its_entry_keeps_the_hold() {
        let point = "holds.file_written";
        let path = scratch("hold-add-between");
        assert!(
            crash("stores::child_hold_add", point, &path),
            "the child died of the abort there"
        );
        let (volume, store, mutations) = open_holds(&path);
        let recovered = mutations.recover(&Holds(&store)).expect("recovers");
        assert_eq!(
            recovered.reconciled.len(),
            1,
            "its file names the operation"
        );
        assert!(mutations.open_intents().is_empty());
        assert_eq!(store.list().expect("the holds read").len(), 1);
        assert!(store.keeps(ZONE, LEDGER, now()).expect("read"));
        let found = store.verify().expect("the holds read");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains(UNRECORDED), "{found:?}");
        // An operation records it with its own hold.
        add_hold(&store, &mutations);
        assert_eq!(store.list().expect("the holds read").len(), 2);
        assert!(store.verify().expect("the holds read").is_empty());
        drop((mutations, store, volume));
        let _ = std::fs::remove_dir_all(path);
    }

    /// A release killed between its entry and its file: the hold still keeps, the operation is
    /// recorded failed, the hold is named unrecorded, and the release run again ends it.
    #[test]
    fn a_hold_release_killed_between_its_entry_and_its_file_keeps_the_hold() {
        let point = "holds.entry_removed";
        let path = scratch("hold-release-between");
        let held = {
            let (_volume, store, mutations) = open_holds(&path);
            add_hold(&store, &mutations)
        };
        assert!(
            crash("stores::child_hold_release", point, &path),
            "the child died of the abort there"
        );
        let (volume, store, mutations) = open_holds(&path);
        let recovered = mutations.recover(&Holds(&store)).expect("recovers");
        assert_eq!(recovered.failed.len(), 1, "the hold is still there");
        assert!(mutations.open_intents().is_empty());
        assert_eq!(store.list().expect("the holds read"), vec![held.clone()]);
        assert!(store.keeps(ZONE, LEDGER, now()).expect("read"));
        let found = store.verify().expect("the holds read");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains(UNRECORDED), "{found:?}");
        holds::release(
            &mutations,
            &store,
            Initiator::System("test".to_owned()),
            &held.id,
        )
        .expect("released when run again");
        assert!(store.list().expect("the holds read").is_empty());
        assert!(!store.keeps(ZONE, LEDGER, now()).expect("read"));
        assert!(store.verify().expect("the holds read").is_empty());
        drop((mutations, store, volume));
        let _ = std::fs::remove_dir_all(path);
    }

    fn open_plans(path: &Path) -> (Volume, Arc<FileReplay>, Replay, Mutations) {
        let volume = claim_volume(path);
        let (store, _) = FileReplay::open(&volume, now()).expect("the replay opens");
        let store = Arc::new(store);
        let replay = Replay::new(Arc::clone(&store) as Arc<dyn replay::ReplayStore>);
        let mutations = Mutations::open_offline(&volume, "test").expect("the journal opens");
        (volume, store, replay, mutations)
    }

    fn plan() -> Plan {
        Plan {
            plan_id: PLAN.to_owned(),
            operation: "host.keys.revoke".to_owned(),
            target: "host.operations/kid-1".to_owned(),
            revision: 7,
            digest: "sha256:00".to_owned(),
            expires: now() + 600,
            principal: "sa:alice".to_owned(),
            kind: "keys.revoke".to_owned(),
            receipt: "cmVjZWlwdA".to_owned(),
            approvals_required: 1,
            approvals: Vec::new(),
            created_at: now(),
        }
    }

    /// One operation of the plans' domain on `target`, as the Host API begins it.
    fn begin(operation: &'static str, target: &str) -> Begin {
        Begin {
            domain: replay::DOMAIN,
            operation,
            action: AUDIT_APPROVED,
            initiator: Initiator::System("test".to_owned()),
            request: None,
            target: Some(target.to_owned()),
        }
    }

    fn seed_plan(path: &Path) {
        let (_volume, _store, replay, mutations) = open_plans(path);
        mutations
            .run(begin("plan.make", "seed"), |applying| {
                replay
                    .plan(applying, plan())
                    .map_err(|_| Failure::Refused("the plan could not be written".to_owned()))?;
                Ok::<_, Failure<String>>(Applied {
                    revision: 7,
                    target: None,
                    value: (),
                })
            })
            .expect("planned");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_plan_approve() {
        let (_volume, _store, replay, mutations) = open_plans(&root());
        mutations
            .run(begin("plan.approve", PLAN), |applying| {
                replay
                    .approve(applying, PLAN, &|_, _| {
                        Ok(PlanApproval {
                            principal: "sa:bob".to_owned(),
                            approved_at: now(),
                            envelope: "ZW52ZWxvcGU".to_owned(),
                            operation_id: applying.operation_id().to_string(),
                            token: None,
                        })
                    })
                    .map_err(|_| Failure::Refused("the approval was refused".to_owned()))?;
                Ok::<_, Failure<String>>(Applied {
                    revision: 7,
                    target: Some(PLAN.to_owned()),
                    value: (),
                })
            })
            .expect("approved");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_plan_consume() {
        let (_volume, _store, replay, mutations) = open_plans(&root());
        let planner = Principal::new("sa:alice").expect("a principal");
        consume_plan(&mutations, &replay, &planner, &plan()).expect("consumed");
    }

    /// An approval killed before its write leaves the plan without it; killed after it, the
    /// approval on the plan and an operation recovery commits.
    #[test]
    fn a_plan_approval_killed_midway_is_recorded_or_absent() {
        for point in POINTS_OF_A_WRITE {
            let path = scratch(&format!("plan-approve-{point}"));
            seed_plan(&path);
            assert!(
                crash("stores::child_plan_approve", point, &path),
                "{point}: the child died of the abort there"
            );
            let (volume, store, replay, mutations) = open_plans(&path);
            let recovered = mutations.recover(&replay).expect("recovers");
            assert!(mutations.open_intents().is_empty(), "{point}");
            let (held, consumed) = replay
                .find(PLAN)
                .expect("the plan reads")
                .expect("the plan is held");
            assert!(!consumed, "{point}");
            if point == "mutation.applied" {
                assert_eq!(recovered.reconciled.len(), 1, "{point}");
                assert_eq!(held.approvals.len(), 1, "{point}: the approval is held");
            } else {
                assert_eq!(recovered.failed.len(), 1, "{point}");
                assert!(held.approvals.is_empty(), "{point}: nothing was written");
            }
            drop((mutations, replay, store, volume));
            let _ = std::fs::remove_dir_all(path);
        }
    }

    /// A consumption killed before its write leaves the plan to run; killed after it, the plan
    /// spent, an operation recovery commits, and a second consumption refused.
    #[test]
    fn a_plan_consumption_killed_midway_spends_the_plan_once_or_not_at_all() {
        let planner = Principal::new("sa:alice").expect("a principal");
        for point in POINTS_OF_A_WRITE {
            let path = scratch(&format!("plan-consume-{point}"));
            seed_plan(&path);
            assert!(
                crash("stores::child_plan_consume", point, &path),
                "{point}: the child died of the abort there"
            );
            let (volume, store, replay, mutations) = open_plans(&path);
            let recovered = mutations.recover(&replay).expect("recovers");
            assert!(mutations.open_intents().is_empty(), "{point}");
            let (held, consumed) = replay
                .find(PLAN)
                .expect("the plan reads")
                .expect("the plan is held");
            if point == "mutation.applied" {
                assert_eq!(recovered.reconciled.len(), 1, "{point}");
                assert!(consumed, "{point}: the plan is spent");
                assert!(
                    consume_plan(&mutations, &replay, &planner, &held).is_err(),
                    "{point}: a plan is spent once"
                );
            } else {
                assert_eq!(recovered.failed.len(), 1, "{point}");
                assert!(!consumed, "{point}: the plan was not spent");
                consume_plan(&mutations, &replay, &planner, &held).expect("spent now");
            }
            drop((mutations, replay, store, volume));
            let _ = std::fs::remove_dir_all(path);
        }
    }
}
