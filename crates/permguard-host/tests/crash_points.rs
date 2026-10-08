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
        "migrate.",
        "mutation.",
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
    use permguard_host::storage::volume::Volume;

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
        let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        layout.declare(1, "data/notes/g1", NOW).expect("declared");
        let old = layout.active(&Reads::only(1)).expect("active");
        write_note(&old, "alpha", b"first note");
        write_note(&old, "beta", b"second note");
    }

    fn migrated(root: &Path) {
        lay_out(root);
        let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .migrate(&migration(), preflight())
            .expect("migrated");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_migrate() {
        let volume = Volume::claim(&root(), AssuranceProfile::Development).expect("claimed");
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .migrate(&migration(), preflight())
            .expect("migrated");
    }

    /// A build refused before the switch leaves the intent; `recover` abandons it.
    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_abandon() {
        let volume = Volume::claim(&root(), AssuranceProfile::Development).expect("claimed");
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
        let volume = Volume::claim(&root(), AssuranceProfile::Development).expect("claimed");
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .finalize(NOW + 1)
            .expect("finalized");
    }

    #[test]
    #[ignore = "started by its parent, with a crash point"]
    fn child_rollback() {
        let volume = Volume::claim(&root(), AssuranceProfile::Development).expect("claimed");
        Layout::open(&volume, SUBSYSTEM)
            .expect("opens")
            .rollback(NOW + 1)
            .expect("rolled back");
    }

    /// What a volume must look like on one side or the other, whatever step the crash hit.
    fn assert_on_one_side(root: &Path, point: &str, expect_new: bool) {
        let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
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
            let volume = Volume::claim(&path, AssuranceProfile::Development).expect("claimed");
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
            let volume = Volume::claim(&path, AssuranceProfile::Development).expect("claimed");
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
// The security-mutation transaction (WP-3.6): a grant issued through the engine.

mod mutating {
    use super::*;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::authz::{Principal, Selector};
    use permguard_host::audit::{Class, HOST, trail};
    use permguard_host::authz::{GrantStore, Issue};
    use permguard_host::operations::grants::{self, Grants, failure};
    use permguard_host::operations::journal::{Initiator, RequestKey};
    use permguard_host::operations::mutation::{Applied, Begin, MutationError, Mutations, Outcome};
    use permguard_host::storage::volume::Volume;

    const NOW: u64 = 1_800_000_000;

    fn root() -> PathBuf {
        PathBuf::from(std::env::var(DIRECTORY).expect("the parent names the directory"))
    }

    fn issue() -> Issue {
        Issue {
            principal: Principal::new("spiffe://acme/billing").expect("a principal"),
            operations: vec!["catalog.read".to_owned()],
            selector: Selector::parse("plane/control/*").expect("a selector"),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            issued_by: "test".to_owned(),
            expires_at: None,
        }
    }

    fn begin() -> Begin {
        Begin {
            domain: grants::DOMAIN,
            operation: grants::CREATE,
            action: grants::AUDIT_ISSUED,
            initiator: Initiator::Principal("spiffe://acme/operators/root".to_owned()),
            request: Some(RequestKey {
                request_id: "r-1".to_owned(),
                digest: "d".to_owned(),
            }),
            target: None,
        }
    }

    /// Issues the grant as the operation of request `r-1`, answering its id.
    fn create(
        mutations: &Mutations,
        store: &GrantStore,
    ) -> Result<Outcome<String>, MutationError<String>> {
        mutations.run(begin(), |applying| {
            let record = store
                .issue(applying, issue(), NOW, None)
                .map_err(|error| failure(error, |error| error.to_string()))?;
            Ok(Applied {
                revision: record.revision,
                target: Some(record.grant_id.to_string()),
                value: record.grant_id.to_string(),
            })
        })
    }

    fn reopen(path: &Path) -> (Volume, std::sync::Arc<GrantStore>, Mutations) {
        let volume = Volume::claim(path, AssuranceProfile::Development).expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("the store opens");
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

    /// A crash at any step leaves either no grant and a failed operation, or the grant and an
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
            let recovered = mutations.recover(&Grants(&store)).expect("recovers");
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
                ("mutation.applied", Outcome::Reconciled { target, .. }) => assert_eq!(
                    target,
                    Some(store.records()[0].grant_id.to_string()),
                    "{point}"
                ),
                (_, Outcome::Replayed(grant_id)) if applied && point != "mutation.applied" => {
                    assert_eq!(grant_id, store.records()[0].grant_id.to_string(), "{point}")
                }
                (_, other) => panic!("{point}: {other:?}"),
            }
            assert_eq!(store.records().len(), 1, "{point}: never two grants");
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
        mutations.recover(&Grants(&store)).expect("recovers");
        let retried = create(&mutations, &store).expect("the retry answers");
        assert!(matches!(retried, Outcome::Replayed(_)), "{retried:?}");
        assert_eq!(store.records().len(), 1);
        let _ = std::fs::remove_dir_all(path);
    }
}
