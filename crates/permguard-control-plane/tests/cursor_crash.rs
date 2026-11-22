// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A cursor root whose minting is interrupted at every step leaves a store that still opens.
//!
//! The test binary runs itself as the child: an ignored test asks a fresh store for its root,
//! which mints one, on the directory the parent names, and aborts at the crash point and pass
//! the parent chose (`PERMGUARD_CRASH_AT`, `PERMGUARD_CRASH_HIT`): every step of the two writes
//! a minting is, the witness and then the root. The parent asks the store again, as a starting
//! Control Plane does, and requires a root, the same at every ask after, whose witness names it:
//! never a root the store refuses as replaced in silence. Built with the `crash-points` feature
//! only.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use permguard_control_plane::decisions::cursorkey::{
    CursorRoots, FileCursorRoots, KEY_FILE, WITNESS_FILE,
};

const CHILD_DIRECTORY: &str = "PERMGUARD_CURSOR_CRASH_DIRECTORY";

/// The steps of one write of the storage library that replaces a file.
const POINTS: &[&str] = &[
    "view.temp_written",
    "view.temp_flushed",
    "view.renamed",
    "view.parent_flushed",
];

/// The passes tried at each point: the witness and the root are a write each.
const HITS: u64 = 2;

/// The child: mints until the crash point the parent chose aborts it.
#[test]
#[ignore = "the crash test's child, run by `a_minting_interrupted_at_every_step_leaves_a_root`"]
fn child_mints_until_it_crashes() {
    let Ok(root) = std::env::var(CHILD_DIRECTORY) else {
        return;
    };
    let _ = FileCursorRoots::new(root).roots();
}

fn crash(root: &Path, point: &str, hit: u64) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("the test binary is known"))
        .args([
            "--ignored",
            "--exact",
            "child_mints_until_it_crashes",
            "--nocapture",
        ])
        .env(CHILD_DIRECTORY, root)
        .env(permguard_host::storage::crash::CRASH_AT, point)
        .env(permguard_host::storage::crash::CRASH_HIT, hit.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the child runs")
}

#[cfg(unix)]
fn aborted(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal() == Some(6)
}

#[cfg(not(unix))]
fn aborted(status: std::process::ExitStatus) -> bool {
    matches!(status.code(), Some(3) | Some(-1_073_740_791))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pg-cursor-crash-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory");
    dir
}

#[test]
fn a_minting_interrupted_at_every_step_leaves_a_root() {
    let (mut kept, mut minted_again) = (0, 0);
    for point in POINTS {
        for hit in 1..=HITS {
            let root = scratch(&format!("{}-{hit}", point.replace('.', "-")));
            assert!(
                aborted(crash(&root, point, hit)),
                "{point} pass {hit}: the child did not stop there"
            );
            // What the crash left: the root the child minted, or none yet.
            let left = std::fs::read(root.join(KEY_FILE)).ok();

            let store = FileCursorRoots::new(&root);
            let first = store
                .roots()
                .unwrap_or_else(|error| panic!("{point} pass {hit}: the store refuses: {error:#}"))
                .issuing
                .to_vec();
            match &left {
                Some(left) => {
                    assert_eq!(&first, left, "{point} pass {hit}: a root kept is the root");
                    kept += 1;
                }
                None => minted_again += 1,
            }
            // The same root at every ask after, by a store opened again, and its witness names it.
            let again = FileCursorRoots::new(&root)
                .roots()
                .unwrap_or_else(|error| panic!("{point} pass {hit}: the next ask: {error:#}"))
                .issuing
                .to_vec();
            assert_eq!(first, again, "{point} pass {hit}");
            assert_eq!(
                std::fs::read(root.join(WITNESS_FILE)).expect("the witness"),
                permguard_host::secrets::witness_of(&first),
                "{point} pass {hit}"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }
    // Both outcomes are met: a crash before the root lands mints again, one after keeps it.
    assert!(
        kept > 0 && minted_again > 0,
        "kept {kept}, minted again {minted_again}"
    );
}
