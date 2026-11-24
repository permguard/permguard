// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An archive whose keeping is interrupted at every step is kept whole or not at all.
//!
//! The test binary runs itself as the child: an ignored test keeps one archive in the zones root
//! the parent names, and aborts at the crash point and pass the parent chose
//! (`PERMGUARD_CRASH_AT`, `PERMGUARD_CRASH_HIT`): every step of the three writes an archive is,
//! the archive, the request that kept it and its record. The parent opens the store again, as a
//! starting Control Plane does, and requires that the archive is listed and answered to its
//! request, or neither; then it retries the import as a client would, and requires one archive of
//! the name, answered to the request. Built with the `crash-points` feature only.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use permguard_control_plane::catalog::archives::{ArchiveStore, FileArchives, Keeping, Requested};
use permguard_control_plane::catalog::imports::ArchiveRecord;

const CHILD_DIRECTORY: &str = "PERMGUARD_ARCHIVE_CRASH_DIRECTORY";
const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";
const REQUEST: &str = "import-1";

/// The steps of one write of the storage library that replaces nothing.
const POINTS: &[&str] = &[
    "immutable.temp_created",
    "immutable.temp_written",
    "immutable.temp_flushed",
    "immutable.linked",
    "immutable.temp_removed",
    "immutable.parent_flushed",
];

/// The passes tried at each point: the archive, its request and its record are a write each.
const HITS: u64 = 3;

fn record(id: &str) -> ArchiveRecord {
    ArchiveRecord {
        id: id.to_owned(),
        name: "backup".to_owned(),
        imported_at: 1_800_000_000,
        manifest_digest: format!("sha256:{}", "ab".repeat(32)),
        source_host_id: "11".repeat(16),
        source_zone_id: "01d00000-0000-7000-8000-00000000000a".to_owned(),
        source_zone_name: "delivery".to_owned(),
        ledgers: Vec::new(),
    }
}

fn asked(record: &ArchiveRecord) -> Requested {
    Requested {
        request_id: REQUEST.to_owned(),
        name: record.name.clone(),
        manifest_digest: record.manifest_digest.clone(),
    }
}

/// Keeps the archive under the id `id`, as the import `REQUEST` does.
fn keep(root: &Path, id: &str) -> Keeping {
    let record = record(id);
    FileArchives::new(root)
        .keep(ZONE, b"the archive, verbatim", &asked(&record), &record)
        .expect("the store answers")
}

/// The child: keeps the archive until the crash point the parent chose aborts it.
#[test]
#[ignore = "the crash test's child, run by `an_archive_interrupted_at_every_step_is_whole_or_absent`"]
fn child_keeps_until_it_crashes() {
    let Ok(root) = std::env::var(CHILD_DIRECTORY) else {
        return;
    };
    let _ = keep(Path::new(&root), "archive-first");
}

fn crash(root: &Path, point: &str, hit: u64) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("the test binary is known"))
        .args([
            "--ignored",
            "--exact",
            "child_keeps_until_it_crashes",
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
    let dir = std::env::temp_dir().join(format!("pg-archive-crash-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory");
    dir
}

#[test]
fn an_archive_interrupted_at_every_step_is_whole_or_absent() {
    let (mut crashed, mut whole, mut absent) = (0, 0, 0);
    for point in POINTS {
        for hit in 1..=HITS {
            let root = scratch(&format!("{}-{hit}", point.replace('.', "-")));
            let status = crash(&root, point, hit);
            assert!(
                aborted(status),
                "{point} pass {hit}: the child did not stop there"
            );
            crashed += 1;

            // A store opened again: the archive is listed and answered to its request, or neither.
            let store = FileArchives::new(&root);
            let listed = store.archived(ZONE).expect("the archives read");
            let answered = store.kept_by(ZONE, REQUEST).expect("the archives read");
            let first = record("archive-first");
            match (listed.as_slice(), &answered) {
                ([], None) => absent += 1,
                ([kept], Some((record, request))) => {
                    assert_eq!((kept, record, request), (&first, &first, &asked(&first)));
                    whole += 1;
                }
                other => panic!("{point} pass {hit}: part of an archive is kept: {other:?}"),
            }

            // The retry a client makes: answered the archive the first request kept, or keeping
            // it now; either way the zone keeps one archive of the name, the request's.
            match keep(&root, "archive-retry") {
                Keeping::Kept => assert!(answered.is_none(), "{point} pass {hit}"),
                Keeping::Requested(record, request) => {
                    assert_eq!((*record, request), (first.clone(), asked(&first)));
                }
                Keeping::Named => panic!("{point} pass {hit}: the name is taken by no request"),
            }
            let store = FileArchives::new(&root);
            let listed = store.archived(ZONE).expect("the archives read");
            assert_eq!(listed.len(), 1, "{point} pass {hit}");
            assert_eq!(listed[0].name, "backup");
            let kept = store
                .kept_by(ZONE, REQUEST)
                .expect("the archives read")
                .expect("the request kept one");
            assert_eq!(kept.0, listed[0]);
            let _ = std::fs::remove_dir_all(&root);
        }
    }
    assert_eq!(crashed, POINTS.len() * HITS as usize);
    // Both outcomes are met: a crash before the record lands keeps nothing, one after keeps all.
    assert!(whole > 0 && absent > 0, "whole {whole}, absent {absent}");
}
