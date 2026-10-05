// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Startup stays bounded on a large fixture (WP-1.6): opening a long journal reads its last segment
//! and the first frame of the others, and opening an unlimited quota walks nothing. What startup
//! skips, deep verification reads.
//!
//! Bounded is proved by what was not read, not by a clock: every older segment is damaged past its
//! first frame, so an open that read one would refuse, and deep verification finds every one.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use permguard_core::volume::{Floors, Limit};
use permguard_host::storage::Dir;
use permguard_host::storage::journal::{Journal, Options};
use permguard_host::storage::quota::{Class, Quota};
use permguard_host::storage::verify::{self, Budget, Mode, Report};

const SEGMENTS: usize = 400;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-startup-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

fn segments(path: &Path) -> Vec<PathBuf> {
    let mut all: Vec<_> = std::fs::read_dir(path)
        .expect("listed")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pgj"))
        .collect();
    all.sort();
    all
}

#[test]
fn a_long_journal_opens_reading_only_its_tail_and_verification_reads_the_rest() {
    let path = scratch("journal");
    let options = Options {
        max_frame: 4096,
        // Two 400-byte frames a segment: a segment rolls once it reaches 600 bytes.
        segment_bytes: 600,
        ..Options::default()
    };
    let (mut journal, _) = Journal::open(Dir::open(&path).expect("dir"), options).expect("opens");
    for index in 0..(SEGMENTS * 2) {
        journal
            .append(1, &[(index % 251) as u8; 400])
            .expect("appended");
    }
    let next = journal.next_index();
    drop(journal);
    let all = segments(&path);
    assert_eq!(all.len(), SEGMENTS);

    // Every older segment damaged past its first frame: its second frame's last byte.
    for segment in &all[..all.len() - 1] {
        let mut bytes = std::fs::read(segment).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(segment, &bytes).expect("damaged");
    }

    let started = std::time::Instant::now();
    let (journal, recovery) = Journal::open(Dir::open(&path).expect("dir"), options)
        .expect("startup does not read what it does not need");
    let opened_in = started.elapsed();
    assert_eq!(
        journal.next_index(),
        next,
        "the tail says where the journal ends"
    );
    assert_eq!(
        recovery.truncated_bytes, 0,
        "nothing in the tail was repaired"
    );
    drop(journal);

    let mut report = Report::new();
    verify::journal(
        &Dir::open(&path).expect("dir"),
        None,
        Mode::Full,
        &mut Budget::unbounded(),
        &mut report,
    )
    .expect("verified");
    assert_eq!(report.files_checked as usize, SEGMENTS);
    assert_eq!(
        report.findings.len(),
        SEGMENTS - 1,
        "every damaged segment is found by deep verification"
    );
    // A loose bound, for the record: the proof is the damage startup did not see.
    assert!(
        opened_in < std::time::Duration::from_secs(5),
        "opened in {opened_in:?}"
    );
}

#[test]
fn an_unlimited_quota_walks_nothing_at_open_and_measures_in_the_background() {
    let root = scratch("quota");
    for fan in 0..50 {
        let dir = root.join(format!("{fan:02}"));
        std::fs::create_dir_all(&dir).expect("fan");
        for file in 0..100 {
            std::fs::write(dir.join(format!("{file:03}")), [0u8; 10]).expect("file");
        }
    }
    let quota = Quota::open(
        Dir::open(&root).expect("root"),
        Floors {
            free_bytes: 4096,
            free_inodes: 1,
            maintenance_bytes: 1024,
            maintenance_inodes: 1,
        },
        Limit::default(),
    )
    .expect("opens");
    let host = |quota: &Quota| {
        quota
            .usage()
            .expect("usage")
            .scopes
            .into_iter()
            .find(|scope| scope.scope == "host")
            .expect("host")
    };
    let at_open = host(&quota);
    assert!(!at_open.measured, "startup did not walk 5,000 files");
    assert_eq!(at_open.used_files, 0);

    // A limited account is measured at open: enforcing the limit needs the count.
    let limited = quota
        .host(Class::Ordinary)
        .child(
            "07",
            &Dir::open(&root.join("07")).expect("fan"),
            Limit {
                bytes: Some(1 << 20),
                inodes: None,
            },
        )
        .expect("account");
    let fan = quota
        .usage()
        .expect("usage")
        .scopes
        .into_iter()
        .find(|scope| scope.scope == "07")
        .expect("reported");
    assert!(fan.measured);
    assert_eq!((fan.used_files, fan.used_bytes), (100, 1000));
    drop(limited);

    assert_eq!(quota.measure_pending().expect("measured"), 1);
    let measured = host(&quota);
    assert!(measured.measured);
    assert_eq!(
        measured.used_files,
        50 * 100 + 50,
        "files and their directories"
    );
}
