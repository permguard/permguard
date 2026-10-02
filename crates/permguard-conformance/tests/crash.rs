// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `kill -9` in the middle of appending, for the decision spool and the event journal.
//!
//! The test binary runs itself as the child: an ignored test, selected by name and told where to
//! write through an environment variable, opens the store and appends until it is killed. The parent
//! kills it with `SIGKILL` after a random delay, reopens the directory and requires a valid chain and
//! `STATE`, then starts the next child on the same directory. Every round therefore recovers what the
//! previous death left, and the store must keep moving forward across all of them.
//!
//! The round count is bounded so the harness runs on every CI build; `PERMGUARD_CRASH_ROUNDS` raises
//! it for a longer local or nightly run.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use permguard_decisions::spool::{Bounds as SpoolBounds, Spool};
use permguard_events::journal::{Bounds as JournalBounds, Journal};

use support::{decision, event, scratch, stream, verified_journal, verified_spool};

const CHILD_DIRECTORY: &str = "PERMGUARD_CRASH_CHILD_DIRECTORY";
const DEFAULT_ROUNDS: u32 = 6;

fn rounds() -> u32 {
    std::env::var("PERMGUARD_CRASH_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_ROUNDS)
}

/// A delay in `[min, max)` milliseconds, drawn from the clock: not secret, only not fixed.
fn jitter(min: u64, max: u64) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    Duration::from_millis(min + u64::from(nanos) % (max - min))
}

fn spawn_child(test: &str, directory: &Path) -> Child {
    Command::new(std::env::current_exe().expect("the test binary is known"))
        .args(["--ignored", "--exact", test, "--nocapture"])
        .env(CHILD_DIRECTORY, directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the child starts")
}

/// Waits until the child has appended at least once, so a kill lands mid-stream rather than before
/// the store was opened; gives up after ten seconds, which is a broken child.
fn wait_for_progress(directory: &Path, past: u64, read: impl Fn(&Path) -> Option<u64>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if read(directory).is_some_and(|seq| seq > past) {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("the child made no progress past {past}");
}

fn kill(mut child: Child) {
    // `Child::kill` is SIGKILL on Unix: no destructor, no flush, no unlock runs in the child.
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
}

/// Durable appends since the directory was created, as the segments show them.
fn spool_progress(directory: &Path) -> Option<u64> {
    std::fs::read_dir(directory).ok().map(|entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("seg-"))
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .map(|text| text.lines().count() as u64)
            .sum()
    })
}

#[test]
fn test_a_spool_killed_mid_append_reopens_to_a_valid_chain_every_round() {
    let directory = scratch("crash-spool");
    let mut recovered = 0u64;
    for round in 0..rounds() {
        let child = spawn_child("child_appends_to_a_spool_until_killed", &directory);
        wait_for_progress(&directory, recovered, spool_progress);
        std::thread::sleep(jitter(1, 40));
        kill(child);

        let spool = Spool::open(&directory, SpoolBounds::default())
            .unwrap_or_else(|error| panic!("round {round}: the spool does not reopen: {error}"));
        let records = verified_spool(&spool);
        assert!(
            records.len() as u64 >= recovered,
            "round {round}: an acknowledged record was lost ({} < {recovered})",
            records.len()
        );
        recovered = records.len() as u64;
    }
    assert!(recovered > 0, "the children appended something");
}

#[test]
fn test_a_journal_killed_mid_append_reopens_to_a_valid_chain_and_state_every_round() {
    let directory = scratch("crash-journal");
    let mut recovered = 0u64;
    for round in 0..rounds() {
        let child = spawn_child("child_appends_to_a_journal_until_killed", &directory);
        wait_for_progress(&directory, recovered, spool_progress);
        std::thread::sleep(jitter(1, 40));
        kill(child);

        let journal = Journal::open(&directory, stream(), JournalBounds::default())
            .unwrap_or_else(|error| panic!("round {round}: the journal does not reopen: {error}"));
        let records = verified_journal(&journal);
        assert!(
            records.len() as u64 >= recovered,
            "round {round}: an acknowledged record was lost ({} < {recovered})",
            records.len()
        );
        recovered = records.len() as u64;
    }
    assert!(recovered > 0, "the children appended something");
}

/// The child half: not a test on its own, only run by the harness above.
#[test]
#[ignore = "the crash harness runs this as its child process"]
fn child_appends_to_a_spool_until_killed() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let mut spool = Spool::open(&directory, SpoolBounds::default()).expect("the child opens");
    loop {
        let (seq, prev) = spool.next_position();
        spool
            .append(&decision(seq, &prev))
            .expect("the child appends");
    }
}

/// The child half for the journal.
#[test]
#[ignore = "the crash harness runs this as its child process"]
fn child_appends_to_a_journal_until_killed() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let mut journal =
        Journal::open(&directory, stream(), JournalBounds::default()).expect("the child opens");
    loop {
        let (seq, prev) = journal.next_position();
        journal
            .append(&event(seq, &prev))
            .expect("the child appends");
    }
}
