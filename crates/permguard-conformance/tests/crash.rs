// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `kill -9` in the middle of appending, for the decision spool, the event journal, and the storage
//! library's journal and immutable publish.
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

use permguard_host::storage::Dir;
use permguard_host::storage::journal::{Journal as StorageJournal, Options as StorageOptions};
use permguard_host::storage::write::publish_immutable;

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

/// The child process, killed when this guard drops: a parent that fails mid-round must not leave
/// a child appending forever.
struct Appender(Option<Child>);

impl Appender {
    fn spawn(test: &str, directory: &Path) -> Self {
        Self(Some(
            Command::new(std::env::current_exe().expect("the test binary is known"))
                .args(["--ignored", "--exact", test, "--nocapture"])
                .env(CHILD_DIRECTORY, directory)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("the child starts"),
        ))
    }

    /// `SIGKILL`: no destructor, no flush, no unlock runs in the child.
    fn kill(mut self) {
        if let Some(child) = self.0.take() {
            reap(child);
        }
    }
}

impl Drop for Appender {
    fn drop(&mut self) {
        if let Some(child) = self.0.take() {
            reap(child);
        }
    }
}

fn reap(mut child: Child) {
    // `Child::kill` is SIGKILL on Unix.
    let _ = child.kill();
    let _ = child.wait();
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

/// Records in the directory's segments, durable or not: the lines of every `seg-*` file, which is
/// the segment naming both the spool and the journal use.
fn segment_lines(directory: &Path) -> Option<u64> {
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
    let mut instance: Option<String> = None;
    for round in 0..rounds() {
        let child = Appender::spawn("child_appends_to_a_spool_until_killed", &directory);
        wait_for_progress(&directory, recovered, segment_lines);
        std::thread::sleep(jitter(1, 40));
        child.kill();

        let spool = Spool::open(&directory, SpoolBounds::default())
            .unwrap_or_else(|error| panic!("round {round}: the spool does not reopen: {error}"));
        let records = verified_spool(&spool);
        assert!(
            records.len() as u64 >= recovered,
            "round {round}: an acknowledged record was lost ({} < {recovered})",
            records.len()
        );
        // STATE: the stream a kill interrupts is the stream that resumes, and nothing is
        // acknowledged that the segments do not hold.
        let current = spool.instance().to_owned();
        if let Some(previous) = &instance {
            assert_eq!(
                &current, previous,
                "round {round}: the stream instance changed"
            );
        }
        instance = Some(current);
        assert!(
            spool.acked() <= spool.seq(),
            "round {round}: acked beyond the tail"
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
        let child = Appender::spawn("child_appends_to_a_journal_until_killed", &directory);
        wait_for_progress(&directory, recovered, segment_lines);
        std::thread::sleep(jitter(1, 40));
        child.kill();

        let journal = Journal::open(&directory, stream(), JournalBounds::default())
            .unwrap_or_else(|error| panic!("round {round}: the journal does not reopen: {error}"));
        let records = verified_journal(&journal);
        assert!(
            records.len() as u64 >= recovered,
            "round {round}: an acknowledged record was lost ({} < {recovered})",
            records.len()
        );
        // STATE after recovery: the stream is the one it was, and the durable watermark covers
        // exactly the records the reopened journal holds.
        let state = journal.state();
        assert_eq!(state.stream, stream(), "round {round}: the stream changed");
        assert_eq!(
            state.durable_through,
            state.next_seq - 1,
            "round {round}: the recovered tail is not durable through its last record"
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

/// The bytes of the files in `directory` whose names start with `prefix`.
fn bytes_of(directory: &Path, prefix: &str) -> Option<u64> {
    std::fs::read_dir(directory).ok().map(|entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .filter_map(|entry| entry.metadata().ok())
            .map(|metadata| metadata.len())
            .sum()
    })
}

/// How many files in `directory` have names starting with `prefix`.
fn count_of(directory: &Path, prefix: &str) -> Option<u64> {
    std::fs::read_dir(directory).ok().map(|entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .count() as u64
    })
}

/// Small enough that the children roll segments as they go.
fn storage_options() -> StorageOptions {
    StorageOptions {
        max_frame: 1024,
        segment_bytes: 4096,
    }
}

/// A frame's payload: its own index, then filler.
fn storage_payload(index: u64) -> Vec<u8> {
    let mut payload = index.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0x5a; 120]);
    payload
}

#[test]
fn test_a_storage_journal_killed_mid_append_reopens_with_every_frame_in_order_every_round() {
    let directory = scratch("crash-storage-journal");
    let mut recovered = 0usize;
    let mut held_bytes = 0u64;
    for round in 0..rounds() {
        let child = Appender::spawn(
            "child_appends_to_a_storage_journal_until_killed",
            &directory,
        );
        wait_for_progress(&directory, held_bytes, |path| bytes_of(path, "seg-"));
        std::thread::sleep(jitter(1, 40));
        child.kill();

        let opened = StorageJournal::open(
            Dir::open(&directory).expect("the directory opens"),
            storage_options(),
        );
        let (journal, _) = opened
            .unwrap_or_else(|error| panic!("round {round}: the journal does not reopen: {error}"));
        let frames = journal
            .frames()
            .unwrap_or_else(|error| panic!("round {round}: the frames do not read: {error}"));
        assert!(
            frames.len() >= recovered,
            "round {round}: a recovered frame was lost ({} < {recovered})",
            frames.len()
        );
        for (position, frame) in frames.iter().enumerate() {
            assert_eq!(frame.index, position as u64, "round {round}");
            assert_eq!(
                frame.payload,
                storage_payload(position as u64),
                "round {round}: frame {position} is not the one appended there"
            );
        }
        assert_eq!(journal.next_index(), frames.len() as u64, "round {round}");
        recovered = frames.len();
        held_bytes = bytes_of(&directory, "seg-").unwrap_or_default();
    }
    assert!(recovered > 0, "the children appended something");
}

#[test]
fn test_immutable_publishes_killed_mid_write_leave_whole_files_or_none_every_round() {
    let directory = scratch("crash-storage-publish");
    let mut published = 0usize;
    for round in 0..rounds() {
        let child = Appender::spawn("child_publishes_until_killed", &directory);
        wait_for_progress(&directory, published as u64, |path| count_of(path, "obj-"));
        std::thread::sleep(jitter(1, 40));
        child.kill();

        let dir = Dir::open(&directory).expect("the directory opens");
        dir.sweep_temps().expect("the temporaries are swept");
        let names = dir.names().expect("listed");
        for name in &names {
            let index = name
                .strip_prefix("obj-")
                .unwrap_or_else(|| panic!("round {round}: `{name}` survived the sweep"));
            assert_eq!(
                dir.read(name).expect("read"),
                Some(format!("content-{index}").into_bytes()),
                "round {round}: `{name}` is partial or wrong"
            );
        }
        assert!(
            names.len() >= published,
            "round {round}: a published file was lost"
        );
        published = names.len();
    }
    assert!(published > 0, "the children published something");
}

/// The child half for the storage library's journal.
#[test]
#[ignore = "the crash harness runs this as its child process"]
fn child_appends_to_a_storage_journal_until_killed() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let dir = Dir::open(Path::new(&directory)).expect("the child opens the directory");
    let (mut journal, _) = StorageJournal::open(dir, storage_options()).expect("the child opens");
    loop {
        let index = journal.next_index();
        journal
            .append(1, &storage_payload(index))
            .expect("the child appends");
    }
}

/// The child half for immutable publishes: the same names every round, so a round republishes
/// what earlier rounds wrote before it adds more.
#[test]
#[ignore = "the crash harness runs this as its child process"]
fn child_publishes_until_killed() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let dir = Dir::open(Path::new(&directory)).expect("the child opens the directory");
    let mut index = 0u64;
    loop {
        let content = format!("content-{index}").into_bytes();
        let same = |held: &[u8]| held == content.as_slice();
        publish_immutable(&dir, &format!("obj-{index}"), &content, &same, &same)
            .expect("the child publishes");
        index += 1;
    }
}
