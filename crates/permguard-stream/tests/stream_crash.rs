// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-10 (WP-5.2): a hundred crashes under load. The test binary runs itself as the child: an
//! ignored test opens the Host on the directory the parent names, on a manual clock whose
//! `data.attest` ring rotates every half minute, then appends to a stream fenced by a membership,
//! seals, cuts over to each new key as a coordinator would, and rolls over, writing each
//! acknowledged record to a file after its receipt, until it aborts at the
//! storage library's crash point and pass the parent chose (`PERMGUARD_CRASH_AT`,
//! `PERMGUARD_CRASH_HIT`) with a fixed seed among the immutable publish's, the view's and the
//! journal's. The parent reopens the Host, seals what is left, and requires every batch to verify
//! under the span naming its key, every run's chain to run from genesis without a gap or a fork,
//! and every acknowledged record to be sealed at the run and sequence its receipt named. The next
//! child starts on the same directory, so every round recovers what the one before left.
//!
//! A hundred rounds by default; `PERMGUARD_CRASH_ROUNDS` changes it. Built with the
//! `crash-points` feature only.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use permguard_core::keys::Sign as _;
use permguard_host::composition::StreamCutovers as _;
use permguard_host::keys::ring::{DATA_ATTEST, Policy};
use permguard_host::time::{ManualClock, ManualMonotonic, TimeGuard};
use permguard_stream::engine::{Fence, Producer, Sealing};

use support::{Host, every_batch, hex, ledger, unhex};

const CHILD_DIRECTORY: &str = "PERMGUARD_STREAM_CRASH_DIRECTORY";
/// The wall time, in seconds, the child's manual clock starts at.
const CHILD_CLOCK: &str = "PERMGUARD_STREAM_CRASH_CLOCK";
/// Simulated seconds a child's clock moves for each record.
const RECORD_SECONDS: i64 = 3;
/// The membership fencing the stream.
const MEMBERSHIP: [u8; 16] = [0x5e; 16];
const ACKS: &str = "acks.txt";
const DEFAULT_ROUNDS: u32 = 100;

fn rounds() -> u32 {
    std::env::var("PERMGUARD_CRASH_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_ROUNDS)
}

fn policy() -> Policy {
    Policy {
        publish_ahead: Duration::from_secs(10),
        rotate_every: Duration::from_secs(30),
        retain: Duration::from_secs(100_000_000),
    }
}

fn fence() -> Fence {
    Fence {
        membership_id: MEMBERSHIP,
        task_id: "decisions".to_owned(),
        epoch: 1,
    }
}

/// The Host on `root`, its clock a manual one at `at`: answers the hands that move it.
fn open(root: &Path, at: i64) -> (Host, Arc<ManualClock>, Arc<ManualMonotonic>) {
    let wall = Arc::new(ManualClock::at(at));
    let mono = Arc::new(ManualMonotonic::default());
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        mono.clone(),
        Duration::from_secs(30),
    ));
    (Host::open(&root.join("volume"), time, policy()), wall, mono)
}

/// Seals `ledger(1)` once; a new key waiting for its cutover is cut over as the coordinator
/// would, journaled and confirmed, and the seal tried again.
fn seal_once(host: &Host, producer: &Producer<support::Text>) -> Sealing {
    match producer.seal(&ledger(1), 5).expect("sealed") {
        Sealing::AwaitingCutover { stream, from_seq } => {
            let kid = host.attest.active_key_id().expect("a key");
            let due = producer
                .due(&MEMBERSHIP, DATA_ATTEST, kid.as_str())
                .expect("due");
            assert_eq!(due, vec![(stream, from_seq)]);
            producer
                .journaled(DATA_ATTEST, kid.as_str(), &due)
                .expect("confirmed");
            producer.seal(&ledger(1), 5).expect("sealed")
        }
        other => other,
    }
}

/// The crash points the seal, the views and the journal pass through.
const POINTS: &[&str] = &[
    "immutable.temp_created",
    "immutable.temp_written",
    "immutable.temp_flushed",
    "immutable.linked",
    "immutable.temp_removed",
    "immutable.parent_flushed",
    "view.temp_written",
    "view.temp_flushed",
    "view.renamed",
    "view.parent_flushed",
    "journal.frame_written",
    "journal.frame_flushed",
];

/// The most passes before the abort: every chosen pass is reached within the child's load.
const MAX_HIT: u64 = 16;

/// A fixed-seed xorshift: the same hundred crashes in every run.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Runs the child told to abort at the `hit`-th pass through `point`; answers whether it died of
/// that abort, a panic or an exit not being one.
fn crash(root: &Path, at: i64, point: &str, hit: u64) -> bool {
    let status = Command::new(std::env::current_exe().expect("the test binary is known"))
        .args([
            "--ignored",
            "--exact",
            "child_appends_and_seals_until_it_crashes",
            "--nocapture",
        ])
        .env(CHILD_DIRECTORY, root)
        .env(CHILD_CLOCK, at.to_string())
        .env(permguard_host::storage::crash::CRASH_AT, point)
        .env(permguard_host::storage::crash::CRASH_HIT, hit.to_string())
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
    matches!(status.code(), Some(3) | Some(-1_073_740_791))
}

/// The records the children acknowledged: `(run, seq) → text`, from every whole line.
fn acknowledged(root: &Path) -> BTreeMap<([u8; 16], u64), Vec<u8>> {
    let text = std::fs::read_to_string(root.join(ACKS)).unwrap_or_default();
    let whole = text.rfind('\n').map_or("", |end| &text[..end]);
    whole
        .lines()
        .map(|line| {
            let mut parts = line.splitn(3, ' ');
            let run = unhex(parts.next().expect("a run"));
            let seq = parts.next().expect("a seq").parse().expect("a number");
            let text = parts.next().expect("a record").as_bytes().to_vec();
            ((run, seq), text)
        })
        .collect()
}

#[test]
fn a_hundred_crashes_under_load_leave_no_fork_gap_or_unverifiable_span() {
    let root: PathBuf = support::scratch("crash");
    let mut sealed_before = 0;
    let mut seed = Seeded(0x5eed_0502_f10a_b0cd);
    // The clock moves on from round to round as far as the child's moved it, so the rings never
    // have a long absence to catch up with.
    let mut clock = i64::try_from(permguard_host::authz::store::now()).expect("in range");
    let mut kids = std::collections::BTreeSet::new();
    for round in 0..rounds() {
        let point = POINTS[(seed.next() % POINTS.len() as u64) as usize];
        let hit = 1 + seed.next() % MAX_HIT;
        let past = acknowledged(&root).len();
        assert!(
            crash(&root, clock, point, hit),
            "round {round}: the child did not abort at pass {hit} of {point}"
        );
        let moved = acknowledged(&root).len() - past + 2;
        clock += RECORD_SECONDS * i64::try_from(moved).expect("in range");
        let (host, ..) = open(&root, clock);
        clock += RECORD_SECONDS;
        let producer = host.sealer();
        // What the death left is sealed now, never refused.
        loop {
            match seal_once(&host, &producer) {
                Sealing::Sealed { .. } => {}
                Sealing::Nothing => break,
                other => panic!("round {round}: the seal after a crash answered {other:?}"),
            }
        }
        let spans = producer.spans(&ledger(1)).expect("spans");
        // Every batch verifies under the span naming its key alone.
        let batches = every_batch(&host.producer_dir(&ledger(1)), &spans);
        kids.extend(batches.iter().map(|batch| batch.kid.clone()));
        let mut sealed = BTreeMap::new();
        for batch in &batches {
            for (offset, record) in batch.records.iter().enumerate() {
                let seq = batch.envelope.first_seq + offset as u64;
                assert!(
                    sealed.insert((batch.run, seq), record.clone()).is_none(),
                    "round {round}: {}:{seq} sealed twice",
                    hex(&batch.run)
                );
            }
        }
        for (at, text) in acknowledged(&root) {
            assert_eq!(
                sealed.get(&at),
                Some(&text),
                "round {round}: the acknowledged {}:{} is not sealed as it was",
                hex(&at.0),
                at.1
            );
        }
        assert!(
            sealed.len() >= sealed_before,
            "round {round}: sealed records went missing"
        );
        sealed_before = sealed.len();
        // A child that died opening the Host left no run; one that wrote any left STATE sealed.
        if let Some(state) = producer.state(&ledger(1)).expect("state") {
            assert_eq!(
                state.signed_seq, state.durable_seq,
                "round {round}: STATE follows the files"
            );
        }
    }
    assert!(sealed_before > 0);
    assert!(
        kids.len() > 10,
        "{} keys signed: the ring rotated",
        kids.len()
    );
}

/// The child: appends, seals at every third sequence, cutting over to each new key, and rolls over
/// at the fortieth, until it
/// aborts at its crash point; a load that never reached it ends the child without an abort.
#[test]
#[ignore = "started by its parent, with a crash point"]
fn child_appends_and_seals_until_it_crashes() {
    let root =
        PathBuf::from(std::env::var(CHILD_DIRECTORY).expect("the parent names the directory"));
    let at: i64 = std::env::var(CHILD_CLOCK)
        .expect("the parent names the clock")
        .parse()
        .expect("seconds");
    let (host, wall, mono) = open(&root, at);
    let producer = host.sealer();
    producer
        .open_run(&ledger(1), Some(fence()))
        .expect("the run");
    let mut acks = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join(ACKS))
        .expect("the acknowledgements open");
    let pid = std::process::id();
    for n in 0..1000u64 {
        // Three seconds a record: the ring rotates every ten records or so.
        wall.jump(RECORD_SECONDS);
        mono.advance(Duration::from_secs(RECORD_SECONDS.unsigned_abs()));
        if n.is_multiple_of(3) {
            host.maintain();
        }
        let text = format!("{pid}-{n}");
        let receipt = producer.append(&ledger(1), &text).expect("appended");
        acks.write_all(format!("{} {} {text}\n", hex(&receipt.run_id), receipt.seq).as_bytes())
            .expect("acknowledged");
        if receipt.seq.is_multiple_of(3) {
            seal_once(&host, &producer);
        }
        // By the run's sequence, not this child's count: a run rolls over whichever child reaches it.
        if receipt.seq.is_multiple_of(40) {
            producer
                .rollover(&ledger(1), Some(fence()))
                .expect("rolled over");
        }
    }
}
