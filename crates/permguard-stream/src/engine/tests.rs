// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::domains::{digest, protected};
use permguard_core::fault::{self, Fault};
use permguard_host::identity::{Suite, directories};
use permguard_host::keys::FileKeyProvider;
use permguard_host::keys::ring::Policy;

use super::producer::RESERVE_BYTES;
use super::*;

/// A record of the tests' streams: text.
struct Text;

impl RecordCodec for Text {
    type Record = String;

    fn encode(&self, record: &String) -> Result<Vec<u8>, String> {
        Ok(record.as_bytes().to_vec())
    }

    fn decode(&self, bytes: &[u8]) -> Result<String, String> {
        String::from_utf8(bytes.to_vec()).map_err(|error| error.to_string())
    }
}

static SCRATCH: AtomicU64 = AtomicU64::new(0);

/// A fresh directory for one test.
fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-stream-engine-{tag}-{}-{}",
        std::process::id(),
        SCRATCH.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// One Host on `root`: its volume, identity, `host.operations` ring and time.
struct Host {
    root: PathBuf,
    volume: Volume,
    identity: Arc<Identity>,
    operations: Arc<Ring>,
    time: Arc<TimeGuard>,
}

impl Host {
    fn new(tag: &str) -> Self {
        Self::on(
            tag,
            Arc::new(TimeGuard::system(Duration::from_secs(30))),
            Policy {
                publish_ahead: Duration::from_secs(600),
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(7200),
            },
        )
    }

    /// A Host on `time`, its operations ring under `policy`.
    fn on(tag: &str, time: Arc<TimeGuard>, policy: Policy) -> Self {
        let root = scratch(tag);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let identity = Arc::new(
            Identity::provision(
                &volume,
                Arc::new(FileKeyProvider::new(
                    directories(&volume).expect("the identity directory").1,
                )),
                Suite::Ed25519Sha256V1,
                permguard_host::authz::store::now(),
                permguard_host::authz::store::now() * 1000,
            )
            .expect("provisioned"),
        );
        let operations = Arc::new(
            Ring::open(
                &volume,
                HOST_OPERATIONS,
                Suite::Ed25519Sha256V1,
                policy,
                Arc::clone(&time),
            )
            .expect("the ring opens")
            .with_binder(identity.clone()),
        );
        permguard_core::KeyManager::maintain(operations.as_ref()).expect("maintained");
        Self {
            root,
            volume,
            identity,
            operations,
            time,
        }
    }

    fn streams(&self) -> Streams {
        Streams::open(
            &self.volume,
            &self.identity,
            Arc::clone(&self.operations),
            Arc::clone(&self.time),
        )
        .expect("the engine opens")
    }

    fn producer(&self) -> Producer<Text> {
        self.streams()
            .register_producer(descriptor(), Text)
            .expect("registered")
    }

    /// The producer directory of `resource`.
    fn producer_dir(&self, resource: &Resource) -> PathBuf {
        let key = descriptor()
            .key(resource, self.identity.host_id())
            .expect("a key");
        self.root
            .join("host")
            .join(STREAMS)
            .join("data")
            .join("decisions")
            .join("1")
            .join("producer")
            .join(key.resource_component())
            .join(hex(&self.identity.host_id()))
    }
}

fn descriptor() -> Descriptor {
    Descriptor {
        plane: "data".to_owned(),
        stream_type: "decisions".to_owned(),
        version: 1,
        batch_typ: protected::DECISION_BATCH,
        record_domain: digest::DECISION_RECORD,
        codec_version: 1,
        event_types: Vec::new(),
        resource_shape: ResourceShape::Ledger,
        max_record_bytes: 4096,
        max_batch_records: 100,
        retention: Retention::Evidence,
        subscription_required: true,
        ring: DATA_ATTEST,
        task: Some(TaskType::DecisionsShip),
    }
}

fn ledger(n: u8) -> Resource {
    Resource::ledger("data", "zone-a", format!("ledger-{n}"))
}

fn records_dir(path: &Path) -> PathBuf {
    path.join("records")
}

/// The current segment of a journal: what a fault is aimed at, so the failure record beside it
/// stays writable and the journal recovers.
fn segment(records: &Path) -> PathBuf {
    let mut segments: Vec<PathBuf> = std::fs::read_dir(records)
        .expect("records")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pgj"))
        .collect();
    segments.sort();
    segments.pop().expect("a segment")
}

/// WP-5.1: a descriptor names lowercase names, versions from 1, registered domains, a known ring
/// and the ring its task's provider signs with; registering a version again with another
/// protected field is refused, while a new version, or a changed limit, registers.
#[test]
fn a_descriptor_is_validated_and_a_protected_change_is_a_new_version() {
    descriptor().check().expect("valid");
    let refused = |change: fn(&mut Descriptor)| {
        let mut changed = descriptor();
        change(&mut changed);
        assert!(
            matches!(changed.check(), Err(StreamError::Descriptor(_))),
            "{changed:?}"
        );
    };
    refused(|d| d.plane = "Data".to_owned());
    refused(|d| d.stream_type = "decisions/v2".to_owned());
    refused(|d| d.version = 0);
    refused(|d| d.codec_version = 0);
    refused(|d| d.batch_typ = "no-such-batch-typ");
    refused(|d| d.record_domain = "no-such-record-domain");
    refused(|d| d.event_types = vec!["Decision".to_owned()]);
    refused(|d| d.event_types = vec!["a".to_owned(), "a".to_owned()]);
    refused(|d| d.max_record_bytes = 0);
    refused(|d| d.max_record_bytes = MAX_RECORD_BYTES + 1);
    refused(|d| d.ring = "audit.sign");
    refused(|d| d.ring = CONTROL_ATTEST);
    refused(|d| d.task = Some(TaskType::PolicyMirror));

    let host = Host::new("descriptor");
    host.streams()
        .register_producer(descriptor(), Text)
        .expect("registered");
    let mut changed = descriptor();
    changed.codec_version = 2;
    assert!(matches!(
        host.streams().register_producer(changed.clone(), Text),
        Err(StreamError::Descriptor(_))
    ));
    changed.version = 2;
    host.streams()
        .register_producer(changed, Text)
        .expect("a new version");
    let mut tuned = descriptor();
    tuned.max_record_bytes = 8192;
    tuned.subscription_required = false;
    host.streams()
        .register_producer(tuned, Text)
        .expect("a limit is no protected field");
}

/// WP-5.1: one engine registers a stream and role once; a consumer of the same stream is
/// another handle.
#[test]
fn a_duplicate_identity_or_handler_is_refused() {
    let host = Host::new("duplicate");
    let streams = host.streams();
    streams
        .register_producer(descriptor(), Text)
        .expect("the producer");
    assert!(matches!(
        streams.register_producer(descriptor(), Text),
        Err(StreamError::Duplicate(_))
    ));
    streams
        .register_consumer(descriptor(), Text)
        .expect("the consumer");
    assert!(matches!(
        streams.register_consumer(descriptor(), Text),
        Err(StreamError::Duplicate(_))
    ));
}

/// WP-5.1: the stream key is `(plane, type, resource, producer_host_id)`; a resource of another
/// shape or plane is refused, and paths hold its digest, never its text.
#[test]
fn a_stream_key_names_its_four_parts_and_no_path_holds_caller_text() {
    let key = descriptor().key(&ledger(1), [7; 16]).expect("a key");
    assert_eq!(key.plane, "data");
    assert_eq!(key.stream_type, "decisions");
    assert_eq!(key.resource, "plane/data/zone/zone-a/ledger/ledger-1");
    assert_eq!(key.producer_host_id, [7; 16]);
    assert_eq!(key.resource_component().len(), 64);
    assert!(
        descriptor()
            .key(&Resource::zone("data", "zone-a"), [7; 16])
            .is_err()
    );
    assert!(
        descriptor()
            .key(&Resource::ledger("control", "zone-a", "l"), [7; 16])
            .is_err()
    );
    let host = Host::new("key");
    host.producer()
        .append(&ledger(1), &"first".to_owned())
        .expect("appended");
    let dir = host.producer_dir(&ledger(1));
    assert!(dir.join("STATE").is_file());
    assert!(dir.join("RESERVE").is_file());
    assert!(records_dir(&dir).is_dir());
    let mut paths = vec![host.root.join("host").join(STREAMS)];
    while let Some(path) = paths.pop() {
        let name = path.to_string_lossy().into_owned();
        assert!(
            !name.contains("ledger-1") && !name.contains("zone-a"),
            "{name}"
        );
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).expect("a directory") {
                paths.push(entry.expect("an entry").path());
            }
        }
    }
    assert!(
        host.root
            .join("host/streams/data/decisions/1/DESCRIPTOR")
            .is_file()
    );
}

/// WP-5.1: the first append opens a genesis run, signed under `host.operations` and durable
/// before the record, its sequence from 1; STATE names it.
#[test]
fn a_genesis_run_is_signed_under_host_operations_and_starts_at_one() {
    let host = Host::new("genesis");
    let producer = host.producer();
    let first = producer
        .append(&ledger(1), &"one".to_owned())
        .expect("appended");
    let second = producer
        .append(&ledger(1), &"two".to_owned())
        .expect("appended");
    assert_eq!((first.seq, second.seq), (1, 2));
    assert_eq!(first.run_id, second.run_id);
    assert_eq!(
        first.record_digest,
        record_digest(digest::DECISION_RECORD, b"one")
    );
    let run = producer.open_run(&ledger(1), None).expect("the run");
    assert_eq!(run.run_id, first.run_id);
    assert_eq!(run.predecessor, None);
    assert_eq!(run.fence, None, "a standalone Host's run");
    assert_eq!(run.producer_boot_id, host.identity.boot_id());
    let state = producer.state(&ledger(1)).expect("read").expect("a STATE");
    assert_eq!(state.run_id, run.run_id);
    // Another resource is another physical stream, from 1 again.
    assert_eq!(
        producer
            .append(&ledger(2), &"other".to_owned())
            .expect("appended")
            .seq,
        1
    );
    // The run statement on disk verifies under the ring and names the stream key.
    let reopened = host.producer();
    assert_eq!(
        reopened.read(&ledger(1), 1, 10).expect("read"),
        vec![(1, "one".to_owned()), (2, "two".to_owned())]
    );
    assert_eq!(
        reopened
            .append(&ledger(1), &"three".to_owned())
            .expect("appended")
            .seq,
        3
    );
}

/// WP-5.1, owner decision: a run opened for a stream shipped under a membership carries its fence.
#[test]
fn a_run_shipped_under_a_membership_carries_its_fence() {
    let host = Host::new("fence");
    let fence = Fence {
        membership_id: [3; 16],
        task_id: "decisions".to_owned(),
        epoch: 4,
    };
    let run = host
        .producer()
        .open_run(&ledger(1), Some(fence.clone()))
        .expect("opened");
    assert_eq!(run.fence, Some(fence.clone()));
    let encoded = run.encode().expect("encodes");
    assert_eq!(RunStatement::decode(&encoded).expect("decodes"), run);
    // The fence moves with a rollover: the successor names the epoch it now ships under.
    let next = Fence { epoch: 5, ..fence };
    let successor = host
        .producer()
        .rollover(&ledger(1), Some(next.clone()))
        .expect("rolled over");
    assert_eq!(successor.fence, Some(next));
}

/// WP-5.1, owner decisions: a rollover ends the run with a TERMINAL its successor names, the
/// sequence restarting at 1; a successor after a fork names the approved plan.
#[test]
fn a_rollover_names_the_terminal_record_and_a_successor_after_a_fork_names_an_approved_plan() {
    let host = Host::new("rollover");
    let producer = host.producer();
    let first = producer.append(&ledger(1), &"a".to_owned()).expect("a");
    producer.append(&ledger(1), &"b".to_owned()).expect("b");
    let successor = producer.rollover(&ledger(1), None).expect("rolled over");
    assert_eq!(
        successor.predecessor,
        Some(RunEnd {
            run_id: first.run_id,
            last_seq: 2,
            last_record_digest: record_digest(digest::DECISION_RECORD, b"b"),
        })
    );
    assert_eq!(successor.approval, None);
    let next = producer.append(&ledger(1), &"c".to_owned()).expect("c");
    assert_eq!((next.run_id, next.seq), (successor.run_id, 1));
    // An approval without a fork is refused; a fork stops appends and plain rollovers.
    assert!(
        producer
            .succeed_after_fork(&ledger(1), [9; 32], None)
            .is_err()
    );
    producer.report_fork(&ledger(1), 1).expect("reported");
    assert!(matches!(
        producer.append(&ledger(1), &"d".to_owned()),
        Err(StreamError::Forked { at_seq: 1 })
    ));
    let approved = producer
        .succeed_after_fork(&ledger(1), [9; 32], None)
        .expect("approved");
    assert_eq!(approved.approval, Some([9; 32]));
    assert_eq!(
        approved.predecessor.map(|end| (end.run_id, end.last_seq)),
        Some((successor.run_id, 1))
    );
    assert_eq!(
        producer.append(&ledger(1), &"e".to_owned()).expect("e").seq,
        1
    );
    // Everything reads back across a reopen.
    let reopened = host.producer();
    assert_eq!(
        reopened.open_run(&ledger(1), None).expect("run").run_id,
        approved.run_id
    );
}

/// WP-5.1: a forked stream opens no run of its own, across a restart too.
#[test]
fn a_forked_stream_opens_no_run_of_its_own() {
    let host = Host::new("forked");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    producer.report_fork(&ledger(1), 1).expect("reported");
    assert!(matches!(
        producer.rollover(&ledger(1), None),
        Err(StreamError::Forked { at_seq: 1 })
    ));
    let reopened = host.producer();
    assert!(matches!(
        reopened.rollover(&ledger(1), None),
        Err(StreamError::Forked { .. })
    ));
    assert!(matches!(
        reopened.append(&ledger(1), &"b".to_owned()),
        Err(StreamError::Forked { .. })
    ));
}

/// WP-5.1, done when: concurrent appenders never share a sequence; every sequence of the run is
/// taken once, and their records read back at the sequence they were answered.
#[test]
fn concurrent_appenders_never_share_a_sequence() {
    let host = Host::new("concurrent");
    let producer = Arc::new(host.producer());
    let threads: Vec<_> = (0..8)
        .map(|thread| {
            let producer = Arc::clone(&producer);
            std::thread::spawn(move || {
                (0..100)
                    .map(|n| {
                        let record = format!("{thread}-{n}");
                        let receipt = producer.append(&ledger(1), &record).expect("appended");
                        (receipt.seq, record)
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut answered: Vec<(u64, String)> = threads
        .into_iter()
        .flat_map(|thread| thread.join().expect("the thread"))
        .collect();
    answered.sort();
    let sequences: Vec<u64> = answered.iter().map(|(seq, _)| *seq).collect();
    assert_eq!(
        sequences,
        (1..=800).collect::<Vec<_>>(),
        "each once, none skipped"
    );
    assert_eq!(
        host.producer().read(&ledger(1), 1, 1000).expect("read"),
        answered,
        "each record at the sequence it was answered"
    );
    // The appends shared flushes: fewer frames than records.
    let frames = permguard_host::storage::journal::Journal::open(
        permguard_host::storage::Dir::open(&records_dir(&host.producer_dir(&ledger(1))))
            .expect("the records"),
        permguard_host::storage::journal::Options::default(),
    )
    .expect("opens")
    .0
    .frames()
    .expect("frames")
    .len();
    assert!(
        frames < 801,
        "{frames} frames for 800 records: no flush was shared"
    );
}

/// WP-5.1: no caller is answered before the flush covering its record: a flush that fails
/// answers an error, the stream stops, and on reopening the record is not there.
#[test]
fn no_append_is_answered_before_the_flush_that_covers_it() {
    let host = Host::new("flush");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let records = records_dir(&host.producer_dir(&ledger(1)));
    {
        let _failing = fault::inject_exact(segment(&records), Fault::Fsync);
        assert!(producer.append(&ledger(1), &"b".to_owned()).is_err());
        assert!(
            producer.append(&ledger(1), &"c".to_owned()).is_err(),
            "the stream stopped"
        );
    }
    drop(producer);
    let reopened = host.producer();
    assert_eq!(
        reopened.read(&ledger(1), 1, 10).expect("read"),
        vec![(1, "a".to_owned())]
    );
    assert_eq!(
        reopened.append(&ledger(1), &"d".to_owned()).expect("d").seq,
        2
    );
}

/// WP-5.1: recovery re-derives the head from the segments, cutting a torn final frame.
#[test]
fn recovery_rederives_the_head_and_truncates_a_torn_tail() {
    let host = Host::new("torn");
    let producer = host.producer();
    for record in ["a", "b", "c"] {
        producer
            .append(&ledger(1), &record.to_owned())
            .expect("appended");
    }
    drop(producer);
    let records = records_dir(&host.producer_dir(&ledger(1)));
    let segment = std::fs::read_dir(&records)
        .expect("records")
        .map(|entry| entry.expect("an entry").path())
        .find(|path| path.extension().is_some_and(|ext| ext == "pgj"))
        .expect("a segment");
    // Half a frame: a length claiming more than is there.
    let mut torn = std::fs::read(&segment).expect("read");
    torn.extend_from_slice(&[0, 0, 0, 40, 0, 2, 1, 2, 3]);
    std::fs::write(&segment, torn).expect("written");
    let reopened = host.producer();
    assert_eq!(reopened.read(&ledger(1), 1, 10).expect("read").len(), 3);
    assert_eq!(
        reopened.append(&ledger(1), &"d".to_owned()).expect("d").seq,
        4
    );
}

/// WP-5.1: a STATE naming another stream's run is refused, and nothing is changed.
#[test]
fn a_state_naming_another_stream_is_refused() {
    let host = Host::new("state");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    producer.append(&ledger(2), &"b".to_owned()).expect("b");
    drop(producer);
    let other = std::fs::read(host.producer_dir(&ledger(2)).join("STATE")).expect("read");
    std::fs::write(host.producer_dir(&ledger(1)).join("STATE"), &other).expect("written");
    assert!(matches!(
        host.producer().append(&ledger(1), &"c".to_owned()),
        Err(StreamError::Corruption(_))
    ));
    assert_eq!(
        std::fs::read(host.producer_dir(&ledger(1)).join("STATE")).expect("read"),
        other,
        "left as it was"
    );
}

/// WP-5.1: RESERVE holds allocated blocks, never a sparse file, kept across a rollover; where
/// the filesystem cannot allocate, it is left empty and the stream keeps closed pressure.
#[test]
fn the_reserve_is_allocated_or_the_stream_closes_under_pressure() {
    let host = Host::new("reserve");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let reserve = host.producer_dir(&ledger(1)).join("RESERVE");
    let check = || {
        let len = std::fs::metadata(&reserve).expect("the reserve").len();
        assert!(len == 0 || len >= RESERVE_BYTES, "{len} bytes");
        #[cfg(unix)]
        if len > 0 {
            use std::os::unix::fs::MetadataExt as _;
            let blocks = std::fs::metadata(&reserve).expect("the reserve").blocks();
            assert!(
                blocks * 512 >= RESERVE_BYTES,
                "allocated, not sparse: {blocks} blocks"
            );
        }
    };
    check();
    producer.rollover(&ledger(1), None).expect("rolled over");
    check();
}

/// WP-5.1: a rollover a crash stopped at any step completes with the same signed successor on
/// reopening: before TERMINAL, before RUN_OPEN, and before STATE followed.
#[test]
fn a_rollover_stopped_at_any_step_completes_on_reopening() {
    let host = Host::new("crash");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let dir = host.producer_dir(&ledger(1));
    let records = records_dir(&dir);
    // Before TERMINAL: STATE names the successor, the journal refuses the write.
    {
        let _failing = fault::inject_exact(segment(&records), Fault::WriteFails);
        assert!(producer.rollover(&ledger(1), None).is_err());
    }
    drop(producer);
    let pending = std::fs::read(dir.join("STATE")).expect("read");
    let reopened = host.producer();
    let run = reopened.open_run(&ledger(1), None).expect("the successor");
    assert_eq!(run.predecessor.map(|end| end.last_seq), Some(1));
    let state = reopened.state(&ledger(1)).expect("read").expect("a STATE");
    assert_eq!((state.run_id, state.pending_successor), (run.run_id, None));
    // Before STATE followed: the successor opened, STATE still names the old run.
    drop(reopened);
    std::fs::write(dir.join("STATE"), &pending).expect("written");
    let reopened = host.producer();
    assert_eq!(
        reopened.open_run(&ledger(1), None).expect("the run").run_id,
        run.run_id
    );
    assert_eq!(
        reopened.append(&ledger(1), &"b".to_owned()).expect("b"),
        Receipt {
            run_id: run.run_id,
            seq: 1,
            record_digest: record_digest(digest::DECISION_RECORD, b"b"),
        }
    );
    // Before RUN_OPEN: TERMINAL written, then the disk full.
    let end_frame = RunEnd {
        run_id: run.run_id,
        last_seq: 1,
        last_record_digest: record_digest(digest::DECISION_RECORD, b"b"),
    }
    .encode()
    .expect("encodes")
    .len()
        + 46;
    {
        let _full = fault::inject_exact(
            segment(&records),
            Fault::DiskFull {
                remaining_bytes: end_frame as u64,
            },
        );
        assert!(reopened.rollover(&ledger(1), None).is_err());
    }
    drop(reopened);
    let reopened = host.producer();
    let third = reopened.open_run(&ledger(1), None).expect("the successor");
    assert_eq!(
        third.predecessor.map(|end| (end.run_id, end.last_seq)),
        Some((run.run_id, 1))
    );
    assert_eq!(
        reopened.append(&ledger(1), &"c".to_owned()).expect("c").seq,
        1
    );
}

/// WP-5.1: a Plane appends through its typed producer and reads through its typed consumer;
/// the consumer keeps a producer run's records contiguous and refuses a gap.
#[test]
fn a_producer_appends_and_a_consumer_reads_back_through_typed_handles() {
    let host = Host::new("handles");
    let streams = host.streams();
    let producer = streams
        .register_producer(descriptor(), Text)
        .expect("the producer");
    let consumer = streams
        .register_consumer(descriptor(), Text)
        .expect("the consumer");
    let receipt = producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let remote = [5; 16];
    assert_eq!(
        consumer
            .admit(
                &ledger(1),
                remote,
                receipt.run_id,
                1,
                &[b"a".to_vec(), b"b".to_vec()]
            )
            .expect("admitted"),
        2
    );
    assert!(
        consumer
            .admit(&ledger(1), remote, receipt.run_id, 4, &[b"d".to_vec()])
            .is_err(),
        "a gap"
    );
    assert!(
        consumer
            .admit(&ledger(1), remote, receipt.run_id, 3, &[vec![0xff]])
            .is_err(),
        "not a record of the codec"
    );
    assert_eq!(
        consumer
            .read(&ledger(1), remote, receipt.run_id, 2, 10)
            .expect("read"),
        vec![(2, "b".to_owned())]
    );
}

/// WP-5.1, after the review: a run stays verifiable after the `host.operations` key that signed
/// it rotated out and was destroyed: the producer checks its own segments against every key the
/// ring ever published.
#[test]
fn a_stream_opens_after_the_key_of_its_first_run_is_gone() {
    let wall = Arc::new(permguard_host::time::ManualClock::at(
        i64::try_from(permguard_host::authz::store::now()).expect("in range"),
    ));
    let mono = Arc::new(permguard_host::time::ManualMonotonic::default());
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        mono.clone(),
        Duration::from_secs(30),
    ));
    let host = Host::on(
        "rotated",
        time,
        Policy {
            publish_ahead: Duration::from_secs(10),
            rotate_every: Duration::from_secs(20),
            retain: Duration::from_secs(30),
        },
    );
    let first = permguard_core::keys::Sign::active_key_id(host.operations.as_ref()).expect("a key");
    host.producer()
        .append(&ledger(1), &"a".to_owned())
        .expect("a");
    let published = |host: &Host| {
        host.operations
            .statement()
            .expect("a statement")
            .keys
            .iter()
            .any(|jwk| jwk.kid == first.as_str())
    };
    for _ in 0..40 {
        if !published(&host) {
            break;
        }
        wall.jump(15);
        mono.advance(Duration::from_secs(15));
        permguard_core::KeyManager::maintain(host.operations.as_ref()).expect("maintained");
    }
    assert!(!published(&host), "the first key left the published set");
    let reopened = host.producer();
    assert_eq!(
        reopened.append(&ledger(1), &"b".to_owned()).expect("b").seq,
        2
    );
}

/// WP-5.1, after the review: appends and rollovers interleaved: every append is answered with
/// the run its record was written in, no two share `(run, seq)`, each run's sequences run from 1
/// without a gap, and the stream never stops.
#[test]
fn appends_interleaved_with_rollovers_are_each_answered_in_their_run() {
    let host = Host::new("interleaved");
    let producer = Arc::new(host.producer());
    producer
        .append(&ledger(1), &"first".to_owned())
        .expect("first");
    let appenders: Vec<_> = (0..4)
        .map(|thread| {
            let producer = Arc::clone(&producer);
            std::thread::spawn(move || {
                (0..150)
                    .map(|n| {
                        producer
                            .append(&ledger(1), &format!("{thread}-{n}"))
                            .expect("answered")
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let rolling = {
        let producer = Arc::clone(&producer);
        std::thread::spawn(move || {
            for _ in 0..20 {
                producer.rollover(&ledger(1), None).expect("rolled over");
                std::thread::yield_now();
            }
        })
    };
    rolling.join().expect("the rollovers");
    let mut by_run: std::collections::BTreeMap<[u8; 16], Vec<u64>> = Default::default();
    for appender in appenders {
        for receipt in appender.join().expect("an appender") {
            by_run.entry(receipt.run_id).or_default().push(receipt.seq);
        }
    }
    assert_eq!(by_run.values().map(Vec::len).sum::<usize>(), 600);
    for sequences in by_run.values_mut() {
        sequences.sort_unstable();
        let first = sequences[0];
        assert!(
            first == 1 || first == 2,
            "a run starts at 1, or after `first`"
        );
        assert!(
            sequences.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "no gap and no repeat inside a run"
        );
    }
    producer
        .append(&ledger(1), &"last".to_owned())
        .expect("the stream did not stop");
    host.producer()
        .append(&ledger(1), &"reopened".to_owned())
        .expect("the segments reopen");
}

/// WP-5.1, after the review: a reserve that cannot be allocated again after the successor opened
/// leaves the stream writing in the successor, in memory as on disk.
#[test]
fn a_rollover_whose_reserve_fails_after_the_successor_opened_writes_in_the_successor() {
    let host = Host::new("reserve-fails");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let reserve = host.producer_dir(&ledger(1)).join("RESERVE");
    std::fs::remove_file(&reserve).expect("removed");
    std::fs::create_dir(&reserve).expect("a directory where the reserve was");
    let successor = producer.rollover(&ledger(1), None).expect("rolled over");
    let next = producer.append(&ledger(1), &"b".to_owned()).expect("b");
    assert_eq!((next.run_id, next.seq), (successor.run_id, 1));
    drop(producer);
    std::fs::remove_dir(&reserve).expect("the directory removed");
    let reopened = host.producer();
    assert_eq!(
        reopened.read(&ledger(1), 1, 10).expect("read"),
        vec![(1, "b".to_owned())]
    );
}

/// WP-5.1, after the review: a stream whose last run ended without naming a successor (its STATE
/// lost mid-rollover) opens no further record after its TERMINAL.
#[test]
fn a_stream_whose_last_run_ended_without_a_successor_is_refused() {
    let host = Host::new("ended");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let dir = host.producer_dir(&ledger(1));
    let end_frame = RunEnd {
        run_id: producer.open_run(&ledger(1), None).expect("the run").run_id,
        last_seq: 1,
        last_record_digest: record_digest(digest::DECISION_RECORD, b"a"),
    }
    .encode()
    .expect("encodes")
    .len()
        + 46;
    {
        let _full = fault::inject_exact(
            segment(&records_dir(&dir)),
            Fault::DiskFull {
                remaining_bytes: end_frame as u64,
            },
        );
        assert!(producer.rollover(&ledger(1), None).is_err());
    }
    drop(producer);
    std::fs::remove_file(dir.join("STATE")).expect("STATE lost");
    assert!(matches!(
        host.producer().append(&ledger(1), &"b".to_owned()),
        Err(StreamError::Corruption(_))
    ));
}

/// A codec whose records are trimmed text: a record with spaces around it is not canonical.
struct Trimmed;

impl RecordCodec for Trimmed {
    type Record = String;

    fn encode(&self, record: &String) -> Result<Vec<u8>, String> {
        Ok(record.trim().as_bytes().to_vec())
    }

    fn decode(&self, bytes: &[u8]) -> Result<String, String> {
        Ok(String::from_utf8(bytes.to_vec())
            .map_err(|error| error.to_string())?
            .trim()
            .to_owned())
    }
}

/// WP-5.1, after the review: bytes appended through the untyped path are taken only in their
/// canonical encoding.
#[test]
fn a_record_is_taken_only_in_its_canonical_encoding() {
    let host = Host::new("canonical");
    let producer = host
        .streams()
        .register_producer(descriptor(), Trimmed)
        .expect("registered");
    assert!(matches!(
        producer.append_bytes(&ledger(1), b" a ".to_vec()),
        Err(StreamError::Invalid(_))
    ));
    assert_eq!(
        producer
            .append_bytes(&ledger(1), b"a".to_vec())
            .expect("a")
            .seq,
        1
    );
}

/// WP-5.1, after the review: when a flush fails with several appenders waiting, none of them is
/// answered as durable, and none of their records is there after reopening.
#[test]
fn a_failed_group_flush_answers_every_waiting_appender_with_an_error() {
    let host = Host::new("group-fails");
    let producer = Arc::new(host.producer());
    producer.open_run(&ledger(1), None).expect("the run");
    let records = records_dir(&host.producer_dir(&ledger(1)));
    let outcomes = {
        let _failing = fault::inject_exact(segment(&records), Fault::Fsync);
        let threads: Vec<_> = (0..6)
            .map(|n| {
                let producer = Arc::clone(&producer);
                std::thread::spawn(move || producer.append(&ledger(1), &format!("r{n}")).is_ok())
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().expect("a thread"))
            .collect::<Vec<_>>()
    };
    assert!(outcomes.iter().all(|ok| !ok), "{outcomes:?}");
    drop(producer);
    assert!(
        host.producer()
            .read(&ledger(1), 1, 10)
            .expect("read")
            .is_empty()
    );
}

/// WP-5.1: a journal holding another stream's runs is refused, even without a STATE to compare.
#[test]
fn a_journal_holding_another_streams_run_is_refused() {
    let host = Host::new("foreign");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    producer.append(&ledger(2), &"b".to_owned()).expect("b");
    drop(producer);
    let mine = host.producer_dir(&ledger(1));
    let theirs = host.producer_dir(&ledger(2));
    std::fs::remove_dir_all(records_dir(&mine)).expect("removed");
    std::fs::remove_file(mine.join("STATE")).expect("removed");
    std::fs::create_dir(records_dir(&mine)).expect("created");
    for entry in std::fs::read_dir(records_dir(&theirs)).expect("theirs") {
        let path = entry.expect("an entry").path();
        std::fs::copy(
            &path,
            records_dir(&mine).join(path.file_name().expect("a name")),
        )
        .expect("copied");
    }
    assert!(matches!(
        host.producer().append(&ledger(1), &"c".to_owned()),
        Err(StreamError::Corruption(_))
    ));
}

/// WP-5.1: a run that does not name the end of the run before it is refused at open.
#[test]
fn a_run_not_succeeding_the_one_before_is_refused() {
    use permguard_host::storage::journal::{Journal, Options};

    let host = Host::new("unlinked");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    producer.rollover(&ledger(1), None).expect("rolled over");
    drop(producer);
    let dir = host.producer_dir(&ledger(1));
    let opened = |records: &Path| {
        Journal::open(
            permguard_host::storage::Dir::open(records).expect("the records"),
            Options {
                claim: host.volume.generation(),
                ..Options::default()
            },
        )
        .expect("opens")
        .0
    };
    let frames = opened(&records_dir(&dir)).frames().expect("frames");
    let runs: Vec<Vec<u8>> = frames
        .iter()
        .filter(|frame| frame.kind == super::producer::RUN_OPEN)
        .map(|frame| frame.payload.clone())
        .collect();
    assert_eq!(runs.len(), 2);
    let genesis = RunStatement::decode(payload_of(&runs[0]).as_slice()).expect("the genesis");
    // The genesis ended with no record, while its successor names an end at sequence 1.
    std::fs::remove_dir_all(records_dir(&dir)).expect("removed");
    std::fs::remove_file(dir.join("STATE")).expect("removed");
    std::fs::create_dir(records_dir(&dir)).expect("created");
    let mut journal = opened(&records_dir(&dir));
    journal
        .append(super::producer::RUN_OPEN, &runs[0])
        .expect("written");
    journal
        .append(
            super::producer::TERMINAL,
            &RunEnd {
                run_id: genesis.run_id,
                last_seq: 0,
                last_record_digest: [0; 32],
            }
            .encode()
            .expect("encodes"),
        )
        .expect("written");
    journal
        .append(super::producer::RUN_OPEN, &runs[1])
        .expect("written");
    drop(journal);
    assert!(matches!(
        host.producer().append(&ledger(1), &"b".to_owned()),
        Err(StreamError::Corruption(_))
    ));
}

/// The payload of a COSE_Sign1 envelope, unverified: what a test reads a statement from.
fn payload_of(envelope: &[u8]) -> Vec<u8> {
    permguard_objects::cose::Sign1::decode(envelope)
        .expect("a COSE_Sign1")
        .payload_unverified()
        .to_vec()
}
