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
    /// The `data.attest` ring the tests' batches are sealed under.
    attest: Arc<Ring>,
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
        let attest = Arc::new(
            Ring::open(
                &volume,
                DATA_ATTEST,
                Suite::Ed25519Sha256V1,
                policy,
                Arc::clone(&time),
            )
            .expect("the ring opens")
            .with_binder(identity.clone()),
        );
        permguard_core::KeyManager::maintain(attest.as_ref()).expect("maintained");
        Self {
            root,
            volume,
            identity,
            operations,
            attest,
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

    /// A producer sealing under the `data.attest` ring.
    fn sealer(&self) -> Producer<Text> {
        self.producer()
            .with_signer(Arc::clone(&self.attest))
            .expect("the descriptor's ring")
    }

    /// The `data.attest` keys published now.
    fn attest_keys(&self) -> Vec<permguard_core::keys::Jwk> {
        self.attest.statement().expect("a statement").keys
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

/// A Host on a manual clock whose rings rotate every 20 seconds, and the hands of that clock.
fn manual_host(
    tag: &str,
) -> (
    Host,
    Arc<permguard_host::time::ManualClock>,
    Arc<permguard_host::time::ManualMonotonic>,
) {
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
        tag,
        time,
        Policy {
            publish_ahead: Duration::from_secs(10),
            rotate_every: Duration::from_secs(20),
            retain: Duration::from_secs(600),
        },
    );
    (host, wall, mono)
}

/// Moves the clock until `data.attest` activates another key: answers it.
fn rotate_attest(
    host: &Host,
    wall: &permguard_host::time::ManualClock,
    mono: &permguard_host::time::ManualMonotonic,
) -> String {
    use permguard_core::keys::Sign as _;
    let before = host.attest.active_key_id().expect("a key");
    for _ in 0..20 {
        wall.jump(5);
        mono.advance(Duration::from_secs(5));
        permguard_core::KeyManager::maintain(host.attest.as_ref()).expect("maintained");
        permguard_core::KeyManager::maintain(host.operations.as_ref()).expect("maintained");
        let now = host.attest.active_key_id().expect("a key");
        if now != before {
            return now.as_str().to_owned();
        }
    }
    panic!("the ring did not rotate");
}

fn sealed(sealing: Sealing) -> ([u8; 16], u64, u64, Vec<u8>) {
    match sealing {
        Sealing::Sealed {
            run,
            first,
            last,
            bytes,
        } => (run, first, last, bytes),
        other => panic!("not sealed: {other:?}"),
    }
}

/// Verifies `bytes` as a batch of the tests' descriptor under `keys`.
fn open_batch(bytes: &[u8], keys: &[permguard_core::keys::Jwk]) -> (batch::Envelope, Vec<Vec<u8>>) {
    batch::SealedBatch::decode(bytes)
        .expect("a canonical batch")
        .verify(keys, protected::DECISION_BATCH, digest::DECISION_RECORD)
        .expect("the batch verifies")
}

/// WP-5.2, F-01: a run's first batch chains to the genesis head, every later batch to the head
/// of the batch before it; a successor run starts again from genesis; a stream with nothing
/// unsealed seals nothing.
#[test]
fn a_batch_chains_to_the_one_before_and_a_run_starts_from_genesis() {
    let host = Host::new("chain");
    let producer = host.sealer();
    assert_eq!(
        producer.seal(&ledger(1), 10).expect("sealed"),
        Sealing::Nothing
    );
    for n in 0..5 {
        producer
            .append(&ledger(1), &format!("r{n}"))
            .expect("appended");
    }
    let keys = host.attest_keys();
    let mut previous = batch::GENESIS_HEAD.to_owned();
    let mut ranges = Vec::new();
    while let Sealing::Sealed {
        first, last, bytes, ..
    } = producer.seal(&ledger(1), 2).expect("sealed")
    {
        let (envelope, _) = open_batch(&bytes, &keys);
        assert_eq!(envelope.previous_head, previous);
        previous = envelope.head.clone();
        ranges.push((first, last));
    }
    assert_eq!(ranges, vec![(1, 2), (3, 4), (5, 5)]);
    assert_eq!(
        producer
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .signed_seq,
        5
    );
    producer.rollover(&ledger(1), None).expect("rolled over");
    producer
        .append(&ledger(1), &"s".to_owned())
        .expect("appended");
    let (run, first, last, bytes) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let (envelope, _) = open_batch(&bytes, &keys);
    assert_eq!((first, last), (1, 1));
    assert_eq!(envelope.previous_head, batch::GENESIS_HEAD);
    assert_eq!(envelope.run, hex(&run));
    assert_eq!(
        producer
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .run_id,
        run
    );
}

/// WP-5.2, F-01: the oldest run is sealed first: records a rollover left unsealed are sealed in
/// their own run before the successor's.
#[test]
fn an_ended_runs_unsealed_records_are_sealed_before_its_successors() {
    let host = Host::new("ended");
    let producer = host.sealer();
    let first_run = producer
        .append(&ledger(1), &"a".to_owned())
        .expect("a")
        .run_id;
    producer.rollover(&ledger(1), None).expect("rolled over");
    let second_run = producer
        .append(&ledger(1), &"b".to_owned())
        .expect("b")
        .run_id;
    let (run, ..) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    assert_eq!(run, first_run);
    let (run, ..) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    assert_eq!(run, second_run);
    assert_eq!(
        producer.seal(&ledger(1), 10).expect("sealed"),
        Sealing::Nothing
    );
}

/// WP-5.2: the envelope names the stream key, the run, its fence, the range, the count, the
/// commitments, the batch id, the time and the epoch of the ring that signed it; the batch is
/// bounded by the descriptor's `max_batch_records`.
#[test]
fn a_sealed_batch_names_its_stream_run_range_and_commitments() {
    let host = Host::new("envelope");
    let producer = host.sealer();
    let fence = Fence {
        membership_id: [7; 16],
        task_id: "decisions".to_owned(),
        epoch: 3,
    };
    producer.open_run(&ledger(2), Some(fence)).expect("opened");
    for n in 0..150 {
        producer
            .append(&ledger(2), &format!("r{n}"))
            .expect("appended");
    }
    let (run, first, last, bytes) = sealed(producer.seal(&ledger(2), 1000).expect("sealed"));
    assert_eq!((first, last), (1, 100), "bounded by max_batch_records");
    let (envelope, records) = open_batch(&bytes, &host.attest_keys());
    let key = descriptor()
        .key(&ledger(2), host.identity.host_id())
        .expect("a key");
    assert_eq!(envelope.stream_key, batch::KeyView::of(&key));
    assert_eq!(
        envelope.stream_key.producer_host_id,
        permguard_host::identity::record::uuid_text(&host.identity.host_id())
    );
    assert_eq!(envelope.descriptor_version, 1);
    assert_eq!(envelope.run, hex(&run));
    assert_eq!(
        envelope.membership_id.as_deref(),
        Some(permguard_host::identity::record::uuid_text(&[7; 16]).as_str())
    );
    assert_eq!(envelope.epoch, Some(3));
    assert_eq!(
        (envelope.first_seq, envelope.last_seq, envelope.count),
        (1, 100, 100)
    );
    assert_eq!(envelope.batch_id, format!("{}-1", hex(&run)));
    assert_eq!(envelope.key_set_epoch, host.attest.epoch());
    assert_eq!(
        envelope.head,
        batch::digest_string(digest::DECISION_RECORD, b"r99")
    );
    let digests: Vec<String> = records
        .iter()
        .map(|record| batch::digest_string(digest::DECISION_RECORD, record))
        .collect();
    assert_eq!(
        Some(envelope.merkle_root.clone()),
        crate::merkle::root(&digests)
    );
    assert!(
        permguard_core::time::from_rfc3339(&envelope.created_at).is_some(),
        "created_at is RFC 3339: {}",
        envelope.created_at
    );
    // Unfenced, the envelope names no membership.
    producer.append(&ledger(3), &"x".to_owned()).expect("x");
    let (.., bytes) = sealed(producer.seal(&ledger(3), 10).expect("sealed"));
    let (envelope, _) = open_batch(&bytes, &host.attest_keys());
    assert_eq!((envelope.membership_id, envelope.epoch), (None, None));
    assert!(
        !String::from_utf8(bytes)
            .expect("JSON")
            .contains("membership_id")
    );
}

/// WP-5.2: a batch verifies under the ring's published keys and carries every record's exact
/// bytes; another `typ` or record domain does not verify; a producer handed another ring than
/// its descriptor's, or none, seals nothing.
#[test]
fn a_sealed_batch_verifies_and_carries_the_exact_record_bytes() {
    let host = Host::new("exact");
    let producer = host.sealer();
    let texts = ["alpha", "", "gamma \u{1F600}"];
    for text in texts {
        producer
            .append(&ledger(1), &text.to_owned())
            .expect("appended");
    }
    let (.., bytes) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let (_, records) = open_batch(&bytes, &host.attest_keys());
    assert_eq!(
        records,
        texts
            .iter()
            .map(|text| text.as_bytes().to_vec())
            .collect::<Vec<_>>()
    );
    let batch = batch::SealedBatch::decode(&bytes).expect("decodes");
    assert_eq!(batch.encode().expect("encodes"), bytes, "canonical");
    assert!(
        batch
            .verify(
                &host.attest_keys(),
                protected::EVENT_BATCH,
                digest::DECISION_RECORD
            )
            .is_err()
    );
    assert!(
        batch
            .verify(
                &host.attest_keys(),
                protected::DECISION_BATCH,
                digest::EVENT_RECORD
            )
            .is_err()
    );
    let operations = host.operations.statement().expect("a statement").keys;
    assert!(
        batch
            .verify(
                &operations,
                protected::DECISION_BATCH,
                digest::DECISION_RECORD
            )
            .is_err(),
        "another ring's keys"
    );
    assert!(matches!(
        host.producer().with_signer(Arc::clone(&host.operations)),
        Err(StreamError::Sign(_))
    ));
    assert!(matches!(
        host.producer().seal(&ledger(1), 10),
        Err(StreamError::Sign(_))
    ));
}

/// WP-5.2: a batch whose records, envelope, header or signature were changed, or whose file is
/// not canonical, is refused.
#[test]
fn a_batch_whose_records_do_not_match_its_commitments_is_refused() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let host = Host::new("tampered");
    let producer = host.sealer();
    for n in 0..3 {
        producer
            .append(&ledger(1), &format!("r{n}"))
            .expect("appended");
    }
    let (.., bytes) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let keys = host.attest_keys();
    let good = batch::SealedBatch::decode(&bytes).expect("decodes");
    let refused = |batch: &batch::SealedBatch| {
        batch
            .verify(&keys, protected::DECISION_BATCH, digest::DECISION_RECORD)
            .is_err()
    };
    let mut changed = good.clone();
    changed.records[1] = B64.encode(b"forged");
    assert!(refused(&changed), "a changed record");
    let mut changed = good.clone();
    changed.records.swap(0, 1);
    assert!(refused(&changed), "reordered records");
    let mut changed = good.clone();
    changed.records.pop();
    assert!(refused(&changed), "a dropped record");
    let mut changed = good.clone();
    changed.records.push(B64.encode(b"r3"));
    assert!(refused(&changed), "an added record");
    let mut changed = good.clone();
    let mut payload = B64.decode(&changed.signature.payload).expect("b64");
    let at = payload.len() - 3;
    payload[at] ^= 1;
    changed.signature.payload = B64.encode(payload);
    assert!(refused(&changed), "a changed envelope");
    let mut changed = good.clone();
    changed.signature.protected = B64.encode(br#"{"alg":"EdDSA","kid":"someone-else","typ":"x"}"#);
    assert!(refused(&changed), "a changed header");
    let mut changed = good.clone();
    let mut signature = B64.decode(&changed.signature.signature).expect("b64");
    signature[0] ^= 1;
    changed.signature.signature = B64.encode(signature);
    assert!(refused(&changed), "a changed signature");
    // A file that is not canonical JSON, or carries an unknown member, does not decode.
    let text = String::from_utf8(bytes.clone()).expect("JSON");
    assert!(batch::SealedBatch::decode(format!(" {text}").as_bytes()).is_err());
    let extra = text.replacen('{', r#"{"extra":1,"#, 1);
    assert!(batch::SealedBatch::decode(extra.as_bytes()).is_err());
    assert!(!refused(&good));
}

/// WP-5.2, F-10: a batch is durable before the seal answers it; a crash after its file and before
/// its span or STATE leaves it sealed, its span appended on the next seal, and it is never signed
/// again.
#[test]
fn a_sealed_batch_is_kept_before_it_is_answered_and_never_signed_again() {
    let host = Host::new("kept");
    let producer = host.sealer();
    for n in 0..4 {
        producer
            .append(&ledger(1), &format!("r{n}"))
            .expect("appended");
    }
    let (run, first, last, bytes) = sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    let dir = host.producer_dir(&ledger(1));
    let file = dir
        .join("batches")
        .join(hex(&run))
        .join(format!("{first}-{last}.jws"));
    assert_eq!(std::fs::read(&file).expect("the batch is on disk"), bytes);
    let spans = producer.spans(&ledger(1)).expect("spans");
    drop(producer);
    // The crash: the span and STATE's watermark never written.
    std::fs::remove_file(dir.join("signers.cbor")).expect("removed");
    let reopened = host.sealer();
    let (_, next_first, next_last, _) = sealed(reopened.seal(&ledger(1), 2).expect("sealed"));
    assert_eq!((next_first, next_last), (3, 4), "1-2 is not signed again");
    assert_eq!(std::fs::read(&file).expect("kept"), bytes);
    assert_eq!(reopened.spans(&ledger(1)).expect("spans"), spans);
    assert_eq!(
        reopened
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .signed_seq,
        4
    );
    // A batch file that is not its run's next range is corruption, never overwritten.
    std::fs::write(dir.join("batches").join(hex(&run)).join("9-9.jws"), b"{}").expect("written");
    reopened
        .append(&ledger(1), &"r4".to_owned())
        .expect("appended");
    assert!(matches!(
        host.sealer().seal(&ledger(1), 2),
        Err(StreamError::Corruption(_))
    ));
}

/// WP-5.2: a span is appended when another key seals, from the batch it first signs, and the spans
/// before it are kept as they were; every batch verifies under the key its span names, also after
/// that key left the ring.
#[test]
fn a_signer_span_is_appended_with_its_batch_and_never_amended() {
    let (host, wall, mono) = manual_host("spans");
    let producer = host.sealer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let (run, _, _, first_batch) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let before = producer.spans(&ledger(1)).expect("spans");
    assert_eq!(before.runs.len(), 1);
    assert_eq!(before.runs[0].1.len(), 1);
    assert_eq!(before.runs[0].1[0].from_seq, 1);
    let rotated = rotate_attest(&host, &wall, &mono);
    producer.append(&ledger(1), &"b".to_owned()).expect("b");
    let (.., second_batch) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let after = producer.spans(&ledger(1)).expect("spans");
    let spans = &after.runs[0].1;
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0], before.runs[0].1[0], "the first span is kept");
    assert_eq!(
        (spans[1].from_seq, spans[1].kid.as_str()),
        (2, rotated.as_str())
    );
    assert_eq!(after.signing(&run, 1), Some(&spans[0]));
    assert_eq!(after.signing(&run, 2), Some(&spans[1]));
    // Each batch verifies under its span's key alone.
    for (batch, span) in [(&first_batch, &spans[0]), (&second_batch, &spans[1])] {
        let jwk: permguard_core::keys::Jwk = serde_json::from_str(&span.jwk).expect("a JWK");
        open_batch(batch, &[jwk]);
    }
    assert_eq!(
        Spans::decode(&after.encode().expect("encodes")).expect("decodes"),
        after
    );
    let mut unordered = after.clone();
    unordered.runs[0].1.swap(0, 1);
    assert!(Spans::decode(&unordered.encode().expect("encodes")).is_err());
}

/// WP-5.2, WP-4.5: under a fence, a new key seals nothing until the coordinator journaled the
/// cutover naming the stream's next sequence; the cutover is listed until confirmed, and only
/// the cutover the stream waits for is confirmed.
#[test]
fn a_new_key_seals_only_after_its_cutover_is_journaled() {
    let (host, wall, mono) = manual_host("cutover");
    let producer = host.sealer();
    let fence = Fence {
        membership_id: [5; 16],
        task_id: "decisions".to_owned(),
        epoch: 1,
    };
    let run = producer
        .open_run(&ledger(1), Some(fence))
        .expect("opened")
        .run_id;
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    assert!(producer.pending_cutovers().expect("listed").is_empty());
    let rotated = rotate_attest(&host, &wall, &mono);
    producer.append(&ledger(1), &"b".to_owned()).expect("b");
    let key = descriptor()
        .key(&ledger(1), host.identity.host_id())
        .expect("a key");
    let stream = format!("data/decisions/{}/{}", key.resource_component(), hex(&run));
    let waiting = Sealing::AwaitingCutover {
        stream: stream.clone(),
        from_seq: 2,
    };
    assert_eq!(producer.seal(&ledger(1), 10).expect("waits"), waiting);
    assert_eq!(producer.seal(&ledger(1), 10).expect("waits"), waiting);
    let pending = producer.pending_cutovers().expect("listed");
    assert_eq!(
        pending,
        vec![Cutover {
            stream: stream.clone(),
            membership_id: [5; 16],
            ring: DATA_ATTEST.to_owned(),
            kid: rotated.clone(),
            from_seq: 2,
            confirmed: false,
        }]
    );
    assert!(producer.confirm_cutover(&stream, "another-key").is_err());
    assert!(
        producer
            .confirm_cutover("data/decisions/x/y", &rotated)
            .is_err()
    );
    assert_eq!(producer.seal(&ledger(1), 10).expect("waits"), waiting);
    // A fresh handle sees the persisted cutover too.
    assert_eq!(host.sealer().pending_cutovers().expect("listed"), pending);
    producer
        .confirm_cutover(&stream, &rotated)
        .expect("confirmed");
    assert!(producer.pending_cutovers().expect("listed").is_empty());
    let (_, first, _, bytes) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    assert_eq!(first, 2);
    assert_eq!(
        batch::SealedBatch::decode(&bytes)
            .expect("decodes")
            .kid()
            .expect("a kid"),
        rotated
    );
    let spans = producer.spans(&ledger(1)).expect("spans");
    assert_eq!(
        spans.signing(&run, 2).map(|span| span.kid.as_str()),
        Some(rotated.as_str())
    );
    assert_eq!(
        Cutover::decode(&pending[0].encode().expect("encodes")).expect("decodes"),
        pending[0]
    );
}

/// WP-5.2, WP-4.5: the engine names, for a membership and its ring's new key, each stream that
/// membership fences and that sealed under another key, from its next sequence; a stream of
/// another membership, unfenced, or sealing nothing yet is not named; a stream on disk is found
/// by a handle that never opened it; the cutover journaled, the stream seals under the new key.
#[test]
fn a_member_sends_its_streams_cutover_from_the_engine() {
    use permguard_host::composition::StreamCutovers as _;
    let (host, wall, mono) = manual_host("due");
    let producer = host.sealer();
    let fence = |membership: u8| Fence {
        membership_id: [membership; 16],
        task_id: "decisions".to_owned(),
        epoch: 1,
    };
    let run = producer
        .open_run(&ledger(1), Some(fence(5)))
        .expect("opened")
        .run_id;
    producer
        .open_run(&ledger(2), Some(fence(6)))
        .expect("opened");
    producer
        .open_run(&ledger(4), Some(fence(5)))
        .expect("opened");
    for resource in [ledger(1), ledger(2), ledger(3)] {
        producer.append(&resource, &"a".to_owned()).expect("a");
        sealed(producer.seal(&resource, 10).expect("sealed"));
    }
    producer.append(&ledger(1), &"b".to_owned()).expect("b");
    producer.append(&ledger(4), &"a".to_owned()).expect("a");
    let rotated = rotate_attest(&host, &wall, &mono);
    drop(producer);
    let fresh = host.sealer();
    let key = descriptor()
        .key(&ledger(1), host.identity.host_id())
        .expect("a key");
    let stream = format!("data/decisions/{}/{}", key.resource_component(), hex(&run));
    assert_eq!(
        fresh.due(&[5; 16], DATA_ATTEST, &rotated).expect("due"),
        vec![(stream.clone(), 2)]
    );
    assert_eq!(
        fresh.due(&[5; 16], HOST_OPERATIONS, &rotated).expect("due"),
        Vec::new(),
        "another ring"
    );
    // Asked again, the same cutover.
    assert_eq!(
        fresh.due(&[5; 16], DATA_ATTEST, &rotated).expect("due"),
        vec![(stream.clone(), 2)]
    );
    assert_eq!(
        fresh.seal(&ledger(1), 10).expect("waits"),
        Sealing::AwaitingCutover {
            stream: stream.clone(),
            from_seq: 2
        }
    );
    // Another plane's streams are not this producer's to confirm.
    fresh
        .journaled(
            DATA_ATTEST,
            &rotated,
            &[("control/decisions/x/y".to_owned(), 1)],
        )
        .expect("ignored");
    fresh
        .journaled(DATA_ATTEST, &rotated, &[(stream.clone(), 2)])
        .expect("confirmed");
    let (_, first, ..) = sealed(fresh.seal(&ledger(1), 10).expect("sealed"));
    assert_eq!(first, 2);
    // Confirmed and sealed under the new key: named again only as journaled.
    assert_eq!(
        fresh.due(&[5; 16], DATA_ATTEST, &rotated).expect("due"),
        vec![(stream, 2)]
    );
    assert!(
        fresh
            .journaled(
                DATA_ATTEST,
                &rotated,
                &[("data/decisions/x/y".to_owned(), 1)]
            )
            .is_err(),
        "a stream this Host does not hold"
    );
}

/// WP-5.2, after the review: a crash between a batch signed by a new key and its span leaves the
/// run's spans naming the old key; the next seal appends the span of the key that signed it, from
/// that batch, so every batch verifies under its span.
#[test]
fn a_span_a_crash_lost_is_appended_for_the_key_that_signed_its_batch() {
    let (host, wall, mono) = manual_host("lost-span");
    let producer = host.sealer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let (run, ..) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let dir = host.producer_dir(&ledger(1));
    let before = std::fs::read(dir.join("signers.cbor")).expect("the spans");
    let rotated = rotate_attest(&host, &wall, &mono);
    producer.append(&ledger(1), &"b".to_owned()).expect("b");
    let (.., second) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    drop(producer);
    // The crash: the new key's span never written.
    std::fs::write(dir.join("signers.cbor"), &before).expect("restored");
    let reopened = host.sealer();
    reopened.append(&ledger(1), &"c".to_owned()).expect("c");
    sealed(reopened.seal(&ledger(1), 10).expect("sealed"));
    let spans = reopened.spans(&ledger(1)).expect("spans");
    let span = spans.signing(&run, 2).expect("a span");
    assert_eq!((span.from_seq, span.kid.as_str()), (2, rotated.as_str()));
    let jwk: permguard_core::keys::Jwk = serde_json::from_str(&span.jwk).expect("a JWK");
    open_batch(&second, &[jwk]);
}

/// WP-5.2, after the review: a batch stops before its records would pass the file's bound, one
/// record at least, and the next batch goes on from there.
#[test]
fn a_batch_stops_before_its_file_would_pass_its_bound() {
    let host = Host::new("bounded");
    let producer = host.sealer();
    for n in 0..5 {
        producer
            .append(&ledger(1), &format!("{n}").repeat(3000))
            .expect("appended");
    }
    let mut ranges = Vec::new();
    while let Sealing::Sealed { first, last, .. } = producer.seal(&ledger(1), 100).expect("sealed")
    {
        ranges.push((first, last));
    }
    assert_eq!(ranges, vec![(1, 2), (3, 4), (5, 5)]);
}

/// WP-5.2, found by the rotating crash test: a run signed by a `host.operations` key the ring
/// activated after many rotations verifies on reopening: the history runs to the ring's last
/// journal entry, not to the entry its epoch numbers.
#[test]
fn a_run_signed_after_many_rotations_verifies_on_reopening() {
    let (host, wall, mono) = manual_host("operations-rotated");
    let producer = host.producer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    for _ in 0..6 {
        use permguard_core::keys::Sign as _;
        let before = host.operations.active_key_id().expect("a key");
        while host.operations.active_key_id().expect("a key") == before {
            wall.jump(5);
            mono.advance(Duration::from_secs(5));
            permguard_core::KeyManager::maintain(host.operations.as_ref()).expect("maintained");
        }
        producer.rollover(&ledger(1), None).expect("rolled over");
        producer.append(&ledger(1), &"b".to_owned()).expect("b");
    }
    drop(producer);
    assert_eq!(
        host.producer()
            .append(&ledger(1), &"c".to_owned())
            .expect("the stream reopens")
            .seq,
        2
    );
}

/// `batch` with its envelope changed by `change` and its header by `header`, signed again under
/// the test's `data.attest` ring: a forger holding the key, so only the commitments catch it.
fn resign(
    host: &Host,
    batch: &batch::SealedBatch,
    header: impl FnOnce(&mut batch::Protected),
    change: impl FnOnce(&mut batch::Envelope),
) -> batch::SealedBatch {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let mut protected: batch::Protected =
        serde_json::from_slice(&B64.decode(&batch.signature.protected).expect("b64"))
            .expect("JSON");
    header(&mut protected);
    let mut envelope: batch::Envelope =
        serde_json::from_slice(&B64.decode(&batch.signature.payload).expect("b64")).expect("JSON");
    change(&mut envelope);
    let protected = B64.encode(
        crate::jcs::canonicalize(&serde_json::to_value(&protected).expect("JSON")).expect("JCS"),
    );
    let payload = B64.encode(envelope.signed_bytes().expect("bytes"));
    let signature = permguard_core::keys::Sign::sign(
        host.attest.as_ref(),
        format!("{protected}.{payload}").as_bytes(),
    )
    .expect("signed");
    batch::SealedBatch {
        signature: batch::Jws {
            protected,
            payload,
            signature: B64.encode(signature.bytes()),
        },
        records: batch.records.clone(),
    }
}

/// WP-5.2, after the mutants: a batch signed by the key itself is still refused when its header
/// names another algorithm, or its envelope another count, head or batch id than its records.
#[test]
fn a_batch_signed_again_over_wrong_commitments_is_refused() {
    let host = Host::new("resigned");
    let producer = host.sealer();
    for n in 0..3 {
        producer
            .append(&ledger(1), &format!("r{n}"))
            .expect("appended");
    }
    let (.., bytes) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let good = batch::SealedBatch::decode(&bytes).expect("decodes");
    let keys = host.attest_keys();
    let verdict = |batch: &batch::SealedBatch| {
        batch
            .verify(&keys, protected::DECISION_BATCH, digest::DECISION_RECORD)
            .is_ok()
    };
    assert!(
        verdict(&resign(&host, &good, |_| {}, |_| {})),
        "the same, signed again"
    );
    assert!(!verdict(&resign(
        &host,
        &good,
        |header| header.alg = "ES256".to_owned(),
        |_| {}
    )));
    assert!(!verdict(&resign(
        &host,
        &good,
        |_| {},
        |envelope| {
            envelope.count = 2;
            envelope.last_seq = 2;
        }
    )));
    assert!(!verdict(&resign(
        &host,
        &good,
        |_| {},
        |envelope| {
            envelope.head = batch::digest_string(digest::DECISION_RECORD, b"r1");
        }
    )));
    assert!(!verdict(&resign(
        &host,
        &good,
        |_| {},
        |envelope| {
            envelope.batch_id = format!("{}-2", envelope.run);
        }
    )));
}

/// WP-5.2, after the mutants: a batch file past its bound is refused before it is parsed, even
/// canonical; a signer that rotated between the key it named and the signature is refused.
#[test]
fn a_batch_past_its_bound_or_signed_by_another_key_is_refused() {
    let big = batch::SealedBatch {
        signature: batch::Jws {
            protected: "a".to_owned(),
            payload: "b".to_owned(),
            signature: "c".to_owned(),
        },
        records: vec!["A".repeat(batch::MAX_BATCH_FILE_BYTES)],
    };
    let bytes = big.encode().expect("encodes");
    assert!(bytes.len() > batch::MAX_BATCH_FILE_BYTES);
    assert!(batch::SealedBatch::decode(&bytes).is_err());
    let small = batch::SealedBatch {
        records: vec!["A".to_owned()],
        ..big
    };
    assert_eq!(
        batch::SealedBatch::decode(&small.encode().expect("encodes")).expect("decodes"),
        small
    );

    /// Signs under a key other than the one it was asked about.
    struct Rotated;
    impl permguard_core::keys::Sign for Rotated {
        fn active_key_id(&self) -> permguard_core::keys::Result<permguard_core::keys::KeyId> {
            Ok(permguard_core::keys::KeyId::new(
                "data.attest:next".to_owned(),
            ))
        }
        fn sign(&self, _: &[u8]) -> permguard_core::keys::Result<permguard_core::keys::Signature> {
            Ok(permguard_core::keys::Signature::new(
                permguard_core::keys::KeyId::new("data.attest:next".to_owned()),
                "EdDSA",
                vec![0; 64],
            ))
        }
    }
    let host = Host::new("rotated-signer");
    let jwk = host.attest_keys().remove(0);
    let envelope = batch::Envelope {
        descriptor_version: 1,
        stream_key: batch::KeyView::of(
            &descriptor()
                .key(&ledger(1), host.identity.host_id())
                .expect("a key"),
        ),
        run: "00".repeat(16),
        membership_id: None,
        epoch: None,
        first_seq: 1,
        last_seq: 1,
        count: 1,
        previous_head: batch::GENESIS_HEAD.to_owned(),
        head: batch::digest_string(digest::DECISION_RECORD, b"a"),
        merkle_root: crate::merkle::root(&[batch::digest_string(digest::DECISION_RECORD, b"a")])
            .expect("a root"),
        batch_id: format!("{}-1", "00".repeat(16)),
        created_at: "2027-01-01T00:00:00Z".to_owned(),
        key_set_epoch: 1,
    };
    assert!(matches!(
        batch::SealedBatch::seal(
            &Rotated,
            &jwk,
            protected::DECISION_BATCH,
            &envelope,
            &[b"a".to_vec()]
        ),
        Err(StreamError::Sign(_))
    ));
}

/// WP-5.2, after the mutants: a cutover journaled for one run does not let the new key seal the
/// next run, which waits for its own; a batch file sealing past the run's records is corruption;
/// a forked stream seals nothing.
#[test]
fn a_cutover_names_its_run_and_a_batch_its_records() {
    let (host, wall, mono) = manual_host("cutover-run");
    let producer = host.sealer();
    let fence = Fence {
        membership_id: [5; 16],
        task_id: "decisions".to_owned(),
        epoch: 1,
    };
    let run = producer
        .open_run(&ledger(1), Some(fence.clone()))
        .expect("opened")
        .run_id;
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let rotated = rotate_attest(&host, &wall, &mono);
    let first = producer.due_cutovers(&[5; 16], &rotated).expect("due");
    assert_eq!(first.len(), 1);
    producer
        .confirm_cutover(&first[0].0, &rotated)
        .expect("confirmed");
    let next = producer
        .rollover(&ledger(1), Some(fence))
        .expect("rolled over")
        .run_id;
    assert_ne!(next, run);
    producer.append(&ledger(1), &"b".to_owned()).expect("b");
    let key = descriptor()
        .key(&ledger(1), host.identity.host_id())
        .expect("a key");
    assert_eq!(
        producer.seal(&ledger(1), 10).expect("waits"),
        Sealing::AwaitingCutover {
            stream: format!("data/decisions/{}/{}", key.resource_component(), hex(&next)),
            from_seq: 1
        }
    );
    // A batch file sealing past the run's records.
    drop(producer);
    let other = Host::new("past-records");
    let producer = other.sealer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let (run, ..) = sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    drop(producer);
    let batches = other
        .producer_dir(&ledger(1))
        .join("batches")
        .join(hex(&run));
    std::fs::rename(batches.join("1-1.jws"), batches.join("1-5.jws")).expect("renamed");
    let producer = other.sealer();
    producer.append(&ledger(1), &"b".to_owned()).expect("b");
    assert!(matches!(
        producer.seal(&ledger(1), 10),
        Err(StreamError::Corruption(_))
    ));
    // A forked stream seals nothing.
    let forked = Host::new("forked-seal");
    let producer = forked.sealer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    producer.report_fork(&ledger(1), 1).expect("reported");
    assert!(matches!(
        producer.seal(&ledger(1), 10),
        Err(StreamError::Forked { at_seq: 1 })
    ));
}

/// WP-5.2, after the mutants: a span whose JWK names another key does not decode; a span that
/// would pass the file's bound is refused and the spans stay as they were; a stream directory
/// holding another stream's journal is refused.
#[test]
fn spans_and_stream_directories_are_checked() {
    let host = Host::new("spans-checked");
    let jwk = host.attest_keys().remove(0);
    let span = |from_seq: u64, kid: &str| Span {
        from_seq,
        kid: kid.to_owned(),
        jwk: canonical_jwk(&permguard_core::keys::Jwk {
            kid: kid.to_owned(),
            ..jwk.clone()
        })
        .expect("canonical"),
    };
    let wrong = Spans {
        runs: vec![(
            [1; 16],
            vec![Span {
                jwk: span(1, "data.attest:b").jwk,
                ..span(1, "data.attest:a")
            }],
        )],
    };
    assert!(Spans::decode(&wrong.encode().expect("encodes")).is_err());
    // Spans close to their bound, then a seal whose run needs one more.
    let mut full = Spans {
        runs: vec![([1; 16], Vec::new())],
    };
    let mut n = 1;
    while full.encode().expect("encodes").len() < MAX_SIGNERS_BYTES - 300 {
        full.runs[0].1.push(span(n, &format!("data.attest:k{n}")));
        n += 1;
    }
    let producer = host.sealer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    let dir = host.producer_dir(&ledger(1));
    permguard_host::storage::write::replace_view(
        &permguard_host::storage::Dir::open(&dir).expect("the directory"),
        "signers.cbor",
        format::VIEW,
        &full.encode().expect("encodes"),
    )
    .expect("written");
    drop(producer);
    let producer = host.sealer();
    assert!(matches!(
        producer.seal(&ledger(1), 10),
        Err(StreamError::Invalid(_))
    ));
    assert_eq!(producer.spans(&ledger(1)).expect("spans"), full);
    // A stream directory moved under another resource's digest.
    let moved = Host::new("moved-stream");
    let producer = moved.sealer();
    producer.append(&ledger(1), &"a".to_owned()).expect("a");
    drop(producer);
    let from = moved.producer_dir(&ledger(1));
    let parent = from
        .parent()
        .expect("a host directory")
        .parent()
        .expect("a resource directory");
    std::fs::rename(
        from.parent().expect("a host directory"),
        parent.join("ab".repeat(32)),
    )
    .expect("moved");
    assert!(matches!(
        moved.sealer().pending_cutovers(),
        Err(StreamError::Corruption(_))
    ));
}
