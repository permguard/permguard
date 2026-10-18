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
        reopened.read(&ledger(1), 1, 10).expect("read").records,
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
        host.producer()
            .read(&ledger(1), 1, 1000)
            .expect("read")
            .records,
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
        reopened.read(&ledger(1), 1, 10).expect("read").records,
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
    assert_eq!(
        reopened
            .read(&ledger(1), 1, 10)
            .expect("read")
            .records
            .len(),
        3
    );
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
            .expect("read")
            .records,
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
        reopened.read(&ledger(1), 1, 10).expect("read").records,
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

/// WP-6.1: a record built by `append_with` is handed the position it takes, under concurrent
/// appenders, across a reopening and across a rollover; a build that fails or a record the codec
/// refuses takes no sequence.
#[test]
fn append_with_builds_each_record_at_the_engines_position() {
    let host = Host::new("append-with");
    let producer = Arc::new(host.producer());
    // Each record names its sequence and the digest it says precedes it; two per append.
    let named = |position: Position| {
        Ok(vec![
            format!("{}|{}", position.seq, hex(&position.prev)).into_bytes(),
            format!("{}|next", position.seq + 1).into_bytes(),
        ])
    };
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let producer = Arc::clone(&producer);
            std::thread::spawn(move || {
                for _ in 0..25 {
                    producer.append_with(&ledger(1), named).expect("appended");
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("the thread");
    }
    let records = producer.read(&ledger(1), 1, 1000).expect("read").records;
    assert_eq!(records.len(), 200);
    let mut prev = [0u8; 32];
    for (seq, record) in &records {
        let (named_seq, named_prev) = record.split_once('|').expect("a named record");
        assert_eq!(named_seq, seq.to_string(), "the sequence it was handed");
        if named_prev != "next" {
            assert_eq!(named_prev, hex(&prev), "the digest of the record before it");
        }
        prev = record_digest(digest::DECISION_RECORD, record.as_bytes());
    }
    // A failing build and a record the codec refuses take nothing.
    assert!(
        producer
            .append_with(&ledger(1), |_| Err("refused".to_owned()))
            .is_err()
    );
    assert!(
        producer
            .append_with(&ledger(1), |_| Ok(Vec::new()))
            .is_err()
    );
    assert!(
        producer
            .append_with(&ledger(1), |_| Ok(vec![vec![0xff]]))
            .is_err(),
        "not text"
    );
    drop(producer);
    // Reopened, the next record is handed the digest of the last one on disk.
    let reopened = host.producer();
    let run = reopened
        .state(&ledger(1))
        .expect("state")
        .expect("a run")
        .run_id;
    let mut seen = None;
    let receipt = reopened
        .append_with(&ledger(1), |position| {
            seen = Some(position);
            Ok(vec![b"after".to_vec()])
        })
        .expect("appended");
    assert_eq!(
        seen,
        Some(Position {
            run_id: run,
            seq: 201,
            prev,
        })
    );
    assert_eq!((receipt.run_id, receipt.seq), (run, 201));
    // A successor run starts from sequence 1 and the zero digest.
    let successor = reopened.rollover(&ledger(1), None).expect("rolled over");
    reopened
        .append_with(&ledger(1), |position| {
            seen = Some(position);
            Ok(vec![b"first".to_vec()])
        })
        .expect("appended");
    assert_eq!(
        seen,
        Some(Position {
            run_id: successor.run_id,
            seq: 1,
            prev: [0; 32],
        })
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
            .records
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
        permguard_host::composition::StreamCutovers::due(&fresh, &[5; 16], DATA_ATTEST, &rotated)
            .expect("due"),
        vec![(stream.clone(), 2)]
    );
    assert_eq!(
        permguard_host::composition::StreamCutovers::due(
            &fresh,
            &[5; 16],
            HOST_OPERATIONS,
            &rotated
        )
        .expect("due"),
        Vec::new(),
        "another ring"
    );
    // Asked again, the same cutover.
    assert_eq!(
        permguard_host::composition::StreamCutovers::due(&fresh, &[5; 16], DATA_ATTEST, &rotated)
            .expect("due"),
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
        permguard_host::composition::StreamCutovers::due(&fresh, &[5; 16], DATA_ATTEST, &rotated)
            .expect("due"),
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

// ---- WP-5.3: the ingest ----

use super::ingest::{Answer, Forked, Outcome, Ship, Shipping};

/// The membership the tests' streams are fenced by.
const MEMBERSHIP: [u8; 16] = [5; 16];

fn fence(epoch: u64) -> Fence {
    Fence {
        membership_id: MEMBERSHIP,
        task_id: "decisions".to_owned(),
        epoch,
    }
}

/// The member's `data.attest` pin, as the coordinator's manifest holds it.
fn pin_of(host: &Host) -> permguard_host::membership::record::RingPin {
    let statement = host.attest.statement().expect("a statement");
    permguard_host::membership::record::RingPin {
        owner: permguard_host::membership::record::Role::Member,
        ring: DATA_ATTEST.to_owned(),
        epoch: statement.epoch,
        key_set_digest: statement.key_set_digest,
        binding: statement.binding.expect("a binding"),
        retiring: false,
    }
}

/// The ship message of `batch` with the member's statement.
fn ship_of(host: &Host, batch: &[u8]) -> Vec<u8> {
    Ship {
        batch: batch.to_vec(),
        statement: permguard_host::membership::statement_of(&host.attest)
            .expect("a statement")
            .encode()
            .expect("encodes"),
    }
    .encode()
    .expect("encodes")
}

/// The coordinator's consumer of the tests' descriptor, on `host`.
fn consumer_on(host: &Host) -> Consumer<Text> {
    host.streams()
        .register_consumer(descriptor(), Text)
        .expect("registered")
}

/// Ships `body` from `member` at epoch 1 of the test membership, the member's pin current.
fn ingest(
    consumer: &Consumer<Text>,
    member: &Host,
    body: &[u8],
) -> Result<(Answer, Option<Forked>), StreamError> {
    ingest_at(consumer, member, body, 1, vec![pin_of(member)])
}

fn ingest_at(
    consumer: &Consumer<Text>,
    member: &Host,
    body: &[u8],
    epoch: u64,
    pins: Vec<permguard_host::membership::record::RingPin>,
) -> Result<(Answer, Option<Forked>), StreamError> {
    let pinned = move |_: &str, _: u64| pins.clone();
    let resource = ledger(1).to_string();
    consumer.ingest(
        &Shipping {
            membership_id: MEMBERSHIP,
            epoch,
            member: member.identity.host_id(),
            resource: &resource,
            pins: &pinned,
        },
        body,
    )
}

/// A member streaming `n` records on `ledger(1)` under the test fence, sealed `per` a batch:
/// the producer, its run and the batches' bytes.
fn shipped(host: &Host, n: usize, per: u64) -> (Producer<Text>, [u8; 16], Vec<Vec<u8>>) {
    let producer = host.sealer();
    let run = producer
        .open_run(&ledger(1), Some(fence(1)))
        .expect("opened")
        .run_id;
    for at in 0..n {
        producer
            .append(&ledger(1), &format!("r{at}"))
            .expect("appended");
    }
    let mut batches = Vec::new();
    while let Sealing::Sealed { bytes, .. } = producer.seal(&ledger(1), per).expect("sealed") {
        batches.push(bytes);
    }
    (producer, run, batches)
}

/// A batch of `records` from `first_seq` of the run `run`, after `previous`, signed by the
/// member's active key: what a forking member could sign.
fn forge(
    host: &Host,
    run: [u8; 16],
    first_seq: u64,
    previous: String,
    records: &[&str],
    epoch: u64,
) -> Vec<u8> {
    forge_with(
        host.attest.as_ref(),
        host,
        run,
        first_seq,
        previous,
        records
            .iter()
            .map(|text| text.as_bytes().to_vec())
            .collect(),
        epoch,
        |_| {},
    )
}

/// [`forge`] under `ring`, of any record bytes, the envelope changed by `tweak` before it is
/// signed.
#[allow(clippy::too_many_arguments)]
fn forge_with(
    ring: &Ring,
    host: &Host,
    run: [u8; 16],
    first_seq: u64,
    previous: String,
    records: Vec<Vec<u8>>,
    epoch: u64,
    tweak: impl FnOnce(&mut batch::Envelope),
) -> Vec<u8> {
    use permguard_core::keys::Sign as _;
    let digests: Vec<String> = records
        .iter()
        .map(|record| batch::digest_string(digest::DECISION_RECORD, record))
        .collect();
    let kid = ring.active_key_id().expect("a key");
    let jwk = ring
        .statement()
        .expect("a statement")
        .keys
        .into_iter()
        .find(|jwk| jwk.kid == kid.as_str())
        .expect("the active key");
    let key = descriptor()
        .key(&ledger(1), host.identity.host_id())
        .expect("a key");
    let mut envelope = batch::Envelope {
        descriptor_version: 1,
        stream_key: batch::KeyView::of(&key),
        run: hex(&run),
        membership_id: Some(permguard_host::identity::record::uuid_text(&MEMBERSHIP)),
        epoch: Some(epoch),
        first_seq,
        last_seq: first_seq + records.len() as u64 - 1,
        count: records.len() as u64,
        previous_head: previous,
        head: digests.last().cloned().expect("a record"),
        merkle_root: crate::merkle::root(&digests).expect("a root"),
        batch_id: format!("{}-{first_seq}", hex(&run)),
        created_at: "2027-01-01T00:00:00Z".to_owned(),
        key_set_epoch: ring.epoch(),
    };
    tweak(&mut envelope);
    batch::SealedBatch::seal(ring, &jwk, protected::DECISION_BATCH, &envelope, &records)
        .expect("sealed")
        .encode()
        .expect("encoded")
}

fn record_digest_of(text: &str) -> String {
    batch::digest_string(digest::DECISION_RECORD, text.as_bytes())
}

/// The consumer directory of `member`'s run `run` on `host`.
fn consumer_run_dir(host: &Host, member: &Host, run: &[u8; 16]) -> PathBuf {
    let key = descriptor()
        .key(&ledger(1), member.identity.host_id())
        .expect("a key");
    host.root
        .join("host")
        .join(STREAMS)
        .join("data")
        .join("decisions")
        .join("1")
        .join("consumer")
        .join(key.resource_component())
        .join(hex(&member.identity.host_id()))
        .join(hex(run))
}

/// WP-5.3: a batch continuing what is held is acknowledged through its last sequence, after its
/// batch file, its span, its records and STATE are on disk.
#[test]
fn an_acknowledgement_follows_every_durable_write() {
    let host = Host::new("ingest-ok");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 5, 3);
    assert_eq!(batches.len(), 2);
    let (answer, forked) =
        ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("ingested");
    assert_eq!((answer, forked), (Answer::of(Outcome::Ok, 3), None));
    let dir = consumer_run_dir(&host, &host, &run);
    assert_eq!(
        std::fs::read(dir.join("batches").join("1-3.jws")).expect("the batch file"),
        batches[0]
    );
    let spans = consumer
        .spans(&ledger(1), host.identity.host_id(), run)
        .expect("spans");
    assert_eq!(spans.signing(&run, 1).map(|span| span.from_seq), Some(1));
    let state = ConsumerState::decode(
        &permguard_host::storage::write::read_view(
            &permguard_host::storage::Dir::open(&dir).expect("the run"),
            "STATE",
            format::VIEW,
        )
        .expect("read")
        .expect("a STATE"),
    )
    .expect("decodes");
    assert_eq!((state.acked, state.oldest_retained), (3, 1));
    assert!(state.opened.is_some(), "the first admission dates the run");
    let (answer, _) = ingest(&consumer, &host, &ship_of(&host, &batches[1])).expect("ingested");
    assert_eq!(answer, Answer::of(Outcome::Ok, 5));
    let records: Vec<String> = consumer
        .read(&ledger(1), host.identity.host_id(), run, 1, 10)
        .expect("read")
        .records
        .into_iter()
        .map(|(_, text)| text)
        .collect();
    assert_eq!(records, ["r0", "r1", "r2", "r3", "r4"]);
    // A reopened consumer holds the same, from its records.
    drop(consumer);
    assert_eq!(
        consumer_on(&host)
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        5
    );
}

/// WP-5.3: a batch already held is acknowledged again, the records unchanged; the same range
/// with another record is a fork, which marks the producer: every later batch is `fork`.
#[test]
fn an_exact_replay_is_ok_and_a_differing_one_a_fork() {
    let host = Host::new("ingest-replay");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 3, 3);
    let body = ship_of(&host, &batches[0]);
    assert_eq!(
        ingest(&consumer, &host, &body).expect("ok").0,
        Answer::of(Outcome::Ok, 3)
    );
    assert_eq!(
        ingest(&consumer, &host, &body).expect("ok").0,
        Answer::of(Outcome::Ok, 3)
    );
    // Another batching of the records held: the same records, an exact replay.
    let rebatched = forge(&host, run, 2, record_digest_of("r0"), &["r1", "r2"], 1);
    assert_eq!(
        ingest(&consumer, &host, &ship_of(&host, &rebatched))
            .expect("ok")
            .0,
        Answer::of(Outcome::Ok, 3)
    );
    let differing = forge(&host, run, 2, record_digest_of("r0"), &["r1", "x2"], 1);
    let (answer, forked) = ingest(&consumer, &host, &ship_of(&host, &differing)).expect("fork");
    assert_eq!(answer.outcome, Outcome::Fork);
    let key = descriptor()
        .key(&ledger(1), host.identity.host_id())
        .expect("a key");
    assert_eq!(
        forked,
        Some(Forked {
            stream: format!("data/decisions/{}/{}", key.resource_component(), hex(&run)),
            at_seq: 3,
        })
    );
    assert_eq!(
        consumer
            .forked(&ledger(1), host.identity.host_id())
            .expect("read"),
        Some(ForkMark { run, at_seq: 3 })
    );
    // Marked: even the exact replay is `fork` now, the incident reported again until the
    // membership is suspended.
    assert_eq!(
        ingest(&consumer, &host, &body).expect("fork"),
        (
            Answer::of(Outcome::Fork, 0),
            Some(Forked {
                stream: format!("data/decisions/{}/{}", key.resource_component(), hex(&run)),
                at_seq: 3,
            })
        )
    );
    assert_eq!(
        consumer
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        3,
        "nothing the fork carried was kept"
    );
}

/// WP-5.3: a batch whose previous head is not the record before it is a fork, and a batch file
/// of a range held with other bytes, signed again, is a fork.
#[test]
fn a_batch_that_does_not_chain_or_was_signed_twice_is_a_fork() {
    let host = Host::new("ingest-chain");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 3, 2);
    ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("ok");
    let unchained = forge(&host, run, 3, record_digest_of("other"), &["r2"], 1);
    assert_eq!(
        ingest(&consumer, &host, &ship_of(&host, &unchained))
            .expect("fork")
            .0
            .outcome,
        Outcome::Fork
    );
    let other = Host::new("ingest-twice");
    let consumer = consumer_on(&other);
    let (_producer, run, batches) = shipped(&other, 2, 2);
    ingest(&consumer, &other, &ship_of(&other, &batches[0])).expect("ok");
    let twice = forge(
        &other,
        run,
        1,
        batch::GENESIS_HEAD.to_owned(),
        &["r0", "r1"],
        1,
    );
    assert_ne!(twice, batches[0]);
    assert_eq!(
        ingest(&consumer, &other, &ship_of(&other, &twice))
            .expect("fork")
            .0
            .outcome,
        Outcome::Fork
    );
}

/// WP-5.3: a batch overlapping what is held keeps only its suffix.
#[test]
fn an_overlap_appends_only_its_suffix() {
    let host = Host::new("ingest-overlap");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 2, 2);
    ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("ok");
    let overlapping = forge(
        &host,
        run,
        2,
        record_digest_of("r0"),
        &["r1", "r2", "r3"],
        1,
    );
    assert_eq!(
        ingest(&consumer, &host, &ship_of(&host, &overlapping))
            .expect("ok")
            .0,
        Answer::of(Outcome::Ok, 4)
    );
    let records: Vec<(u64, String)> = consumer
        .read(&ledger(1), host.identity.host_id(), run, 1, 10)
        .expect("read")
        .records;
    assert_eq!(
        records,
        vec![
            (1, "r0".to_owned()),
            (2, "r1".to_owned()),
            (3, "r2".to_owned()),
            (4, "r3".to_owned())
        ]
    );
}

/// WP-5.3: a batch beyond the next sequence is `out_of_order` with the sequence to resend from,
/// and nothing of it is kept.
#[test]
fn a_batch_ahead_is_out_of_order_and_stores_nothing() {
    let host = Host::new("ingest-ahead");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 4, 2);
    let (answer, _) = ingest(&consumer, &host, &ship_of(&host, &batches[1])).expect("answered");
    assert_eq!(
        answer,
        Answer {
            outcome: Outcome::OutOfOrder,
            acked: 0,
            expected_seq: Some(1)
        }
    );
    let dir = consumer_run_dir(&host, &host, &run);
    assert!(!dir.join("batches").join("3-4.jws").exists());
    assert!(!dir.join("signers.cbor").exists());
    assert_eq!(
        consumer
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        0
    );
}

/// WP-5.3: a range below the oldest sequence retained is `gone`, never an exact replay.
#[test]
fn a_range_below_the_oldest_retained_is_gone() {
    let host = Host::new("ingest-gone");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 4, 2);
    ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("ok");
    ingest(&consumer, &host, &ship_of(&host, &batches[1])).expect("ok");
    drop(consumer);
    // What retention (WP-5.6) leaves: the bytes from 3 on.
    let dir = consumer_run_dir(&host, &host, &run);
    permguard_host::storage::write::replace_view(
        &permguard_host::storage::Dir::open(&dir).expect("the run"),
        "STATE",
        format::VIEW,
        &ConsumerState {
            acked: 4,
            oldest_retained: 3,
            opened: None,
        }
        .encode()
        .expect("encodes"),
    )
    .expect("written");
    let consumer = consumer_on(&host);
    assert_eq!(
        ingest(&consumer, &host, &ship_of(&host, &batches[0]))
            .expect("gone")
            .0,
        Answer::of(Outcome::Gone, 4)
    );
    assert_eq!(
        ingest(&consumer, &host, &ship_of(&host, &batches[1]))
            .expect("ok")
            .0,
        Answer::of(Outcome::Ok, 4)
    );
}

/// WP-5.3: a batch whose statement is not the member's pin, whose key is outside the pinned set,
/// whose signature, membership, producer or resource is not the task's, or whose epoch is above
/// the lease's, is `unverifiable`; below it, `closed`; nothing of any is kept.
#[test]
fn an_unverifiable_batch_stores_nothing() {
    let host = Host::new("ingest-unverifiable");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 2, 2);
    let body = ship_of(&host, &batches[0]);
    let outcome =
        |answer: Result<(Answer, Option<Forked>), StreamError>| answer.expect("answered").0.outcome;
    // No pin, or the pin of another epoch.
    assert_eq!(
        outcome(ingest_at(&consumer, &host, &body, 1, Vec::new())),
        Outcome::Unverifiable
    );
    let mut stale = pin_of(&host);
    stale.epoch += 1;
    assert_eq!(
        outcome(ingest_at(&consumer, &host, &body, 1, vec![stale])),
        Outcome::Unverifiable
    );
    let mut digest = pin_of(&host);
    digest.key_set_digest = [9; 32];
    assert_eq!(
        outcome(ingest_at(&consumer, &host, &body, 1, vec![digest])),
        Outcome::Unverifiable
    );
    // Another member's statement, or a member shipping another's batch.
    let other = Host::new("ingest-other-member");
    assert_eq!(
        outcome(ingest_at(&consumer, &other, &body, 1, vec![pin_of(&other)])),
        Outcome::Unverifiable
    );
    let foreign = Ship {
        batch: batches[0].clone(),
        statement: permguard_host::membership::statement_of(&other.attest)
            .expect("a statement")
            .encode()
            .expect("encodes"),
    }
    .encode()
    .expect("encodes");
    assert_eq!(
        outcome(ingest_at(
            &consumer,
            &host,
            &foreign,
            1,
            vec![pin_of(&host)]
        )),
        Outcome::Unverifiable
    );
    // A changed signature.
    let mut tampered = batch::SealedBatch::decode(&batches[0]).expect("decodes");
    // One character in the middle, always changed: a random signature may hold no given letter.
    let mut chars: Vec<char> = tampered.signature.signature.chars().collect();
    let middle = chars.len() / 2;
    chars[middle] = if chars[middle] == 'A' { 'B' } else { 'A' };
    tampered.signature.signature = chars.into_iter().collect();
    let tampered = ship_of(&host, &tampered.encode().expect("encodes"));
    assert_eq!(
        outcome(ingest(&consumer, &host, &tampered)),
        Outcome::Unverifiable
    );
    // Not a message, or a message of no batch.
    assert_eq!(
        outcome(ingest(&consumer, &host, b"not cbor")),
        Outcome::Unverifiable
    );
    // Another membership's batch.
    let other_membership = {
        let producer = host.sealer();
        producer
            .open_run(
                &ledger(2),
                Some(Fence {
                    membership_id: [6; 16],
                    ..fence(1)
                }),
            )
            .expect("opened");
        producer.append(&ledger(2), &"a".to_owned()).expect("a");
        match producer.seal(&ledger(2), 10).expect("sealed") {
            Sealing::Sealed { bytes, .. } => bytes,
            other => panic!("{other:?}"),
        }
    };
    let resource = ledger(2).to_string();
    let pins = vec![pin_of(&host)];
    let pinned = move |_: &str, _: u64| pins.clone();
    let shipping = Shipping {
        membership_id: MEMBERSHIP,
        epoch: 1,
        member: host.identity.host_id(),
        resource: &resource,
        pins: &pinned,
    };
    assert_eq!(
        consumer
            .ingest(&shipping, &ship_of(&host, &other_membership))
            .expect("answered")
            .0
            .outcome,
        Outcome::Unverifiable
    );
    // Another resource than the task's.
    let shipping = Shipping {
        resource: "plane/data/zone/zone-a/ledger/ledger-9",
        ..shipping
    };
    assert_eq!(
        consumer
            .ingest(&shipping, &body)
            .expect("answered")
            .0
            .outcome,
        Outcome::Unverifiable
    );
    // A batch's epoch above the lease's is `unverifiable`.
    let ahead = forge(&host, run, 1, batch::GENESIS_HEAD.to_owned(), &["r0"], 3);
    assert_eq!(
        outcome(ingest_at(
            &consumer,
            &host,
            &ship_of(&host, &ahead),
            2,
            vec![pin_of(&host)]
        )),
        Outcome::Unverifiable
    );
    assert_eq!(
        consumer
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        0
    );
    assert!(
        !consumer_run_dir(&host, &host, &run)
            .join("batches")
            .exists()
    );
}

/// WP-5.3: the checks run in the documented order: a forked producer is `fork` before its batch
/// is read; a batch that does not verify is `unverifiable` before its epoch, range or retention
/// is judged.
#[test]
fn each_check_refuses_in_the_documented_order() {
    let host = Host::new("ingest-order");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 4, 2);
    // Ahead and stale, but not verifiable: `unverifiable`, not `out_of_order` nor `closed`.
    let mut tampered = batch::SealedBatch::decode(&batches[1]).expect("decodes");
    tampered.records.swap(0, 1);
    let tampered = ship_of(&host, &tampered.encode().expect("encodes"));
    assert_eq!(
        ingest_at(&consumer, &host, &tampered, 2, vec![pin_of(&host)])
            .expect("answered")
            .0
            .outcome,
        Outcome::Unverifiable
    );
    // Ahead and of an epoch no lease issued: `unverifiable` before `out_of_order`.
    assert_eq!(
        ingest_at(
            &consumer,
            &host,
            &ship_of(&host, &batches[1]),
            0,
            vec![pin_of(&host)]
        )
        .expect("answered")
        .0
        .outcome,
        Outcome::Unverifiable
    );
    // A forked producer: `fork`, even for a message that does not read.
    ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("ok");
    let differing = forge(
        &host,
        run,
        1,
        batch::GENESIS_HEAD.to_owned(),
        &["x0", "r1"],
        1,
    );
    ingest(&consumer, &host, &ship_of(&host, &differing)).expect("fork");
    assert_eq!(
        ingest(&consumer, &host, &ship_of(&host, b"garbage"))
            .expect("answered")
            .0
            .outcome,
        Outcome::Fork
    );
}

/// WP-5.3: a store that cannot keep a batch is an error, the handler's `deferred`; the retry,
/// the store back, is acknowledged.
#[test]
fn a_store_failure_is_deferred() {
    let host = Host::new("ingest-deferred");
    let consumer = consumer_on(&host);
    let (_producer, run, batches) = shipped(&host, 4, 2);
    ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("ok");
    let records = records_dir(&consumer_run_dir(&host, &host, &run));
    {
        let _failing = fault::inject_exact(segment(&records), Fault::Fsync);
        assert!(matches!(
            ingest(&consumer, &host, &ship_of(&host, &batches[1])),
            Err(StreamError::Storage(_))
        ));
    }
    // The same consumer: the failed run is opened again, its journal recovered.
    assert_eq!(
        ingest(&consumer, &host, &ship_of(&host, &batches[1]))
            .expect("ok")
            .0,
        Answer::of(Outcome::Ok, 4)
    );
    // The batch file and span the failed delivery left are the retry's: one span.
    let spans = consumer
        .spans(&ledger(1), host.identity.host_id(), run)
        .expect("spans");
    assert_eq!(spans.runs.len(), 1);
    assert_eq!(spans.runs[0].1.len(), 1);
}

/// WP-5.3: every outcome travels as its stable code; `expected_seq` comes with `out_of_order`
/// only; the message reads back as it was written.
#[test]
fn the_answers_carry_the_stable_codes() {
    use permguard_core::codes::stream;
    for (outcome, code) in [
        (Outcome::Ok, super::ingest::OK),
        (Outcome::OutOfOrder, stream::OUT_OF_ORDER),
        (Outcome::Fork, stream::FORK),
        (Outcome::Unverifiable, stream::UNVERIFIABLE),
        (Outcome::Gone, stream::GONE),
        (Outcome::Closed, stream::CLOSED),
    ] {
        assert_eq!(outcome.code(), code);
        let answer = Answer {
            outcome,
            acked: 7,
            expected_seq: (outcome == Outcome::OutOfOrder).then_some(8),
        };
        assert_eq!(
            Answer::decode(&answer.encode().expect("encodes")).expect("decodes"),
            answer
        );
    }
    let wrong = Answer {
        outcome: Outcome::Ok,
        acked: 1,
        expected_seq: Some(2),
    };
    assert!(Answer::decode(&wrong.encode().expect("encodes")).is_err());
    let ship = Ship {
        batch: b"batch".to_vec(),
        statement: b"statement".to_vec(),
    };
    assert_eq!(
        Ship::decode(&ship.encode().expect("encodes")).expect("decodes"),
        ship
    );
    assert!(
        Ship::decode(&vec![
            0u8;
            permguard_host::membership::record::MAX_BODY_BYTES + 1
        ])
        .is_err()
    );
}

/// WP-5.3: the handler answers through the session's incidents: a fork is reported with its
/// stream and sequence, and again on the next delivery; a store that cannot keep a batch is the
/// refusal `store_unavailable`.
#[test]
fn the_handler_reports_a_fork_and_defers_a_store_failure() {
    use permguard_host::membership::task::{Incidents, TaskContext, TaskHandler};
    struct Reported(Mutex<Vec<(String, u64)>>);
    impl Incidents for Reported {
        fn stream_forked(&self, stream: &str, at_seq: u64) -> Result<(), String> {
            self.0
                .lock()
                .expect("lock")
                .push((stream.to_owned(), at_seq));
            Ok(())
        }
    }
    struct Pinned(permguard_host::membership::record::RingPin);
    impl super::ingest::StreamPins for Pinned {
        fn verifying_pins(
            &self,
            membership_id: &[u8; 16],
            _: &str,
            _: &str,
            _: u64,
        ) -> Vec<permguard_host::membership::record::RingPin> {
            if *membership_id == MEMBERSHIP {
                vec![self.0.clone()]
            } else {
                Vec::new()
            }
        }
    }
    let host = Host::new("ingest-handler");
    let (_producer, run, batches) = shipped(&host, 4, 2);
    let handler = super::ingest::Ingest {
        consumer: Arc::new(consumer_on(&host)),
        pins: Arc::new(Pinned(pin_of(&host))),
    };
    let context = TaskContext {
        membership_id: MEMBERSHIP,
        task_id: "decisions".to_owned(),
        task_type: TaskType::DecisionsShip,
        version: super::ingest::VERSION,
        epoch: 1,
        resource: ledger(1).to_string(),
        member: host.identity.host_id(),
        request_id: "r".to_owned(),
        limits: permguard_host::membership::record::Limits {
            max_body_bytes: 1 << 20,
            max_concurrency: 1,
            max_rate_per_minute: 60,
            max_batch_records: 100,
            retention_seconds: 3600,
        },
        channel_binding: [0; 32],
    };
    let reported = Reported(Mutex::new(Vec::new()));
    let answer = |body: &[u8]| {
        Answer::decode(
            &handler
                .handle_with(&context, body, &reported)
                .expect("answered"),
        )
        .expect("decodes")
    };
    assert_eq!(
        answer(&ship_of(&host, &batches[0])),
        Answer::of(Outcome::Ok, 2)
    );
    // A store that cannot keep the next batch.
    let records = records_dir(&consumer_run_dir(&host, &host, &run));
    {
        let _failing = fault::inject_exact(segment(&records), Fault::Fsync);
        let refused = handler
            .handle_with(&context, &ship_of(&host, &batches[1]), &reported)
            .expect_err("deferred");
        assert_eq!(
            refused.code,
            permguard_core::codes::stream::STORE_UNAVAILABLE
        );
    }
    assert_eq!(
        answer(&ship_of(&host, &batches[1])),
        Answer::of(Outcome::Ok, 4)
    );
    // A fork: answered, reported; reported again on the next delivery.
    let differing = forge(&host, run, 3, record_digest_of("r1"), &["r2", "x3"], 1);
    assert_eq!(answer(&ship_of(&host, &differing)).outcome, Outcome::Fork);
    assert_eq!(answer(&ship_of(&host, &batches[0])).outcome, Outcome::Fork);
    let key = descriptor()
        .key(&ledger(1), host.identity.host_id())
        .expect("a key");
    let stream = format!("data/decisions/{}/{}", key.resource_component(), hex(&run));
    assert_eq!(
        reported.0.lock().expect("lock").clone(),
        vec![(stream.clone(), 4), (stream, 4)]
    );
    // Without a session's incidents, the fork is still answered.
    assert_eq!(
        Answer::decode(
            &handler
                .handle(&context, &ship_of(&host, &batches[0]))
                .expect("answered")
        )
        .expect("decodes")
        .outcome,
        Outcome::Fork
    );
}

/// WP-5.3, after the review: a run opened under an earlier epoch of the membership ships after
/// a re-pin moved the lease's on: its batches under the replaced key verify against the retiring
/// pin, those under the new key against the current one, each with its span.
#[test]
fn a_run_ships_on_after_a_repin_under_both_pins() {
    let (host, wall, mono) = manual_host("ingest-repin");
    let consumer = consumer_on(&host);
    let producer = host.sealer();
    let run = producer
        .open_run(&ledger(1), Some(fence(1)))
        .expect("opened")
        .run_id;
    for n in 0..4 {
        producer
            .append(&ledger(1), &format!("r{n}"))
            .expect("appended");
    }
    let old_pin = pin_of(&host);
    let old_statement = ship_of(&host, b"");
    let (.., first) = sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    let (.., second) = sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    rotate_attest(&host, &wall, &mono);
    producer
        .append(&ledger(1), &"r4".to_owned())
        .expect("appended");
    let new_pin = pin_of(&host);
    assert_ne!(old_pin, new_pin);
    let retiring = permguard_host::membership::record::RingPin {
        retiring: true,
        ..old_pin
    };
    let with_old = |batch: &[u8]| {
        let mut ship = Ship::decode(&old_statement).expect("decodes");
        ship.batch = batch.to_vec();
        ship.encode().expect("encodes")
    };
    // The lease is at epoch 2 now; the run's fence is epoch 1.
    let pins = vec![new_pin.clone(), retiring.clone()];
    assert_eq!(
        ingest_at(&consumer, &host, &with_old(&first), 2, pins.clone())
            .expect("ok")
            .0,
        Answer::of(Outcome::Ok, 2)
    );
    assert_eq!(
        ingest_at(&consumer, &host, &with_old(&second), 2, pins.clone())
            .expect("ok")
            .0,
        Answer::of(Outcome::Ok, 4)
    );
    // The new key's batch, after its cutover, under the current pin and statement.
    let stream = {
        let key = descriptor()
            .key(&ledger(1), host.identity.host_id())
            .expect("a key");
        format!("data/decisions/{}/{}", key.resource_component(), hex(&run))
    };
    let rotated = {
        use permguard_core::keys::Sign as _;
        host.attest
            .active_key_id()
            .expect("a key")
            .as_str()
            .to_owned()
    };
    let due = producer.due_cutovers(&MEMBERSHIP, &rotated).expect("due");
    assert_eq!(due, vec![(stream.clone(), 5)]);
    producer
        .confirm_cutover(&stream, &rotated)
        .expect("confirmed");
    let (.., third) = sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    assert_eq!(
        ingest_at(&consumer, &host, &ship_of(&host, &third), 2, pins.clone())
            .expect("ok")
            .0,
        Answer::of(Outcome::Ok, 5)
    );
    let spans = consumer
        .spans(&ledger(1), host.identity.host_id(), run)
        .expect("spans");
    assert_eq!(
        spans.runs[0]
            .1
            .iter()
            .map(|span| span.from_seq)
            .collect::<Vec<_>>(),
        vec![1, 5]
    );
    // The new key over a range the replaced one covers: a conflicting transition, a fork,
    // decided before any file of it is written.
    let conflicting = forge(&host, run, 3, record_digest_of("r1"), &["r2", "r3"], 1);
    let (answer, forked) =
        ingest_at(&consumer, &host, &ship_of(&host, &conflicting), 2, pins).expect("fork");
    assert_eq!(answer.outcome, Outcome::Fork);
    assert_eq!(forked.map(|forked| forked.at_seq), Some(3));
    assert_eq!(
        std::fs::read(
            consumer_run_dir(&host, &host, &run)
                .join("batches")
                .join("3-4.jws")
        )
        .expect("the first delivery's file"),
        second
    );
}

/// WP-5.3: frames written under a later claim of the volume are refused when the consumer opens
/// the run: a restored volume never answers for records it did not write.
#[test]
fn a_consumer_journal_of_a_later_claim_is_refused() {
    let host = Host::new("ingest-claim");
    let (_producer, run, batches) = shipped(&host, 2, 2);
    let at = |claim: u64| {
        Consumer::new(
            permguard_host::storage::Dir::open(
                &host
                    .root
                    .join("host")
                    .join(STREAMS)
                    .join("data")
                    .join("decisions")
                    .join("1")
                    .join("consumer"),
            )
            .expect("the consumer directory"),
            claim,
            descriptor(),
            Text,
            Arc::clone(&host.time),
        )
    };
    std::fs::create_dir_all(
        host.root
            .join("host")
            .join(STREAMS)
            .join("data")
            .join("decisions")
            .join("1")
            .join("consumer"),
    )
    .expect("the consumer directory");
    // Written under claim 7.
    let later = at(7);
    ingest(&later, &host, &ship_of(&host, &batches[0])).expect("ok");
    drop(later);
    // Opened under claim 3: the frames are ahead of the claim, refused.
    let refused = at(3).acked(&ledger(1), host.identity.host_id(), run);
    assert!(
        matches!(
            refused,
            Err(StreamError::Storage(
                permguard_host::storage::StorageError::ClaimBehindData { .. }
            ))
        ),
        "{refused:?}"
    );
    assert_eq!(
        at(7)
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        2
    );
}

/// WP-5.3, after the mutants: a batch of another descriptor version, of a record the codec does
/// not read, signed under another of the member's rings with that ring's statement and pin, or
/// presented with a statement whose binding is not the pinned one, is `unverifiable`; below the
/// oldest retained sequence no chain is compared; a span conflict over a range with no batch file
/// yet is still a fork.
#[test]
fn the_ingest_refuses_what_its_task_does_not_pin() {
    let (host, wall, mono) = manual_host("ingest-mutants");
    let consumer = consumer_on(&host);
    let producer = host.sealer();
    let run = producer
        .open_run(&ledger(1), Some(fence(1)))
        .expect("opened")
        .run_id;
    let genesis = batch::GENESIS_HEAD.to_owned();
    let outcome = |body: &[u8], pins: Vec<permguard_host::membership::record::RingPin>| {
        ingest_at(&consumer, &host, body, 1, pins)
            .expect("answered")
            .0
            .outcome
    };
    let version = forge_with(
        host.attest.as_ref(),
        &host,
        run,
        1,
        genesis.clone(),
        vec![b"r0".to_vec()],
        1,
        |envelope| envelope.descriptor_version = 2,
    );
    assert_eq!(
        outcome(&ship_of(&host, &version), vec![pin_of(&host)]),
        Outcome::Unverifiable
    );
    let unreadable = forge_with(
        host.attest.as_ref(),
        &host,
        run,
        1,
        genesis.clone(),
        vec![vec![0xff, 0xfe]],
        1,
        |_| {},
    );
    assert_eq!(
        outcome(&ship_of(&host, &unreadable), vec![pin_of(&host)]),
        Outcome::Unverifiable
    );
    // Signed under `host.operations`, with that ring's own statement and pin.
    let operations = forge_with(
        host.operations.as_ref(),
        &host,
        run,
        1,
        genesis.clone(),
        vec![b"r0".to_vec()],
        1,
        |_| {},
    );
    let statement = host.operations.statement().expect("a statement");
    let operations_pin = permguard_host::membership::record::RingPin {
        owner: permguard_host::membership::record::Role::Member,
        ring: HOST_OPERATIONS.to_owned(),
        epoch: statement.epoch,
        key_set_digest: statement.key_set_digest,
        binding: statement.binding.expect("a binding"),
        retiring: false,
    };
    let body = Ship {
        batch: operations,
        statement: permguard_host::membership::statement_of(&host.operations)
            .expect("a statement")
            .encode()
            .expect("encodes"),
    }
    .encode()
    .expect("encodes");
    assert_eq!(outcome(&body, vec![operations_pin]), Outcome::Unverifiable);
    // A statement of the pinned keys under another binding.
    producer.append(&ledger(1), &"r0".to_owned()).expect("r0");
    producer.append(&ledger(1), &"r1".to_owned()).expect("r1");
    let (.., first) = sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    let mut rebound = permguard_host::membership::statement_of(&host.attest).expect("a statement");
    rebound.binding.push(0);
    let body = Ship {
        batch: first.clone(),
        statement: rebound.encode().expect("encodes"),
    }
    .encode()
    .expect("encodes");
    let mut pin = pin_of(&host);
    pin.binding = rebound.binding.clone();
    pin.binding.pop();
    assert_eq!(outcome(&body, vec![pin.clone()]), Outcome::Unverifiable);
    assert_eq!(outcome(&ship_of(&host, &first), vec![pin]), Outcome::Ok);
    // A span conflict over a range with no batch file yet: the new key over the old key's.
    for n in 2..4 {
        producer
            .append(&ledger(1), &format!("r{n}"))
            .expect("appended");
    }
    let (.., second) = sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    assert_eq!(
        outcome(&ship_of(&host, &second), vec![pin_of(&host)]),
        Outcome::Ok
    );
    let old_pin = pin_of(&host);
    rotate_attest(&host, &wall, &mono);
    let pins = vec![pin_of(&host), old_pin];
    // The new key from 5, then over 3 alone, which the old key's span covers.
    let late = forge(&host, run, 5, record_digest_of("r3"), &["r4"], 1);
    assert_eq!(outcome(&ship_of(&host, &late), pins.clone()), Outcome::Ok);
    let conflicting = forge(&host, run, 3, record_digest_of("r1"), &["r2"], 1);
    assert_eq!(outcome(&ship_of(&host, &conflicting), pins), Outcome::Fork);
    assert!(
        !consumer_run_dir(&host, &host, &run)
            .join("batches")
            .join("3-3.jws")
            .exists()
    );
    // Below the oldest retained sequence, no chain is compared: a replay there answers `gone`,
    // one starting at it, whatever head it names, is compared record by record.
    let fresh = Host::new("ingest-retained");
    let consumer = consumer_on(&fresh);
    let (_producer, run, batches) = shipped(&fresh, 4, 2);
    ingest(&consumer, &fresh, &ship_of(&fresh, &batches[0])).expect("ok");
    ingest(&consumer, &fresh, &ship_of(&fresh, &batches[1])).expect("ok");
    drop(consumer);
    permguard_host::storage::write::replace_view(
        &permguard_host::storage::Dir::open(&consumer_run_dir(&fresh, &fresh, &run))
            .expect("the run"),
        "STATE",
        format::VIEW,
        &ConsumerState {
            acked: 4,
            oldest_retained: 3,
            opened: None,
        }
        .encode()
        .expect("encodes"),
    )
    .expect("written");
    let consumer = consumer_on(&fresh);
    let unanchored = forge(&fresh, run, 3, record_digest_of("not-r1"), &["r2"], 1);
    assert_eq!(
        ingest(&consumer, &fresh, &ship_of(&fresh, &unanchored))
            .expect("answered")
            .0,
        Answer::of(Outcome::Ok, 4)
    );
}

// ---- WP-5.4: fan-out acknowledgements ----

use permguard_host::composition::{StreamShipping, Subscribed};

/// A selector covering no stream: the tests' runs are fenced where they open, and a subscription
/// rolls none over (WP-6.1).
static NO_STREAM: std::sync::LazyLock<permguard_core::authz::Selector> =
    std::sync::LazyLock::new(|| permguard_core::authz::Selector::exactly(Resource::host()));

fn subscribed(task_id: &str, required: bool, epoch: u64) -> Subscribed<'_> {
    Subscribed {
        membership_id: MEMBERSHIP,
        task_type: TaskType::DecisionsShip,
        task_id,
        required,
        epoch,
        selector: &NO_STREAM,
    }
}

/// Ships `subscription`'s due batches of `ledger(1)` into `consumer` as a coordinator would, its
/// pins `pins` at the lease's `epoch`: answers the outcomes, in order.
fn pump(
    producer: &Producer<Text>,
    consumer: &Consumer<Text>,
    member: &Host,
    subscription: &Subscribed<'_>,
    pins: Vec<permguard_host::membership::record::RingPin>,
    epoch: u64,
) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    let resource = ledger(1).to_string();
    let due = producer.due(subscription).expect("due");
    if !due.contains(&resource) {
        return outcomes;
    }
    while let Some(shipment) = producer
        .next(subscription, &resource, 448 * 1024)
        .expect("next")
    {
        let (answer, _) =
            ingest_at(consumer, member, &shipment.body, epoch, pins.clone()).expect("ingested");
        outcomes.push(answer.outcome);
        if !producer
            .answered(
                subscription,
                &resource,
                &shipment,
                &answer.encode().expect("encodes"),
            )
            .expect("answered")
        {
            break;
        }
    }
    outcomes
}

/// A member streaming `n` records on `ledger(1)` under the test fence, nothing sealed yet.
fn streaming(host: &Host, n: usize) -> (Producer<Text>, [u8; 16]) {
    let producer = host.sealer();
    let run = producer
        .open_run(&ledger(1), Some(fence(1)))
        .expect("opened")
        .run_id;
    for at in 0..n {
        producer
            .append(&ledger(1), &format!("r{at}"))
            .expect("appended");
    }
    (producer, run)
}

/// WP-5.4: each subscription keeps its own acknowledgement; `truncate_safe` is the least of the
/// required ones; the batch files at or below it are deleted, never one beyond; sealing goes on
/// after them.
#[test]
fn each_subscription_keeps_its_own_ack_and_truncate_safe_is_the_least_required() {
    let host = Host::new("fanout");
    let consumer = consumer_on(&host);
    let (producer, run) = streaming(&host, 4);
    let first = subscribed("decisions", true, 1);
    let second = subscribed("decisions-copy", true, 1);
    let optional = subscribed("decisions-tail", false, 1);
    producer.due(&second).expect("due");
    producer.due(&optional).expect("due");
    // The first ships everything; the second and the optional nothing yet.
    assert!(
        pump(&producer, &consumer, &host, &first, vec![pin_of(&host)], 1)
            .iter()
            .all(|outcome| *outcome == Outcome::Ok)
    );
    let ack = |task: &str| {
        producer
            .subscription(&ledger(1), &MEMBERSHIP, task)
            .expect("read")
            .expect("held")
            .acked(&run)
    };
    assert_eq!(
        (
            ack("decisions"),
            ack("decisions-copy"),
            ack("decisions-tail")
        ),
        (4, 0, 0)
    );
    assert_eq!(
        producer.truncate_safe(&ledger(1), &run).expect("safe"),
        Some(0)
    );
    let batches = host
        .producer_dir(&ledger(1))
        .join("batches")
        .join(hex(&run));
    gc(&producer);
    assert!(
        batches.join("1-4.jws").exists(),
        "nothing is deleted beyond truncate_safe"
    );
    // The second catches up: everything is acknowledged by every required one.
    assert!(!pump(&producer, &consumer, &host, &second, vec![pin_of(&host)], 1).is_empty());
    assert_eq!(
        producer.truncate_safe(&ledger(1), &run).expect("safe"),
        Some(4)
    );
    gc(&producer);
    assert!(
        !batches.join("1-4.jws").exists(),
        "acknowledged by every required one"
    );
    assert_eq!(
        producer
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .acknowledged_seq,
        4
    );
    // The optional one, behind, never blocked it, and now cannot be served what is deleted.
    assert_eq!(ack("decisions-tail"), 0);
    let resource = ledger(1).to_string();
    assert!(producer.next(&optional, &resource, 448 * 1024).is_err());
    // Sealing goes on after the deleted files.
    producer
        .append(&ledger(1), &"r4".to_owned())
        .expect("appended");
    assert_eq!(
        pump(&producer, &consumer, &host, &first, vec![pin_of(&host)], 1),
        vec![Outcome::Ok]
    );
    assert_eq!(ack("decisions"), 5);
}

/// WP-5.4: a required subscription that stays silent still blocks deletion; it is dropped only
/// when its task leaves the manifest.
#[test]
fn a_silent_required_subscription_still_blocks_until_its_task_leaves_the_manifest() {
    let host = Host::new("fanout-silent");
    let consumer = consumer_on(&host);
    let (producer, run) = streaming(&host, 2);
    let shipping = subscribed("decisions", true, 1);
    let silent = subscribed("decisions-copy", true, 1);
    producer.due(&silent).expect("due");
    pump(
        &producer,
        &consumer,
        &host,
        &shipping,
        vec![pin_of(&host)],
        1,
    );
    assert_eq!(
        producer.truncate_safe(&ledger(1), &run).expect("safe"),
        Some(0)
    );
    producer
        .retain(&MEMBERSHIP, &["decisions".to_owned()])
        .expect("retained");
    assert_eq!(
        producer
            .subscription(&ledger(1), &MEMBERSHIP, "decisions-copy")
            .expect("read"),
        None
    );
    assert_eq!(
        producer.truncate_safe(&ledger(1), &run).expect("safe"),
        Some(2)
    );
}

/// WP-5.4, F-08: a producer the coordinator refuses (`unverifiable`: no pin of its key) pauses;
/// once approved (its pin in a manifest at a later epoch) it resumes by itself on the next pass,
/// no restart; `fork` and `gone` stop it, an acknowledgement beyond what it holds stops it as
/// `ack_ahead`, a deferral backs it off.
#[test]
fn a_refused_producer_ships_once_approved_without_restart() {
    let (host, wall, mono) = manual_host("fanout-f08");
    let consumer = consumer_on(&host);
    let (producer, run) = streaming(&host, 3);
    let resource = ledger(1).to_string();
    let refused = subscribed("decisions", true, 1);
    // The other subscriptions exist from the start: a required one keeps every batch until it has
    // it.
    producer
        .due(&subscribed("decisions-copy", true, 2))
        .expect("due");
    producer
        .due(&subscribed("decisions-resend", true, 2))
        .expect("due");
    assert_eq!(
        pump(&producer, &consumer, &host, &refused, Vec::new(), 1),
        vec![Outcome::Unverifiable]
    );
    let held = producer
        .subscription(&ledger(1), &MEMBERSHIP, "decisions")
        .expect("read")
        .expect("held");
    assert_eq!(held.state, SubscriptionState::Paused { epoch: 1 });
    // The same epoch: still paused, nothing due.
    assert!(producer.due(&refused).expect("due").is_empty());
    // Approved: the manifest moves to epoch 2 with the member's pin; the next pass ships.
    let approved = subscribed("decisions", true, 2);
    assert_eq!(
        pump(
            &producer,
            &consumer,
            &host,
            &approved,
            vec![pin_of(&host)],
            2
        ),
        vec![Outcome::Ok]
    );
    assert_eq!(
        consumer
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        3
    );
    // A deferral backs the subscription off: not due until its wait passes.
    producer
        .append(&ledger(1), &"r3".to_owned())
        .expect("appended");
    producer.deferred(&approved, &resource).expect("deferred");
    producer.deferred(&approved, &resource).expect("deferred");
    let mut waited = 0;
    while producer.due(&approved).expect("due").is_empty() {
        wall.jump(1);
        mono.advance(Duration::from_secs(1));
        waited += 1;
        assert!(waited <= 2, "a second deferral waits at most two seconds");
    }
    // An acknowledgement beyond what the producer holds stops it as `ack_ahead`.
    let shipment = producer
        .next(&approved, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let ahead = Answer::of(Outcome::Ok, 99).encode().expect("encodes");
    assert!(
        !producer
            .answered(&approved, &resource, &shipment, &ahead)
            .expect("answered")
    );
    assert_eq!(
        producer
            .subscription(&ledger(1), &MEMBERSHIP, "decisions")
            .expect("read")
            .expect("held")
            .state,
        SubscriptionState::Stopped {
            reason: permguard_core::codes::stream::ACK_AHEAD.to_owned()
        }
    );
    // Stopped: never due again, whatever the epoch.
    assert!(
        producer
            .due(&subscribed("decisions", true, 9))
            .expect("due")
            .is_empty()
    );
    // A fork stops another subscription.
    let other = subscribed("decisions-copy", true, 2);
    producer.due(&other).expect("due");
    let shipment = producer
        .next(&other, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let fork = Answer::of(Outcome::Fork, 0).encode().expect("encodes");
    assert!(
        !producer
            .answered(&other, &resource, &shipment, &fork)
            .expect("answered")
    );
    assert_eq!(
        producer
            .subscription(&ledger(1), &MEMBERSHIP, "decisions-copy")
            .expect("read")
            .expect("held")
            .state,
        SubscriptionState::Stopped {
            reason: permguard_core::codes::stream::FORK.to_owned()
        }
    );
    // `out_of_order` resends from the consumer's next sequence.
    let resend = subscribed("decisions-resend", true, 2);
    producer.due(&resend).expect("due");
    let shipment = producer
        .next(&resend, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let behind = Answer {
        outcome: Outcome::OutOfOrder,
        acked: 0,
        expected_seq: Some(1),
    }
    .encode()
    .expect("encodes");
    assert!(
        producer
            .answered(&resend, &resource, &shipment, &behind)
            .expect("answered")
    );
    let again = producer
        .next(&resend, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    assert_eq!(again.first_seq, 1);
    assert_ne!(again.request_id, shipment.request_id, "a fresh request id");
}

/// WP-6.1 (owner decision of 2026-10-13): a subscription rolls a stream its task covers over to a
/// run carrying its fence, once per epoch; a stream it does not cover, a run another membership
/// fences and an older epoch are left alone.
#[test]
fn a_subscription_fences_the_streams_its_task_covers() {
    let host = Host::new("fence-on-ship");
    let producer = host.sealer();
    for n in [1, 2] {
        producer
            .append(&ledger(n), &"genesis".to_owned())
            .expect("appended");
    }
    let genesis = producer.open_run(&ledger(1), None).expect("a run");
    assert_eq!(
        genesis.fence, None,
        "a standalone Host opens its genesis run unfenced"
    );
    let covering = permguard_core::authz::Selector::exactly(ledger(1));
    let shipping = Subscribed {
        selector: &covering,
        ..subscribed("decisions", true, 1)
    };
    assert!(
        producer.due(&shipping).expect("due").is_empty(),
        "the fenced successor holds nothing yet"
    );
    let fenced = producer.open_run(&ledger(1), None).expect("a run");
    assert_eq!(fenced.fence, Some(fence(1)));
    assert_eq!(
        fenced.predecessor.map(|end| end.run_id),
        Some(genesis.run_id),
        "a successor of the genesis run"
    );
    assert_eq!(
        producer.open_run(&ledger(2), None).expect("a run").fence,
        None,
        "a stream the task does not cover"
    );
    producer
        .append(&ledger(1), &"shipped".to_owned())
        .expect("appended");
    assert_eq!(
        producer.due(&shipping).expect("due"),
        vec![ledger(1).to_string()]
    );
    assert_eq!(
        producer.open_run(&ledger(1), None).expect("a run").run_id,
        fenced.run_id,
        "once per epoch"
    );
    // Another membership, and an older epoch of this one, leave the run alone.
    // Another membership's task of the same name, at a later epoch, still leaves it alone.
    let foreign = Subscribed {
        membership_id: [6; 16],
        epoch: 9,
        ..shipping
    };
    producer.due(&foreign).expect("due");
    let older = Subscribed {
        epoch: 0,
        ..shipping
    };
    producer.due(&older).expect("due");
    assert_eq!(
        producer.open_run(&ledger(1), None).expect("a run").run_id,
        fenced.run_id
    );
    // A new epoch of the same task: a successor naming it.
    let renewed = Subscribed {
        epoch: 2,
        ..shipping
    };
    producer.due(&renewed).expect("due");
    let successor = producer.open_run(&ledger(1), None).expect("a run");
    assert_eq!(successor.fence, Some(fence(2)));
    assert_ne!(successor.run_id, fenced.run_id);
    // A forked stream the task covers is left to its operator, and the others still ship.
    producer.report_fork(&ledger(2), 1).expect("reported");
    let forked = producer.open_run(&ledger(2), None).expect("a run");
    let everything = permguard_core::authz::Selector::under(Resource::plane("data"));
    let wide = Subscribed {
        selector: &everything,
        epoch: 3,
        ..shipping
    };
    producer
        .due(&wide)
        .expect("a forked stream does not stop the others");
    assert_eq!(
        producer.open_run(&ledger(1), None).expect("a run").fence,
        Some(fence(3))
    );
    assert_eq!(
        producer.open_run(&ledger(2), None).expect("a run"),
        forked,
        "not rolled over"
    );
    // A stream a subscription seen shipping covers opens its genesis run under its fence, so its
    // first records ship too (after the review).
    producer
        .append(&ledger(5), &"first".to_owned())
        .expect("appended");
    assert_eq!(
        producer.open_run(&ledger(5), None).expect("a run").fence,
        Some(fence(3))
    );
    assert!(
        producer
            .due(&wide)
            .expect("due")
            .contains(&ledger(5).to_string()),
        "the genesis run's record is due at once"
    );
    // A producer handed no ring seals nothing, so its pressure is unknown, never `None`.
    let unsealed = host.producer();
    unsealed
        .append(&ledger(3), &"r".to_owned())
        .expect("appended");
    assert!(
        permguard_host::composition::StreamAppender::pressure(&unsealed, &ledger(3), 1 << 30, 3600)
            .is_err()
    );
}

/// WP-6.1b: what a Plane reads of the consumer: its runs over a resource in the order they
/// opened, their records, the batch file covering a sequence, and where a run is held.
#[test]
fn the_consumer_answers_its_runs_records_and_batches() {
    use permguard_host::composition::StreamConsumerReads as _;

    let host = Host::new("consumer-reads");
    let consumer = consumer_on(&host);
    let (producer, first_run) = streaming(&host, 3);
    let shipping = subscribed("decisions", true, 1);
    assert!(
        pump(
            &producer,
            &consumer,
            &host,
            &shipping,
            vec![pin_of(&host)],
            1
        )
        .iter()
        .all(|outcome| *outcome == Outcome::Ok)
    );
    // A second run of the same producer, shipped after the first.
    let second_run = producer
        .rollover(&ledger(1), Some(fence(1)))
        .expect("rolled over")
        .run_id;
    for at in 0..2 {
        producer
            .append(&ledger(1), &format!("s{at}"))
            .expect("appended");
    }
    assert!(
        pump(
            &producer,
            &consumer,
            &host,
            &shipping,
            vec![pin_of(&host)],
            1
        )
        .iter()
        .all(|outcome| *outcome == Outcome::Ok)
    );
    let runs = consumer.runs(&ledger(1)).expect("runs");
    assert_eq!(
        runs.iter()
            .map(|run| (run.run, run.acked))
            .collect::<Vec<_>>(),
        vec![(first_run, 3), (second_run, 2)],
        "in the order they opened"
    );
    assert!(
        runs.iter()
            .all(|run| run.producer == host.identity.host_id())
    );
    assert!(consumer.runs(&ledger(2)).expect("runs").is_empty());
    let page = consumer
        .records(&ledger(1), &host.identity.host_id(), &first_run, 2, 10)
        .expect("records");
    assert_eq!(page.records, vec![(2, b"r1".to_vec()), (3, b"r2".to_vec())]);
    assert_eq!(page.low_watermark, None);
    let batch = consumer
        .batch(&ledger(1), &host.identity.host_id(), &second_run, 2)
        .expect("read")
        .expect("a batch covers it");
    let sealed = batch::SealedBatch::decode(&batch).expect("a batch file");
    let envelope = sealed.envelope_unverified().expect("an envelope");
    assert!((envelope.first_seq..=envelope.last_seq).contains(&2));
    assert_eq!(
        consumer
            .batch(&ledger(1), &host.identity.host_id(), &second_run, 9)
            .expect("read"),
        None
    );
    assert_eq!(
        consumer
            .locate(&host.identity.host_id(), &second_run)
            .expect("located"),
        Some(ledger(1))
    );
    assert_eq!(
        consumer
            .locate(&host.identity.host_id(), &[9; 16])
            .expect("read"),
        None
    );
    assert_eq!(
        consumer.locate(&[7; 16], &second_run).expect("read"),
        None,
        "the run of another producer"
    );
}

/// WP-5.4, F-11: pressure counts only what no required subscription acknowledged: a stream
/// whose subscriptions acknowledged everything is neither full nor expired after 48 hours; one
/// behind is full past its byte bound and expired past its age bound.
#[test]
fn pressure_counts_only_the_unacknowledged() {
    let (host, wall, mono) = manual_host("fanout-f11");
    let consumer = consumer_on(&host);
    let (producer, _run) = streaming(&host, 3);
    let bounds = PressureBounds {
        max_bytes: 6,
        max_age_secs: 3600,
    };
    // No subscription yet: nothing is owed.
    assert_eq!(
        producer.pressure(&ledger(1), bounds).expect("pressure"),
        None
    );
    let shipping = subscribed("decisions", true, 1);
    producer.due(&shipping).expect("due");
    assert_eq!(
        producer.pressure(&ledger(1), bounds).expect("pressure"),
        Some(permguard_core::codes::stream::SPOOL_FULL)
    );
    let loose = PressureBounds {
        max_bytes: 1 << 20,
        max_age_secs: 3600,
    };
    sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    assert_eq!(
        producer.pressure(&ledger(1), loose).expect("pressure"),
        None
    );
    wall.jump(3601);
    mono.advance(Duration::from_secs(3601));
    assert_eq!(
        producer.pressure(&ledger(1), loose).expect("pressure"),
        Some(permguard_core::codes::stream::AGE_EXPIRY)
    );
    // Shipped and acknowledged: then idle for 48 hours.
    let pins = vec![pin_of(&host)];
    assert_eq!(
        pump(&producer, &consumer, &host, &shipping, pins, 1),
        vec![Outcome::Ok]
    );
    wall.jump(48 * 3600);
    mono.advance(Duration::from_secs(48 * 3600));
    assert_eq!(
        producer.pressure(&ledger(1), bounds).expect("pressure"),
        None
    );
    assert_eq!(
        producer.pressure(&ledger(1), loose).expect("pressure"),
        None
    );
}

/// WP-5.4, after the review: a crash between the pruned mark and the deletion of the files below
/// it leaves files every reader skips, sealing and shipping go on, and the next truncation
/// deletes them.
#[test]
fn files_a_crash_left_below_the_pruned_mark_are_skipped_then_deleted() {
    let host = Host::new("fanout-crash");
    let consumer = consumer_on(&host);
    let (producer, run) = streaming(&host, 2);
    let shipping = subscribed("decisions", true, 1);
    producer.due(&shipping).expect("due");
    let batches = host
        .producer_dir(&ledger(1))
        .join("batches")
        .join(hex(&run));
    // Seal and keep a copy of the batch the truncation will delete.
    sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let copy = std::fs::read(batches.join("1-2.jws")).expect("the batch");
    assert_eq!(
        pump(
            &producer,
            &consumer,
            &host,
            &shipping,
            vec![pin_of(&host)],
            1
        ),
        vec![Outcome::Ok]
    );
    assert!(
        batches.join("1-2.jws").exists(),
        "shipping deletes nothing (WP-5.6b)"
    );
    gc(&producer);
    assert!(!batches.join("1-2.jws").exists());
    // The crash: the mark written, the file not yet deleted.
    std::fs::write(batches.join("1-2.jws"), &copy).expect("restored");
    drop(producer);
    let producer = host.sealer();
    producer
        .append(&ledger(1), &"r2".to_owned())
        .expect("appended");
    assert_eq!(
        pump(
            &producer,
            &consumer,
            &host,
            &shipping,
            vec![pin_of(&host)],
            1
        ),
        vec![Outcome::Ok]
    );
    gc(&producer);
    assert!(
        !batches.join("1-2.jws").exists(),
        "the next pass deleted it"
    );
    // A file straddling the mark is refused.
    drop(producer);
    std::fs::write(batches.join("3-4.jws"), &copy).expect("written");
    assert!(matches!(
        host.sealer().seal(&ledger(1), 10),
        Err(StreamError::Corruption(_))
    ));
}

/// WP-5.4, after the review: a run is blocked only by the required subscriptions of the membership
/// fencing it, the only ones it is ever shipped to.
#[test]
fn only_the_fencing_memberships_subscriptions_block_a_run() {
    let host = Host::new("fanout-fence");
    let consumer = consumer_on(&host);
    let (producer, first_run) = streaming(&host, 2);
    let first = subscribed("decisions", true, 1);
    producer.due(&first).expect("due");
    pump(&producer, &consumer, &host, &first, vec![pin_of(&host)], 1);
    // The stream moves to another membership, whose required subscription never sees the first
    // run.
    let other_membership = [6; 16];
    producer
        .rollover(
            &ledger(1),
            Some(Fence {
                membership_id: other_membership,
                ..fence(1)
            }),
        )
        .expect("rolled over");
    producer
        .append(&ledger(1), &"s0".to_owned())
        .expect("appended");
    let other = Subscribed {
        membership_id: other_membership,
        ..subscribed("decisions", true, 1)
    };
    producer.due(&other).expect("due");
    assert_eq!(
        producer
            .truncate_safe(&ledger(1), &first_run)
            .expect("safe"),
        Some(2)
    );
}

/// WP-5.4, after the review: an acknowledgement below the one recorded stops the subscription as
/// `ack_behind` and moves nothing back; one beyond what was sealed is `ack_ahead`; one short of
/// the batch sent ships no further this pass.
#[test]
fn an_acknowledgement_never_moves_back_nor_past_what_was_sealed() {
    let host = Host::new("fanout-backwards");
    let consumer = consumer_on(&host);
    let (producer, run) = streaming(&host, 4);
    let resource = ledger(1).to_string();
    let shipping = subscribed("decisions", true, 1);
    producer.due(&shipping).expect("due");
    pump(
        &producer,
        &consumer,
        &host,
        &shipping,
        vec![pin_of(&host)],
        1,
    );
    assert_eq!(
        producer
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .acknowledged_seq,
        4
    );
    producer
        .append(&ledger(1), &"r4".to_owned())
        .expect("appended");
    let shipment = producer
        .next(&shipping, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let behind = Answer {
        outcome: Outcome::OutOfOrder,
        acked: 1,
        expected_seq: Some(2),
    }
    .encode()
    .expect("encodes");
    assert!(
        !producer
            .answered(&shipping, &resource, &shipment, &behind)
            .expect("answered")
    );
    let held = producer
        .subscription(&ledger(1), &MEMBERSHIP, "decisions")
        .expect("read")
        .expect("held");
    assert_eq!(
        held.state,
        SubscriptionState::Stopped {
            reason: permguard_core::codes::stream::ACK_BEHIND.to_owned()
        }
    );
    assert_eq!(held.acked(&run), 4);
    assert_eq!(
        producer
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .acknowledged_seq,
        4
    );
    // Beyond what was sealed, though within the records: `ack_ahead`.
    let ahead = subscribed("decisions-ahead", true, 1);
    let fresh = Host::new("fanout-ahead");
    let (producer, _run) = streaming(&fresh, 4);
    producer.due(&ahead).expect("due");
    sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    let shipment = producer
        .next(&ahead, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let past = Answer::of(Outcome::Ok, 3).encode().expect("encodes");
    assert!(
        !producer
            .answered(&ahead, &resource, &shipment, &past)
            .expect("answered")
    );
    assert_eq!(
        producer
            .subscription(&ledger(1), &MEMBERSHIP, "decisions-ahead")
            .expect("read")
            .expect("held")
            .state,
        SubscriptionState::Stopped {
            reason: permguard_core::codes::stream::ACK_AHEAD.to_owned()
        }
    );
    // Short of the batch sent: no further this pass, the ack kept.
    let short = subscribed("decisions-short", true, 1);
    producer.due(&short).expect("due");
    let shipment = producer
        .next(&short, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    assert_eq!((shipment.first_seq, shipment.last_seq), (1, 2));
    let partial = Answer::of(Outcome::Ok, 1).encode().expect("encodes");
    assert!(
        !producer
            .answered(&short, &resource, &shipment, &partial)
            .expect("answered")
    );
}

/// WP-5.4, after the review: an immutable batch sealed for a wider bound than a subscription's
/// task allows stops that subscription as `unshippable` instead of failing every pass.
#[test]
fn a_batch_over_a_subscriptions_bound_stops_it_as_unshippable() {
    let host = Host::new("fanout-oversized");
    let producer = host.sealer();
    producer
        .open_run(&ledger(1), Some(fence(1)))
        .expect("opened");
    for n in 0..3 {
        producer
            .append(&ledger(1), &format!("{n}").repeat(3000))
            .expect("appended");
    }
    let narrow = subscribed("decisions", true, 1);
    producer.due(&narrow).expect("due");
    sealed(producer.seal(&ledger(1), 10).expect("sealed"));
    let resource = ledger(1).to_string();
    assert_eq!(
        producer.next(&narrow, &resource, 8 * 1024).expect("next"),
        None
    );
    assert_eq!(
        producer
            .subscription(&ledger(1), &MEMBERSHIP, "decisions")
            .expect("read")
            .expect("held")
            .state,
        SubscriptionState::Stopped {
            reason: permguard_core::codes::stream::UNSHIPPABLE.to_owned()
        }
    );
}

/// WP-5.4, after the mutants: deletion stops at `truncate_safe` exactly; STATE's acknowledgement
/// never moves back when a required subscription joins; a subscription held off is not due; a
/// stream waiting for a cutover, or fenced by another membership, is not due.
#[test]
fn the_bounds_of_what_is_due_and_deleted_are_exact() {
    let (host, wall, mono) = manual_host("fanout-exact");
    let consumer = consumer_on(&host);
    let (producer, run) = streaming(&host, 3);
    let resource = ledger(1).to_string();
    let first = subscribed("decisions", true, 1);
    let second = subscribed("decisions-copy", true, 1);
    producer.due(&first).expect("due");
    producer.due(&second).expect("due");
    sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    sealed(producer.seal(&ledger(1), 2).expect("sealed"));
    pump(&producer, &consumer, &host, &first, vec![pin_of(&host)], 1);
    // The second takes only the first batch: `truncate_safe` is 2, and 3-3 stays.
    let shipment = producer
        .next(&second, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    assert_eq!(shipment.last_seq, 2);
    let ok = Answer::of(Outcome::Ok, 2).encode().expect("encodes");
    producer
        .answered(&second, &resource, &shipment, &ok)
        .expect("answered");
    let batches = host
        .producer_dir(&ledger(1))
        .join("batches")
        .join(hex(&run));
    gc(&producer);
    assert!(!batches.join("1-2.jws").exists());
    assert!(
        batches.join("3-3.jws").exists(),
        "one past truncate_safe stays"
    );
    assert_eq!(
        producer
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .acknowledged_seq,
        2
    );
    // A required subscription joins: nothing moves back.
    producer
        .due(&subscribed("decisions-late", true, 1))
        .expect("due");
    producer
        .append(&ledger(1), &"r3".to_owned())
        .expect("appended");
    pump(&producer, &consumer, &host, &first, vec![pin_of(&host)], 1);
    assert_eq!(
        producer
            .state(&ledger(1))
            .expect("state")
            .expect("held")
            .acknowledged_seq,
        2
    );
    // Held off: not due until the wait passes.
    let now = host.time.now_secs();
    producer.hold_off(&resource, &second, now + 10);
    assert!(producer.due(&second).expect("due").is_empty());
    wall.jump(11);
    mono.advance(Duration::from_secs(11));
    assert_eq!(producer.due(&second).expect("due"), vec![resource.clone()]);
    // Another membership's subscription: the stream is not fenced by it.
    let foreign = Subscribed {
        membership_id: [6; 16],
        ..subscribed("decisions", true, 1)
    };
    assert!(producer.due(&foreign).expect("due").is_empty());
    // A new key waiting for its cutover: nothing is due.
    rotate_attest(&host, &wall, &mono);
    producer
        .append(&ledger(1), &"r4".to_owned())
        .expect("appended");
    assert!(matches!(
        producer.seal(&ledger(1), 10).expect("waits"),
        Sealing::AwaitingCutover { .. }
    ));
    assert!(producer.due(&first).expect("due").is_empty());
}

/// WP-5.8: STATE's `unshipped` mark round-trips under label 10, and a mark whose tail is
/// acknowledged is refused.
#[test]
fn a_state_carries_its_unshipped_mark_and_refuses_a_shipped_one() {
    let state = |unshipped| state::State {
        run_id: [1; 16],
        run_statement_digest: [2; 32],
        next_seq: 9,
        durable_seq: 8,
        signed_seq: 8,
        acknowledged_seq: 3,
        oldest_retained_seq: 1,
        pending_successor: None,
        forked_at_seq: None,
        unshipped,
        base: None,
    };
    let marked = state(Some(state::Unshipped {
        tail: 8,
        truncate_safe: 3,
        run: [1; 16],
    }));
    let bytes = marked.encode().expect("encodes");
    assert_eq!(state::State::decode(&bytes).expect("decodes"), marked);
    let unmarked = state(None).encode().expect("encodes");
    assert_eq!(
        state::State::decode(&unmarked).expect("decodes").unshipped,
        None,
        "a STATE written before the mark existed reads without one"
    );
    let shipped = state(Some(state::Unshipped {
        tail: 3,
        truncate_safe: 3,
        run: [1; 16],
    }))
    .encode()
    .expect("encodes");
    assert!(matches!(
        state::State::decode(&shipped),
        Err(StreamError::Invalid(_))
    ));
}

/// WP-5.8: a stream behind its required subscription is marked `unshipped` as an incomplete
/// drain leaves it; the mark survives a reopen and a rollover, stays while the drain's tail is
/// not acknowledged, reports what is, and goes once the tail is shipped. An optional
/// subscription marks nothing.
#[test]
fn an_incomplete_drain_marks_the_streams_behind_and_shipping_settles_them() {
    let host = Host::new("unshipped");
    let consumer = consumer_on(&host);
    let (producer, run) = streaming(&host, 3);
    let resource = ledger(1).to_string();
    let optional = subscribed("decisions-optional", false, 1);
    producer.due(&optional).expect("due");
    assert!(
        producer.behind().expect("behind").is_empty(),
        "an optional subscription owes nothing"
    );
    let shipping = subscribed("decisions", true, 1);
    producer.due(&shipping).expect("due");
    let behind = producer.behind().expect("behind");
    let expected = permguard_host::composition::Unshipped {
        stream: "data/decisions".to_owned(),
        resource: resource.clone(),
        tail: 3,
        truncate_safe: 0,
    };
    assert_eq!(behind, vec![expected.clone()]);
    assert!(
        producer.settle_unshipped().expect("settled").is_empty(),
        "behind but not marked: no drain left it"
    );
    assert_eq!(
        producer.mark_unshipped().expect("marked"),
        vec![expected.clone()]
    );

    // Reopened: the mark is STATE's, and records appended since do not move its tail.
    drop(producer);
    let producer = host.sealer();
    producer
        .append(&ledger(1), &"r3".to_owned())
        .expect("appended");
    assert_eq!(
        producer.unshipped_on(&shipping, &resource).expect("read"),
        Some(expected.clone())
    );
    assert_eq!(
        producer.unshipped_on(&optional, &resource).expect("read"),
        Some(expected.clone()),
        "the mark is the stream's, whichever task asks"
    );

    // Acknowledged short of the tail: the mark stays and reports what is acknowledged.
    producer.due(&shipping).expect("due");
    let shipment = producer
        .next(&shipping, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let short = Answer {
        outcome: Outcome::Ok,
        acked: 2,
        expected_seq: None,
    }
    .encode()
    .expect("encodes");
    producer
        .answered(&shipping, &resource, &shipment, &short)
        .expect("answered");
    assert_eq!(
        producer.settle_unshipped().expect("settled"),
        vec![permguard_host::composition::Unshipped {
            truncate_safe: 2,
            ..expected.clone()
        }]
    );

    // A rollover keeps it: the old run is still behind.
    producer
        .rollover(&ledger(1), Some(fence(1)))
        .expect("rolled over");
    assert_eq!(producer.settle_unshipped().expect("settled").len(), 1);
    assert_eq!(
        producer.truncate_safe(&ledger(1), &run).expect("safe"),
        Some(2)
    );

    // Shipped through the tail: the mark goes, and STATE no longer holds it.
    let outcomes = pump(
        &producer,
        &consumer,
        &host,
        &shipping,
        vec![pin_of(&host)],
        1,
    );
    assert!(
        outcomes.iter().all(|outcome| *outcome == Outcome::Ok),
        "{outcomes:?}"
    );
    assert!(producer.settle_unshipped().expect("settled").is_empty());
    assert!(
        producer.behind().expect("behind").is_empty(),
        "a stream acknowledged through its end is behind nothing"
    );
    assert_eq!(
        producer_state(&host).unshipped,
        None,
        "the settle removed the mark from STATE itself"
    );
    drop(producer);
    let producer = host.sealer();
    assert_eq!(
        producer.unshipped_on(&shipping, &resource).expect("read"),
        None
    );
}

/// The producer STATE of `ledger(1)`, as the volume holds it.
fn producer_state(host: &Host) -> state::State {
    state::State::decode(
        &permguard_host::storage::write::read_view(
            &permguard_host::storage::Dir::open(&host.producer_dir(&ledger(1)))
                .expect("the stream"),
            "STATE",
            format::VIEW,
        )
        .expect("read")
        .expect("a STATE"),
    )
    .expect("decodes")
}

/// WP-5.8, after the review: the marked run owes only the drain's tail, never the records
/// appended to it since.
#[test]
fn a_mark_goes_once_its_tail_is_acknowledged_whatever_was_appended_since() {
    let host = Host::new("unshipped-tail");
    let (producer, _run) = streaming(&host, 3);
    let resource = ledger(1).to_string();
    let shipping = subscribed("decisions", true, 1);
    producer.due(&shipping).expect("due");
    producer.mark_unshipped().expect("marked");
    producer
        .append(&ledger(1), &"r3".to_owned())
        .expect("appended");
    producer.due(&shipping).expect("due");
    let shipment = producer
        .next(&shipping, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let through_tail = Answer {
        outcome: Outcome::Ok,
        acked: 3,
        expected_seq: None,
    }
    .encode()
    .expect("encodes");
    producer
        .answered(&shipping, &resource, &shipment, &through_tail)
        .expect("answered");
    assert_eq!(
        producer.behind().expect("behind").len(),
        1,
        "record 4 is owed"
    );
    assert!(
        producer.settle_unshipped().expect("settled").is_empty(),
        "the drain's tail is shipped"
    );
}

/// WP-5.8, after the review: a mark holds every run before its own to that run's end, whatever
/// membership fences it: the newest run shipped does not clear it while an older one, fenced to
/// another membership, is behind; runs opened after the drain owe it nothing.
#[test]
fn a_mark_waits_for_every_older_run_whichever_membership_fences_it() {
    let host = Host::new("unshipped-runs");
    let consumer = consumer_on(&host);
    let (producer, first_run) = streaming(&host, 3);
    let resource = ledger(1).to_string();
    let first = subscribed("decisions", true, 1);
    producer.due(&first).expect("due");
    // The stream moves to another membership before the first is shipped.
    let other_membership = [6; 16];
    producer
        .rollover(
            &ledger(1),
            Some(Fence {
                membership_id: other_membership,
                ..fence(1)
            }),
        )
        .expect("rolled over");
    producer
        .append(&ledger(1), &"s0".to_owned())
        .expect("appended");
    let other = Subscribed {
        membership_id: other_membership,
        ..subscribed("decisions", true, 1)
    };
    producer.due(&other).expect("due");
    let marked = producer.mark_unshipped().expect("marked");
    assert_eq!(marked.len(), 1);
    assert_eq!(marked[0].tail, 1, "the newest run behind: one record");

    // The newest run is shipped to its membership: the older run still owes the first.
    let shipment = producer
        .next(&other, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let all = Answer {
        outcome: Outcome::Ok,
        acked: shipment.last_seq,
        expected_seq: None,
    }
    .encode()
    .expect("encodes");
    producer
        .answered(&other, &resource, &shipment, &all)
        .expect("answered");
    assert_eq!(
        producer.settle_unshipped().expect("settled").len(),
        1,
        "the first membership's run is still behind"
    );

    // The older run acknowledged past the mark's tail but short of its own end still holds it.
    let shipment = producer
        .next(&first, &resource, 448 * 1024)
        .expect("next")
        .expect("a batch");
    let partly = Answer {
        outcome: Outcome::Ok,
        acked: 2,
        expected_seq: None,
    }
    .encode()
    .expect("encodes");
    producer
        .answered(&first, &resource, &shipment, &partly)
        .expect("answered");
    assert_eq!(
        producer.settle_unshipped().expect("settled").len(),
        1,
        "two of the first run's three records are acknowledged"
    );

    // A run opened after the drain, behind its own membership, owes the drain nothing.
    let third_membership = [7; 16];
    producer
        .rollover(
            &ledger(1),
            Some(Fence {
                membership_id: third_membership,
                ..fence(1)
            }),
        )
        .expect("rolled over");
    producer
        .append(&ledger(1), &"t0".to_owned())
        .expect("appended");
    producer
        .due(&Subscribed {
            membership_id: third_membership,
            ..subscribed("decisions", true, 1)
        })
        .expect("due");

    // The first run shipped too: the mark goes, the later run still behind notwithstanding.
    let outcomes = pump(&producer, &consumer, &host, &first, vec![pin_of(&host)], 1);
    assert!(
        outcomes.iter().all(|outcome| *outcome == Outcome::Ok),
        "{outcomes:?}"
    );
    assert_eq!(
        producer
            .truncate_safe(&ledger(1), &first_run)
            .expect("safe"),
        Some(3)
    );
    assert!(producer.settle_unshipped().expect("settled").is_empty());
}

/// One garbage collection pass over `prunable`, every record accepted (WP-5.6b).
fn gc(prunable: &dyn super::retention::Prunable) -> Vec<super::retention::Pruned> {
    prunable
        .run(u64::MAX / 4, &|_| Ok(()))
        .expect("a pass")
        .expect("no pass running")
}

/// A producer on 256-byte journal segments, sealing under `data.attest`: a prefix deletion has
/// segments to remove (WP-5.6b).
fn small_sealer(host: &Host, descriptor: Descriptor) -> Producer<Text> {
    host.streams()
        .with_segment_bytes(256)
        .register_producer(descriptor, Text)
        .expect("registered")
        .with_signer(Arc::clone(&host.attest))
        .expect("the descriptor's ring")
}

/// `n` records on `ledger(1)` under the test fence, sealed two a batch and shipped to `consumer`
/// by the one required subscription: the producer's run.
fn acknowledged(
    producer: &Producer<Text>,
    consumer: &Consumer<Text>,
    host: &Host,
    n: usize,
) -> [u8; 16] {
    let run = producer
        .open_run(&ledger(1), Some(fence(1)))
        .expect("opened")
        .run_id;
    for at in 0..n {
        producer
            .append(&ledger(1), &format!("r{at}"))
            .expect("appended");
    }
    while let Sealing::Sealed { .. } = producer.seal(&ledger(1), 2).expect("sealed") {}
    let shipping = subscribed("decisions", true, 1);
    producer.due(&shipping).expect("due");
    assert!(
        pump(producer, consumer, host, &shipping, vec![pin_of(host)], 1)
            .iter()
            .all(|outcome| *outcome == Outcome::Ok)
    );
    run
}

/// WP-5.6b: a pass writes the run's anchor, then the audit record, then deletes the batch files
/// every required subscription acknowledged and the journal segments that held only them; the
/// producer reopens from STATE's base and goes on at the next sequence.
#[test]
fn a_pass_anchors_audits_then_deletes_what_was_acknowledged() {
    let host = Host::new("prune-producer");
    let consumer = consumer_on(&host);
    let producer = small_sealer(&host, descriptor());
    let run = acknowledged(&producer, &consumer, &host, 12);
    let dir = host.producer_dir(&ledger(1));
    let batches = dir.join("batches").join(hex(&run));
    let last = std::fs::read(batches.join("11-12.jws")).expect("the last batch");
    let segments_before = std::fs::read_dir(dir.join("records"))
        .expect("records")
        .count();
    assert!(segments_before > 2, "{segments_before} segments");

    let audited = std::sync::Mutex::new(Vec::new());
    let pruned = super::retention::Prunable::run(&producer, 0, &|record| {
        // The anchor first, every batch file still there.
        assert!(batches.join(super::anchor::ANCHOR).exists());
        assert!(batches.join("1-2.jws").exists());
        audited.lock().expect("held").push(record.clone());
        Ok(())
    })
    .expect("a pass")
    .expect("no pass running");
    assert_eq!(pruned, audited.into_inner().expect("held"));
    assert_eq!(pruned.len(), 1);
    assert_eq!(
        (pruned[0].run, pruned[0].through, pruned[0].batches),
        (Some(run), 12, 6)
    );
    assert_eq!(pruned[0].role, "producer");
    for at in (1..=11).step_by(2) {
        assert!(!batches.join(format!("{at}-{}.jws", at + 1)).exists());
    }
    let anchor = super::anchor::Anchor::decode(
        &permguard_host::storage::write::read_view(
            &permguard_host::storage::Dir::open(&batches).expect("dir"),
            super::anchor::ANCHOR,
            permguard_host::storage::format::VIEW,
        )
        .expect("read")
        .expect("held"),
    )
    .expect("decoded");
    let envelope = batch::SealedBatch::decode(&last)
        .expect("decoded")
        .envelope_unverified()
        .expect("an envelope");
    assert_eq!(
        (anchor.through, anchor.low_watermark, anchor.covering.len()),
        (12, 13, 6)
    );
    assert_eq!(anchor.resource, ledger(1).to_string());
    assert_eq!(anchor.run, run);
    assert_eq!(anchor.checkpoint, last);
    assert_eq!(anchor.terminal_head, envelope.head);
    assert_eq!(
        anchor.covering.last(),
        Some(&format!(
            "sha256:{}",
            hex(&<sha2::Sha256 as sha2::Digest>::digest(
                envelope.signed_bytes().expect("signed bytes")
            ))
        ))
    );
    assert_eq!(anchor.signers.first().map(|span| span.from_seq), Some(1));
    // The journal lost its prefix, and STATE names what it gave the open.
    let state = producer.state(&ledger(1)).expect("state").expect("held");
    let base = state.base.expect("a base");
    assert!(base.first_index > 0);
    let segments_after = std::fs::read_dir(dir.join("records"))
        .expect("records")
        .count();
    assert!(segments_after < segments_before, "{segments_after}");

    // Reopened from the base: the run goes on, sealed and shipped.
    drop(producer);
    let producer = small_sealer(&host, descriptor());
    let receipt = producer
        .append(&ledger(1), &"r12".to_owned())
        .expect("appended");
    assert_eq!((receipt.run_id, receipt.seq), (run, 13));
    assert!(matches!(
        producer.seal(&ledger(1), 2).expect("sealed"),
        Sealing::Sealed { .. }
    ));
    assert_eq!(
        pump(
            &producer,
            &consumer,
            &host,
            &subscribed("decisions", true, 1),
            vec![pin_of(&host)],
            1
        ),
        vec![Outcome::Ok]
    );
    // A read from the start answers from the low watermark, with the gap and the anchor.
    let page = producer.read(&ledger(1), 1, 100).expect("read");
    assert_eq!(
        page.records.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![13]
    );
    let gap = page.gap.expect("a gap");
    assert_eq!((gap.low_watermark, gap.anchor.through), (13, 12));
    assert!(base.last_seq <= 12);
    assert_eq!(producer.read(&ledger(1), 13, 100).expect("read").gap, None);
    let limited = producer.read(&ledger(1), 1, 1).expect("read");
    assert_eq!((limited.records.len(), limited.gap.is_some()), (1, true));

    // Nothing left to delete: audited all the same.
    let again = gc(&producer);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].run, Some(run), "13 was acknowledged");
    let nothing = gc(&producer);
    assert_eq!(
        nothing,
        vec![super::retention::Pruned::nothing(
            nothing[0].stream.clone(),
            "producer"
        )]
    );
}

/// WP-5.6b: a record that cannot be written deletes nothing, and a later pass deletes; a pass
/// never overlaps another of the same handle; a plan changes nothing.
#[test]
fn an_unaudited_pass_deletes_nothing_and_passes_never_overlap() {
    let host = Host::new("prune-refused");
    let consumer = consumer_on(&host);
    let producer = small_sealer(&host, descriptor());
    let run = acknowledged(&producer, &consumer, &host, 4);
    let batches = host
        .producer_dir(&ledger(1))
        .join("batches")
        .join(hex(&run));
    let records = host.producer_dir(&ledger(1)).join("records");
    let before = std::fs::read_dir(&records).expect("records").count();

    let planned = super::retention::Prunable::plan(&producer, 0).expect("planned");
    assert_eq!((planned[0].through, planned[0].batches), (4, 2));
    assert!(batches.join("1-2.jws").exists(), "a plan deletes nothing");

    let refused = super::retention::Prunable::run(&producer, 0, &|_| Err("full".to_owned()));
    assert_eq!(refused.expect("the pass goes on"), Some(Vec::new()));
    assert!(batches.join("1-2.jws").exists() && batches.join("3-4.jws").exists());
    assert_eq!(
        std::fs::read_dir(&records).expect("records").count(),
        before
    );
    assert!(!batches.join("PRUNED").exists(), "no mark moved");

    {
        let _held = producer.lease.take().expect("free");
        assert_eq!(
            super::retention::Prunable::run(&producer, 0, &|_| Ok(())).expect("a pass"),
            None
        );
    }
    assert_eq!(gc(&producer)[0].through, 4);
    assert!(!batches.join("1-2.jws").exists());
}

/// WP-5.6b: a `history` stream is kept above the floor its Plane registered, and without one is
/// bounded by `truncate_safe` alone.
#[test]
fn a_history_stream_is_kept_above_its_floor() {
    struct Floor(u64);
    impl super::retention::RetentionFloor for Floor {
        fn retention_safe(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(self.0)
        }
    }
    let history = Descriptor {
        retention: Retention::History,
        ..descriptor()
    };
    let host = Host::new("prune-history");
    let consumer = host
        .streams()
        .register_consumer(history.clone(), Text)
        .expect("registered");
    let producer = small_sealer(&host, history.clone()).with_retention_floor(Arc::new(Floor(5)));
    acknowledged(&producer, &consumer, &host, 8);
    assert_eq!(
        gc(&producer)[0].through,
        4,
        "the last whole batch at or below 5"
    );

    let host = Host::new("prune-history-unbounded");
    let consumer = host
        .streams()
        .register_consumer(history.clone(), Text)
        .expect("registered");
    let producer = small_sealer(&host, history);
    acknowledged(&producer, &consumer, &host, 8);
    assert_eq!(gc(&producer)[0].through, 8);
}

/// WP-5.6b: a consumer deletes the batches admitted at least its task's retention ago, after
/// its anchor and the record; below them a batch is `gone`; reopened, it holds what it kept.
#[test]
fn a_consumer_deletes_what_its_retention_passed() {
    struct Source(Option<u64>);
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            self.0
        }
    }
    let (host, wall, mono) = manual_host("prune-consumer");
    let small = |source: Option<u64>| {
        host.streams()
            .with_segment_bytes(256)
            .register_consumer(descriptor(), Text)
            .expect("registered")
            .with_retention_source(Arc::new(Source(source)))
    };
    let (producer, run, batches) = shipped(&host, 8, 2);
    drop(producer);
    let consumer = small(Some(60));
    for body in &batches[..2] {
        ingest(&consumer, &host, &ship_of(&host, body)).expect("ingested");
    }
    let now = host.time.now_secs();
    // Not yet past the retention: nothing, audited.
    let early = super::retention::Prunable::run(&consumer, now + 59, &|_| Ok(()))
        .expect("a pass")
        .expect("free");
    assert_eq!(early.len(), 1);
    assert_eq!(early[0].run, None);
    // Without a task, nothing either.
    drop(consumer);
    let unknown = small(None);
    assert_eq!(gc(&unknown)[0].run, None);
    drop(unknown);

    wall.jump(61);
    mono.advance(Duration::from_secs(61));
    let consumer = small(Some(60));
    for body in &batches[2..] {
        ingest(&consumer, &host, &ship_of(&host, body)).expect("ingested");
    }
    let pruned = super::retention::Prunable::run(&consumer, now + 61, &|_| Ok(()))
        .expect("a pass")
        .expect("free");
    assert_eq!(
        (pruned[0].run, pruned[0].through, pruned[0].batches),
        (Some(run), 4, 2)
    );
    assert_eq!(pruned[0].role, "consumer");
    // The run's journal lost the segments that held only what went.
    let records = host
        .root
        .join("host")
        .join(STREAMS)
        .join("data")
        .join("decisions")
        .join("1")
        .join("consumer")
        .join(
            descriptor()
                .key(&ledger(1), host.identity.host_id())
                .expect("a key")
                .resource_component(),
        )
        .join(hex(&host.identity.host_id()))
        .join(hex(&run))
        .join("records");
    assert!(!records.join("seg-00000000000000000000.pgj").exists());
    assert!(records.join("BASE").exists());
    // Below what is kept (WP-5.6c): the batch that went is proved equal by the anchor and
    // answered `ok`, nothing written; another batch of that range, or one straddling the low
    // watermark, is `gone`.
    let state_before = std::fs::read(run_dir_of(&host, run).join("STATE")).expect("STATE");
    let (answer, _) = ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("answered");
    assert_eq!((answer.outcome, answer.acked), (Outcome::Ok, 8));
    assert!(
        !run_dir_of(&host, run)
            .join("batches")
            .join("1-2.jws")
            .exists(),
        "nothing written"
    );
    assert_eq!(
        std::fs::read(run_dir_of(&host, run).join("STATE")).expect("STATE"),
        state_before
    );
    let other = forge(
        &host,
        run,
        1,
        batch::GENESIS_HEAD.to_owned(),
        &["x", "y"],
        1,
    );
    let (answer, _) = ingest(&consumer, &host, &ship_of(&host, &other)).expect("answered");
    assert_eq!(answer.outcome, Outcome::Gone);
    let straddling = forge(
        &host,
        run,
        3,
        batch::GENESIS_HEAD.to_owned(),
        &["r2", "r3", "r4"],
        1,
    );
    let (answer, _) = ingest(&consumer, &host, &ship_of(&host, &straddling)).expect("answered");
    assert_eq!(answer.outcome, Outcome::Gone);
    // A read below what is kept answers from the low watermark, with the gap and the anchor.
    let page = consumer
        .read(&ledger(1), host.identity.host_id(), run, 1, 10)
        .expect("read");
    assert_eq!(
        page.records.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![5, 6, 7, 8]
    );
    let gap = page.gap.expect("a gap");
    assert_eq!(
        (gap.low_watermark, gap.anchor.through, gap.anchor.run),
        (5, 4, run)
    );
    let page = consumer
        .read(&ledger(1), host.identity.host_id(), run, 5, 2)
        .expect("read");
    assert_eq!((page.records.len(), page.gap), (2, None));
    drop(consumer);
    let reopened = small(Some(60));
    assert_eq!(
        reopened
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        8
    );
}

/// The anchor of a run's batches directory, decoded.
fn anchor_in(dir: &Path) -> super::anchor::Anchor {
    super::anchor::Anchor::decode(
        &permguard_host::storage::write::read_view(
            &permguard_host::storage::Dir::open(dir).expect("dir"),
            super::anchor::ANCHOR,
            permguard_host::storage::format::VIEW,
        )
        .expect("read")
        .expect("an anchor"),
    )
    .expect("decoded")
}

/// WP-5.6b: a pass a crash stopped after its anchor, before its mark (here: its record
/// refused), is finished by the next without covering a batch twice; a crash after STATE's base
/// and before the journal's `BASE` is finished by the open.
#[test]
fn a_pass_stopped_after_its_anchor_or_its_base_is_finished() {
    let host = Host::new("prune-crashed");
    let consumer = consumer_on(&host);
    let producer = small_sealer(&host, descriptor());
    let run = acknowledged(&producer, &consumer, &host, 8);
    let dir = host.producer_dir(&ledger(1));
    let batches = dir.join("batches").join(hex(&run));
    // The stream whose record is refused is skipped, logged, and nothing of it goes.
    assert_eq!(
        super::retention::Prunable::run(&producer, 0, &|_| Err("down".to_owned()))
            .expect("the pass goes on"),
        Some(Vec::new())
    );
    assert_eq!(anchor_in(&batches).through, 8, "the anchor went first");
    assert!(batches.join("1-2.jws").exists());
    let pruned = gc(&producer);
    assert_eq!((pruned[0].through, pruned[0].batches), (8, 4));
    let anchor = anchor_in(&batches);
    assert_eq!(
        (anchor.through, anchor.covering.len()),
        (8, 4),
        "no batch covered twice"
    );

    // STATE's base written, the journal's BASE and segments not yet: the next open finishes.
    let host = Host::new("prune-crashed-base");
    let consumer = consumer_on(&host);
    let producer = small_sealer(&host, descriptor());
    let run = acknowledged(&producer, &consumer, &host, 8);
    let records = host.producer_dir(&ledger(1)).join("records");
    let saved: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(&records)
        .expect("records")
        .map(|entry| {
            let path = entry.expect("entry").path();
            let bytes = std::fs::read(&path).expect("read");
            (path, bytes)
        })
        .collect();
    gc(&producer);
    drop(producer);
    std::fs::remove_file(records.join("BASE")).expect("BASE removed");
    for (path, bytes) in &saved {
        std::fs::write(path, bytes).expect("restored");
    }
    let producer = small_sealer(&host, descriptor());
    let receipt = producer
        .append(&ledger(1), &"r8".to_owned())
        .expect("the open finished the deletion");
    assert_eq!((receipt.run_id, receipt.seq), (run, 9));
    assert!(records.join("BASE").exists());
    assert!(!records.join("seg-00000000000000000000.pgj").exists());

    // A journal starting after frame 0 where STATE names no base is refused.
    drop(producer);
    let state = host.producer_dir(&ledger(1)).join("STATE");
    let mut held = State::decode(
        &permguard_host::storage::write::read_view(
            &permguard_host::storage::Dir::open(&host.producer_dir(&ledger(1))).expect("dir"),
            "STATE",
            permguard_host::storage::format::VIEW,
        )
        .expect("read")
        .expect("held"),
    )
    .expect("decoded");
    held.base = None;
    permguard_host::storage::write::replace_view(
        &permguard_host::storage::Dir::open(&host.producer_dir(&ledger(1))).expect("dir"),
        "STATE",
        permguard_host::storage::format::VIEW,
        &held.encode().expect("encodes"),
    )
    .expect("rewritten");
    assert!(state.exists());
    assert!(matches!(
        small_sealer(&host, descriptor()).append(&ledger(1), &"r9".to_owned()),
        Err(StreamError::Corruption(_))
    ));
}

/// WP-5.6b: a consumer's pass stopped after its anchor (its record refused) is finished by the
/// next without covering a batch twice; once every record went, the reopened run takes its
/// head from the anchor.
#[test]
fn a_consumer_pass_stopped_after_its_anchor_is_finished() {
    struct Source;
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(1)
        }
    }
    let host = Host::new("prune-consumer-crashed");
    // One frame a segment: once everything held went, no RECORDS frame is left.
    let small = || {
        host.streams()
            .with_segment_bytes(1)
            .register_consumer(descriptor(), Text)
            .expect("registered")
            .with_retention_source(Arc::new(Source))
    };
    let (producer, run, batches) = shipped(&host, 10, 2);
    drop(producer);
    let consumer = small();
    for body in &batches[..4] {
        ingest(&consumer, &host, &ship_of(&host, body)).expect("ingested");
    }
    let later = host.time.now_secs() + 10;
    // The stream whose record is refused is skipped, logged, and nothing of it goes.
    assert_eq!(
        super::retention::Prunable::run(&consumer, later, &|_| Err("down".to_owned()))
            .expect("the pass goes on"),
        Some(Vec::new())
    );
    let pruned = super::retention::Prunable::run(&consumer, later, &|_| Ok(()))
        .expect("a pass")
        .expect("free");
    assert_eq!((pruned[0].through, pruned[0].batches), (8, 4));
    let run_dir = host
        .root
        .join("host")
        .join(STREAMS)
        .join("data")
        .join("decisions")
        .join("1")
        .join("consumer")
        .join(
            descriptor()
                .key(&ledger(1), host.identity.host_id())
                .expect("a key")
                .resource_component(),
        )
        .join(hex(&host.identity.host_id()))
        .join(hex(&run));
    let anchor = anchor_in(&run_dir);
    assert_eq!(
        (anchor.through, anchor.covering.len()),
        (8, 4),
        "no batch covered twice"
    );
    drop(consumer);
    let reopened = small();
    assert_eq!(
        reopened
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        8
    );
    // The last batch again is proved equal by the anchor: `ok`, nothing written.
    let (answer, _) = ingest(&reopened, &host, &ship_of(&host, &batches[3])).expect("answered");
    assert_eq!((answer.outcome, answer.acked), (Outcome::Ok, 8));
    // The next continues from the anchor's head.
    let (answer, _) = ingest(&reopened, &host, &ship_of(&host, &batches[4])).expect("answered");
    assert_eq!((answer.outcome, answer.acked), (Outcome::Ok, 10));
}

/// WP-5.6b, after the review: records not yet sealed that start a kept segment are sealed and
/// shipped after a reopen from STATE's base; a run ended and succeeded below the base reopens
/// into its successor.
#[test]
fn a_reopened_stream_seals_what_follows_its_base() {
    let host = Host::new("prune-base-seal");
    let consumer = consumer_on(&host);
    let tiny = || {
        host.streams()
            .with_segment_bytes(1)
            .register_producer(descriptor(), Text)
            .expect("registered")
            .with_signer(Arc::clone(&host.attest))
            .expect("the descriptor's ring")
    };
    let producer = tiny();
    let run = acknowledged(&producer, &consumer, &host, 6);
    for at in 6..8 {
        producer
            .append(&ledger(1), &format!("r{at}"))
            .expect("appended");
    }
    assert_eq!(gc(&producer)[0].through, 6);
    drop(producer);
    let producer = tiny();
    assert!(matches!(
        producer.seal(&ledger(1), 10).expect("sealed"),
        Sealing::Sealed { first: 7, .. }
    ));
    let shipping = subscribed("decisions", true, 1);
    assert_eq!(
        pump(
            &producer,
            &consumer,
            &host,
            &shipping,
            vec![pin_of(&host)],
            1
        ),
        vec![Outcome::Ok]
    );
    assert_eq!(
        consumer
            .acked(&ledger(1), host.identity.host_id(), run)
            .expect("acked"),
        8
    );

    // The run ends and a successor opens; the whole first run goes, its TERMINAL with it.
    // The successor holds nothing yet: the kept segment is its RUN_OPEN, and the base is the
    // first run, ended.
    let successor = producer
        .rollover(&ledger(1), Some(fence(1)))
        .expect("rolled over")
        .run_id;
    let pruned = gc(&producer);
    assert_eq!((pruned[0].run, pruned[0].through), (Some(run), 8));
    let base = producer
        .state(&ledger(1))
        .expect("state")
        .expect("held")
        .base
        .expect("a base");
    assert!(base.ended && base.last_seq == 8, "{base:?}");
    drop(producer);
    let producer = tiny();
    let receipt = producer
        .append(&ledger(1), &"s0".to_owned())
        .expect("the successor goes on");
    assert_eq!((receipt.run_id, receipt.seq), (successor, 1));
    assert!(matches!(
        producer.seal(&ledger(1), 10).expect("sealed"),
        Sealing::Sealed { .. }
    ));
}

/// WP-5.6b, after the review: a registered floor answering `None` keeps the run whole.
#[test]
fn a_floor_answering_none_keeps_the_run() {
    struct Keep;
    impl super::retention::RetentionFloor for Keep {
        fn retention_safe(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            None
        }
    }
    let history = Descriptor {
        retention: Retention::History,
        ..descriptor()
    };
    let host = Host::new("prune-floor-none");
    let consumer = host
        .streams()
        .register_consumer(history.clone(), Text)
        .expect("registered");
    let producer = small_sealer(&host, history).with_retention_floor(Arc::new(Keep));
    acknowledged(&producer, &consumer, &host, 4);
    assert_eq!(gc(&producer)[0].run, None, "nothing goes");
}

/// WP-5.6b, after the mutants: a run the WP-5.4 shipping loop truncated, its mark written and no
/// anchor, is anchored from its mark on; a pass with nothing new still catches the journal up.
#[test]
fn a_pre_anchor_mark_is_anchored_and_the_journal_is_caught_up() {
    let host = Host::new("prune-pre-anchor");
    let consumer = consumer_on(&host);
    let producer = small_sealer(&host, descriptor());
    let run = acknowledged(&producer, &consumer, &host, 4);
    let dir = host.producer_dir(&ledger(1));
    let batches = dir.join("batches").join(hex(&run));
    // What WP-5.4 left: the mark through 2, the file below it gone, no anchor.
    permguard_host::storage::write::replace_view(
        &permguard_host::storage::Dir::open(&batches).expect("dir"),
        "PRUNED",
        permguard_host::storage::format::VIEW,
        &[0xa1, 0x01, 0x02],
    )
    .expect("marked");
    std::fs::remove_file(batches.join("1-2.jws")).expect("deleted");
    let pruned = gc(&producer);
    assert_eq!((pruned[0].through, pruned[0].batches), (4, 1));
    assert_eq!(
        anchor_in(&batches).covering.len(),
        1,
        "covered from the mark on"
    );

    // A pass stopped after its marks and files, before STATE's base and the journal.
    let records = dir.join("records");
    let host = Host::new("prune-catch-up");
    let consumer = consumer_on(&host);
    let producer = small_sealer(&host, descriptor());
    acknowledged(&producer, &consumer, &host, 8);
    let dir = host.producer_dir(&ledger(1));
    let records = {
        let _ = records;
        dir.join("records")
    };
    let snapshot = |path: &Path| -> Vec<(PathBuf, Vec<u8>)> {
        std::fs::read_dir(path)
            .expect("listed")
            .map(|entry| {
                let path = entry.expect("entry").path();
                let bytes = std::fs::read(&path).expect("read");
                (path, bytes)
            })
            .collect()
    };
    let saved = snapshot(&records);
    let state = std::fs::read(dir.join("STATE")).expect("STATE");
    gc(&producer);
    drop(producer);
    std::fs::remove_file(records.join("BASE")).expect("BASE removed");
    for (path, bytes) in &saved {
        std::fs::write(path, bytes).expect("restored");
    }
    std::fs::write(dir.join("STATE"), &state).expect("STATE restored");
    let producer = small_sealer(&host, descriptor());
    assert_eq!(gc(&producer)[0].run, None, "nothing new to delete");
    assert!(records.join("BASE").exists(), "the journal caught up");
    assert!(!records.join("seg-00000000000000000000.pgj").exists());
}

/// WP-5.6b, after the mutants: records a crash left without their admission are dated by the
/// open and written by the next pass, which may then delete them; a batch file straddling what
/// a run retains is corruption, and that run's pass fails alone.
#[test]
fn an_undated_admission_is_written_by_the_pass_and_a_straddle_is_refused() {
    struct Source;
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(1)
        }
    }
    let host = Host::new("prune-undated");
    let small = || {
        host.streams()
            .with_segment_bytes(256)
            .register_consumer(descriptor(), Text)
            .expect("registered")
            .with_retention_source(Arc::new(Source))
    };
    let (producer, run, batches) = shipped(&host, 6, 2);
    drop(producer);
    let consumer = small();
    ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("ingested");
    drop(consumer);
    let run_dir = host
        .root
        .join("host")
        .join(STREAMS)
        .join("data")
        .join("decisions")
        .join("1")
        .join("consumer")
        .join(
            descriptor()
                .key(&ledger(1), host.identity.host_id())
                .expect("a key")
                .resource_component(),
        )
        .join(hex(&host.identity.host_id()))
        .join(hex(&run));
    // The second batch's records and file, without its admission: a crash between them.
    let (mut journal, _) = permguard_host::storage::journal::Journal::open(
        permguard_host::storage::Dir::open(&run_dir.join("records")).expect("dir"),
        permguard_host::storage::journal::Options {
            segment_bytes: 256,
            ..Default::default()
        },
    )
    .expect("opened");
    journal
        .append(
            super::producer::RECORDS,
            &encode_group(3, [b"r2".as_slice(), b"r3".as_slice()]).expect("a group"),
        )
        .expect("appended");
    drop(journal);
    std::fs::write(run_dir.join("batches").join("3-4.jws"), &batches[1]).expect("the file");
    let consumer = small();
    let later = host.time.now_secs() + 10;
    let pruned = super::retention::Prunable::run(&consumer, later, &|_| Ok(()))
        .expect("a pass")
        .expect("free");
    assert_eq!(pruned[0].through, 4, "the undated records went too");

    // A file straddling what the run retains: that run's pass fails, nothing else.
    std::fs::write(run_dir.join("batches").join("3-6.jws"), &batches[2]).expect("a straddle");
    let pruned = super::retention::Prunable::run(&consumer, later, &|_| Ok(()))
        .expect("a pass")
        .expect("free");
    assert!(pruned.is_empty(), "{pruned:?}");
}

/// The directory of `run` on the test consumer, as `host`'s member.
fn run_dir_of(host: &Host, run: [u8; 16]) -> PathBuf {
    host.root
        .join("host")
        .join(STREAMS)
        .join("data")
        .join("decisions")
        .join("1")
        .join("consumer")
        .join(
            descriptor()
                .key(&ledger(1), host.identity.host_id())
                .expect("a key")
                .resource_component(),
        )
        .join(hex(&host.identity.host_id()))
        .join(hex(&run))
}

/// WP-5.6c, after the review: a run never pruned reads from the start with no gap, sequence 0
/// included.
#[test]
fn a_run_never_pruned_reads_without_a_gap() {
    let host = Host::new("read-no-gap");
    let consumer = consumer_on(&host);
    let (producer, run, batches) = shipped(&host, 4, 2);
    for body in &batches {
        ingest(&consumer, &host, &ship_of(&host, body)).expect("ingested");
    }
    for from in [0, 1] {
        let page = consumer
            .read(&ledger(1), host.identity.host_id(), run, from, 10)
            .expect("read");
        assert_eq!((page.records.len(), page.gap), (4, None), "from {from}");
        let page = producer.read(&ledger(1), from, 10).expect("read");
        assert_eq!((page.records.len(), page.gap), (4, None), "from {from}");
    }
}

/// WP-5.6c, after the review: a replay below the low watermark is equal only under the key the
/// anchor names for its range: the same envelope signed by another key of the ring is `gone`.
#[test]
fn a_replay_signed_by_another_key_is_gone() {
    struct Source;
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(1)
        }
    }
    let (host, wall, mono) = manual_host("replay-key");
    let consumer = host
        .streams()
        .register_consumer(descriptor(), Text)
        .expect("registered")
        .with_retention_source(Arc::new(Source));
    let (producer, run, batches) = shipped(&host, 4, 2);
    drop(producer);
    for body in &batches {
        ingest(&consumer, &host, &ship_of(&host, body)).expect("ingested");
    }
    let later = host.time.now_secs() + 10;
    assert_eq!(gc_at(&consumer, later)[0].through, 4);
    let (answer, _) = ingest(&consumer, &host, &ship_of(&host, &batches[0])).expect("answered");
    assert_eq!(answer.outcome, Outcome::Ok, "under its own key, equal");
    rotate_attest(&host, &wall, &mono);
    let original = batch::SealedBatch::decode(&batches[0])
        .expect("decoded")
        .envelope_unverified()
        .expect("an envelope");
    let resigned = forge_with(
        host.attest.as_ref(),
        &host,
        run,
        1,
        original.previous_head.clone(),
        vec![b"r0".to_vec(), b"r1".to_vec()],
        1,
        |envelope| *envelope = original.clone(),
    );
    let (answer, _) = ingest(&consumer, &host, &ship_of(&host, &resigned)).expect("answered");
    assert_eq!(answer.outcome, Outcome::Gone);
}

/// One garbage collection pass over `prunable` at `now`, every record accepted.
fn gc_at(prunable: &dyn super::retention::Prunable, now: u64) -> Vec<super::retention::Pruned> {
    prunable
        .run(now, &|_| Ok(()))
        .expect("a pass")
        .expect("no pass running")
}

/// WP-5.7a: the Host API's reads over a real producer and consumer: the list, the frontier of
/// both roles, a page with its gap and anchor after a prefix went, the signers, subscriptions,
/// gaps and anchors; a resource the engine does not hold is read without creating anything.
#[test]
fn the_host_api_reads_what_the_engine_holds() {
    use permguard_host::api::streams::StreamReads as _;
    struct Source;
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(1)
        }
    }
    let host = Host::new("reads");
    let consumer = Arc::new(
        host.streams()
            .register_consumer(descriptor(), Text)
            .expect("registered")
            .with_retention_source(Arc::new(Source)),
    );
    let producer = Arc::new(small_sealer(&host, descriptor()));
    let run = acknowledged(&producer, &consumer, &host, 6);
    gc(producer.as_ref());
    gc_at(consumer.as_ref(), host.time.now_secs() + 10);
    let reads = super::reads::Reads::default()
        .with(Arc::clone(&producer) as Arc<dyn super::reads::Inspect>)
        .with(Arc::clone(&consumer) as Arc<dyn super::reads::Inspect>);
    let resource = ledger(1).to_string();
    let me = hex(&host.identity.host_id());

    let list = reads.list().expect("listed");
    assert_eq!(
        list.iter()
            .map(|stream| (stream.role.as_str(), stream.resources.len()))
            .collect::<Vec<_>>(),
        vec![("producer", 1), ("consumer", 1)]
    );
    assert_eq!(list[0].retention, "evidence");
    assert_eq!(list[0].task.as_deref(), Some("decisions.ship"));
    assert_eq!(list[0].resources[0].state, "open");
    assert_eq!(list[1].resources[0].state, "held");

    let frontier = reads
        .frontier("data", "decisions", &resource)
        .expect("read")
        .expect("served");
    assert_eq!(frontier.producer.len(), 1);
    let produced = &frontier.producer[0];
    assert_eq!(
        (
            produced.run.as_str(),
            produced.ended,
            produced.last_seq,
            produced.sealed
        ),
        (hex(&run).as_str(), false, 6, 6)
    );
    assert_eq!(
        (produced.acknowledged, produced.low_watermark),
        (Some(6), 7)
    );
    assert_eq!(frontier.consumer.len(), 1);
    let consumed = &frontier.consumer[0];
    assert_eq!(
        (
            consumed.producer.as_str(),
            consumed.acked,
            consumed.oldest_retained
        ),
        (me.as_str(), 6, 7)
    );

    // Everything went: a page from the start is empty and states the gap and its anchor.
    let page = reads
        .records("data", "decisions", &resource, None, 1, 10)
        .expect("read")
        .expect("served");
    assert!(page.records.is_empty());
    let gap = page.gap.expect("a gap");
    assert_eq!(
        (
            gap.low_watermark,
            gap.anchor.through,
            gap.anchor.role.as_str()
        ),
        (7, 6, "producer")
    );
    // The producer goes on: a page of what follows, its digests, and the next sequence.
    for at in 6..9 {
        producer
            .append(&ledger(1), &format!("r{at}"))
            .expect("appended");
    }
    let page = reads
        .records("data", "decisions", &resource, None, 7, 2)
        .expect("read")
        .expect("served");
    assert_eq!(
        page.records
            .iter()
            .map(|record| record.seq)
            .collect::<Vec<_>>(),
        vec![7, 8]
    );
    assert_eq!(page.next, Some(9));
    // A full last page names no next one.
    let last = reads
        .records("data", "decisions", &resource, None, 8, 2)
        .expect("read")
        .expect("served");
    assert_eq!(
        (last.records.len(), last.next),
        (2, None),
        "8 and 9, and nothing after"
    );
    // Sealed from the batch files still held.
    assert!(matches!(
        producer.seal(&ledger(1), 10).expect("sealed"),
        Sealing::Sealed { .. }
    ));
    let sealed = reads
        .frontier("data", "decisions", &resource)
        .expect("read")
        .expect("served");
    assert_eq!(sealed.producer[0].sealed, 9);
    // A consumer run asked under another producer is not this one.
    let other = reads
        .records(
            "data",
            "decisions",
            &resource,
            Some((&[9; 16], &run)),
            1,
            10,
        )
        .expect("read")
        .expect("served");
    assert!(other.records.is_empty() && other.gap.is_none());
    assert_eq!(
        page.records[0].digest,
        batch::digest_string(digest::DECISION_RECORD, b"r6")
    );
    let consumer_page = reads
        .records(
            "data",
            "decisions",
            &resource,
            Some((&host.identity.host_id(), &run)),
            1,
            10,
        )
        .expect("read")
        .expect("served");
    assert_eq!(consumer_page.gap.expect("a gap").anchor.role, "consumer");

    let signers = reads
        .signers("data", "decisions", &resource)
        .expect("read")
        .expect("served");
    assert_eq!(
        signers
            .iter()
            .map(|run| run.role.as_str())
            .collect::<Vec<_>>(),
        vec!["producer", "consumer"]
    );
    assert!(
        signers
            .iter()
            .all(|run| run.spans.first().map(|span| span.from_seq) == Some(1))
    );
    let subscriptions = reads
        .subscriptions("data", "decisions", &resource)
        .expect("read")
        .expect("served");
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(
        (
            subscriptions[0].task.as_str(),
            subscriptions[0].required,
            subscriptions[0].state.as_str()
        ),
        ("decisions", true, "active")
    );
    assert_eq!(subscriptions[0].acked[0].acked, 6);
    let gaps = reads
        .gaps("data", "decisions", &resource)
        .expect("read")
        .expect("served");
    assert_eq!(
        gaps.iter()
            .map(|gap| (gap.role.as_str(), gap.low_watermark))
            .collect::<Vec<_>>(),
        vec![("producer", 7), ("consumer", 7)]
    );
    let anchors = reads
        .anchors("data", "decisions", &resource)
        .expect("read")
        .expect("served");
    assert_eq!(anchors.len(), 2);
    assert_eq!((anchors[0].through, anchors[0].covering), (6, 3));
    use base64::Engine as _;
    let decoded = super::anchor::Anchor::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&anchors[0].anchor)
            .expect("base64url"),
    )
    .expect("the anchor's CBOR");
    assert_eq!(decoded.through, 6);

    // Not served, and not held: nothing answered, nothing created.
    assert!(
        reads
            .frontier("data", "nothing", &resource)
            .expect("read")
            .is_none()
    );
    let before = std::fs::read_dir(
        host.producer_dir(&ledger(1))
            .parent()
            .expect("a parent")
            .parent()
            .expect("the producer root"),
    )
    .expect("listed")
    .count();
    let other = ledger(2).to_string();
    let empty = reads
        .frontier("data", "decisions", &other)
        .expect("read")
        .expect("served");
    assert!(empty.producer.is_empty() && empty.consumer.is_empty());
    assert!(
        reads
            .records("data", "decisions", &other, None, 1, 10)
            .expect("read")
            .expect("served")
            .records
            .is_empty()
    );
    let after = std::fs::read_dir(
        host.producer_dir(&ledger(1))
            .parent()
            .expect("a parent")
            .parent()
            .expect("the producer root"),
    )
    .expect("listed")
    .count();
    assert_eq!(before, after, "a read creates no stream");
}

/// WP-5.7a, after the review: the frontier of a stream that never sealed creates nothing and
/// answers its run, and a forked stream's frontier still answers its runs.
#[test]
fn a_frontier_read_writes_nothing_and_answers_a_forked_stream() {
    use permguard_host::api::streams::StreamReads as _;
    let host = Host::new("reads-unsealed");
    let producer = Arc::new(host.sealer());
    let run = producer
        .open_run(&ledger(1), Some(fence(1)))
        .expect("opened")
        .run_id;
    producer
        .append(&ledger(1), &"r0".to_owned())
        .expect("appended");
    let reads = super::reads::Reads::default()
        .with(Arc::clone(&producer) as Arc<dyn super::reads::Inspect>);
    let dir = host.producer_dir(&ledger(1));
    let listing = || {
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("listed")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    };
    let before = listing();
    let state = std::fs::read(dir.join("STATE")).expect("STATE");
    let frontier = reads
        .frontier("data", "decisions", &ledger(1).to_string())
        .expect("read")
        .expect("served");
    assert_eq!(frontier.producer.len(), 1);
    assert_eq!(
        (
            frontier.producer[0].last_seq,
            frontier.producer[0].sealed,
            frontier.producer[0].ended
        ),
        (1, 0, false)
    );
    for what in ["signers", "anchors", "subscriptions"] {
        let resource = ledger(1).to_string();
        match what {
            "signers" => drop(reads.signers("data", "decisions", &resource).expect("read")),
            "anchors" => drop(reads.anchors("data", "decisions", &resource).expect("read")),
            _ => drop(
                reads
                    .subscriptions("data", "decisions", &resource)
                    .expect("read"),
            ),
        }
    }
    assert_eq!(listing(), before, "no batches directory, nothing else");
    assert!(!dir.join("batches").exists());
    assert_eq!(
        std::fs::read(dir.join("STATE")).expect("STATE"),
        state,
        "STATE untouched"
    );

    // A rollover ends the first run.
    let successor = producer
        .rollover(&ledger(1), Some(fence(1)))
        .expect("rolled over")
        .run_id;
    let frontier = reads
        .frontier("data", "decisions", &ledger(1).to_string())
        .expect("read")
        .expect("served");
    assert_eq!(
        frontier
            .producer
            .iter()
            .map(|run| (run.run.clone(), run.ended))
            .collect::<Vec<_>>(),
        vec![(hex(&run), true), (hex(&successor), false)]
    );
    // Forked: the runs are still answered.
    producer.report_fork(&ledger(1), 1).expect("reported");
    let frontier = reads
        .frontier("data", "decisions", &ledger(1).to_string())
        .expect("a forked stream answers")
        .expect("served");
    assert_eq!(frontier.producer[0].run, hex(&run));
    assert_eq!(
        reads.list().expect("listed")[0].resources[0].state,
        "forked"
    );
}

/// WP-5.7c: a stream directory copied off the volume verifies offline under its ring's keys,
/// before and after a prefix went; an altered record, in a batch file or in the journal, is a
/// finding; keys of another ring are refused.
#[test]
fn an_altered_record_fails_the_offline_check() {
    struct Source;
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(1)
        }
    }
    let host = Host::new("verify-offline");
    let consumer = host
        .streams()
        .with_segment_bytes(256)
        .register_consumer(descriptor(), Text)
        .expect("registered")
        .with_retention_source(Arc::new(Source));
    let producer = small_sealer(&host, descriptor());
    let run = acknowledged(&producer, &consumer, &host, 6);
    for at in 6..8 {
        producer
            .append(&ledger(1), &format!("r{at}"))
            .expect("appended");
    }
    let keys = super::verify::Keys::from_document(
        &host.attest.export_document().expect("the ring exports"),
        DATA_ATTEST,
    )
    .expect("the keys");
    let descriptors = [descriptor()];
    let copy = |from: &Path, tag: &str| -> PathBuf {
        let to = scratch(tag);
        let _ = std::fs::remove_dir_all(&to);
        copy_tree(from, &to);
        to
    };
    let producer_dir = host.producer_dir(&ledger(1));
    let report =
        super::verify::verify_directory(&copy(&producer_dir, "verify-copy"), &keys, &descriptors)
            .expect("checked");
    assert!(report.sound(), "{}", report.render());
    assert_eq!(
        (report.role.as_str(), report.batches, report.records),
        ("producer", 3, 6)
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("2 record(s) past the last batch"))
    );

    // A record altered in a batch file: its batch no longer verifies.
    let altered = copy(&producer_dir, "verify-batch");
    let file = altered.join("batches").join(hex(&run)).join("3-4.jws");
    let text = std::fs::read_to_string(&file).expect("the batch");
    let records_at = text.find("\"records\"").expect("records");
    let mut bytes = text.into_bytes();
    let at = records_at + 15;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    std::fs::write(&file, bytes).expect("altered");
    let report = super::verify::verify_directory(&altered, &keys, &descriptors).expect("checked");
    assert!(!report.sound(), "{}", report.render());

    // A record altered in the journal: not the one the batch signed.
    let altered = copy(&producer_dir, "verify-journal");
    let mut changed = false;
    for entry in std::fs::read_dir(altered.join("records")).expect("records") {
        let path = entry.expect("entry").path();
        let mut bytes = std::fs::read(&path).expect("a segment");
        if let Some(at) = bytes.windows(2).position(|pair| pair == b"r3") {
            bytes[at + 1] = b'9';
            std::fs::write(&path, &bytes).expect("altered");
            changed = true;
        }
    }
    assert!(changed);
    let report = super::verify::verify_directory(&altered, &keys, &descriptors)
        .expect("a damaged journal is a finding, not an error");
    assert!(!report.sound(), "{}", report.render());

    // After a prefix went, the anchor carries the chain; the consumer's run verifies too.
    gc(&producer);
    gc_at(&consumer, host.time.now_secs() + 10);
    let report =
        super::verify::verify_directory(&copy(&producer_dir, "verify-pruned"), &keys, &descriptors)
            .expect("checked");
    assert!(report.sound(), "{}", report.render());
    let consumer_run = run_dir_of(&host, run);
    let consumer_copy = scratch("verify-consumer").join(hex(&run));
    copy_tree(&consumer_run, &consumer_copy);
    let report =
        super::verify::verify_directory(&consumer_copy, &keys, &descriptors).expect("checked");
    assert!(report.sound(), "{}", report.render());
    assert_eq!(report.role, "consumer");

    assert!(
        super::verify::Keys::from_document(
            &host.operations.export_document().expect("the ring exports"),
            DATA_ATTEST
        )
        .is_err()
    );
}

/// A copy of the directory tree at `from` into `to`.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("listed") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copied");
        }
    }
}

/// WP-5.7c, after the review: what an attacker holding the copy can do and the check finds — a
/// journal record altered with its frame's checksum recomputed, a run's batches deleted, a batch
/// in the middle deleted, the journal's tail cut, another run's batches dropped in, a consumer's
/// anchor deleted.
#[test]
fn the_offline_check_finds_each_alteration() {
    struct Source;
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(1)
        }
    }
    let host = Host::new("verify-tamper");
    let consumer = host
        .streams()
        .with_segment_bytes(1)
        .register_consumer(descriptor(), Text)
        .expect("registered")
        .with_retention_source(Arc::new(Source));
    // One frame a segment: each journal frame is its own file.
    let producer = host
        .streams()
        .with_segment_bytes(1)
        .register_producer(descriptor(), Text)
        .expect("registered")
        .with_signer(Arc::clone(&host.attest))
        .expect("the descriptor's ring");
    let run = acknowledged(&producer, &consumer, &host, 6);
    let keys = super::verify::Keys::from_document(
        &host.attest.export_document().expect("the ring exports"),
        DATA_ATTEST,
    )
    .expect("the keys");
    let descriptors = [descriptor()];
    let producer_dir = host.producer_dir(&ledger(1));
    let check =
        |dir: &Path| super::verify::verify_directory(dir, &keys, &descriptors).expect("checked");
    let copy = |from: &Path, tag: &str| -> PathBuf {
        let to = scratch(tag).join(from.file_name().expect("a name"));
        copy_tree(from, &to);
        to
    };
    assert!(check(&copy(&producer_dir, "tamper-sound")).sound());

    // A journal record altered, its frame's checksum recomputed: only the batch says otherwise.
    let altered = copy(&producer_dir, "tamper-journal");
    let mut rewritten = false;
    for entry in std::fs::read_dir(altered.join("records")).expect("records") {
        let path = entry.expect("entry").path();
        let bytes = std::fs::read(&path).expect("a segment");
        let Some(at) = bytes.windows(2).position(|pair| pair == b"r3") else {
            continue;
        };
        // header (48) | length u32 | kind u16 | claim u64 | payload | checksum (32)
        let kind = u16::from_be_bytes([bytes[52], bytes[53]]);
        let claim = u64::from_be_bytes(bytes[54..62].try_into().expect("eight bytes"));
        let mut payload = bytes[62..bytes.len() - 32].to_vec();
        payload[at - 62 + 1] = b'9';
        let mut segment = bytes[..48].to_vec();
        segment.extend(
            permguard_host::storage::journal::encode_frame(kind, claim, &payload).expect("a frame"),
        );
        std::fs::write(&path, segment).expect("rewritten");
        rewritten = true;
    }
    assert!(rewritten);
    let report = check(&altered);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("record 4 is not the one")),
        "{}",
        report.render()
    );

    // A run's batches deleted: STATE says they were sealed.
    let altered = copy(&producer_dir, "tamper-run");
    std::fs::remove_dir_all(altered.join("batches").join(hex(&run))).expect("deleted");
    let report = check(&altered);
    assert_eq!(report.role, "producer");
    assert!(!report.sound(), "{}", report.render());

    // A batch in the middle deleted: a gap.
    let altered = copy(&producer_dir, "tamper-gap");
    std::fs::remove_file(altered.join("batches").join(hex(&run)).join("3-4.jws")).expect("deleted");
    let report = check(&altered);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("starts at 5, and 3 was next")),
        "{}",
        report.render()
    );

    // The journal's tail cut: the sealed records it held are missing.
    let altered = copy(&producer_dir, "tamper-tail");
    let mut segments: Vec<PathBuf> = std::fs::read_dir(altered.join("records"))
        .expect("records")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pgj"))
        .collect();
    segments.sort();
    let last = segments.last().expect("a segment");
    let bytes = std::fs::read(last).expect("the last segment");
    std::fs::write(last, &bytes[..bytes.len() - 5]).expect("cut");
    let report = check(&altered);
    assert!(
        report.notes.iter().any(|note| note.contains("torn")),
        "{}",
        report.render()
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("lacks record 6")),
        "{}",
        report.render()
    );

    // Another run's batches dropped in.
    let altered = copy(&producer_dir, "tamper-foreign");
    copy_tree(
        &altered.join("batches").join(hex(&run)),
        &altered.join("batches").join("ab".repeat(16)),
    );
    let report = check(&altered);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("a run the journal does not hold")),
        "{}",
        report.render()
    );

    // A consumer's anchor deleted after its prefix went: its batches no longer start at 1.
    gc_at(&consumer, host.time.now_secs() + 10);
    let consumer_copy = copy(&run_dir_of(&host, run), "tamper-consumer");
    assert!(consumer_copy.join("ANCHOR").exists());
    assert!(
        check(&consumer_copy).sound(),
        "{}",
        check(&consumer_copy).render()
    );
    std::fs::remove_file(consumer_copy.join("ANCHOR")).expect("deleted");
    let report = check(&consumer_copy);
    assert!(!report.sound(), "{}", report.render());
}

/// WP-5.7c, after the mutants: batches signed by the ring's own key and still refused — one that
/// breaks the chain, one of another stream; an anchor whose checkpoint is another batch; a
/// consumer's records no batch signed.
#[test]
fn the_offline_check_refuses_well_signed_lies() {
    struct Source;
    impl super::retention::RetentionSource for Source {
        fn retention_seconds(&self, _: &str, _: &[u8; 16]) -> Option<u64> {
            Some(1)
        }
    }
    let host = Host::new("verify-lies");
    let consumer = host
        .streams()
        .register_consumer(descriptor(), Text)
        .expect("registered")
        .with_retention_source(Arc::new(Source));
    let producer = small_sealer(&host, descriptor());
    let run = acknowledged(&producer, &consumer, &host, 6);
    let keys = super::verify::Keys::from_document(
        &host.attest.export_document().expect("the ring exports"),
        DATA_ATTEST,
    )
    .expect("the keys");
    let descriptors = [descriptor()];
    let check =
        |dir: &Path| super::verify::verify_directory(dir, &keys, &descriptors).expect("checked");
    let copy = |from: &Path, tag: &str| -> PathBuf {
        let to = scratch(tag).join(from.file_name().expect("a name"));
        copy_tree(from, &to);
        to
    };
    let producer_dir = host.producer_dir(&ledger(1));
    let batches = producer_dir.join("batches").join(hex(&run));
    let envelope_of = |bytes: &[u8]| {
        batch::SealedBatch::decode(bytes)
            .expect("decoded")
            .envelope_unverified()
            .expect("an envelope")
    };
    let first = std::fs::read(batches.join("1-2.jws")).expect("the first batch");
    let second = envelope_of(&std::fs::read(batches.join("3-4.jws")).expect("the second"));

    // Signed by the ring, the right records, a chain that does not continue.
    let altered = copy(&producer_dir, "lies-chain");
    let broken = forge(
        &host,
        run,
        3,
        format!("sha256:{}", "0".repeat(64)),
        &["r2", "r3"],
        1,
    );
    std::fs::write(
        altered.join("batches").join(hex(&run)).join("3-4.jws"),
        broken,
    )
    .expect("replaced");
    let report = check(&altered);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("does not continue the chain")),
        "{}",
        report.render()
    );

    // Signed by the ring, continuing the chain, of another resource.
    let altered = copy(&producer_dir, "lies-stream");
    let foreign = forge_with(
        host.attest.as_ref(),
        &host,
        run,
        5,
        second.head.clone(),
        vec![b"r4".to_vec(), b"r5".to_vec()],
        1,
        |envelope| envelope.stream_key.resource = ledger(2).to_string(),
    );
    std::fs::write(
        altered.join("batches").join(hex(&run)).join("5-6.jws"),
        foreign,
    )
    .expect("replaced");
    let report = check(&altered);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("is of another stream")),
        "{}",
        report.render()
    );

    // A consumer's records no batch signed, its STATE gone with the batch.
    let consumer_run = run_dir_of(&host, run);
    let altered = copy(&consumer_run, "lies-unsigned");
    std::fs::remove_file(altered.join("batches").join("5-6.jws")).expect("deleted");
    std::fs::remove_file(altered.join("STATE")).expect("deleted");
    let report = check(&altered);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("no batch signed")),
        "{}",
        report.render()
    );

    // An anchor whose checkpoint is another batch, its covering made to match.
    gc_at(&consumer, host.time.now_secs() + 10);
    let altered = copy(&consumer_run, "lies-anchor");
    let held = super::anchor::Anchor::decode(
        &permguard_host::storage::write::read_view(
            &permguard_host::storage::Dir::open(&altered).expect("dir"),
            super::anchor::ANCHOR,
            permguard_host::storage::format::VIEW,
        )
        .expect("read")
        .expect("an anchor"),
    )
    .expect("decoded");
    let mut covering = held.covering.clone();
    if let Some(last) = covering.last_mut() {
        *last = super::anchor::envelope_digest(&envelope_of(&first)).expect("a digest");
    }
    let lying = super::anchor::Anchor {
        checkpoint: first.clone(),
        covering,
        ..held
    };
    permguard_host::storage::write::replace_view(
        &permguard_host::storage::Dir::open(&altered).expect("dir"),
        super::anchor::ANCHOR,
        permguard_host::storage::format::VIEW,
        &lying.encode().expect("encodes"),
    )
    .expect("replaced");
    let report = check(&altered);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("checkpoint ends at 2")),
        "{}",
        report.render()
    );
}
