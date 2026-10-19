// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-6.2c1: the coordinator's `events.import` provider.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_host::composition::{ConsumedPage, ConsumedRun, StreamConsumerReads};
use permguard_host::membership::import::{Checkpoint, Origin};
use permguard_host::membership::record::{Limits, TaskType};
use permguard_objects::cose::Sign1;
use permguard_stream::engine::batch::{Jws, SealedBatch};

use super::*;

const ZONE: &str = "zone-1";
const LEDGER: &str = "ledger-1";
/// The member asking.
const MEMBER: [u8; 16] = [9; 16];
/// Two other origins, and a producer the set does not name.
const A: [u8; 16] = [1; 16];
const B: [u8; 16] = [2; 16];
const STRANGER: [u8; 16] = [3; 16];

/// A's `data.attest` pin, as its membership's manifests held it.
fn a_pin() -> permguard_host::membership::record::RingPin {
    permguard_host::membership::record::RingPin {
        owner: permguard_host::membership::record::Role::Member,
        ring: permguard_host::keys::ring::DATA_ATTEST.to_owned(),
        epoch: 2,
        key_set_digest: [0xA2; 32],
        binding: vec![0xA2; 8],
        retiring: false,
    }
}

fn ledger() -> Resource {
    Resource::ledger("data", ZONE, LEDGER)
}

/// A batch file naming `kid`, unsigned: the provider reads its key and forwards it verbatim.
fn batch_file(kid: &str, first: u64) -> Vec<u8> {
    let protected = B64.encode(format!(
        "{{\"alg\":\"EdDSA\",\"kid\":\"{kid}\",\"typ\":\"{}\"}}",
        permguard_core::domains::protected::EVENT_BATCH
    ));
    SealedBatch {
        signature: Jws {
            protected,
            payload: B64.encode(format!("{{\"first\":{first}}}")),
            signature: "c2ln".to_owned(),
        },
        records: Vec::new(),
    }
    .encode()
    .expect("a batch file")
}

/// One run the fake consumer holds: two records a batch, the statement `kid` signed them under.
struct Run {
    held: ConsumedRun,
    kid: &'static str,
    statement: Option<Vec<u8>>,
    admitted_at: Option<u64>,
}

#[derive(Default)]
struct Held {
    runs: Mutex<Vec<Run>>,
}

impl StreamConsumerReads for Held {
    fn runs(&self, resource: &Resource) -> Result<Vec<ConsumedRun>, String> {
        assert_eq!(resource, &ledger(), "the session's ledger, and only it");
        Ok(self
            .runs
            .lock()
            .unwrap()
            .iter()
            .map(|run| run.held.clone())
            .collect())
    }

    fn locate(&self, _: &[u8; 16], _: &[u8; 16]) -> Result<Option<Resource>, String> {
        Ok(None)
    }

    fn records(
        &self,
        _: &Resource,
        _: &[u8; 16],
        _: &[u8; 16],
        _: u64,
        _: usize,
    ) -> Result<ConsumedPage, String> {
        Ok(ConsumedPage {
            records: Vec::new(),
            low_watermark: None,
        })
    }

    fn batch(
        &self,
        _: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        seq: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        let runs = self.runs.lock().unwrap();
        Ok(runs
            .iter()
            .find(|held| held.held.producer == *producer && held.held.run == *run)
            .filter(|held| seq <= held.held.acked)
            .map(|held| batch_file(held.kid, (seq - 1) / 2 * 2 + 1)))
    }

    fn statement(
        &self,
        _: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        kid: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let runs = self.runs.lock().unwrap();
        Ok(runs
            .iter()
            .find(|held| held.held.producer == *producer && held.held.run == *run)
            .filter(|held| held.kid == kid)
            .and_then(|held| held.statement.clone()))
    }

    fn admitted_at(
        &self,
        _: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
    ) -> Result<Option<u64>, String> {
        let runs = self.runs.lock().unwrap();
        Ok(runs
            .iter()
            .find(|held| held.held.producer == *producer && held.held.run == *run)
            .and_then(|held| held.admitted_at))
    }
}

fn run(producer: [u8; 16], run: u8, acked: u64, oldest_retained: u64) -> Run {
    Run {
        held: ConsumedRun {
            producer,
            run: [run; 16],
            acked,
            oldest_retained,
        },
        kid: "k1",
        statement: Some(vec![0xA0 + run]),
        admitted_at: (acked > 0).then_some(1_700_000_000 + u64::from(run)),
    }
}

struct Fixture {
    import: Import,
    held: Arc<Held>,
    keys: Arc<dyn permguard_core::KeyManager>,
}

fn fixture(tag: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "permguard-events-import-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let keys = crate::handles::ring_for_tests(&root);
    let held = Arc::new(Held::default());
    held.runs.lock().unwrap().extend([
        run(B, 7, 4, 1),
        run(A, 5, 3, 2),
        run(A, 4, 0, 1),
        run(MEMBER, 6, 2, 1),
        run(STRANGER, 8, 1, 1),
    ]);
    let origin = |host_id: [u8; 16]| Origin {
        host_id,
        membership_id: [host_id[0] + 0x10; 16],
        manifest: vec![host_id[0]; 4],
    };
    let set = OriginSet {
        revision: [0x5E; 32],
        origins: vec![origin(A), origin(B), origin([4; 16]), origin(MEMBER)],
        // A's history: the pin its batches verify under, signed into the checkpoint.
        pins: vec![(A, vec![a_pin()])],
    };
    Fixture {
        import: Import {
            consumer: StreamConsumer::over(Arc::clone(&held) as Arc<dyn StreamConsumerReads>),
            origins: Arc::new(move |resource: &Resource| {
                assert_eq!(resource, &ledger());
                Ok(set.clone())
            }),
            signer: crate::handles::import_signer_for_tests(Arc::clone(&keys)),
            coordinator: [0xC0; 16],
        },
        held,
        keys,
    }
}

fn context(resource: &str) -> TaskContext {
    TaskContext {
        membership_id: [0x19; 16],
        task_id: "import".to_owned(),
        task_type: TaskType::EventsImport,
        version: VERSION,
        epoch: 1,
        resource: resource.to_owned(),
        member: MEMBER,
        request_id: "r1".to_owned(),
        limits: Limits {
            max_body_bytes: 1 << 20,
            max_concurrency: 1,
            max_rate_per_minute: 60,
            max_batch_records: 100,
            retention_seconds: 86_400,
        },
        channel_binding: [0xBB; 32],
    }
}

fn session() -> TaskContext {
    context(&ledger().to_string())
}

/// The checkpoint's claims, its signature verified under the ring's key its `kid` names.
fn verified(fixture: &Fixture, envelope: &[u8]) -> Checkpoint {
    let sign1 = Sign1::decode(envelope).expect("a COSE_Sign1");
    let kid = String::from_utf8(sign1.header().expect("a header").kid).expect("text");
    let jwk = fixture
        .keys
        .public_keys()
        .expect("the published set")
        .into_iter()
        .find(|jwk| jwk.kid == kid)
        .expect("a key of the ring");
    let payload = sign1
        .verify(
            permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
            &B64.decode(&jwk.x).expect("base64url"),
            permguard_core::domains::protected::EVENT_IMPORT_CHECKPOINT,
        )
        .expect("signed by the coordinator's control.attest");
    Checkpoint::decode(payload).expect("a checkpoint")
}

fn refused(result: Result<Vec<u8>, Refusal>) -> &'static str {
    result.expect_err("refused").code
}

#[test]
fn the_origins_come_with_a_checkpoint_of_what_the_consumer_holds_of_each() {
    let fixture = fixture("origins");
    let answer = Origins::decode(
        &fixture
            .import
            .handle(&session(), &Request::Origins.encode().expect("encodes"))
            .expect("answered"),
    )
    .expect("an answer");
    let hosts: Vec<[u8; 16]> = answer.origins.iter().map(|origin| origin.host_id).collect();
    assert_eq!(hosts, vec![A, B, [4; 16], MEMBER], "the required set");
    assert_eq!(
        answer.origins[0].manifest,
        vec![1; 4],
        "each manifest as held"
    );
    let checkpoint = verified(&fixture, &answer.checkpoint);
    assert_eq!(checkpoint.coordinator, [0xC0; 16]);
    assert_eq!(checkpoint.resource, ledger().to_string());
    assert_eq!(checkpoint.revision, [0x5E; 32]);
    assert_eq!(
        checkpoint.channel_binding, [0xBB; 32],
        "bound to the session"
    );
    assert!(checkpoint.issued_at > 1_700_000_000, "signed now");
    assert_eq!(
        checkpoint.ring_epoch, 1,
        "the ring's epoch, bound by the signer"
    );
    let of = |host: [u8; 16]| {
        checkpoint
            .origins
            .iter()
            .find(|origin| origin.host_id == host)
            .expect("named")
            .runs
            .iter()
            .map(|run| (run.run[0], run.acked, run.oldest_retained, run.admitted_at))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        of(A),
        vec![(4, 0, 1, None), (5, 3, 2, Some(1_700_000_005))],
        "every run, by run id, with what was admitted and retained"
    );
    assert_eq!(of(B), vec![(7, 4, 1, Some(1_700_000_007))]);
    let pins_of = |host: [u8; 16]| {
        checkpoint
            .origins
            .iter()
            .find(|origin| origin.host_id == host)
            .expect("named")
            .pins
            .clone()
    };
    assert_eq!(pins_of(A), vec![a_pin()], "each origin's pins, signed");
    assert!(pins_of(B).is_empty());
    assert_eq!(of([4; 16]), vec![], "a required origin with nothing yet");
    assert_eq!(
        of(MEMBER).len(),
        1,
        "the member sees what the coordinator holds of it"
    );
    assert!(
        checkpoint
            .origins
            .iter()
            .all(|origin| origin.host_id != STRANGER),
        "a producer outside the set is not named"
    );

    // Published even when nothing is new: a second request signs a checkpoint again.
    let again = Origins::decode(
        &fixture
            .import
            .handle(&session(), &Request::Origins.encode().expect("encodes"))
            .expect("answered"),
    )
    .expect("an answer");
    assert_eq!(
        verified(&fixture, &again.checkpoint).origins,
        checkpoint.origins
    );
}

#[test]
fn a_batch_is_answered_as_its_origin_shipped_it() {
    let fixture = fixture("batch");
    let ask = |host_id, run: u8, seq| {
        fixture.import.handle(
            &session(),
            &Request::Batch {
                host_id,
                run: [run; 16],
                seq,
            }
            .encode()
            .expect("encodes"),
        )
    };
    // The edges: the last sequence admitted, the first retained.
    assert!(ask(B, 7, 4).is_ok());
    assert!(ask(A, 5, 2).is_ok());
    let ship = Ship::decode(&ask(B, 7, 3).expect("answered")).expect("a ship message");
    assert_eq!(ship.batch, batch_file("k1", 3), "the batch file, verbatim");
    assert_eq!(
        ship.statement,
        vec![0xA7],
        "the statement it was verified under"
    );

    assert_eq!(
        refused(ask(MEMBER, 6, 1)),
        codes::common::FORBIDDEN,
        "its own"
    );
    assert_eq!(
        refused(ask(STRANGER, 8, 1)),
        codes::common::FORBIDDEN,
        "not required"
    );
    assert_eq!(
        refused(ask(B, 9, 1)),
        codes::common::NOT_FOUND,
        "no such run"
    );
    assert_eq!(
        refused(ask(B, 7, 5)),
        codes::common::NOT_FOUND,
        "past what was admitted"
    );
    assert_eq!(
        refused(ask(A, 5, 1)),
        codes::stream::GONE,
        "below what is retained"
    );
    // A batch admitted before the statements were kept is not forwarded.
    fixture.held.runs.lock().unwrap()[0].statement = None;
    assert_eq!(refused(ask(B, 7, 1)), codes::common::UNAVAILABLE);
}

#[test]
fn a_session_reads_one_data_ledger_and_a_malformed_message_is_refused() {
    let fixture = fixture("scope");
    let origins = Request::Origins.encode().expect("encodes");
    for resource in [
        "plane/data/zone/zone-1".to_owned(),
        "plane/data".to_owned(),
        Resource::ledger("control", ZONE, LEDGER).to_string(),
    ] {
        assert_eq!(
            refused(fixture.import.handle(&context(&resource), &origins)),
            codes::common::FORBIDDEN,
            "{resource}"
        );
    }
    assert_eq!(
        refused(fixture.import.handle(&session(), b"not cbor")),
        codes::notp::BODY_REJECTED
    );
}

/// After the review: a set or a run no member could read is refused, never signed.
#[test]
fn a_checkpoint_a_member_would_refuse_is_never_signed() {
    let mut fixture = fixture("unreadable");
    // A run whose consumer reports a retained prefix past what it acknowledged.
    fixture.held.runs.lock().unwrap()[0].held.oldest_retained = 9;
    assert_eq!(
        refused(
            fixture
                .import
                .handle(&session(), &Request::Origins.encode().expect("encodes"))
        ),
        codes::common::UNAVAILABLE
    );
    fixture.held.runs.lock().unwrap()[0].held.oldest_retained = 1;
    // More required origins than a member reads.
    fixture.import.origins = Arc::new(|_: &Resource| {
        Ok(OriginSet {
            pins: Vec::new(),
            revision: [1; 32],
            origins: (0..=MAX_ORIGINS)
                .map(|at| Origin {
                    host_id: (at as u128 + 100).to_be_bytes(),
                    membership_id: [1; 16],
                    manifest: vec![1],
                })
                .collect(),
        })
    });
    assert_eq!(
        refused(
            fixture
                .import
                .handle(&session(), &Request::Origins.encode().expect("encodes"))
        ),
        codes::common::UNAVAILABLE
    );
}

#[test]
fn a_checkpoint_past_its_run_bound_is_refused_rather_than_cut() {
    let fixture = fixture("bound");
    {
        let mut runs = fixture.held.runs.lock().unwrap();
        runs.clear();
        for at in 0..=MAX_CHECKPOINT_RUNS {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(at as u64).to_be_bytes());
            runs.push(Run {
                held: ConsumedRun {
                    producer: A,
                    run: id,
                    acked: 1,
                    oldest_retained: 1,
                },
                kid: "k1",
                statement: None,
                admitted_at: None,
            });
        }
    }
    assert_eq!(
        refused(
            fixture
                .import
                .handle(&session(), &Request::Origins.encode().expect("encodes"))
        ),
        codes::common::UNAVAILABLE
    );
}
