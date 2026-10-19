// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-6.2c2a: the member's `events.import` pass, through real sessions to a coordinator whose
//! provider signs real checkpoints and forwards a real origin's manifest.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use permguard_core::authz::Resource;

use super::*;
use crate::composition::Payload as _;
use crate::keys::ring::{CONTROL_ATTEST, Ring};
use crate::membership::import::{Checkpoint, CheckpointOrigin, CheckpointRun, Origin, revision};
use crate::membership::record::Task;
use crate::membership::task::{TaskContext, TaskHandler, TaskHandlers};
use crate::membership::tests::protocol::{Loopback, Side, active_with, member};
use crate::membership::tests::{Host, decisions};
use crate::session::Refusal;
use crate::time::TimeGuard;

const LEDGER: &str = "plane/data/zone/z1/ledger/l1";
const RUN: [u8; 16] = [7; 16];

fn who() -> Initiator {
    Initiator::Principal("spiffe://acme/operators/member".to_owned())
}

fn task(task_type: TaskType, task_id: &str) -> Task {
    Task {
        task_id: task_id.to_owned(),
        task_type,
        resource_types: vec!["ledger".to_owned()],
        ..decisions("plane/data/*")
    }
}

/// What the coordinator's provider answers: its runs of the origin, and a refusal per sequence.
#[derive(Default)]
struct Served {
    /// `(origin, membership_id, manifest)`; the member itself among them when asked.
    origins: Vec<Origin>,
    /// The origin's runs as the checkpoint names them.
    runs: Vec<CheckpointRun>,
    /// A sequence the provider refuses, with the code.
    refused: Vec<(u64, &'static str)>,
    /// The channel binding the checkpoint names instead of the session's, when set.
    other_channel: bool,
    /// The sequences asked for, in order.
    asked: Vec<u64>,
    /// How many `origins` requests were answered.
    checkpoints: usize,
    /// The origin's `data.attest` pins the checkpoint names.
    pins: Vec<crate::membership::record::RingPin>,
    /// Another coordinator or ledger the checkpoint names, when set.
    coordinator: Option<[u8; 16]>,
    resource: Option<String>,
    /// An origin the answer names beyond the checkpoint's set, when set.
    unsigned: Option<Origin>,
    /// A membership the answer names for the origin, other than the one the revision signed.
    swapped: Option<[u8; 16]>,
    /// The checkpoint leaves the first origin out while its revision still names it.
    dropped: bool,
}

/// The coordinator's `events.import`, as the Control Plane serves it, over `served`.
struct Provider {
    control: Arc<Ring>,
    coordinator: [u8; 16],
    served: Arc<Mutex<Served>>,
}

impl TaskHandler for Provider {
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let mut served = self.served.lock().expect("lock");
        match Request::decode(body).expect("a request") {
            Request::Origins => {
                served.checkpoints += 1;
                let named: Vec<([u8; 16], [u8; 16])> = served
                    .origins
                    .iter()
                    .map(|origin| (origin.host_id, origin.membership_id))
                    .collect();
                let checkpoint = Checkpoint {
                    coordinator: served.coordinator.unwrap_or(self.coordinator),
                    resource: served
                        .resource
                        .clone()
                        .unwrap_or_else(|| context.resource.clone()),
                    revision: revision(&named).expect("a revision"),
                    origins: served
                        .origins
                        .iter()
                        .skip(usize::from(served.dropped))
                        .map(|origin| CheckpointOrigin {
                            host_id: origin.host_id,
                            runs: served.runs.clone(),
                            pins: served.pins.clone(),
                        })
                        .collect(),
                    issued_at: crate::authz::store::now(),
                    channel_binding: if served.other_channel {
                        [0xEE; 32]
                    } else {
                        context.channel_binding
                    },
                    ring_epoch: 0,
                    key_set_digest: [0; 32],
                }
                .sign_with(self.control.as_ref())
                .expect("signed");
                let mut origins = served.origins.clone();
                if let Some(unsigned) = served.unsigned.clone() {
                    origins.push(unsigned);
                    origins.sort_by_key(|origin| origin.host_id);
                }
                if let Some(swapped) = served.swapped {
                    origins[0].membership_id = swapped;
                }
                Ok(Origins {
                    checkpoint,
                    origins,
                }
                .encode()
                .expect("encodes"))
            }
            Request::Batch { seq, .. } => {
                served.asked.push(seq);
                if let Some((_, code)) = served.refused.iter().find(|(at, _)| *at == seq) {
                    return Err(Refusal {
                        code,
                        reason: "refused".to_owned(),
                    });
                }
                Ok(format!("batch-{seq}").into_bytes())
            }
        }
    }
}

/// One ingest: the origin's membership, epoch, host and pin count, and the body.
type Ingested = ([u8; 16], u64, [u8; 16], usize, Vec<u8>);

/// The member's consumer: what it holds per run, and what each body ingests as.
#[derive(Default)]
struct Engine {
    held: Mutex<u64>,
    /// The answer to a body, by sequence; admitted through it by default.
    answers: Mutex<Vec<(u64, Imported)>>,
    /// What was ingested: the origin's membership, epoch, host and pins, and the body.
    ingested: Mutex<Vec<Ingested>>,
    state: Mutex<Option<State>>,
}

impl StreamImport for Engine {
    fn held(&self, resource: &Resource, _: &[u8; 16], run: &[u8; 16]) -> Result<u64, String> {
        assert_eq!(resource.to_string(), LEDGER);
        assert_eq!(*run, RUN);
        Ok(*self.held.lock().expect("lock"))
    }

    fn import(
        &self,
        _: &Resource,
        origin: &ImportOrigin<'_>,
        body: &[u8],
    ) -> Result<Imported, String> {
        self.ingested.lock().expect("lock").push((
            origin.membership_id,
            origin.epoch,
            origin.host_id,
            origin.pins.len(),
            body.to_vec(),
        ));
        let seq: u64 = String::from_utf8_lossy(body)
            .trim_start_matches("batch-")
            .parse()
            .expect("a sequence");
        let answer = self
            .answers
            .lock()
            .expect("lock")
            .iter()
            .find(|(at, _)| *at == seq)
            .map(|(_, answer)| *answer)
            .unwrap_or(Imported::Admitted { acked: seq });
        if let Imported::Admitted { acked } = answer {
            *self.held.lock().expect("lock") = acked;
        }
        Ok(answer)
    }

    fn import_state(&self, _: &Resource) -> Result<Option<State>, String> {
        Ok(self.state.lock().expect("lock").clone())
    }

    fn keep_import_state(&self, _: &Resource, state: &State) -> Result<(), String> {
        *self.state.lock().expect("lock") = Some(state.clone());
        Ok(())
    }
}

/// A coordinator serving `served`, an origin shipping events to it, and a member importing.
struct World {
    c: Side,
    m: Side,
    o: Side,
    served: Arc<Mutex<Served>>,
    import_id: [u8; 16],
}

async fn world_of(tag: &str) -> World {
    let served = Arc::new(Mutex::new(Served::default()));
    let host = Host::new(&format!("{tag}-c"));
    let control = Arc::clone(
        host.rings
            .iter()
            .find(|ring| ring.id() == CONTROL_ATTEST)
            .expect("the ring"),
    );
    let coordinator = host.identity.host_id();
    let provider = Arc::new(Provider {
        control,
        coordinator,
        served: Arc::clone(&served),
    });
    let c = Side::handling(
        host,
        true,
        Arc::new(TimeGuard::system(Duration::from_secs(30))),
        move |_, _| {
            TaskHandlers::default()
                .register(TaskType::EventsImport, 1, provider)
                .expect("one handler")
        },
    );
    let m = Side::new(&format!("{tag}-m"), false);
    let o = Side::new(&format!("{tag}-o"), false);
    let import_id = active_with(&c, &m, task(TaskType::EventsImport, "import"), &[], &[]).await;
    let ship_id = active_with(&c, &o, task(TaskType::EventsShip, "events"), &[], &[]).await;
    let (shipping, envelope, _) = c
        .host
        .store
        .membership(&ship_id)
        .expect("held")
        .manifest
        .expect("approved");
    {
        let mut served = served.lock().expect("lock");
        served.origins = vec![Origin {
            host_id: o.host.identity.host_id(),
            membership_id: ship_id,
            manifest: envelope,
        }];
        served.pins = shipping
            .ring_pins
            .iter()
            .filter(|pin| pin.owner == Role::Member)
            .cloned()
            .collect();
        served.runs = vec![CheckpointRun {
            run: RUN,
            acked: 3,
            oldest_retained: 1,
            admitted_at: Some(1),
        }];
    }
    World {
        c,
        m,
        o,
        served,
        import_id,
    }
}

impl World {
    async fn pass(&self, engine: &Arc<Engine>) -> usize {
        let connector = Loopback {
            member: &self.m,
            coordinator: &self.c,
            tamper: false,
        };
        member(&self.m, &connector)
            .import_due(
                who(),
                &Importing {
                    engine: Arc::clone(engine) as Arc<dyn StreamImport>,
                    ledgers: vec![Resource::parse(LEDGER).expect("a ledger")],
                },
            )
            .await
    }
}

#[tokio::test]
async fn a_pass_verifies_the_checkpoint_and_imports_each_batch_past_what_is_held() {
    let world = world_of("import-pass").await;
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 3);
    let ingested = engine.ingested.lock().expect("lock").clone();
    let bodies: Vec<Vec<u8>> = ingested.iter().map(|held| held.4.clone()).collect();
    assert_eq!(
        bodies,
        vec![
            b"batch-1".to_vec(),
            b"batch-2".to_vec(),
            b"batch-3".to_vec()
        ]
    );
    let origin = world.served.lock().expect("lock").origins[0].clone();
    assert!(
        ingested
            .iter()
            .all(|(membership_id, epoch, host, pins, _)| {
                *membership_id == origin.membership_id
                    && *epoch == 1
                    && *host == world.o.host.identity.host_id()
                    && *pins == 1
            }),
        "under the origin's membership, epoch and data.attest pin"
    );
    let state = engine.state.lock().expect("lock").clone().expect("kept");
    assert_eq!(state.membership_id, world.import_id);
    assert!(state.gaps.is_empty());
    assert!(state.verified_at > 0);
    assert_eq!(
        state.revision,
        revision(&[(origin.host_id, origin.membership_id)]).expect("a revision")
    );

    // Caught up: the next pass asks for no batch, and still asks for and verifies a checkpoint.
    assert_eq!(world.pass(&engine).await, 0);
    let served = world.served.lock().expect("lock");
    assert_eq!(served.asked, vec![1, 2, 3]);
    assert_eq!(served.checkpoints, 2, "a checkpoint on every pass");
    let after = engine.state.lock().expect("lock").clone().expect("kept");
    assert!(after.verified_at >= state.verified_at);
}

#[tokio::test]
async fn retention_refusals_and_bad_batches_leave_durable_gaps_and_stop_the_run() {
    // The coordinator holds the run from 3, this Host from nothing: a gap of 1-2, nothing asked.
    let world = world_of("import-retention").await;
    world.served.lock().expect("lock").runs[0].oldest_retained = 3;
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 0);
    let state = engine.state.lock().expect("lock").clone().expect("kept");
    assert_eq!(state.gaps.len(), 1);
    let gap = &state.gaps[0];
    assert_eq!(
        (gap.from, gap.through, gap.reason.as_str()),
        (1, Some(2), RETENTION)
    );
    assert_eq!(gap.origin, world.o.host.identity.host_id());
    assert!(world.served.lock().expect("lock").asked.is_empty());
    // Found again on the next pass, kept once, and never removed.
    world.pass(&engine).await;
    assert_eq!(
        engine
            .state
            .lock()
            .expect("lock")
            .clone()
            .expect("kept")
            .gaps
            .len(),
        1
    );

    // A sequence the coordinator answers `gone`.
    let world = world_of("import-gone").await;
    world.served.lock().expect("lock").refused = vec![(2, permguard_core::codes::stream::GONE)];
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 1);
    let gaps = engine
        .state
        .lock()
        .expect("lock")
        .clone()
        .expect("kept")
        .gaps;
    assert_eq!((gaps[0].from, gaps[0].reason.as_str()), (2, RETENTION));
    // The run is not asked past its gap again.
    world.pass(&engine).await;
    assert_eq!(world.served.lock().expect("lock").asked, vec![1, 2]);

    // A batch that does not verify, and one that forks.
    for (answer, reason) in [
        (Imported::Unverifiable, UNVERIFIABLE),
        (Imported::Fork { run: RUN, at: 2 }, FORK),
        // Another run of the origin forked: this one closes where it was asked.
        (
            Imported::Fork {
                run: [9; 16],
                at: 7,
            },
            FORK,
        ),
    ] {
        let world = world_of(&format!("import-{reason}")).await;
        let engine = Arc::new(Engine::default());
        engine.answers.lock().expect("lock").push((2, answer));
        assert_eq!(world.pass(&engine).await, 1);
        let gaps = engine
            .state
            .lock()
            .expect("lock")
            .clone()
            .expect("kept")
            .gaps;
        assert_eq!((gaps[0].from, gaps[0].reason.as_str()), (2, reason));
        assert_eq!(*engine.held.lock().expect("lock"), 1, "no advance past it");
    }

    // A refusal that is not retention is asked again on the next pass, no gap.
    let world = world_of("import-deferred").await;
    world.served.lock().expect("lock").refused =
        vec![(2, permguard_core::codes::common::UNAVAILABLE)];
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 1);
    assert!(
        engine
            .state
            .lock()
            .expect("lock")
            .clone()
            .expect("kept")
            .gaps
            .is_empty()
    );
    world.served.lock().expect("lock").refused.clear();
    assert_eq!(world.pass(&engine).await, 2);
}

#[tokio::test]
async fn a_checkpoint_for_another_session_or_an_unverifiable_origin_imports_nothing_of_it() {
    // A checkpoint bound to another channel: the whole answer is refused.
    let world = world_of("import-channel").await;
    world.served.lock().expect("lock").other_channel = true;
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 0);
    assert!(engine.state.lock().expect("lock").is_none(), "nothing kept");
    assert!(world.served.lock().expect("lock").asked.is_empty());

    // An origin whose manifest is not one the coordinator signed is left out.
    let world = world_of("import-forged").await;
    world.served.lock().expect("lock").origins[0].manifest = b"not a manifest".to_vec();
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 0);
    assert!(
        engine.state.lock().expect("lock").is_some(),
        "the checkpoint verified"
    );
    assert!(world.served.lock().expect("lock").asked.is_empty());

    // The member's own stream, named among the origins, is never asked for.
    let world = world_of("import-own").await;
    {
        let mut served = world.served.lock().expect("lock");
        let own = Origin {
            host_id: world.m.host.identity.host_id(),
            membership_id: world.import_id,
            manifest: Vec::new(),
        };
        served.origins.push(own);
        served.origins.sort_by_key(|origin| origin.host_id);
    }
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 3, "the other origin only");
    assert!(
        engine
            .ingested
            .lock()
            .expect("lock")
            .iter()
            .all(|held| held.2 == world.o.host.identity.host_id())
    );
}

#[tokio::test]
async fn the_checkpoints_pins_verify_the_batches_not_the_manifests_alone() {
    // A set the origin rotated away from, signed into the checkpoint beside the current one.
    let world = world_of("import-retired").await;
    let retired = crate::membership::record::RingPin {
        epoch: 0,
        key_set_digest: [0xAA; 32],
        binding: vec![0xAA; 8],
        ..world.served.lock().expect("lock").pins[0].clone()
    };
    world.served.lock().expect("lock").pins.insert(0, retired);
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 3);
    assert!(
        engine
            .ingested
            .lock()
            .expect("lock")
            .iter()
            .all(|held| held.3 == 2),
        "every set the checkpoint names"
    );
}

/// What a test changes in what the coordinator answers.
type Tamper = Box<dyn Fn(&mut Served)>;

#[tokio::test]
async fn an_answer_the_checkpoint_does_not_sign_is_refused_whole() {
    let other_host = Host::new("import-not-signed").identity.host_id();
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "coordinator",
            Box::new(|served| served.coordinator = Some([0xC1; 16])),
        ),
        (
            "ledger",
            Box::new(|served| served.resource = Some("plane/data/zone/z1/ledger/l2".to_owned())),
        ),
        (
            "unsigned",
            Box::new(move |served| {
                served.unsigned = Some(Origin {
                    host_id: other_host,
                    membership_id: [3; 16],
                    manifest: Vec::new(),
                });
            }),
        ),
        (
            "swapped",
            Box::new(|served| served.swapped = Some([0x51; 16])),
        ),
        ("dropped", Box::new(|served| served.dropped = true)),
    ];
    for (tag, tamper) in cases {
        let world = world_of(&format!("import-{tag}")).await;
        tamper(&mut world.served.lock().expect("lock"));
        let engine = Arc::new(Engine::default());
        assert_eq!(world.pass(&engine).await, 0, "{tag}");
        assert!(
            engine.state.lock().expect("lock").is_none(),
            "{tag}: nothing kept"
        );
        assert!(world.served.lock().expect("lock").asked.is_empty(), "{tag}");
    }
}

#[tokio::test]
async fn an_origin_whose_manifest_is_not_its_own_shipping_one_is_left_out() {
    // The manifest of another membership, or of another Host, or one shipping no events.
    let world = world_of("import-not-its-own").await;
    let decisions_host = Side::new("import-decisions-o", false);
    let decisions_id = active_with(
        &world.c,
        &decisions_host,
        task(TaskType::DecisionsShip, "decisions"),
        &[],
        &[],
    )
    .await;
    let (_, decisions_manifest, _) = world
        .c
        .host
        .store
        .membership(&decisions_id)
        .expect("held")
        .manifest
        .expect("approved");
    let origin = world.served.lock().expect("lock").origins[0].clone();
    let variants = vec![
        Origin {
            membership_id: [0x52; 16],
            ..origin.clone()
        },
        Origin {
            host_id: decisions_host.host.identity.host_id(),
            ..origin.clone()
        },
        Origin {
            host_id: decisions_host.host.identity.host_id(),
            membership_id: decisions_id,
            manifest: decisions_manifest,
        },
    ];
    for variant in variants {
        world.served.lock().expect("lock").origins = vec![variant];
        let engine = Arc::new(Engine::default());
        assert_eq!(world.pass(&engine).await, 0);
        assert!(
            engine.state.lock().expect("lock").is_some(),
            "the checkpoint verified"
        );
        assert!(engine.ingested.lock().expect("lock").is_empty());
    }
}

#[tokio::test]
async fn a_pass_is_bounded_and_an_answer_behind_the_ask_stops_the_run() {
    let world = world_of("import-budget").await;
    world.served.lock().expect("lock").runs[0].acked = MAX_BATCHES_PER_PASS as u64 + 10;
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, MAX_BATCHES_PER_PASS);
    assert_eq!(world.pass(&engine).await, 10, "the rest on the next pass");

    // The consumer holds less than what was asked for: nothing more of the run this pass.
    let world = world_of("import-behind").await;
    let engine = Arc::new(Engine::default());
    engine
        .answers
        .lock()
        .expect("lock")
        .push((2, Imported::OutOfOrder { acked: 0 }));
    assert_eq!(world.pass(&engine).await, 1);
    assert_eq!(world.served.lock().expect("lock").asked, vec![1, 2]);
}

#[tokio::test]
async fn a_ledger_two_memberships_import_or_full_of_gaps_is_not_imported() {
    let world = world_of("import-twice").await;
    let second = Side::new("import-twice-c2", true);
    active_with(
        &second,
        &world.m,
        task(TaskType::EventsImport, "import"),
        &[],
        &[],
    )
    .await;
    let engine = Arc::new(Engine::default());
    assert_eq!(world.pass(&engine).await, 0);
    assert_eq!(
        world.served.lock().expect("lock").checkpoints,
        0,
        "nothing asked"
    );

    let world = world_of("import-full").await;
    let engine = Arc::new(Engine::default());
    *engine.state.lock().expect("lock") = Some(State {
        membership_id: world.import_id,
        revision: [0; 32],
        checkpoint: Vec::new(),
        verified_at: 1,
        gaps: (1..=MAX_GAPS as u64)
            .map(|from| Gap {
                origin: [1; 16],
                run: [1; 16],
                from,
                through: None,
                reason: RETENTION.to_owned(),
                detected_at: 1,
                revision: [0; 32],
            })
            .collect(),
    });
    assert_eq!(world.pass(&engine).await, 0);
    assert_eq!(
        world.served.lock().expect("lock").checkpoints,
        0,
        "nothing asked"
    );
}

#[tokio::test]
async fn a_suspended_or_expired_origin_manifest_is_left_out_and_each_pass_refreshes_the_check() {
    use crate::operations::mutation::Applying;

    let world = world_of("import-suspended").await;
    let origin = world.served.lock().expect("lock").origins[0].clone();
    let now = crate::authz::store::now();
    for (status, expired, op) in [(Status::Suspended, false, 91), (Status::Active, true, 92)] {
        let mut next = world
            .c
            .host
            .store
            .check_successor(
                &world.c.host.coordinator(),
                &origin.membership_id,
                status,
                None,
                now,
            )
            .expect("a successor");
        if expired {
            next.not_after = now - 1;
        }
        let (envelope, _) = world
            .c
            .host
            .store
            .transition(
                &Applying::for_tests(op),
                &world.c.host.coordinator(),
                &next,
                now,
            )
            .expect("issued");
        world.served.lock().expect("lock").origins[0].manifest = envelope;
        let engine = Arc::new(Engine::default());
        assert_eq!(world.pass(&engine).await, 0, "{status:?} expired={expired}");
        assert!(engine.ingested.lock().expect("lock").is_empty());
        if status == Status::Suspended {
            let resumed = world
                .c
                .host
                .store
                .check_successor(
                    &world.c.host.coordinator(),
                    &origin.membership_id,
                    Status::Active,
                    None,
                    now,
                )
                .expect("a successor");
            world
                .c
                .host
                .store
                .transition(
                    &Applying::for_tests(93),
                    &world.c.host.coordinator(),
                    &resumed,
                    now,
                )
                .expect("resumed");
        }
    }

    // The checkpoint verified on every pass is the one freshness counts from.
    let world = world_of("import-refreshed").await;
    let engine = Arc::new(Engine::default());
    *engine.state.lock().expect("lock") = Some(State {
        membership_id: world.import_id,
        revision: [0; 32],
        checkpoint: Vec::new(),
        verified_at: 1,
        gaps: Vec::new(),
    });
    world.pass(&engine).await;
    let state = engine.state.lock().expect("lock").clone().expect("kept");
    assert!(
        state.verified_at > 1,
        "the instant of this pass's verification"
    );
    assert!(!state.checkpoint.is_empty());
}
