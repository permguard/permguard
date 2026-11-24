// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`Trails`]: what every backend of the audit engine's storage does
//! the same way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes the trails of one empty Host and runs every case on trails
//! of its own. A case panics with what it expected, as a test does. What a record must be and
//! who may write it are the engine's, proven by its own tests on a backend that passes this
//! suite; a backend proves what only it can, that its trails survive its own restart, in its
//! own tests.
//!
//! | Case                                  | Rule of the contract                                    |
//! | ------------------------------------- | ------------------------------------------------------- |
//! | `nothing_is_held`                     | no trail is listed, and none is there to read           |
//! | `a_trail_continues_where_it_was_left` | sequence and chain go on across holds                   |
//! | `trails_are_apart_and_listed`         | each `(class, resource)` its own chain; all are listed  |
//! | `a_seal_closes_a_day`                 | a sealed day takes no record; its checkpoint is kept    |
//! | `a_checkpoint_is_published_once`      | the same again is the first; another is refused         |
//! | `retention_leaves_an_anchor`          | sealed days past retention go; the anchor says from where |
//! | `appends_together_keep_one_chain`     | no sequence twice, no record lost, one chain            |

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use permguard_core::domains::protected;
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;

use super::Class;
use super::checkpoint::{Checkpoint, CheckpointSigner, file_name, read_unverified, witness_name};
use super::record::{AuditRecord, genesis};
use super::store::Trails;
use super::trail::{self, DAY_SUFFIX};

const RESOURCE: &str = "plane/control";
const OTHER: &str = "plane/control/zone/z1";
/// 2026-11-20T12:00:00Z.
const DAY_1: u64 = 1_795_176_000;
const DAY: u64 = 86_400;

/// A signer for the suite: the envelope reads as a checkpoint, and nothing here verifies it.
struct SuiteSigner;

impl CheckpointSigner for SuiteSigner {
    fn seal(&self, checkpoint: &mut Checkpoint) -> Result<Vec<u8>, String> {
        checkpoint.key_set_epoch = 1;
        let payload = checkpoint.encode().map_err(|error| error.to_string())?;
        Sign1::sign_with(
            Suite::Ed25519Sha256V1,
            protected::AUDIT_CHECKPOINT,
            b"suite",
            payload,
            |_| Ok::<_, String>(vec![0; 64]),
        )
        .map_err(|error| error.to_string())?
        .encode()
        .map_err(|error| error.to_string())
    }
}

fn record(class: Class, resource: &str, at: u64, target: &str) -> AuditRecord {
    AuditRecord {
        trail: format!("{}:{resource}", class.as_str()),
        seq: 0,
        operation_id: None,
        phase: None,
        host_id: [1; 16],
        boot_id: [2; 16],
        component: "host".to_owned(),
        action: "suite.recorded".to_owned(),
        principal: "system:suite".to_owned(),
        resource: resource.to_owned(),
        target: Some(target.to_owned()),
        outcome: "ok".to_owned(),
        facts: BTreeMap::new(),
        build: "9.9.9".to_owned(),
        config_revision: Digest::compute(b"settings"),
        at,
        monotonic_offset: 0,
        previous: genesis(),
    }
}

/// Appends one record at `at` and answers the sequence it was given.
fn append<T: Trails + ?Sized>(
    trails: &T,
    class: Class,
    resource: &str,
    retention: Option<Duration>,
    at: u64,
    target: &str,
) -> u64 {
    let mut given = None;
    trails
        .hold(class, resource, retention, &mut |trail| {
            trail
                .append(record(class, resource, at, target))
                .expect("appended");
            given = Some(trail.next_seq() - 1);
            true
        })
        .expect("held");
    given.expect("the work ran")
}

fn day(at: u64) -> String {
    trail::day_name(at)
}

/// Runs every case, each on the trails `make` has just made empty.
pub fn run<T: Trails + ?Sized>(make: &dyn Fn() -> Arc<T>) {
    nothing_is_held(&*make());
    a_trail_continues_where_it_was_left(&*make());
    trails_are_apart_and_listed(&*make());
    a_seal_closes_a_day(&*make());
    a_checkpoint_is_published_once(&*make());
    retention_leaves_an_anchor(&*make());
    appends_together_keep_one_chain(&*make());
}

fn nothing_is_held<T: Trails + ?Sized>(trails: &T) {
    assert!(trails.held().expect("listed").is_empty());
    assert!(
        trails
            .view(Class::Security, RESOURCE)
            .expect("answered")
            .is_none(),
        "reading a trail never creates it"
    );
    assert!(trails.held().expect("listed").is_empty());
}

fn a_trail_continues_where_it_was_left<T: Trails + ?Sized>(trails: &T) {
    for (n, target) in ["a", "b", "c"].into_iter().enumerate() {
        assert_eq!(
            append(
                trails,
                Class::Security,
                RESOURCE,
                None,
                DAY_1 + n as u64,
                target
            ),
            n as u64
        );
    }
    let mut continued = None;
    trails
        .hold(Class::Security, RESOURCE, None, &mut |trail| {
            continued = Some((trail.next_seq(), trail.head().clone(), trail.state()));
            true
        })
        .expect("held");
    let (next_seq, head, state) = continued.expect("the work ran");
    assert_eq!(next_seq, 3);
    assert_eq!(state.last_day.as_deref(), Some(day(DAY_1).as_str()));

    let view = trails
        .view(Class::Security, RESOURCE)
        .expect("answered")
        .expect("the trail is held");
    assert_eq!(view.days().expect("days"), [day(DAY_1)]);
    let records = trail::read_day(view.as_ref(), &day(DAY_1)).expect("the day reads");
    assert_eq!(
        records
            .iter()
            .map(|record| (record.seq, record.target.as_deref()))
            .collect::<Vec<_>>(),
        [(0, Some("a")), (1, Some("b")), (2, Some("c"))]
    );
    assert_eq!(records[0].previous, genesis());
    assert_eq!(records[2].digest().expect("a digest"), head);
    assert_eq!(trail::verify(view.as_ref()).expect("one chain"), 3);
    assert_eq!(view.anchor().expect("answered"), None);
    assert!(view.checkpoint_names().expect("names").is_empty());
}

fn trails_are_apart_and_listed<T: Trails + ?Sized>(trails: &T) {
    append(trails, Class::Security, RESOURCE, None, DAY_1, "a");
    append(trails, Class::Security, OTHER, None, DAY_1, "b");
    append(trails, Class::Operations, RESOURCE, None, DAY_1, "c");
    append(trails, Class::Security, RESOURCE, None, DAY_1, "d");
    let mut held: Vec<(Class, Result<String, String>)> = trails
        .held()
        .expect("listed")
        .into_iter()
        .map(|(class, digest, resource)| {
            if let Ok(resource) = &resource {
                assert_eq!(digest, trail::resource_digest(resource));
            }
            (class, resource)
        })
        .collect();
    held.sort_by(|a, b| (a.0.as_str(), &a.1).cmp(&(b.0.as_str(), &b.1)));
    assert_eq!(
        held,
        [
            (Class::Operations, Ok(RESOURCE.to_owned())),
            (Class::Security, Ok(RESOURCE.to_owned())),
            (Class::Security, Ok(OTHER.to_owned())),
        ]
    );
    for (class, resource, expected) in [
        (Class::Security, RESOURCE, 2),
        (Class::Security, OTHER, 1),
        (Class::Operations, RESOURCE, 1),
    ] {
        let view = trails
            .view(class, resource)
            .expect("answered")
            .expect("held");
        assert_eq!(trail::verify(view.as_ref()).expect("a chain"), expected);
    }
}

fn a_seal_closes_a_day<T: Trails + ?Sized>(trails: &T) {
    append(trails, Class::Security, RESOURCE, None, DAY_1, "a");
    append(trails, Class::Security, RESOURCE, None, DAY_1 + 1, "b");
    append(trails, Class::Security, RESOURCE, None, DAY_1 + DAY, "c");
    let mut written = Vec::new();
    trails
        .hold(Class::Security, RESOURCE, None, &mut |trail| {
            written = trail
                .seal_before(&day(DAY_1 + DAY), &SuiteSigner, [1; 16], DAY_1 + DAY)
                .expect("sealed");
            true
        })
        .expect("held");
    let first = file_name(&trail::period_of(&day(DAY_1)), None);
    assert_eq!(written, std::slice::from_ref(&first));
    // Sealed again: nothing more to seal.
    trails
        .hold(Class::Security, RESOURCE, None, &mut |trail| {
            assert!(
                trail
                    .seal_before(&day(DAY_1 + DAY), &SuiteSigner, [1; 16], DAY_1 + DAY)
                    .expect("sealed")
                    .is_empty()
            );
            assert_eq!(trail.newest_checkpoint(), Some(first.as_str()));
            true
        })
        .expect("held");
    let view = trails
        .view(Class::Security, RESOURCE)
        .expect("answered")
        .expect("held");
    let envelope = view
        .checkpoint(&first)
        .expect("answered")
        .expect("the seal is kept");
    let seal = read_unverified(&envelope).expect("a checkpoint");
    assert_eq!((seal.first_seq, seal.last_seq), (0, 1));
    assert_eq!(seal.trail, format!("security:{RESOURCE}"));

    // The wall clock steps back into the sealed day: the record goes after what is held.
    assert_eq!(
        append(trails, Class::Security, RESOURCE, None, DAY_1 + 2, "late"),
        3
    );
    assert_eq!(
        trail::read_day(view.as_ref(), &day(DAY_1))
            .expect("the sealed day reads")
            .len(),
        2,
        "a sealed day takes no record"
    );
    assert_eq!(trail::verify(view.as_ref()).expect("one chain"), 4);

    // An on-demand checkpoint covers the last record, chained to the seal, and is not repeated.
    let mut on_demand = Vec::new();
    trails
        .hold(Class::Security, RESOURCE, None, &mut |trail| {
            on_demand = trail
                .checkpoint_now(&day(DAY_1 + DAY), &SuiteSigner, [1; 16], DAY_1 + DAY + 9)
                .expect("checkpointed");
            assert!(
                trail
                    .checkpoint_now(&day(DAY_1 + DAY), &SuiteSigner, [1; 16], DAY_1 + DAY + 9)
                    .expect("checkpointed")
                    .is_empty()
            );
            true
        })
        .expect("held");
    assert_eq!(on_demand.len(), 1);
    let covering = read_unverified(
        &view
            .checkpoint(&on_demand[0])
            .expect("answered")
            .expect("kept"),
    )
    .expect("a checkpoint");
    assert_eq!(covering.last_seq, 3);
    assert_eq!(
        covering.previous_checkpoint,
        super::checkpoint::envelope_digest(&envelope)
    );
}

fn a_checkpoint_is_published_once<T: Trails + ?Sized>(trails: &T) {
    append(trails, Class::Security, RESOURCE, None, DAY_1, "a");
    let view = trails
        .view(Class::Security, RESOURCE)
        .expect("answered")
        .expect("held");
    let name = file_name("2026-11-20", None);
    let cosigned = witness_name(&name);
    view.publish_checkpoint(&name, b"an envelope")
        .expect("kept");
    view.publish_checkpoint(&name, b"an envelope")
        .expect("the same again is the first");
    assert!(
        view.publish_checkpoint(&name, b"another").is_err(),
        "a checkpoint is never replaced"
    );
    view.publish_checkpoint(&cosigned, b"a co-signature")
        .expect("kept beside it");
    let mut names = view.checkpoint_names().expect("names");
    names.sort();
    let mut expected = vec![name.clone(), cosigned.clone()];
    expected.sort();
    assert_eq!(names, expected);
    assert_eq!(
        view.checkpoint(&name).expect("answered").as_deref(),
        Some(&b"an envelope"[..])
    );
    assert_eq!(view.checkpoint("2026-11-21.cose").expect("answered"), None);
}

fn retention_leaves_an_anchor<T: Trails + ?Sized>(trails: &T) {
    let retention = Some(Duration::from_secs(2 * DAY));
    for n in 0..5u64 {
        append(
            trails,
            Class::Operations,
            RESOURCE,
            retention,
            DAY_1 + n * DAY,
            "kept",
        );
    }
    let today = day(DAY_1 + 4 * DAY);
    let mut anchor = None;
    trails
        .hold(Class::Operations, RESOURCE, retention, &mut |trail| {
            trail
                .seal_before(&today, &SuiteSigner, [1; 16], DAY_1 + 4 * DAY)
                .expect("sealed");
            anchor = trail.prune(&today, None).expect("pruned");
            true
        })
        .expect("held");
    let anchor = anchor.expect("days past the retention went");
    // Days 0 and 1 are older than two days before today; days 2, 3 and today stay.
    assert_eq!(anchor.low_watermark, 2);
    assert_eq!(anchor.through, trail::period_of(&day(DAY_1 + DAY)));
    let view = trails
        .view(Class::Operations, RESOURCE)
        .expect("answered")
        .expect("held");
    assert_eq!(
        view.days().expect("days"),
        [day(DAY_1 + 2 * DAY), day(DAY_1 + 3 * DAY), today.clone()]
    );
    assert_eq!(
        trail::anchor(view.as_ref()).expect("answered"),
        Some(anchor)
    );
    assert_eq!(
        trail::verify(view.as_ref()).expect("what is left is one chain"),
        3
    );
    // The seals of the days that went are kept: the anchor names one.
    assert!(
        view.checkpoint(&file_name(&trail::period_of(&day(DAY_1 + DAY)), None))
            .expect("answered")
            .is_some()
    );
    // And the trail goes on from where it was.
    assert_eq!(
        append(
            trails,
            Class::Operations,
            RESOURCE,
            retention,
            DAY_1 + 4 * DAY + 1,
            "next"
        ),
        5
    );
    assert!(today.ends_with(DAY_SUFFIX));
}

fn appends_together_keep_one_chain<T: Trails + ?Sized>(trails: &T) {
    const THREADS: usize = 8;
    const EACH: usize = 12;
    let together = Barrier::new(THREADS);
    let given: Vec<u64> = std::thread::scope(|scope| {
        let running: Vec<_> = (0..THREADS)
            .map(|thread| {
                let together = &together;
                scope.spawn(move || {
                    together.wait();
                    (0..EACH)
                        .map(|n| {
                            append(
                                trails,
                                Class::Security,
                                RESOURCE,
                                None,
                                DAY_1,
                                &format!("t{thread}n{n}"),
                            )
                        })
                        .collect::<Vec<u64>>()
                })
            })
            .collect();
        running
            .into_iter()
            .flat_map(|thread| thread.join().expect("a writer finished"))
            .collect()
    });
    let mut sorted = given.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        (0..(THREADS * EACH) as u64).collect::<Vec<_>>(),
        "every record its own sequence, none twice and none skipped"
    );
    let view = trails
        .view(Class::Security, RESOURCE)
        .expect("answered")
        .expect("held");
    assert_eq!(
        trail::verify(view.as_ref()).expect("one chain"),
        (THREADS * EACH) as u64
    );
}
