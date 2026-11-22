// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`Runs`]: what every backend of a stream consumer's runs does the
//! same way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes the runs of one empty consumer and runs every case on runs
//! of their own. What a frame, a batch or a view holds is the consumer's, proven by its own
//! tests on a backend that passes this suite.
//!
//! | Case                               | Rule of the contract                                    |
//! | ---------------------------------- | ------------------------------------------------------- |
//! | `nothing_is_held`                  | no run is listed, and none is opened without asking    |
//! | `a_journal_keeps_its_frames`       | in order, from where it starts, across opens            |
//! | `a_prefix_goes`                    | below a segment's start; the rest stays where it was     |
//! | `views_are_replaced`               | a run's, a producer's and a resource's, each its own    |
//! | `a_file_is_published_once`         | the same again is the first; others are refused         |
//! | `runs_are_listed`                  | by resource, producer and run                           |
//! | `opens_together_append_one_journal`| one holder at a time: no index given twice              |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};

use super::super::StreamError;
use super::store::Runs;

const COMPONENT: &str = "c0ffee";
const PRODUCER: &str = "0102030405060708090a0b0c0d0e0f10";
const RUN: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0";
const OTHER_RUN: &str = "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";

/// Runs every case, each on the runs `make` has just made empty.
pub fn run<R: Runs + ?Sized>(make: &dyn Fn() -> Arc<R>) {
    nothing_is_held(&*make());
    a_journal_keeps_its_frames(&*make());
    a_prefix_goes(&*make());
    views_are_replaced(&*make());
    a_file_is_published_once(&*make());
    runs_are_listed(&*make());
    opens_together_append_one_journal(&make());
}

fn nothing_is_held<R: Runs + ?Sized>(runs: &R) {
    assert!(runs.components().expect("listed").is_empty());
    assert!(
        runs.open(COMPONENT, PRODUCER, RUN, false)
            .expect("answered")
            .is_none()
    );
    assert!(
        runs.peek(COMPONENT, PRODUCER, RUN)
            .expect("answered")
            .is_none()
    );
    assert!(
        runs.components().expect("listed").is_empty(),
        "a read creates nothing"
    );
    assert_eq!(
        runs.producer_view(COMPONENT, PRODUCER, "FORKED")
            .expect("read"),
        None
    );
    assert_eq!(runs.resource_view(COMPONENT, "IMPORT").expect("read"), None);
}

fn a_journal_keeps_its_frames<R: Runs + ?Sized>(runs: &R) {
    {
        let mut run = runs
            .open(COMPONENT, PRODUCER, RUN, true)
            .expect("opened")
            .expect("made");
        assert_eq!((run.first_index(), run.next_index()), (0, 0));
        assert!(run.frames().expect("read").is_empty());
        for n in 0..5u16 {
            assert_eq!(
                run.append(1 + n % 2, &[n as u8; 3]).expect("appended"),
                u64::from(n)
            );
        }
        assert_eq!(run.next_index(), 5);
    }
    let run = runs
        .open(COMPONENT, PRODUCER, RUN, false)
        .expect("opened")
        .expect("held");
    assert_eq!((run.first_index(), run.next_index()), (0, 5));
    let frames = run.frames().expect("read");
    assert_eq!(
        frames
            .iter()
            .map(|frame| (frame.index, frame.kind, frame.payload.clone()))
            .collect::<Vec<_>>(),
        (0..5u16)
            .map(|n| (u64::from(n), 1 + n % 2, vec![n as u8; 3]))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        run.frames_from(3)
            .expect("read")
            .iter()
            .map(|frame| frame.index)
            .collect::<Vec<_>>(),
        [3, 4]
    );
}

fn a_prefix_goes<R: Runs + ?Sized>(runs: &R) {
    let mut run = runs
        .open(COMPONENT, PRODUCER, RUN, true)
        .expect("opened")
        .expect("made");
    for n in 0..6u8 {
        run.append(1, &[n]).expect("appended");
    }
    let at = run
        .segment_starts()
        .into_iter()
        .filter(|start| *start <= 3)
        .max()
        .expect("a place to end");
    let reached = run.drop_prefix(at).expect("dropped");
    assert_eq!(reached, at);
    assert_eq!(run.first_index(), at);
    assert_eq!(
        run.frames().expect("read").first().map(|frame| frame.index),
        Some(at)
    );
    assert_eq!(run.drop_prefix(0).expect("nothing below"), at);
    drop(run);
    let mut run = runs
        .open(COMPONENT, PRODUCER, RUN, false)
        .expect("opened")
        .expect("held");
    assert_eq!((run.first_index(), run.next_index()), (at, 6));
    assert_eq!(
        run.append(1, &[9]).expect("appended"),
        6,
        "an index is never given again"
    );
}

fn views_are_replaced<R: Runs + ?Sized>(runs: &R) {
    let run = runs
        .open(COMPONENT, PRODUCER, RUN, true)
        .expect("opened")
        .expect("made");
    run.replace_view("STATE", b"first").expect("written");
    run.replace_view("STATE", b"second, longer")
        .expect("replaced");
    assert_eq!(
        run.view("STATE").expect("read").as_deref(),
        Some(&b"second, longer"[..])
    );
    assert_eq!(run.view("ANCHOR").expect("read"), None);
    drop(run);
    let peeked = runs
        .peek(COMPONENT, PRODUCER, RUN)
        .expect("answered")
        .expect("held");
    assert_eq!(
        peeked.view("STATE").expect("read").as_deref(),
        Some(&b"second, longer"[..])
    );
    runs.replace_producer_view(COMPONENT, PRODUCER, "FORKED", b"mark")
        .expect("written");
    runs.replace_resource_view(COMPONENT, "IMPORT", b"state")
        .expect("written");
    assert_eq!(
        runs.producer_view(COMPONENT, PRODUCER, "FORKED")
            .expect("read")
            .as_deref(),
        Some(&b"mark"[..])
    );
    assert_eq!(
        runs.resource_view(COMPONENT, "IMPORT")
            .expect("read")
            .as_deref(),
        Some(&b"state"[..])
    );
    assert_eq!(
        peeked.view("FORKED").expect("read"),
        None,
        "a producer's view is not a run's"
    );
}

fn a_file_is_published_once<R: Runs + ?Sized>(runs: &R) {
    let run = runs
        .open(COMPONENT, PRODUCER, RUN, true)
        .expect("opened")
        .expect("made");
    run.publish("batches", "1-3.jws", b"the batch")
        .expect("published");
    run.publish("batches", "1-3.jws", b"the batch")
        .expect("the same again is the first");
    assert!(matches!(
        run.publish("batches", "1-3.jws", b"another"),
        Err(StreamError::Corruption(_))
    ));
    run.publish("batches", "4-6.jws", b"the next")
        .expect("published");
    run.publish("statements", "ab.cbor", b"a statement")
        .expect("published");
    assert_eq!(
        run.read("batches", "1-3.jws").expect("read").as_deref(),
        Some(&b"the batch"[..])
    );
    assert_eq!(run.read("batches", "7-9.jws").expect("read"), None);
    let mut names = run.names("batches").expect("listed");
    names.sort();
    assert_eq!(names, ["1-3.jws", "4-6.jws"]);
    assert_eq!(run.names("statements").expect("listed"), ["ab.cbor"]);
    run.unlink("batches", &["1-3.jws".to_owned()])
        .expect("unlinked");
    assert_eq!(run.read("batches", "1-3.jws").expect("read"), None);
    assert_eq!(run.names("batches").expect("listed"), ["4-6.jws"]);
    drop(run);
    let peeked = runs
        .peek(COMPONENT, PRODUCER, RUN)
        .expect("answered")
        .expect("held");
    assert_eq!(
        peeked.read("batches", "4-6.jws").expect("read").as_deref(),
        Some(&b"the next"[..])
    );
}

fn runs_are_listed<R: Runs + ?Sized>(runs: &R) {
    for (component, run) in [(COMPONENT, RUN), (COMPONENT, OTHER_RUN), ("beef", RUN)] {
        drop(
            runs.open(component, PRODUCER, run, true)
                .expect("opened")
                .expect("made"),
        );
    }
    let mut components = runs.components().expect("listed");
    components.sort();
    assert_eq!(components, ["beef", COMPONENT]);
    assert_eq!(runs.producers(COMPONENT).expect("listed"), [PRODUCER]);
    let mut held = runs.runs(COMPONENT, PRODUCER).expect("listed");
    held.sort();
    assert_eq!(held, [RUN, OTHER_RUN]);
    assert!(runs.runs("absent", PRODUCER).expect("listed").is_empty());
    runs.release_reserve(COMPONENT, PRODUCER).expect("released");
    runs.keep_reserve(COMPONENT, PRODUCER);
}

fn opens_together_append_one_journal<R: Runs + ?Sized>(runs: &Arc<R>) {
    const THREADS: usize = 6;
    const EACH: usize = 10;
    drop(
        runs.open(COMPONENT, PRODUCER, RUN, true)
            .expect("opened")
            .expect("made"),
    );
    if runs.kept_open() {
        // A backend whose runs are kept open in the process has one writer: the consumer's own
        // lock holds the others out, and opening one run twice is not its contract.
        return;
    }
    let together = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let (runs, together) = (Arc::clone(runs), &together);
            scope.spawn(move || {
                together.wait();
                for n in 0..EACH {
                    let mut run = runs
                        .open(COMPONENT, PRODUCER, RUN, false)
                        .expect("opened")
                        .expect("held");
                    run.append(1, &[thread as u8, n as u8]).expect("appended");
                }
            });
        }
    });
    let run = runs
        .open(COMPONENT, PRODUCER, RUN, false)
        .expect("opened")
        .expect("held");
    let frames = run.frames().expect("read");
    assert_eq!(frames.len(), THREADS * EACH);
    assert!(
        frames
            .iter()
            .enumerate()
            .all(|(n, frame)| frame.index == n as u64),
        "every frame its own index, none twice, none skipped"
    );
}
