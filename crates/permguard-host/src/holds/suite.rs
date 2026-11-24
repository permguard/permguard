// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`HoldStore`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! its holds survive its own restart and what it does of a hold damaged at rest, in its own
//! tests.
//!
//! | Case                              | Rule of the contract                                    |
//! | --------------------------------- | ------------------------------------------------------- |
//! | `an_empty_store`                  | nothing held, nothing kept, nothing found wrong         |
//! | `a_hold_is_kept_and_read`         | what is added is read whole, listed by id, and keeps    |
//! | `an_id_is_kept_once`              | a second hold of an id is refused and changes nothing   |
//! | `a_release_answers_and_ends`      | a release answers the hold it was; then it is not found |
//! | `an_expired_hold_keeps_nothing`   | held and listed, and the ledger is no longer kept       |
//! | `adds_together_are_all_held`      | holds added at once are all held, none found wrong      |
//! | `releases_together_end_it_once`   | one release of a hold succeeds, however many are tried  |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{Hold, HoldError, HoldStore};
use crate::operations::mutation::Applying;

const NOW: u64 = 1_800_000_000;
const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";
const LEDGER: &str = "01a00000-0000-7000-8000-00000000000b";
const OTHER: &str = "01a00000-0000-7000-8000-00000000000c";

/// How a suite runs something inside one operation of the mutation engine: the token it is
/// given is one the engine built, a new operation at every call, from any thread.
pub type Operate<'a> = &'a (dyn Fn(&mut dyn FnMut(&Applying<'_>)) + Sync);

fn id(n: usize) -> String {
    format!("01b00000-0000-7000-8000-{n:012x}")
}

fn ledger() -> String {
    format!("plane/control/zone/{ZONE}/ledger/{LEDGER}")
}

/// The hold `n` on the suite's ledger, written by the operation `applying`.
fn hold(n: usize, applying: &Applying<'_>) -> Hold {
    Hold {
        id: id(n),
        resource: ledger(),
        owner: "legal@acme".to_owned(),
        reason: "litigation 2026-17".to_owned(),
        created_at: NOW,
        expires_at: None,
        review_at: Some(NOW + 86_400),
        operation: Some(applying.operation_id().to_string()),
    }
}

/// Adds the hold `n` in an operation of its own and answers what was added.
fn added<S: HoldStore + ?Sized>(store: &S, operate: Operate<'_>, n: usize) -> Hold {
    // An engine may run the operation again when its unit of work kept nothing of a first run:
    // what counts is the hold of the last run and what the store said of it.
    let mut made = None;
    operate(&mut |applying| {
        let hold = hold(n, applying);
        let said = store.add(applying, &hold);
        made = Some((hold, said));
    });
    let (hold, said) = made.expect("the operation ran");
    said.expect("added");
    hold
}

/// Releases `id` in an operation of its own and answers what the store said.
fn released<S: HoldStore + ?Sized>(
    store: &S,
    operate: Operate<'_>,
    id: &str,
) -> Result<Hold, HoldError> {
    let mut said = None;
    operate(&mut |applying| said = Some(store.release(applying, id)));
    said.expect("the operation ran")
}

/// Runs every case, each on a store `make` has just made empty; `operate` runs what it is given
/// inside one operation of the holds' domain.
pub fn run<S: HoldStore + ?Sized>(make: &dyn Fn() -> Arc<S>, operate: Operate<'_>) {
    an_empty_store(&*make());
    a_hold_is_kept_and_read(&*make(), operate);
    an_id_is_kept_once(&*make(), operate);
    a_release_answers_and_ends(&*make(), operate);
    an_expired_hold_keeps_nothing(&*make(), operate);
    adds_together_are_all_held(&*make(), operate);
    releases_together_end_it_once(&*make(), operate);
}

fn an_empty_store<S: HoldStore + ?Sized>(store: &S) {
    assert!(store.list().expect("the holds read").is_empty());
    assert!(store.get(&id(1)).expect("the hold reads").is_none());
    assert!(!store.keeps(ZONE, LEDGER, NOW).expect("the holds read"));
    assert!(store.verify().expect("the holds read").is_empty());
    // An id that is not one names no hold: not found, never an error.
    assert!(store.get("../escape").expect("the hold reads").is_none());
}

fn a_hold_is_kept_and_read<S: HoldStore + ?Sized>(store: &S, operate: Operate<'_>) {
    // Added out of order, listed by id.
    let second = added(store, operate, 2);
    let first = added(store, operate, 1);
    assert_eq!(
        store.get(&first.id).expect("the hold reads").as_ref(),
        Some(&first),
        "read whole, with the operation that wrote it"
    );
    assert_eq!(
        store.list().expect("the holds read"),
        vec![first, second],
        "every hold, by id"
    );
    assert!(store.keeps(ZONE, LEDGER, NOW).expect("the holds read"));
    assert!(
        !store.keeps(ZONE, OTHER, NOW).expect("the holds read"),
        "a ledger no hold names"
    );
    assert!(!store.keeps(OTHER, LEDGER, NOW).expect("the holds read"));
    assert!(store.verify().expect("the holds read").is_empty());
}

fn an_id_is_kept_once<S: HoldStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let first = added(store, operate, 1);
    operate(&mut |applying| {
        let mut again = hold(1, applying);
        again.reason = "another reason".to_owned();
        assert!(
            matches!(store.add(applying, &again), Err(HoldError::Invalid(_))),
            "an id that is held is not kept twice"
        );
    });
    assert_eq!(
        store.list().expect("the holds read"),
        vec![first],
        "the refusal changed nothing"
    );
    assert!(store.verify().expect("the holds read").is_empty());
}

fn a_release_answers_and_ends<S: HoldStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let kept = added(store, operate, 1);
    let gone = added(store, operate, 2);
    assert_eq!(
        released(store, operate, &gone.id).expect("released"),
        gone,
        "the hold it was"
    );
    assert!(store.get(&gone.id).expect("the hold reads").is_none());
    assert!(
        matches!(
            released(store, operate, &gone.id),
            Err(HoldError::NotFound(_))
        ),
        "a hold is released once"
    );
    assert!(matches!(
        released(store, operate, &id(9)),
        Err(HoldError::NotFound(_))
    ));
    assert!(matches!(
        released(store, operate, "../escape"),
        Err(HoldError::NotFound(_))
    ));
    // The other hold was never touched, and still keeps.
    assert_eq!(store.list().expect("the holds read"), vec![kept.clone()]);
    assert!(store.keeps(ZONE, LEDGER, NOW).expect("the holds read"));
    assert!(store.verify().expect("the holds read").is_empty());
    released(store, operate, &kept.id).expect("released");
    assert!(!store.keeps(ZONE, LEDGER, NOW).expect("the holds read"));
    assert!(store.list().expect("the holds read").is_empty());
    assert!(store.verify().expect("the holds read").is_empty());
}

fn an_expired_hold_keeps_nothing<S: HoldStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let mut made = None;
    operate(&mut |applying| {
        let mut expiring = hold(1, applying);
        expiring.review_at = None;
        expiring.expires_at = Some(NOW + 60);
        store.add(applying, &expiring).expect("added");
        made = Some(expiring);
    });
    let expiring = made.expect("the operation ran");
    assert!(store.keeps(ZONE, LEDGER, NOW + 59).expect("the holds read"));
    assert!(
        !store.keeps(ZONE, LEDGER, NOW + 60).expect("the holds read"),
        "at its expiry a hold keeps nothing"
    );
    // Expired, and still held until it is released.
    assert_eq!(store.list().expect("the holds read"), vec![expiring]);
}

fn adds_together_are_all_held<S: HoldStore + ?Sized>(store: &S, operate: Operate<'_>) {
    const THREADS: usize = 8;
    const EACH: usize = 6;
    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            scope.spawn(move || {
                for n in 0..EACH {
                    added(store, operate, 1 + thread * EACH + n);
                }
            });
        }
    });
    let listed = store.list().expect("the holds read");
    assert_eq!(listed.len(), THREADS * EACH, "no hold was lost to another");
    let ids: Vec<&str> = listed.iter().map(|hold| hold.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    assert!(
        store.verify().expect("the holds read").is_empty(),
        "and none is held without its record"
    );
}

fn releases_together_end_it_once<S: HoldStore + ?Sized>(store: &S, operate: Operate<'_>) {
    const THREADS: usize = 8;
    const ROUNDS: usize = 6;
    let kept = added(store, operate, 100);
    for round in 0..ROUNDS {
        let held = added(store, operate, 1 + round);
        let won = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| match released(store, operate, &held.id) {
                    Ok(was) => {
                        assert_eq!(was, held);
                        won.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(HoldError::NotFound(_)) => {}
                    Err(other) => panic!("a release answered {other}"),
                });
            }
        });
        assert_eq!(
            won.load(Ordering::Relaxed),
            1,
            "one release ends a hold, the others do not find it"
        );
    }
    assert_eq!(store.list().expect("the holds read"), vec![kept]);
    assert!(store.verify().expect("the holds read").is_empty());
}
