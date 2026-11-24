// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`SlotStore`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! what it keeps survives its own restart and who may read it, in its own tests.
//!
//! | Case                           | Rule of the contract                                     |
//! | ------------------------------ | -------------------------------------------------------- |
//! | `nothing_is_kept`              | no slot holds anything                                   |
//! | `a_slot_is_filled_once`        | a second fill is refused and changes nothing             |
//! | `kinds_are_apart`              | a slot's key is not its reference                        |
//! | `what_fills_a_slot_is_replaced` | by the custody that sealed it, never by a fill          |
//! | `a_slot_is_emptied`            | and filled again by the next key                         |
//! | `what_is_no_slot_is_refused`   | by every call, whatever it names                         |
//! | `fills_together_fill_once`     | one key fills the slot, the others are refused           |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use super::{Kind, SlotStore};
use crate::keys::KeyError;

const SLOT: &str = "4mZ-x_7Q";

fn held<S: SlotStore + ?Sized>(store: &S, kind: Kind, slot: &str) -> Option<Vec<u8>> {
    store.read(kind, slot).expect("the slot reads")
}

fn listed<S: SlotStore + ?Sized>(store: &S, kind: Kind) -> Vec<String> {
    let mut slots = store.slots(kind).expect("the slots read");
    slots.sort();
    slots
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: SlotStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    nothing_is_kept(&*make());
    a_slot_is_filled_once(&*make());
    kinds_are_apart(&*make());
    what_fills_a_slot_is_replaced(&*make());
    a_slot_is_emptied(&*make());
    what_is_no_slot_is_refused(&*make());
    fills_together_fill_once(&*make());
}

fn nothing_is_kept<S: SlotStore + ?Sized>(store: &S) {
    for kind in [Kind::Key, Kind::Reference] {
        assert_eq!(held(store, kind, SLOT), None);
        assert!(listed(store, kind).is_empty());
        store
            .empty(kind, SLOT)
            .expect("nothing to empty is no error");
        assert!(!store.place(kind, SLOT).is_empty());
    }
}

fn a_slot_is_filled_once<S: SlotStore + ?Sized>(store: &S) {
    store
        .fill(Kind::Key, SLOT, b"the first key")
        .expect("filled");
    assert_eq!(
        held(store, Kind::Key, SLOT).as_deref(),
        Some(&b"the first key"[..])
    );
    for again in [&b"the first key"[..], b"another key"] {
        assert!(
            matches!(
                store.fill(Kind::Key, SLOT, again),
                Err(KeyError::Exists(slot)) if slot == SLOT
            ),
            "a slot that holds a key takes no other, not even the same"
        );
    }
    assert_eq!(
        held(store, Kind::Key, SLOT).as_deref(),
        Some(&b"the first key"[..]),
        "the refusal changed nothing"
    );
    store
        .fill(Kind::Key, "2", b"an epoch's key")
        .expect("filled");
    assert_eq!(listed(store, Kind::Key), vec!["2", SLOT]);
}

fn kinds_are_apart<S: SlotStore + ?Sized>(store: &S) {
    store.fill(Kind::Key, SLOT, b"a key").expect("filled");
    assert_eq!(held(store, Kind::Reference, SLOT), None);
    assert!(listed(store, Kind::Reference).is_empty());
    store
        .fill(Kind::Reference, SLOT, b"a label")
        .expect("a reference beside a key");
    store
        .fill(Kind::Reference, "9", b"another label")
        .expect("filled");
    assert_eq!(held(store, Kind::Key, SLOT).as_deref(), Some(&b"a key"[..]));
    assert_eq!(
        held(store, Kind::Reference, SLOT).as_deref(),
        Some(&b"a label"[..])
    );
    assert_eq!(listed(store, Kind::Key), vec![SLOT]);
    assert_eq!(listed(store, Kind::Reference), vec![SLOT, "9"]);
    store.empty(Kind::Reference, SLOT).expect("emptied");
    assert_eq!(held(store, Kind::Key, SLOT).as_deref(), Some(&b"a key"[..]));
}

fn what_fills_a_slot_is_replaced<S: SlotStore + ?Sized>(store: &S) {
    store
        .fill(Kind::Key, SLOT, b"in the clear")
        .expect("filled");
    store
        .replace(Kind::Key, SLOT, b"sealed, and longer than it was")
        .expect("replaced");
    assert_eq!(
        held(store, Kind::Key, SLOT).as_deref(),
        Some(&b"sealed, and longer than it was"[..])
    );
    store
        .replace(Kind::Key, SLOT, b"rewrapped")
        .expect("replaced");
    assert_eq!(
        held(store, Kind::Key, SLOT).as_deref(),
        Some(&b"rewrapped"[..])
    );
    assert_eq!(listed(store, Kind::Key), vec![SLOT]);
    assert!(matches!(
        store.fill(Kind::Key, SLOT, b"a fill"),
        Err(KeyError::Exists(_))
    ));
    // A slot that holds nothing holds what it is replaced with, and is filled from then on.
    store.replace(Kind::Key, "2", b"kept").expect("replaced");
    assert_eq!(held(store, Kind::Key, "2").as_deref(), Some(&b"kept"[..]));
    assert!(matches!(
        store.fill(Kind::Key, "2", b"a fill"),
        Err(KeyError::Exists(_))
    ));
}

fn a_slot_is_emptied<S: SlotStore + ?Sized>(store: &S) {
    store.fill(Kind::Key, SLOT, b"retired").expect("filled");
    store.fill(Kind::Key, "2", b"kept").expect("filled");
    store.empty(Kind::Key, SLOT).expect("emptied");
    store.empty(Kind::Key, SLOT).expect("twice");
    assert_eq!(held(store, Kind::Key, SLOT), None);
    assert_eq!(listed(store, Kind::Key), vec!["2"]);
    // Emptied, it is a slot nothing was ever generated in.
    store.fill(Kind::Key, SLOT, b"the next").expect("filled");
    assert_eq!(
        held(store, Kind::Key, SLOT).as_deref(),
        Some(&b"the next"[..])
    );
}

fn what_is_no_slot_is_refused<S: SlotStore + ?Sized>(store: &S) {
    for slot in ["", "../escape", "a/b", "a.key", "with space"] {
        let refused = |said: Result<(), KeyError>| {
            assert!(matches!(said, Err(KeyError::Malformed(_))), "`{slot}`");
        };
        refused(store.read(Kind::Key, slot).map(drop));
        refused(store.fill(Kind::Key, slot, b"x"));
        refused(store.replace(Kind::Key, slot, b"x"));
        refused(store.empty(Kind::Key, slot));
    }
    assert!(listed(store, Kind::Key).is_empty(), "and nothing was kept");
}

fn fills_together_fill_once<S: SlotStore + ?Sized>(store: &S) {
    const THREADS: u8 = 8;
    const ROUNDS: usize = 6;
    for round in 0..ROUNDS {
        let slot = format!("together-{round}");
        let filled = AtomicUsize::new(0);
        let winner = Mutex::new(None);
        let together = Barrier::new(usize::from(THREADS));
        std::thread::scope(|scope| {
            for thread in 1..=THREADS {
                let (slot, filled, winner, together) = (&slot, &filled, &winner, &together);
                scope.spawn(move || {
                    together.wait();
                    match store.fill(Kind::Key, slot, &[thread; 48]) {
                        Ok(()) => {
                            filled.fetch_add(1, Ordering::Relaxed);
                            *winner.lock().expect("lock") = Some(thread);
                        }
                        Err(KeyError::Exists(_)) => {}
                        Err(other) => panic!("a fill answered {other}"),
                    }
                });
            }
        });
        assert_eq!(filled.load(Ordering::Relaxed), 1, "one key fills a slot");
        let winner = winner.into_inner().expect("lock").expect("one filled it");
        assert_eq!(
            held(store, Kind::Key, &slot),
            Some(vec![winner; 48]),
            "and it is the key that was answered filled"
        );
    }
}
