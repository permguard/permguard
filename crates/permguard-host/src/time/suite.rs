// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`ClockMark`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! its mark survives its own restart and what it does of one damaged at rest, in its own tests.
//!
//! | Case                             | Rule of the contract                                   |
//! | -------------------------------- | ------------------------------------------------------ |
//! | `no_mark_was_kept`               | a store that never kept one answers none               |
//! | `a_mark_only_rises`              | a mark not above the one held changes nothing          |
//! | `raises_together_keep_the_highest` | a lower mark never replaces a higher one             |

#![allow(clippy::expect_used)]

use std::sync::{Arc, Barrier};

use super::ClockMark;

const START: i64 = 1_800_000_000;

fn read<S: ClockMark + ?Sized>(store: &S) -> Option<i64> {
    store.read().expect("the mark reads")
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: ClockMark + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    no_mark_was_kept(&*make());
    a_mark_only_rises(&*make());
    raises_together_keep_the_highest(&*make());
}

fn no_mark_was_kept<S: ClockMark + ?Sized>(store: &S) {
    assert_eq!(read(store), None);
    assert!(!store.remedy().is_empty(), "an operator is told what to do");
}

fn a_mark_only_rises<S: ClockMark + ?Sized>(store: &S) {
    store.raise(START).expect("raised");
    assert_eq!(read(store), Some(START));
    store.raise(START + 60).expect("raised");
    assert_eq!(read(store), Some(START + 60));
    store.raise(START + 60).expect("the same mark");
    store.raise(START).expect("a lower mark is no error");
    assert_eq!(read(store), Some(START + 60), "and changes nothing");
}

fn raises_together_keep_the_highest<S: ClockMark + ?Sized>(store: &S) {
    const THREADS: i64 = 8;
    const ROUNDS: i64 = 6;
    for round in 1..=ROUNDS {
        let base = START + round * 1_000;
        let together = Barrier::new(THREADS as usize);
        std::thread::scope(|scope| {
            for thread in 1..=THREADS {
                let together = &together;
                scope.spawn(move || {
                    together.wait();
                    store.raise(base + thread).expect("raised");
                });
            }
        });
        assert_eq!(read(store), Some(base + THREADS), "the highest mark raised");
    }
}
