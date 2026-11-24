// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`MarkStore`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts, decision E30).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. What only a backend does, a mark that only
//! rises across instances on PostgreSQL, a file that survives a restart on files, is proven in its
//! own tests.
//!
//! | Case                         | Rule of the contract                                          |
//! | ---------------------------- | ------------------------------------------------------------- |
//! | `an_empty_store`             | a store that kept nothing holds no mark                       |
//! | `what_is_kept_is_held`       | every list's mark kept is held, at the value kept             |
//! | `a_mark_kept_higher_is_held` | a list kept again past its mark is held at the higher one     |
//! | `lists_are_apart`            | keeping one list's mark leaves another's named with it as is  |

use std::collections::BTreeMap;
use std::sync::Arc;

use super::MarkStore;

/// Runs every case of the contract, each on a store `make` answers empty.
pub fn run<S: MarkStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    an_empty_store(&*make());
    what_is_kept_is_held(&*make());
    a_mark_kept_higher_is_held(&*make());
    lists_are_apart(&*make());
}

fn an_empty_store<S: MarkStore + ?Sized>(store: &S) {
    assert!(store.held().is_empty(), "a new store holds no mark");
}

fn what_is_kept_is_held<S: MarkStore + ?Sized>(store: &S) {
    let marks = BTreeMap::from([([1; 16], 100), ([2; 16], 200)]);
    store.keep(&marks).expect("kept");
    assert_eq!(store.held(), marks, "every mark kept is held");
}

fn a_mark_kept_higher_is_held<S: MarkStore + ?Sized>(store: &S) {
    store.keep(&BTreeMap::from([([1; 16], 100)])).expect("kept");
    store
        .keep(&BTreeMap::from([([1; 16], 150)]))
        .expect("kept higher");
    assert_eq!(store.held().get(&[1; 16]), Some(&150), "the higher mark");
}

fn lists_are_apart<S: MarkStore + ?Sized>(store: &S) {
    store
        .keep(&BTreeMap::from([([1; 16], 100), ([2; 16], 200)]))
        .expect("kept");
    store
        .keep(&BTreeMap::from([([1; 16], 120), ([2; 16], 200)]))
        .expect("kept again");
    let held = store.held();
    assert_eq!(held.get(&[1; 16]), Some(&120));
    assert_eq!(held.get(&[2; 16]), Some(&200), "the other list as it was");
}
