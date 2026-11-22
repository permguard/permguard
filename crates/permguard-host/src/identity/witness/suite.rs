// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`VersionWitnesses`]: what every backend of the contract does the
//! same way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! its entries survive its own restart, in its own tests.
//!
//! | Case                            | Rule of the contract                                      |
//! | ------------------------------- | --------------------------------------------------------- |
//! | `nothing_is_kept`               | a change is given no entry                                |
//! | `a_change_is_kept_when_it_says` | what it left is what the next is given; else nothing is   |
//! | `scopes_are_apart`              | a realm's entries are not the server's, nor another's     |
//! | `updates_together_lose_none`    | each is given what the one before it kept                 |

#![allow(clippy::expect_used)]

use std::sync::{Arc, Barrier};

use super::VersionWitnesses;

fn held<S: VersionWitnesses + ?Sized>(store: &S, realm: Option<&str>) -> Vec<(String, String)> {
    let mut read = Vec::new();
    store
        .update(realm, &mut |entries| {
            read.clone_from(entries);
            false
        })
        .expect("reads");
    read
}

fn entry(label: &str, witness: &str) -> (String, String) {
    (label.to_owned(), witness.to_owned())
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: VersionWitnesses + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    nothing_is_kept(&*make());
    a_change_is_kept_when_it_says(&*make());
    scopes_are_apart(&*make());
    updates_together_lose_none(&*make());
}

fn nothing_is_kept<S: VersionWitnesses + ?Sized>(store: &S) {
    assert!(held(store, None).is_empty());
    assert!(held(store, Some("acme")).is_empty());
    assert!(!store.place(None).is_empty());
    assert_ne!(store.place(None), store.place(Some("acme")));
}

fn a_change_is_kept_when_it_says<S: VersionWitnesses + ?Sized>(store: &S) {
    store
        .update(None, &mut |entries| {
            entries.push(entry("v1@host", "w1"));
            true
        })
        .expect("kept");
    assert_eq!(held(store, None), vec![entry("v1@host", "w1")]);
    // A change that says it changed nothing leaves what was kept, whatever it did to its copy.
    store
        .update(None, &mut |entries| {
            entries.clear();
            false
        })
        .expect("answered");
    assert_eq!(held(store, None), vec![entry("v1@host", "w1")]);
    // Entries are kept in the order they were left in, a label renamed in place.
    store
        .update(None, &mut |entries| {
            entries[0].0 = "v1@retired".to_owned();
            entries.push(entry("v1@next", "w2"));
            true
        })
        .expect("kept");
    assert_eq!(
        held(store, None),
        vec![entry("v1@retired", "w1"), entry("v1@next", "w2")]
    );
}

fn scopes_are_apart<S: VersionWitnesses + ?Sized>(store: &S) {
    for (realm, witness) in [
        (None, "server"),
        (Some("acme"), "acme"),
        (Some("globex"), "globex"),
    ] {
        store
            .update(realm, &mut |entries| {
                assert!(entries.is_empty(), "another scope's entries are not given");
                entries.push(entry("v1", witness));
                true
            })
            .expect("kept");
    }
    assert_eq!(held(store, None), vec![entry("v1", "server")]);
    assert_eq!(held(store, Some("acme")), vec![entry("v1", "acme")]);
    assert_eq!(held(store, Some("globex")), vec![entry("v1", "globex")]);
}

fn updates_together_lose_none<S: VersionWitnesses + ?Sized>(store: &S) {
    const THREADS: usize = 8;
    const EACH: usize = 6;
    let together = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let together = &together;
            scope.spawn(move || {
                together.wait();
                for n in 0..EACH {
                    store
                        .update(Some("together"), &mut |entries| {
                            entries.push(entry(&format!("v{thread}-{n}"), "w"));
                            true
                        })
                        .expect("kept");
                }
            });
        }
    });
    assert_eq!(
        held(store, Some("together")).len(),
        THREADS * EACH,
        "no entry was lost to an update that read before another wrote"
    );
}
