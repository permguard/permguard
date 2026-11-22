// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suites of [`WitnessStore`] and [`DeliveredKeys`]: what every backend of each
//! contract does the same way (`1-architecture/8` Store contracts).
//!
//! Each `run` takes how a backend makes one empty store and runs every case on a store of its
//! own. A case panics with what it expected, as a test does. A backend proves what only it can,
//! that what it keeps survives its own restart and how it keeps a key from other readers, in its
//! own tests.
//!
//! | Suite     | Case                               | Rule of the contract                              |
//! | --------- | ---------------------------------- | ------------------------------------------------- |
//! | witnesses | `the_first_witness_stays`          | a later witness under a name is answered the first |
//! | witnesses | `names_are_apart`                  | a name of several parts is not one of its parts   |
//! | witnesses | `witnesses_together_keep_one`      | every caller is answered the one that was kept    |
//! | delivered | `no_key_was_delivered`             | none is held, none is listed                      |
//! | delivered | `the_first_key_stays`              | a later key under a tuple is answered the first   |
//! | delivered | `keys_are_listed_by_their_version` | by authority, purpose and version                 |
//! | delivered | `keys_together_keep_one`           | every caller is answered the one that was kept    |

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::{Arc, Barrier, Mutex};

use permguard_objects::crypto::kdf::KEY_LEN;

use super::{DeliveredKeys, KeyVersion, WitnessStore, ZonePurpose, ZoneTuple};

fn name(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// Runs every case of the witnesses, each on a store `make` has just made empty.
pub fn run_witnesses<S: WitnessStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    the_first_witness_stays(&*make());
    names_are_apart(&*make());
    witnesses_together_keep_one(&*make());
}

fn the_first_witness_stays<S: WitnessStore + ?Sized>(store: &S) {
    let at = name(&["audit-pseudonym", "v1"]);
    assert_eq!(store.first(&at, &[1; 32]).expect("kept"), vec![1; 32]);
    assert_eq!(
        store.first(&at, &[1; 32]).expect("the same again"),
        vec![1; 32]
    );
    assert_eq!(
        store.first(&at, &[2; 32]).expect("answered"),
        vec![1; 32],
        "another witness is answered the first, which stays"
    );
    assert_eq!(store.first(&at, &[1; 32]).expect("still"), vec![1; 32]);
}

fn names_are_apart<S: WitnessStore + ?Sized>(store: &S) {
    let first = name(&["by-role", "coordinator", "v1"]);
    let next = name(&["by-role", "coordinator", "v2"]);
    let other = name(&["coordinator", "v1"]);
    assert_eq!(store.first(&first, &[1; 32]).expect("kept"), vec![1; 32]);
    assert_eq!(store.first(&next, &[2; 32]).expect("kept"), vec![2; 32]);
    assert_eq!(store.first(&other, &[3; 32]).expect("kept"), vec![3; 32]);
    assert_eq!(store.first(&first, &[9; 32]).expect("held"), vec![1; 32]);
}

fn witnesses_together_keep_one<S: WitnessStore + ?Sized>(store: &S) {
    const THREADS: u8 = 8;
    const ROUNDS: usize = 6;
    for round in 0..ROUNDS {
        let at = name(&["together", &format!("v{}", round + 1)]);
        let answered = Mutex::new(BTreeSet::new());
        let together = Barrier::new(usize::from(THREADS));
        std::thread::scope(|scope| {
            for thread in 1..=THREADS {
                let (at, answered, together) = (&at, &answered, &together);
                scope.spawn(move || {
                    together.wait();
                    let held = store.first(at, &[thread; 32]).expect("answered");
                    answered.lock().expect("lock").insert(held);
                });
            }
        });
        let answered = answered.into_inner().expect("lock");
        assert_eq!(answered.len(), 1, "every caller is answered one witness");
        let kept = answered.into_iter().next().expect("one");
        assert_eq!(store.first(&at, &[0; 32]).expect("held"), kept);
    }
}

const AUTHORITY: [u8; 16] = [0xa1; 16];
const ZONE: [u8; 16] = [0xb2; 16];

fn version(n: u64) -> KeyVersion {
    KeyVersion::new(n).expect("a version")
}

fn tuple(scope: u8, n: u64) -> ZoneTuple {
    ZoneTuple {
        authority: AUTHORITY,
        zone: ZONE,
        purpose: ZonePurpose::DecisionCommitment,
        scope: [scope; 16],
        version: version(n),
    }
}

/// Runs every case of the delivered keys, each on a store `make` has just made empty.
pub fn run_delivered<S: DeliveredKeys + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    no_key_was_delivered(&*make());
    the_first_key_stays(&*make());
    keys_are_listed_by_their_version(&*make());
    keys_together_keep_one(&*make());
}

fn no_key_was_delivered<S: DeliveredKeys + ?Sized>(store: &S) {
    assert!(store.key(&tuple(1, 1)).expect("reads").is_none());
    assert!(
        store
            .delivered(&AUTHORITY, ZonePurpose::DecisionCommitment, version(1))
            .expect("reads")
            .is_empty()
    );
}

fn the_first_key_stays<S: DeliveredKeys + ?Sized>(store: &S) {
    let at = tuple(1, 1);
    assert_eq!(*store.keep(&at, &[1; KEY_LEN]).expect("kept"), [1; KEY_LEN]);
    assert_eq!(
        store.key(&at).expect("reads").as_deref(),
        Some(&[1; KEY_LEN])
    );
    assert_eq!(
        *store.keep(&at, &[1; KEY_LEN]).expect("the same again"),
        [1; KEY_LEN]
    );
    assert_eq!(
        *store.keep(&at, &[2; KEY_LEN]).expect("answered"),
        [1; KEY_LEN],
        "another key is answered the first, which stays"
    );
    assert_eq!(
        store.key(&at).expect("reads").as_deref(),
        Some(&[1; KEY_LEN])
    );
}

fn keys_are_listed_by_their_version<S: DeliveredKeys + ?Sized>(store: &S) {
    store.keep(&tuple(1, 1), &[1; KEY_LEN]).expect("kept");
    store.keep(&tuple(2, 1), &[2; KEY_LEN]).expect("kept");
    store.keep(&tuple(2, 2), &[3; KEY_LEN]).expect("kept");
    let pseudonyms = ZoneTuple {
        purpose: ZonePurpose::AuditPseudonym,
        scope: ZONE,
        ..tuple(0, 1)
    };
    store.keep(&pseudonyms, &[4; KEY_LEN]).expect("kept");
    let listed = |purpose, n| {
        let mut found = store
            .delivered(&AUTHORITY, purpose, version(n))
            .expect("reads");
        found.sort();
        found
    };
    assert_eq!(
        listed(ZonePurpose::DecisionCommitment, 1),
        vec![tuple(1, 1), tuple(2, 1)]
    );
    assert_eq!(
        listed(ZonePurpose::DecisionCommitment, 2),
        vec![tuple(2, 2)]
    );
    assert_eq!(listed(ZonePurpose::AuditPseudonym, 1), vec![pseudonyms]);
    assert!(listed(ZonePurpose::AuditPseudonym, 2).is_empty());
    assert!(
        store
            .delivered(&[0xee; 16], ZonePurpose::DecisionCommitment, version(1))
            .expect("reads")
            .is_empty(),
        "another authority delivered nothing"
    );
    // Each key is its tuple's.
    assert_eq!(
        store.key(&tuple(2, 2)).expect("reads").as_deref(),
        Some(&[3; KEY_LEN])
    );
}

fn keys_together_keep_one<S: DeliveredKeys + ?Sized>(store: &S) {
    const THREADS: u8 = 8;
    const ROUNDS: u64 = 6;
    for round in 1..=ROUNDS {
        let at = tuple(7, round);
        let answered = Mutex::new(BTreeSet::new());
        let together = Barrier::new(usize::from(THREADS));
        std::thread::scope(|scope| {
            for thread in 1..=THREADS {
                let (at, answered, together) = (&at, &answered, &together);
                scope.spawn(move || {
                    together.wait();
                    let held = store.keep(at, &[thread; KEY_LEN]).expect("answered");
                    answered.lock().expect("lock").insert(*held);
                });
            }
        });
        let answered = answered.into_inner().expect("lock");
        assert_eq!(answered.len(), 1, "every caller is answered one key");
        assert_eq!(
            store.key(&at).expect("reads").map(|key| *key),
            answered.into_iter().next()
        );
    }
}
