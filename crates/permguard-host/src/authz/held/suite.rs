// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`HeldStore`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. The suite's tokens are plain text: the
//! store keeps what it is given and trusts none of it, and `verify` here reads the name a token
//! was written with. A backend proves what only it can, that what it keeps survives its own
//! restart, in its own tests.
//!
//! | Case                              | Rule of the contract                                    |
//! | --------------------------------- | ------------------------------------------------------- |
//! | `nothing_is_kept`                 | no key set, no list                                     |
//! | `a_key_set_replaces_the_one_kept` | the last one kept is the one read                       |
//! | `a_list_is_kept_and_restored`     | every list kept is restored once, as it was given       |
//! | `an_older_list_is_not_kept`       | a list not newer than the one kept changes nothing      |
//! | `what_does_not_verify_is_dropped` | a restore keeps only what `verify` names as it is kept  |
//! | `a_list_is_dropped`               | and a newer or an older one is kept after it            |
//! | `lists_together_keep_the_newest`  | a list that arrives late never replaces a newer one     |

#![allow(clippy::expect_used)]

use std::sync::{Arc, Barrier};

use super::{HeldStore, KeptKeys, Named};

const ISSUER: &str = "https://authority.example";
const OTHER: &str = "https://other.example";

fn named(issuer: &str, list: &str, iat: u64) -> Named {
    Named {
        issuer: issuer.to_owned(),
        uri: format!("{issuer}/authority/v1/status-lists/{list}"),
        iat,
    }
}

/// The token the suite keeps for `named`: its name, in text.
fn token(named: &Named) -> String {
    format!("{}|{}|{}", named.issuer, named.uri, named.iat)
}

/// What a token of the suite names.
fn verify(token: &str) -> Option<Named> {
    let mut parts = token.split('|');
    Some(Named {
        issuer: parts.next()?.to_owned(),
        uri: parts.next()?.to_owned(),
        iat: parts.next()?.parse().ok()?,
    })
}

fn keep<S: HeldStore + ?Sized>(store: &S, named: &Named) -> bool {
    store.keep_list(named, &token(named)).expect("answered")
}

/// The lists the store holds, as a restore reads them, in order.
fn restored<S: HeldStore + ?Sized>(store: &S) -> Vec<Named> {
    let mut lists: Vec<Named> = store
        .restore(&verify)
        .expect("restored")
        .iter()
        .map(|token| verify(token).expect("a token of the suite"))
        .collect();
    lists.sort_by(|a, b| (&a.issuer, &a.uri).cmp(&(&b.issuer, &b.uri)));
    lists
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: HeldStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    nothing_is_kept(&*make());
    a_key_set_replaces_the_one_kept(&*make());
    a_list_is_kept_and_restored(&*make());
    an_older_list_is_not_kept(&*make());
    what_does_not_verify_is_dropped(&*make());
    a_list_is_dropped(&*make());
    lists_together_keep_the_newest(&*make());
}

fn nothing_is_kept<S: HeldStore + ?Sized>(store: &S) {
    assert_eq!(store.keys().expect("reads"), None);
    assert!(restored(store).is_empty());
    store
        .drop_list(ISSUER, "a list never kept")
        .expect("nothing to drop is no error");
}

fn a_key_set_replaces_the_one_kept<S: HeldStore + ?Sized>(store: &S) {
    let first = KeptKeys {
        issuer: ISSUER.to_owned(),
        keys: vec![serde_json::json!({"kid": "k1", "kty": "OKP"})],
    };
    store.keep_keys(&first).expect("kept");
    assert_eq!(store.keys().expect("reads"), Some(first));
    let second = KeptKeys {
        issuer: OTHER.to_owned(),
        keys: vec![
            serde_json::json!({"kid": "k2", "kty": "OKP"}),
            serde_json::json!({"kid": "k3", "kty": "EC"}),
        ],
    };
    store.keep_keys(&second).expect("kept");
    assert_eq!(store.keys().expect("reads"), Some(second));
}

fn a_list_is_kept_and_restored<S: HeldStore + ?Sized>(store: &S) {
    let first = named(ISSUER, "l1", 10);
    let second = named(ISSUER, "l2", 10);
    // The same list of another issuer is another list.
    let foreign = named(OTHER, "l1", 10);
    for list in [&first, &second, &foreign] {
        assert!(keep(store, list));
    }
    assert_eq!(
        restored(store),
        vec![first.clone(), second.clone(), foreign.clone()]
    );
    assert_eq!(
        restored(store),
        vec![first, second, foreign],
        "a restore reads, and keeps what it read"
    );
}

fn an_older_list_is_not_kept<S: HeldStore + ?Sized>(store: &S) {
    assert!(keep(store, &named(ISSUER, "l1", 10)));
    assert!(keep(store, &named(ISSUER, "l1", 20)), "a newer one");
    assert!(!keep(store, &named(ISSUER, "l1", 20)), "the same again");
    assert!(!keep(store, &named(ISSUER, "l1", 15)), "an older one");
    assert_eq!(restored(store), vec![named(ISSUER, "l1", 20)]);
    // What a restore read is what a later list is held against.
    assert!(!keep(store, &named(ISSUER, "l1", 19)));
    assert!(keep(store, &named(ISSUER, "l1", 21)));
    assert_eq!(restored(store), vec![named(ISSUER, "l1", 21)]);
}

fn what_does_not_verify_is_dropped<S: HeldStore + ?Sized>(store: &S) {
    let stays = named(ISSUER, "l1", 10);
    let expired = named(ISSUER, "l2", 10);
    let renamed = named(ISSUER, "l3", 10);
    for list in [&stays, &expired, &renamed] {
        assert!(keep(store, list));
    }
    // One no longer verifies; one verifies as another list than the one it is kept as.
    let tokens = store
        .restore(&|token| {
            let read = verify(token)?;
            if read.uri == expired.uri {
                None
            } else if read.uri == renamed.uri {
                Some(named(ISSUER, "l9", 10))
            } else {
                Some(read)
            }
        })
        .expect("restored");
    assert_eq!(tokens, vec![token(&stays)]);
    assert_eq!(restored(store), vec![stays], "what was dropped is gone");
    // A list dropped is held against nothing: the same one is kept again.
    assert!(keep(store, &expired));
}

fn a_list_is_dropped<S: HeldStore + ?Sized>(store: &S) {
    let dropped = named(ISSUER, "l1", 20);
    let stays = named(ISSUER, "l2", 20);
    assert!(keep(store, &dropped));
    assert!(keep(store, &stays));
    store.drop_list(ISSUER, &dropped.uri).expect("dropped");
    store.drop_list(ISSUER, &dropped.uri).expect("twice");
    assert_eq!(restored(store), vec![stays]);
    assert!(
        keep(store, &named(ISSUER, "l1", 5)),
        "nothing is kept of it: an older one is the only one"
    );
}

fn lists_together_keep_the_newest<S: HeldStore + ?Sized>(store: &S) {
    const THREADS: u64 = 8;
    const ROUNDS: u64 = 6;
    for round in 1..=ROUNDS {
        let list = format!("together-{round}");
        let together = Barrier::new(THREADS as usize);
        std::thread::scope(|scope| {
            for iat in 1..=THREADS {
                let (list, together) = (&list, &together);
                scope.spawn(move || {
                    together.wait();
                    keep(store, &named(ISSUER, list, iat));
                });
            }
        });
        assert!(
            restored(store).contains(&named(ISSUER, &list, THREADS)),
            "the newest list is the one kept"
        );
    }
}
