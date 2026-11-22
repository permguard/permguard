// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`RingStore`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. The suite's records are plain bytes: the
//! store keeps what it is given and trusts none of it, and what an entry must be is
//! [`Ring`](super::Ring)'s, proven by its own tests on a store that passes this suite. A backend
//! proves what only it can, that its records survive its own restart and what it cuts of an
//! entry half written, in its own tests.
//!
//! | Case                               | Rule of the contract                                   |
//! | ---------------------------------- | ------------------------------------------------------ |
//! | `nothing_is_kept`                  | no entry, no view, no binding, no public key           |
//! | `entries_are_added_in_order`       | oldest first, each the item it was added as            |
//! | `a_view_and_a_binding_are_replaced` | the last one written is the one read                  |
//! | `a_binding_is_kept_by_its_entry`   | by the sequence of the entry that records it           |
//! | `a_public_key_is_published_once`   | the same again is the first; another is refused        |
//! | `a_retired_ring_loses_its_entries_first` | then what is built from them; each step leaves the rest |
//! | `public_keys_together_publish_once` | of those that arrive together one is published        |
//! | `entries_together_add_one`         | of the transitions that read one ring, one is added    |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use permguard_objects::cbor::{self, Value};

use super::RingError;
use super::store::RingStore;
use crate::operations::mutation::Applying;

/// How a suite runs something inside one operation of the mutation engine: the token it is
/// given is one the engine built, a new operation at every call.
pub type Operate<'a> = &'a dyn Fn(&mut dyn FnMut(&Applying<'_>));

const OLD: [u8; 16] = [0x0a; 16];

fn item(n: i64) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Int(n),
        Value::Text("entry".to_owned()),
    ]))
    .expect("an item encodes")
}

fn entries<S: RingStore + ?Sized>(store: &S) -> Vec<Vec<u8>> {
    store
        .entries()
        .expect("the entries read")
        .iter()
        .map(|value| cbor::encode(value).expect("encodes"))
        .collect()
}

/// Runs every case, each on a store `make` has just made empty; `operate` runs what it is given
/// inside one operation of the keys' domain.
pub fn run<S: RingStore + ?Sized>(make: &dyn Fn() -> Arc<S>, operate: Operate<'_>) {
    nothing_is_kept(&*make());
    entries_are_added_in_order(&*make());
    a_view_and_a_binding_are_replaced(&*make());
    a_binding_is_kept_by_its_entry(&*make());
    a_public_key_is_published_once(&*make());
    a_retired_ring_loses_its_entries_first(&*make(), operate);
    public_keys_together_publish_once(&*make());
    entries_together_add_one(&*make());
}

fn nothing_is_kept<S: RingStore + ?Sized>(store: &S) {
    assert!(entries(store).is_empty());
    assert_eq!(store.view().expect("reads"), None);
    assert_eq!(store.binding().expect("reads"), None);
    assert_eq!(store.kept_binding(1).expect("reads"), None);
    assert!(store.kept_bindings().expect("reads").is_empty());
    assert_eq!(store.public("thumb").expect("reads"), None);
    store.forget_entries().expect("nothing to forget");
    store.clear().expect("nothing to clear");
}

fn entries_are_added_in_order<S: RingStore + ?Sized>(store: &S) {
    for n in 1..=4 {
        store.append(n as u64, &item(n)).expect("added");
    }
    assert_eq!(entries(store), vec![item(1), item(2), item(3), item(4)]);
    assert_eq!(entries(store).len(), 4, "a read leaves them as they are");
    // An entry is the one after the last: the same sequence again, one skipped and one before
    // the first are refused, and nothing is added.
    for seq in [4, 6, 0, 1] {
        assert!(
            matches!(store.append(seq, &item(99)), Err(RingError::Refused(_))),
            "the entry {seq} does not follow the fourth"
        );
    }
    assert_eq!(entries(store).len(), 4);
    store.append(5, &item(5)).expect("the next one");
    assert_eq!(entries(store).len(), 5);
}

fn a_view_and_a_binding_are_replaced<S: RingStore + ?Sized>(store: &S) {
    store.replace_view(b"view at epoch 1").expect("written");
    store
        .replace_view(b"view at epoch 2, longer")
        .expect("replaced");
    assert_eq!(
        store.view().expect("reads").as_deref(),
        Some(&b"view at epoch 2, longer"[..])
    );
    assert_eq!(
        store.binding().expect("reads"),
        None,
        "a view is no binding"
    );
    store
        .replace_binding(b"binding of epoch 1")
        .expect("written");
    store
        .replace_binding(b"binding of epoch 2")
        .expect("replaced");
    assert_eq!(
        store.binding().expect("reads").as_deref(),
        Some(&b"binding of epoch 2"[..])
    );
    assert!(
        store.kept_bindings().expect("reads").is_empty(),
        "the current binding is not one kept by an entry"
    );
}

fn a_binding_is_kept_by_its_entry<S: RingStore + ?Sized>(store: &S) {
    store.keep_binding(3, b"never recorded").expect("kept");
    // Its entry never reached the store: the next binding of that sequence takes its place.
    store.keep_binding(3, b"bound at 3").expect("replaced");
    store.keep_binding(7, b"bound at 7").expect("kept");
    assert_eq!(
        store.kept_binding(3).expect("reads").as_deref(),
        Some(&b"bound at 3"[..])
    );
    assert_eq!(store.kept_binding(4).expect("reads"), None);
    let mut kept = store.kept_bindings().expect("reads");
    kept.sort();
    assert_eq!(kept, vec![b"bound at 3".to_vec(), b"bound at 7".to_vec()]);
}

fn a_public_key_is_published_once<S: RingStore + ?Sized>(store: &S) {
    store
        .publish_public("thumb-a", b"{\"kid\":\"a\"}")
        .expect("published");
    store
        .publish_public("thumb-a", b"{\"kid\":\"a\"}")
        .expect("the same key again is the first");
    assert!(
        store.publish_public("thumb-a", b"{\"kid\":\"b\"}").is_err(),
        "a published key is never replaced"
    );
    store
        .publish_public("thumb-b", b"{\"kid\":\"b\"}")
        .expect("published");
    assert_eq!(
        store.public("thumb-a").expect("reads").as_deref(),
        Some(&b"{\"kid\":\"a\"}"[..])
    );
    assert_eq!(store.public("thumb-c").expect("reads"), None);
}

fn a_retired_ring_loses_its_entries_first<S: RingStore + ?Sized>(store: &S, operate: Operate<'_>) {
    store.append(1, &item(1)).expect("added");
    store.append(2, &item(2)).expect("added");
    store.replace_view(b"view").expect("written");
    store.replace_binding(b"binding").expect("written");
    store.keep_binding(2, b"bound").expect("kept");
    store.publish_public("thumb", b"jwk").expect("published");
    // Retiring keeps evidence and removes nothing.
    operate(&mut |applying| store.retire(applying, &OLD).expect("retired"));
    assert_eq!(entries(store).len(), 2);
    assert!(store.view().expect("reads").is_some());

    store.forget_entries().expect("forgotten");
    store.forget_entries().expect("twice");
    assert!(entries(store).is_empty(), "it opens as a new ring");
    assert!(
        store.public("thumb").expect("reads").is_some(),
        "the rest stays"
    );
    assert!(store.binding().expect("reads").is_some());

    store.clear().expect("cleared");
    assert_eq!(store.view().expect("reads"), None);
    assert_eq!(store.binding().expect("reads"), None);
    assert!(store.kept_bindings().expect("reads").is_empty());
    assert_eq!(store.public("thumb").expect("reads"), None);

    // The ring of the next identity is written where the last one was, from its first entry.
    assert!(matches!(
        store.append(3, &item(3)),
        Err(RingError::Refused(_))
    ));
    store.append(1, &item(1)).expect("added");
    store
        .publish_public("thumb", b"another jwk")
        .expect("published");
    assert_eq!(entries(store), vec![item(1)]);
}

fn public_keys_together_publish_once<S: RingStore + ?Sized>(store: &S) {
    const THREADS: u8 = 8;
    const ROUNDS: usize = 6;
    for round in 0..ROUNDS {
        let thumbprint = format!("together-{round}");
        let published = AtomicUsize::new(0);
        let together = Barrier::new(usize::from(THREADS));
        std::thread::scope(|scope| {
            for thread in 1..=THREADS {
                let (thumbprint, published, together) = (&thumbprint, &published, &together);
                scope.spawn(move || {
                    together.wait();
                    if store.publish_public(thumbprint, &[thread; 40]).is_ok() {
                        published.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(
            published.load(Ordering::Relaxed),
            1,
            "one key is published under a thumbprint, the others are refused"
        );
        assert!(store.public(&thumbprint).expect("reads").is_some());
    }
}

fn entries_together_add_one<S: RingStore + ?Sized>(store: &S) {
    const THREADS: i64 = 8;
    const ROUNDS: u64 = 6;
    for seq in 1..=ROUNDS {
        let added = AtomicUsize::new(0);
        let together = Barrier::new(THREADS as usize);
        std::thread::scope(|scope| {
            for thread in 1..=THREADS {
                let (added, together) = (&added, &together);
                scope.spawn(move || {
                    together.wait();
                    match store.append(seq, &item(thread)) {
                        Ok(()) => {
                            added.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(RingError::Refused(_)) => {}
                        Err(other) => panic!("an entry answered {other}"),
                    }
                });
            }
        });
        assert_eq!(
            added.load(Ordering::Relaxed),
            1,
            "one transition adds the entry {seq}, the others learn the ring moved"
        );
        assert_eq!(entries(store).len() as u64, seq);
    }
}
