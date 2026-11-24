// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`CursorRoots`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, how
//! its root is rotated and what it does of one replaced in silence, in its own tests.
//!
//! | Case                              | Rule of the contract                                         |
//! | --------------------------------- | ------------------------------------------------------------ |
//! | `a_root_is_minted_once`           | minted at the first ask, and the same at every ask after     |
//! | `stores_have_their_own_root`      | two stores never share a root                                |
//! | `an_offset_verifies_at_any_asker` | keys opened twice over one store verify each other's offsets |
//! | `asks_together_are_one_root`      | of the first asks that arrive together, one mints            |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};

use permguard_stream::Cursor;

use super::{CursorKeys, CursorRoots};

const HOST: [u8; 16] = [1; 16];

/// How many callers the concurrency case releases at once, and how many times it does.
const TOGETHER: usize = 8;
const ROUNDS: usize = 6;

/// Runs every case, each on a store `make` made empty for it.
pub fn run(make: &dyn Fn() -> Arc<dyn CursorRoots>) {
    a_root_is_minted_once(make().as_ref());
    stores_have_their_own_root(make().as_ref(), make().as_ref());
    an_offset_verifies_at_any_asker(make().as_ref());
    for _ in 0..ROUNDS {
        asks_together_are_one_root(make().as_ref());
    }
}

fn issuing(store: &dyn CursorRoots) -> Vec<u8> {
    store.roots().expect("the root reads").issuing.to_vec()
}

fn a_root_is_minted_once(store: &dyn CursorRoots) {
    let first = store.roots().expect("minted");
    assert!(first.issuing.len() >= permguard_stream::cursor::MIN_KEY_BYTES);
    assert!(first.previous.is_none(), "a fresh store rotated nothing");
    for _ in 0..3 {
        let again = store.roots().expect("read");
        assert_eq!(again.issuing.as_slice(), first.issuing.as_slice());
        assert!(again.previous.is_none());
    }
}

fn stores_have_their_own_root(one: &dyn CursorRoots, other: &dyn CursorRoots) {
    assert_ne!(issuing(one), issuing(other));
}

fn an_offset_verifies_at_any_asker(store: &dyn CursorRoots) {
    let issuer = CursorKeys::open(store, HOST, "api").expect("opened");
    let verifier = CursorKeys::open(store, HOST, "api").expect("opened again");
    let key = issuer.for_resource("acme/main").expect("a key");
    let offset = Cursor::beginning("api", "acme/main", "f", None)
        .seal(&key)
        .expect("an offset");
    Cursor::open(
        &offset,
        &verifier.for_resource("acme/main").expect("a key"),
        "api",
        "acme/main",
        "f",
    )
    .expect("the offset verifies under keys opened apart");
}

fn asks_together_are_one_root(store: &dyn CursorRoots) {
    let barrier = Barrier::new(TOGETHER);
    let answers: Vec<Vec<u8>> = std::thread::scope(|scope| {
        let callers: Vec<_> = (0..TOGETHER)
            .map(|_| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    issuing(store)
                })
            })
            .collect();
        callers
            .into_iter()
            .map(|caller| caller.join().expect("a caller finished"))
            .collect()
    });
    let kept = issuing(store);
    for answer in &answers {
        assert_eq!(
            answer, &kept,
            "a caller was answered a root that was not kept"
        );
    }
}
