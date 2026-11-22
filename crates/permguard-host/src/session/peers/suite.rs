// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`SeenStore`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! what it saw survives its own restart and what it does of a record damaged at rest, in its own
//! tests.
//!
//! | Case                                 | Rule of the contract                                   |
//! | ------------------------------------ | ------------------------------------------------------ |
//! | `a_peer_not_seen`                    | nothing is held of a peer no session was made with     |
//! | `an_epoch_is_seen_and_only_rises`    | a higher epoch replaces it; the same one changes nothing |
//! | `a_lower_epoch_is_a_rollback`        | refused, and the epoch held stays                      |
//! | `another_key_is_equivocation`        | a chain whose key at the epoch held is another         |
//! | `peers_are_seen_apart`               | one peer's epoch is not another's                      |
//! | `advances_together_keep_the_highest` | an older presentation never moves the epoch back       |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};

use super::{PeerRefusal, Seen, SeenStore};
use crate::identity::record::{Document, subject};
use crate::identity::{Suite, Verified};

const NOW: u64 = 1_800_000_000;

fn host(n: u8) -> [u8; 16] {
    let mut id = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0];
    id[15] = n;
    id
}

/// The fingerprint of the key of `epoch` in the chain `chain` of a peer.
fn fingerprint(chain: u8, epoch: u64) -> String {
    format!("sha256:{chain:02x}{epoch:062x}")
}

/// The peer `n` as it verified at `epoch`, every key of its chain `chain`'s.
fn verified(n: u8, chain: u8, epoch: u64) -> Verified {
    let fingerprints: Vec<String> = (1..=epoch).map(|at| fingerprint(chain, at)).collect();
    let public_key = vec![chain; 32];
    Verified {
        host_id: host(n),
        epoch,
        suite: Suite::Ed25519Sha256V1,
        public_key: public_key.clone(),
        public_keys: vec![public_key.clone(); fingerprints.len()],
        document: Document {
            host_id: host(n),
            subject: subject(&host(n)),
            epoch,
            suite: Suite::Ed25519Sha256V1,
            public_key,
            fingerprint: fingerprint(chain, epoch),
            last_succession: None,
            protocols: Vec::new(),
            revision: epoch,
            issued_at: NOW,
        },
        fingerprints,
    }
}

fn seen<S: SeenStore + ?Sized>(store: &S, n: u8) -> Option<Seen> {
    store.seen(&host(n)).expect("the seen epoch reads")
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: SeenStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    a_peer_not_seen(&*make());
    an_epoch_is_seen_and_only_rises(&*make());
    a_lower_epoch_is_a_rollback(&*make());
    another_key_is_equivocation(&*make());
    peers_are_seen_apart(&*make());
    advances_together_keep_the_highest(&*make());
}

fn a_peer_not_seen<S: SeenStore + ?Sized>(store: &S) {
    assert_eq!(seen(store, 1), None);
}

fn an_epoch_is_seen_and_only_rises<S: SeenStore + ?Sized>(store: &S) {
    store.advance(&verified(1, 0xa, 1), NOW).expect("advanced");
    assert_eq!(
        seen(store, 1),
        Some(Seen {
            host_id: host(1),
            epoch: 1,
            fingerprint: fingerprint(0xa, 1),
            at: NOW,
        })
    );
    // Epochs may be skipped: the chain names the key of the one held.
    store
        .advance(&verified(1, 0xa, 3), NOW + 10)
        .expect("advanced");
    let third = Seen {
        host_id: host(1),
        epoch: 3,
        fingerprint: fingerprint(0xa, 3),
        at: NOW + 10,
    };
    assert_eq!(seen(store, 1), Some(third.clone()));
    // The same epoch again is no news: what was seen stays, with its time.
    store
        .advance(&verified(1, 0xa, 3), NOW + 99)
        .expect("the same epoch");
    assert_eq!(seen(store, 1), Some(third));
}

fn a_lower_epoch_is_a_rollback<S: SeenStore + ?Sized>(store: &S) {
    store.advance(&verified(1, 0xa, 3), NOW).expect("advanced");
    let held = seen(store, 1);
    assert!(matches!(
        store.advance(&verified(1, 0xa, 2), NOW + 1),
        Err(PeerRefusal::Rollback {
            seen: 3,
            presented: 2
        })
    ));
    assert_eq!(seen(store, 1), held, "the refusal changed nothing");
}

fn another_key_is_equivocation<S: SeenStore + ?Sized>(store: &S) {
    store.advance(&verified(1, 0xa, 2), NOW).expect("advanced");
    let held = seen(store, 1);
    // A longer chain of other keys: at the epoch held its key is another.
    assert!(matches!(
        store.advance(&verified(1, 0xb, 4), NOW + 1),
        Err(PeerRefusal::Equivocation { epoch: 2 })
    ));
    assert!(matches!(
        store.advance(&verified(1, 0xb, 2), NOW + 1),
        Err(PeerRefusal::Equivocation { epoch: 2 })
    ));
    assert_eq!(seen(store, 1), held, "the refusal changed nothing");
}

fn peers_are_seen_apart<S: SeenStore + ?Sized>(store: &S) {
    store.advance(&verified(1, 0xa, 4), NOW).expect("advanced");
    store.advance(&verified(2, 0xb, 1), NOW).expect("advanced");
    assert_eq!(seen(store, 1).map(|seen| seen.epoch), Some(4));
    assert_eq!(seen(store, 2).map(|seen| seen.epoch), Some(1));
    assert_eq!(seen(store, 3), None);
}

fn advances_together_keep_the_highest<S: SeenStore + ?Sized>(store: &S) {
    const THREADS: u64 = 8;
    const ROUNDS: u8 = 6;
    for round in 0..ROUNDS {
        let peer = 10 + round;
        let together = Barrier::new(THREADS as usize);
        std::thread::scope(|scope| {
            for epoch in 1..=THREADS {
                let together = &together;
                scope.spawn(move || {
                    together.wait();
                    match store.advance(&verified(peer, 0xa, epoch), NOW) {
                        Ok(()) | Err(PeerRefusal::Rollback { .. }) => {}
                        Err(other) => panic!("an advance answered {other}"),
                    }
                });
            }
        });
        assert_eq!(
            seen(store, peer).map(|seen| seen.epoch),
            Some(THREADS),
            "the highest epoch a session was established at"
        );
    }
}
