// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`MemberStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. The suite's records are plain bytes: the
//! store keeps what it is given and trusts none of it, and what an entry or a document must be
//! is [`Store`](super::Store)'s, proven by its own tests on a store that passes this suite. A
//! backend proves what only it can, that what it keeps survives its own restart and what it
//! cuts of an entry half written, in its own tests.
//!
//! | Case                              | Rule of the contract                                     |
//! | --------------------------------- | -------------------------------------------------------- |
//! | `nothing_is_kept`                 | no entry, no document, no checkpoint, nothing listed     |
//! | `entries_are_added_in_sequence`   | oldest first; one out of sequence is refused             |
//! | `views_are_kept`                  | a summary, a manifest and an invitation are written      |
//! | `a_document_is_kept_whole`        | read as it was kept, replaced whole, each kind apart     |
//! | `a_document_is_changed_in_place`  | given as it stands; what the change answers is kept      |
//! | `a_document_is_removed`           | and none is kept after it                                |
//! | `documents_are_listed`            | of one kind and one task or membership, by name          |
//! | `a_checkpoint_is_published_once`  | under its place in its trail                             |
//! | `entries_together_add_one`        | of the transitions that read one store, one is added     |
//! | `changes_together_lose_none`      | each is given what the one before it kept                |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use permguard_objects::cbor::{self, Value};

use super::MembershipError;
use super::store::{Doc, Listing, MemberStore};

const M: [u8; 16] = [0x0a; 16];
const OTHER: [u8; 16] = [0x0b; 16];
const TASK: &str = "decisions.ship";
const TRAIL: &str = "security:host";

fn item(n: i64) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Int(n),
        Value::Text("entry".to_owned()),
    ]))
    .expect("an item encodes")
}

fn entries<S: MemberStore + ?Sized>(store: &S) -> Vec<Vec<u8>> {
    store
        .entries()
        .expect("the entries read")
        .iter()
        .map(|value| cbor::encode(value).expect("encodes"))
        .collect()
}

fn held<S: MemberStore + ?Sized>(store: &S, doc: &Doc<'_>) -> Option<Vec<u8>> {
    store.doc(doc).expect("the document reads")
}

/// One document of every kind, of the membership `membership`.
fn every_kind(membership: &[u8; 16]) -> Vec<Doc<'_>> {
    vec![
        Doc::Lease {
            membership,
            task: TASK,
        },
        Doc::Progress {
            membership,
            task: TASK,
        },
        Doc::Session {
            membership,
            task: TASK,
        },
        Doc::Delivered { membership },
        Doc::ZoneReceipt {
            membership,
            task: TASK,
            resource: "plane/control/zone/z1",
        },
        Doc::ReplaySlot {
            membership,
            task: TASK,
            slot: 7,
        },
        Doc::Verification { membership },
        Doc::VerificationResult {
            operation: membership,
        },
        Doc::Acks {
            membership,
            task: TASK,
        },
        Doc::TrailName {
            membership,
            trail: TRAIL,
        },
        Doc::TrailLast {
            membership,
            trail: TRAIL,
        },
        Doc::TrailAnchor {
            membership,
            trail: TRAIL,
        },
        Doc::TrailFork {
            membership,
            trail: TRAIL,
        },
    ]
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: MemberStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    nothing_is_kept(&*make());
    entries_are_added_in_sequence(&*make());
    views_are_kept(&*make());
    a_document_is_kept_whole(&*make());
    a_document_is_changed_in_place(&*make());
    a_document_is_removed(&*make());
    documents_are_listed(&*make());
    a_checkpoint_is_published_once(&*make());
    entries_together_add_one(&*make());
    changes_together_lose_none(&*make());
}

fn nothing_is_kept<S: MemberStore + ?Sized>(store: &S) {
    assert!(entries(store).is_empty());
    for doc in every_kind(&M) {
        assert_eq!(held(store, &doc), None, "{doc:?}");
        assert!(!store.remove(&doc).expect("removes"), "{doc:?}");
    }
    assert_eq!(store.checkpoint(&M, TRAIL, 1).expect("reads"), None);
    for listing in [
        Listing::ZoneReceipts {
            membership: &M,
            task: TASK,
        },
        Listing::ReplaySlots {
            membership: &M,
            task: TASK,
        },
        Listing::TrailForks { membership: &M },
    ] {
        assert!(
            store.list(&listing).expect("lists").is_empty(),
            "{listing:?}"
        );
    }
}

fn entries_are_added_in_sequence<S: MemberStore + ?Sized>(store: &S) {
    for n in 1..=4 {
        store.append(n as u64, &item(n)).expect("added");
    }
    assert_eq!(entries(store), vec![item(1), item(2), item(3), item(4)]);
    for seq in [4, 6, 0, 1] {
        assert!(
            matches!(
                store.append(seq, &item(99)),
                Err(MembershipError::Conflict { current: 4, .. })
            ),
            "the entry {seq} does not follow the fourth"
        );
    }
    assert_eq!(entries(store).len(), 4, "a refusal adds nothing");
    store.append(5, &item(5)).expect("the next one");
    assert_eq!(entries(store).len(), 5);
}

fn views_are_kept<S: MemberStore + ?Sized>(store: &S) {
    store.replace_summary(b"at entry 1").expect("written");
    store
        .replace_summary(b"at entry 2, longer")
        .expect("replaced");
    store
        .keep_manifest(&M, 1, "aa11", b"the manifest of epoch 1")
        .expect("kept");
    store
        .keep_manifest(&M, 2, "bb22", b"the manifest of epoch 2")
        .expect("its successor");
    store
        .keep_manifest(&M, 2, "bb22", b"the manifest of epoch 2")
        .expect("the same again");
    store.keep_invitation(&M, b"an invitation").expect("kept");
    // A view is no document and no entry.
    assert!(entries(store).is_empty());
    for doc in every_kind(&M) {
        assert_eq!(held(store, &doc), None, "{doc:?}");
    }
}

fn a_document_is_kept_whole<S: MemberStore + ?Sized>(store: &S) {
    // Every kind beside every other, of two memberships: each reads what it was kept as.
    let kinds = every_kind(&M);
    for (n, doc) in kinds.iter().enumerate() {
        store
            .keep(doc, format!("{n} of the first").as_bytes())
            .expect("kept");
    }
    for (n, doc) in every_kind(&OTHER).iter().enumerate() {
        store
            .keep(doc, format!("{n} of the other").as_bytes())
            .expect("kept");
    }
    for (n, doc) in kinds.iter().enumerate() {
        assert_eq!(
            held(store, doc),
            Some(format!("{n} of the first").into_bytes()),
            "{doc:?}"
        );
    }
    // Replaced whole, by a shorter one and by a longer one.
    let doc = Doc::Progress {
        membership: &M,
        task: TASK,
    };
    store.keep(&doc, b"x").expect("replaced");
    assert_eq!(held(store, &doc).as_deref(), Some(&b"x"[..]));
    store.keep(&doc, &[7; 4096]).expect("replaced");
    assert_eq!(held(store, &doc), Some(vec![7; 4096]));
    // Another task's, another resource's and another slot's are other documents.
    assert_eq!(
        held(
            store,
            &Doc::Progress {
                membership: &M,
                task: "events.ship"
            }
        ),
        None
    );
    assert_eq!(
        held(
            store,
            &Doc::ZoneReceipt {
                membership: &M,
                task: TASK,
                resource: "plane/control/zone/z2"
            }
        ),
        None
    );
    assert_eq!(
        held(
            store,
            &Doc::ReplaySlot {
                membership: &M,
                task: TASK,
                slot: 8
            }
        ),
        None
    );
}

fn a_document_is_changed_in_place<S: MemberStore + ?Sized>(store: &S) {
    let doc = Doc::Delivered { membership: &M };
    // Given none, and what it answers is kept.
    store
        .change(&doc, &mut |held| {
            assert_eq!(held, None);
            Ok(Some(b"epoch 1".to_vec()))
        })
        .expect("changed");
    assert_eq!(held(store, &doc).as_deref(), Some(&b"epoch 1"[..]));
    // Given what is kept; answering none leaves it.
    store
        .change(&doc, &mut |held| {
            assert_eq!(held, Some(&b"epoch 1"[..]));
            Ok(None)
        })
        .expect("left");
    assert_eq!(held(store, &doc).as_deref(), Some(&b"epoch 1"[..]));
    // An error of the change is answered, and nothing is kept.
    let refused = store.change(&doc, &mut |_| {
        Err(MembershipError::OutOfOrder(
            "not above the one held".to_owned(),
        ))
    });
    assert!(matches!(refused, Err(MembershipError::OutOfOrder(_))));
    assert_eq!(held(store, &doc).as_deref(), Some(&b"epoch 1"[..]));
    store
        .change(&doc, &mut |_| Ok(Some(b"epoch 2".to_vec())))
        .expect("changed");
    assert_eq!(held(store, &doc).as_deref(), Some(&b"epoch 2"[..]));
    // A change may keep and read other documents: a checkpoint is kept with its trail's name.
    let last = Doc::TrailLast {
        membership: &M,
        trail: TRAIL,
    };
    let name = Doc::TrailName {
        membership: &M,
        trail: TRAIL,
    };
    store
        .change(&last, &mut |_| {
            assert_eq!(store.doc(&name)?, None);
            store.keep(&name, TRAIL.as_bytes())?;
            store.publish_checkpoint(&M, TRAIL, 1, b"the first checkpoint")?;
            Ok(Some(b"one kept".to_vec()))
        })
        .expect("changed");
    assert_eq!(held(store, &name).as_deref(), Some(TRAIL.as_bytes()));
    assert_eq!(held(store, &last).as_deref(), Some(&b"one kept"[..]));
}

fn a_document_is_removed<S: MemberStore + ?Sized>(store: &S) {
    let asked = Doc::Verification { membership: &M };
    let stays = Doc::Verification { membership: &OTHER };
    store.keep(&asked, b"asked").expect("kept");
    store.keep(&stays, b"asked too").expect("kept");
    assert!(store.remove(&asked).expect("removed"));
    assert!(!store.remove(&asked).expect("twice"), "none is kept");
    assert_eq!(held(store, &asked), None);
    assert_eq!(held(store, &stays).as_deref(), Some(&b"asked too"[..]));
    // Removed, it is a document never kept.
    store.keep(&asked, b"asked again").expect("kept");
    assert_eq!(held(store, &asked).as_deref(), Some(&b"asked again"[..]));
}

fn documents_are_listed<S: MemberStore + ?Sized>(store: &S) {
    let receipt = |membership, task, resource| Doc::ZoneReceipt {
        membership,
        task,
        resource,
    };
    store
        .keep(&receipt(&M, TASK, "zone/b"), b"b")
        .expect("kept");
    store
        .keep(&receipt(&M, TASK, "zone/a"), b"a")
        .expect("kept");
    store
        .keep(&receipt(&M, "events.ship", "zone/a"), b"another task's")
        .expect("kept");
    store
        .keep(&receipt(&OTHER, TASK, "zone/a"), b"another membership's")
        .expect("kept");
    // Beside the receipts, the other documents of the task are not receipts.
    store
        .keep(
            &Doc::Progress {
                membership: &M,
                task: TASK,
            },
            b"a report",
        )
        .expect("kept");
    let mut receipts: Vec<Vec<u8>> = store
        .list(&Listing::ZoneReceipts {
            membership: &M,
            task: TASK,
        })
        .expect("lists")
        .into_iter()
        .map(|listed| listed.bytes.expect("reads"))
        .collect();
    receipts.sort();
    assert_eq!(receipts, vec![b"a".to_vec(), b"b".to_vec()]);

    for slot in [3, 11] {
        store
            .keep(
                &Doc::ReplaySlot {
                    membership: &M,
                    task: TASK,
                    slot,
                },
                format!("answer {slot}").as_bytes(),
            )
            .expect("kept");
    }
    let mut slots: Vec<(String, Vec<u8>)> = store
        .list(&Listing::ReplaySlots {
            membership: &M,
            task: TASK,
        })
        .expect("lists")
        .into_iter()
        .map(|listed| (listed.name, listed.bytes.expect("reads")))
        .collect();
    slots.sort();
    assert_eq!(
        slots,
        vec![
            ("11".to_owned(), b"answer 11".to_vec()),
            ("3".to_owned(), b"answer 3".to_vec()),
        ],
        "each slot by its number"
    );

    for (trail, fork) in [
        ("security:host", &b"fork 1"[..]),
        ("operations:host", b"fork 2"),
    ] {
        store
            .keep(
                &Doc::TrailName {
                    membership: &M,
                    trail,
                },
                trail.as_bytes(),
            )
            .expect("kept");
        store
            .keep(
                &Doc::TrailFork {
                    membership: &M,
                    trail,
                },
                fork,
            )
            .expect("kept");
    }
    // A trail with no fork is not listed.
    store
        .keep(
            &Doc::TrailName {
                membership: &M,
                trail: "access:host",
            },
            b"access:host",
        )
        .expect("kept");
    let forks: Vec<(String, Vec<u8>)> = store
        .list(&Listing::TrailForks { membership: &M })
        .expect("lists")
        .into_iter()
        .map(|listed| (listed.name, listed.bytes.expect("reads")))
        .collect();
    assert_eq!(
        forks,
        vec![
            ("operations:host".to_owned(), b"fork 2".to_vec()),
            ("security:host".to_owned(), b"fork 1".to_vec()),
        ],
        "each fork by its trail, in the order of the trails"
    );
}

fn a_checkpoint_is_published_once<S: MemberStore + ?Sized>(store: &S) {
    store
        .publish_checkpoint(&M, TRAIL, 1, b"the first")
        .expect("published");
    store
        .publish_checkpoint(&M, TRAIL, 1, b"the first")
        .expect("the same checkpoint again is the first");
    assert!(
        store.publish_checkpoint(&M, TRAIL, 1, b"another").is_err(),
        "a kept checkpoint is never replaced"
    );
    store
        .publish_checkpoint(&M, TRAIL, 2, b"the second")
        .expect("published");
    assert_eq!(
        store.checkpoint(&M, TRAIL, 1).expect("reads").as_deref(),
        Some(&b"the first"[..])
    );
    assert_eq!(
        store.checkpoint(&M, TRAIL, 2).expect("reads").as_deref(),
        Some(&b"the second"[..])
    );
    assert_eq!(store.checkpoint(&M, TRAIL, 3).expect("reads"), None);
    assert_eq!(
        store.checkpoint(&M, "operations:host", 1).expect("reads"),
        None,
        "another trail's place is another place"
    );
    assert_eq!(store.checkpoint(&OTHER, TRAIL, 1).expect("reads"), None);
}

fn entries_together_add_one<S: MemberStore + ?Sized>(store: &S) {
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
                        Err(MembershipError::Conflict { .. }) => {}
                        Err(other) => panic!("an entry answered {other}"),
                    }
                });
            }
        });
        assert_eq!(
            added.load(Ordering::Relaxed),
            1,
            "one transition adds the entry {seq}, the others learn the store moved"
        );
        assert_eq!(entries(store).len() as u64, seq);
    }
}

fn changes_together_lose_none<S: MemberStore + ?Sized>(store: &S) {
    const THREADS: u64 = 8;
    const EACH: u64 = 12;
    let doc = Doc::Acks {
        membership: &M,
        task: TASK,
    };
    let together = Barrier::new(THREADS as usize);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            let together = &together;
            scope.spawn(move || {
                together.wait();
                for _ in 0..EACH {
                    store
                        .change(&doc, &mut |held| {
                            let count = held.map_or(0, |bytes| {
                                u64::from_be_bytes(bytes.try_into().expect("eight bytes"))
                            });
                            Ok(Some((count + 1).to_be_bytes().to_vec()))
                        })
                        .expect("changed");
                }
            });
        }
    });
    assert_eq!(
        held(store, &doc),
        Some((THREADS * EACH).to_be_bytes().to_vec()),
        "every change was given what the one before it kept"
    );
}
