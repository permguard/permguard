// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`LedgerStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes the store of one empty ledger and runs every case on a
//! ledger of its own. A case panics with what it expected, as a test does. A backend proves what
//! only it can, that a ledger survives its own restart and what it does of content damaged at
//! rest, in its own tests.
//!
//! | Case                                  | Rule of the contract                                          |
//! | ------------------------------------- | ------------------------------------------------------------- |
//! | `an_empty_ledger`                     | nothing held, no ref, no root, no session, and it verifies    |
//! | `an_object_lands_once`                | written once, read whole, listed with its size                |
//! | `what_is_no_object_never_lands`       | bytes that are no canonical object are refused, nothing kept  |
//! | `a_removed_object_is_gone`            | a removal answers what it freed; a second frees nothing       |
//! | `roots_are_kept_once`                 | kept sorted, a root kept twice is one root                    |
//! | `a_ref_moves_by_compare_and_swap`     | the idempotency table, row by row                             |
//! | `a_ref_carries_its_operation`         | the operation that moved it is read back                      |
//! | `refs_are_listed_by_name`             | every ref, sorted; a name that is no ref name is refused      |
//! | `a_statement_is_kept_and_replaced`    | the last statement kept of a ref is the one read              |
//! | `a_head_not_held_does_not_verify`     | a ledger verifies only when every head is an object it holds  |
//! | `sessions_are_kept_and_removed`       | a session is read as kept, replaced whole, listed by id       |
//! | `pushes_together_write_once`          | of the pushes of one object at once, one writes               |
//! | `creations_together_make_one_ref`     | of the creations of one ref at once, one is written           |
//! | `updates_together_move_once`          | of the updates from one state at once, one is written         |
//! | `the_sessions_are_held_by_one`        | a second holder waits until the first lets go                 |

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use permguard_host::operations::mutation::Applying;
use permguard_notp::ExpectedRef;
use permguard_objects::digest::Digest;
use permguard_objects::object::Blob;

use super::{Landed, LedgerStore, RefState, RefUpdate, StoreError, ref_digest};
use crate::transfer::{Direction, Session, State};

/// How a suite runs something inside one operation of a mutation engine: the token it is given
/// is one an engine built, a new operation at every call. Calls from several threads run
/// together, each in an operation of its own.
pub type Operate<'a> = &'a (dyn Fn(&mut dyn FnMut(&Applying<'_>)) + Sync);

/// How many callers a concurrency case releases at once, and how many times it does.
const TOGETHER: usize = 8;
const ROUNDS: usize = 4;

/// Runs every case, each on the store of a ledger `make` made empty for it.
pub fn run(make: &dyn Fn() -> Arc<dyn LedgerStore>, operate: Operate<'_>) {
    an_empty_ledger(make().as_ref());
    an_object_lands_once(make().as_ref());
    what_is_no_object_never_lands(make().as_ref());
    a_removed_object_is_gone(make().as_ref());
    roots_are_kept_once(make().as_ref());
    a_ref_moves_by_compare_and_swap(make().as_ref(), operate);
    a_ref_carries_its_operation(make().as_ref(), operate);
    refs_are_listed_by_name(make().as_ref(), operate);
    a_statement_is_kept_and_replaced(make().as_ref());
    a_head_not_held_does_not_verify(make().as_ref(), operate);
    sessions_are_kept_and_removed(make().as_ref());
    pushes_together_write_once(make().as_ref());
    creations_together_make_one_ref(make().as_ref(), operate);
    updates_together_move_once(make().as_ref(), operate);
    the_sessions_are_held_by_one(make().as_ref());
}

/// The canonical bytes of a blob holding `text`.
fn blob(text: &str) -> Vec<u8> {
    Blob {
        media_type: crate::engine::MEDIA_TYPE_POLICY_CEDAR.to_owned(),
        data: text.as_bytes().to_vec(),
    }
    .encode()
    .expect("a blob")
}

/// The digest of a blob holding `text`, landed in `store`.
fn landed(store: &dyn LedgerStore, text: &str) -> Digest {
    store.put_object(&blob(text)).expect("landed").0
}

/// One update of the ref `name`, in an operation of its own.
fn update(
    store: &dyn LedgerStore,
    operate: Operate<'_>,
    name: &str,
    expected: Option<&ExpectedRef>,
    new: &Digest,
) -> Result<RefUpdate, StoreError> {
    let mut answer = None;
    operate(&mut |applying| answer = Some(store.update_ref(applying, name, expected, new)));
    answer.expect("the operation ran")
}

/// The state an update names as the one it expects.
fn expecting(state: &RefState) -> ExpectedRef {
    ExpectedRef {
        counter: state.counter,
        digest: ref_digest(state).expect("a ref digest"),
    }
}

/// An open push session `id`.
fn session(id: u8) -> Session {
    Session {
        transfer_id: [id; 16],
        direction: Direction::Push,
        principal: "operator".to_owned(),
        authority_host_id: [1; 16],
        zone: "zone".to_owned(),
        ledger: "ledger".to_owned(),
        r#ref: "main".to_owned(),
        request_id: format!("push-{id}"),
        parameters: Digest::compute(b"parameters"),
        new_head: Some(Digest::compute(b"head")),
        expected_ref: None,
        max_batch_bytes: 1024,
        max_batch_objects: 10,
        reservation: 500,
        landed: 0,
        expiry: 1_000,
        state: State::Open,
        closed_at: None,
        pins: vec![Digest::compute(&[id])],
        result: None,
    }
}

fn an_empty_ledger(store: &dyn LedgerStore) {
    let absent = Digest::compute(b"absent");
    assert!(!store.has_object(&absent));
    assert_eq!(store.get_object(&absent).expect("read"), None);
    assert!(store.list_objects().expect("listed").is_empty());
    assert_eq!(store.stored_bytes().expect("sized"), 0);
    assert!(store.roots().expect("read").is_empty());
    assert_eq!(store.read_ref("main").expect("read"), None);
    assert_eq!(store.ref_operation("main").expect("read"), None);
    assert!(store.list_refs().expect("listed").is_empty());
    assert_eq!(store.read_signature("main").expect("read"), None);
    assert!(
        store
            .transfers()
            .expect("held")
            .list()
            .expect("listed")
            .is_empty()
    );
    assert_eq!(store.verify_at_load().expect("an empty ledger verifies"), 0);
    assert_eq!(store.remove_object(&absent).expect("nothing to free"), 0);
    assert_eq!(
        store
            .sweep_temporaries(Duration::ZERO)
            .expect("nothing to sweep"),
        0
    );
}

fn an_object_lands_once(store: &dyn LedgerStore) {
    let bytes = blob("permit (principal, action, resource);");
    let (digest, _, first) = store.publish_object(&bytes).expect("landed");
    assert_eq!(digest, Digest::compute(&bytes), "named by its bytes");
    assert_eq!(first, Landed::Written);
    let (again, _, second) = store.publish_object(&bytes).expect("landed again");
    assert_eq!((again, second), (digest.clone(), Landed::AlreadyThere));
    assert!(store.has_object(&digest));
    assert_eq!(store.get_object(&digest).expect("read"), Some(bytes));
    let other = landed(store, "forbid (principal, action, resource);");
    let listed = store.list_objects().expect("listed");
    let held: BTreeSet<Digest> = listed.iter().map(|object| object.digest.clone()).collect();
    assert_eq!(held, BTreeSet::from([digest.clone(), other.clone()]));
    assert!(listed.iter().all(|object| object.bytes > 0));
    assert!(store.stored_bytes().expect("sized") >= listed.iter().map(|o| o.bytes).sum());
    store
        .make_durable(&BTreeSet::from([digest, other]))
        .expect("made durable");
}

fn what_is_no_object_never_lands(store: &dyn LedgerStore) {
    for bytes in [&b""[..], b"not an object", &[0xff; 64]] {
        assert!(
            matches!(store.publish_object(bytes), Err(StoreError::Object(_))),
            "{bytes:?}"
        );
    }
    assert!(store.list_objects().expect("listed").is_empty());
}

fn a_removed_object_is_gone(store: &dyn LedgerStore) {
    let kept = landed(store, "kept");
    let gone = landed(store, "gone");
    assert!(store.remove_object(&gone).expect("removed") > 0);
    assert_eq!(store.remove_object(&gone).expect("already gone"), 0);
    assert!(!store.has_object(&gone));
    assert_eq!(store.get_object(&gone).expect("read"), None);
    let listed = store.list_objects().expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].digest, kept);
    // What was removed lands again as any object does.
    assert_eq!(
        store.publish_object(&blob("gone")).expect("landed").2,
        Landed::Written
    );
}

fn roots_are_kept_once(store: &dyn LedgerStore) {
    let mut heads = vec![landed(store, "one"), landed(store, "two")];
    store.keep_roots(&heads).expect("kept");
    store.keep_roots(&heads[..1]).expect("kept again");
    heads.push(landed(store, "three"));
    store.keep_roots(&heads[2..]).expect("another kept");
    heads.sort();
    assert_eq!(store.roots().expect("read"), heads);
}

fn a_ref_moves_by_compare_and_swap(store: &dyn LedgerStore, operate: Operate<'_>) {
    let (a, b, c) = (landed(store, "a"), landed(store, "b"), landed(store, "c"));
    // Creation: only while the ref does not exist, and the counter starts at 1.
    let first = match update(store, operate, "main", None, &a).expect("created") {
        RefUpdate::Updated(state) => state,
        other => panic!("a creation answered {other:?}"),
    };
    assert_eq!(first, RefState::first(a.clone()));
    assert_eq!(store.read_ref("main").expect("read"), Some(first.clone()));
    // The head already there: success, counter untouched, whatever is expected.
    for expected in [None, Some(expecting(&first))] {
        assert_eq!(
            update(store, operate, "main", expected.as_ref(), &a).expect("already there"),
            RefUpdate::AlreadyCurrent(first.clone())
        );
    }
    // A creation of a ref that exists, with another head: a conflict carrying what is current.
    match update(store, operate, "main", None, &b) {
        Err(StoreError::Conflict { current }) => assert_eq!(current, Some(first.clone())),
        other => panic!("a second creation answered {other:?}"),
    }
    // The state expected is the current one: the successor.
    let second = match update(store, operate, "main", Some(&expecting(&first)), &b).expect("moved")
    {
        RefUpdate::Updated(state) => state,
        other => panic!("an update answered {other:?}"),
    };
    assert_eq!(
        (
            &second.head,
            second.counter,
            second.previous_ref_digest.clone()
        ),
        (&b, 2, Some(ref_digest(&first).expect("a ref digest")))
    );
    // A state that is no longer the current one: a conflict, and nothing moves.
    for stale in [
        expecting(&first),
        ExpectedRef {
            counter: second.counter,
            digest: ref_digest(&first).expect("a ref digest"),
        },
    ] {
        match update(store, operate, "main", Some(&stale), &c) {
            Err(StoreError::Conflict { current }) => assert_eq!(current, Some(second.clone())),
            other => panic!("a stale update answered {other:?}"),
        }
    }
    // An update of a ref that does not exist expects nothing that is.
    match update(store, operate, "other", Some(&expecting(&first)), &c) {
        Err(StoreError::Conflict { current }) => assert_eq!(current, None),
        other => panic!("an update of no ref answered {other:?}"),
    }
    assert_eq!(store.read_ref("main").expect("read"), Some(second));
    store.make_ref_durable("main").expect("made durable");
}

fn a_ref_carries_its_operation(store: &dyn LedgerStore, operate: Operate<'_>) {
    let (a, b) = (landed(store, "a"), landed(store, "b"));
    let mut wrote = Vec::new();
    let mut expected = None;
    for head in [&a, &b] {
        operate(&mut |applying| {
            let state = match store
                .update_ref(applying, "main", expected.as_ref(), head)
                .expect("moved")
            {
                RefUpdate::Updated(state) => state,
                other => panic!("an update answered {other:?}"),
            };
            expected = Some(expecting(&state));
            wrote.push(applying.operation_id().to_string());
        });
        assert_eq!(
            store.ref_operation("main").expect("read").as_ref(),
            wrote.last()
        );
    }
    assert_ne!(wrote[0], wrote[1]);
    // An update that finds the head already there writes nothing: the operation stays.
    update(store, operate, "main", None, &b).expect("already there");
    assert_eq!(
        store.ref_operation("main").expect("read").as_ref(),
        wrote.last()
    );
}

fn refs_are_listed_by_name(store: &dyn LedgerStore, operate: Operate<'_>) {
    let head = landed(store, "head");
    for name in ["release/v2", "main", "release/v1"] {
        update(store, operate, name, None, &head).expect("created");
    }
    let listed = store.list_refs().expect("listed");
    let names: Vec<&str> = listed.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["main", "release/v1", "release/v2"]);
    assert!(
        listed
            .iter()
            .all(|(_, state)| *state == RefState::first(head.clone()))
    );
    assert_eq!(store.verify_at_load().expect("verified"), 3);
    for name in ["", "../escape", "a//b", ".hidden"] {
        assert!(
            matches!(store.read_ref(name), Err(StoreError::Grammar(_))),
            "{name}"
        );
        assert!(
            matches!(
                update(store, operate, name, None, &head),
                Err(StoreError::Grammar(_))
            ),
            "{name}"
        );
        assert!(
            matches!(
                store.write_signature(name, b"statement"),
                Err(StoreError::Grammar(_))
            ),
            "{name}"
        );
    }
    assert_eq!(store.list_refs().expect("listed").len(), 3);
}

fn a_statement_is_kept_and_replaced(store: &dyn LedgerStore) {
    store.write_signature("main", b"first").expect("kept");
    store
        .write_signature("release/v1", b"another")
        .expect("kept");
    assert_eq!(
        store.read_signature("main").expect("read").as_deref(),
        Some(&b"first"[..])
    );
    store.write_signature("main", b"second").expect("replaced");
    assert_eq!(
        store.read_signature("main").expect("read").as_deref(),
        Some(&b"second"[..])
    );
    assert_eq!(
        store.read_signature("release/v1").expect("read").as_deref(),
        Some(&b"another"[..])
    );
    assert_eq!(store.read_signature("absent").expect("read"), None);
}

fn a_head_not_held_does_not_verify(store: &dyn LedgerStore, operate: Operate<'_>) {
    let held = landed(store, "held");
    update(store, operate, "main", None, &held).expect("created");
    assert_eq!(store.verify_at_load().expect("verified"), 1);
    update(
        store,
        operate,
        "dangling",
        None,
        &Digest::compute(b"not held"),
    )
    .expect("created");
    assert!(store.verify_at_load().is_err());
}

fn sessions_are_kept_and_removed(store: &dyn LedgerStore) {
    let transfers = store.transfers().expect("held");
    for id in [7, 3, 5] {
        transfers.put(&session(id)).expect("kept");
    }
    assert_eq!(transfers.get(&[3; 16]).expect("read"), Some(session(3)));
    assert_eq!(transfers.get(&[4; 16]).expect("read"), None);
    let ids: Vec<u8> = transfers
        .list()
        .expect("listed")
        .iter()
        .map(|session| session.transfer_id[0])
        .collect();
    assert_eq!(ids, [3, 5, 7], "in the order of their ids");
    let mut closed = session(5);
    closed.state = State::Committed;
    closed.closed_at = Some(900);
    closed.result = Some(b"answered".to_vec());
    transfers.put(&closed).expect("replaced");
    assert_eq!(transfers.get(&[5; 16]).expect("read"), Some(closed));
    transfers.remove(&[3; 16]).expect("removed");
    transfers.remove(&[3; 16]).expect("already removed");
    assert_eq!(transfers.get(&[3; 16]).expect("read"), None);
    assert_eq!(transfers.list().expect("listed").len(), 2);
    drop(transfers);
    // What was kept under one hold is what the next reads.
    assert_eq!(
        store
            .transfers()
            .expect("held again")
            .list()
            .expect("listed")
            .len(),
        2
    );
}

/// Releases `TOGETHER` callers at once on `call` and answers what each was answered.
fn together<T: Send>(call: &(dyn Fn(usize) -> T + Sync)) -> Vec<T> {
    let barrier = Barrier::new(TOGETHER);
    std::thread::scope(|scope| {
        let callers: Vec<_> = (0..TOGETHER)
            .map(|caller| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    call(caller)
                })
            })
            .collect();
        callers
            .into_iter()
            .map(|caller| caller.join().expect("a caller finished"))
            .collect()
    })
}

fn pushes_together_write_once(store: &dyn LedgerStore) {
    for round in 0..ROUNDS {
        let bytes = blob(&format!("contested {round}"));
        let answers = together(&|_| store.publish_object(&bytes).expect("landed").2);
        let written = answers
            .iter()
            .filter(|landed| **landed == Landed::Written)
            .count();
        assert_eq!(written, 1, "one object, one write: {answers:?}");
        assert_eq!(
            store
                .get_object(&Digest::compute(&bytes))
                .expect("read")
                .as_deref(),
            Some(bytes.as_slice())
        );
    }
    assert_eq!(store.list_objects().expect("listed").len(), ROUNDS);
}

fn creations_together_make_one_ref(store: &dyn LedgerStore, operate: Operate<'_>) {
    let heads: Vec<Digest> = (0..TOGETHER)
        .map(|caller| landed(store, &format!("head {caller}")))
        .collect();
    for round in 0..ROUNDS {
        let name = format!("contested-{round}");
        let answers = together(&|caller| update(store, operate, &name, None, &heads[caller]));
        let current = store.read_ref(&name).expect("read").expect("a ref");
        assert_eq!(current.counter, 1);
        let mut created = 0;
        for answer in &answers {
            match answer {
                Ok(RefUpdate::Updated(state)) => {
                    assert_eq!(state, &current);
                    created += 1;
                }
                Err(StoreError::Conflict { current: told }) => {
                    assert_eq!(told.as_ref(), Some(&current));
                }
                other => panic!("a creation answered {other:?}"),
            }
        }
        assert_eq!(created, 1, "one ref, one creation");
    }
}

fn updates_together_move_once(store: &dyn LedgerStore, operate: Operate<'_>) {
    let start = landed(store, "start");
    let mut current = match update(store, operate, "main", None, &start).expect("created") {
        RefUpdate::Updated(state) => state,
        other => panic!("a creation answered {other:?}"),
    };
    for round in 0..ROUNDS {
        // A head of its own for every caller and round: none is the head already there.
        let heads: Vec<Digest> = (0..TOGETHER)
            .map(|caller| landed(store, &format!("head {round} {caller}")))
            .collect();
        let expected = expecting(&current);
        let answers =
            together(&|caller| update(store, operate, "main", Some(&expected), &heads[caller]));
        let moved = store.read_ref("main").expect("read").expect("a ref");
        assert_eq!(moved.counter, current.counter + 1, "round {round}");
        assert_eq!(
            moved.previous_ref_digest,
            Some(ref_digest(&current).expect("a ref digest"))
        );
        let mut written = 0;
        for answer in &answers {
            match answer {
                Ok(RefUpdate::Updated(state)) => {
                    assert_eq!(state, &moved);
                    written += 1;
                }
                Err(StoreError::Conflict { current: told }) => {
                    assert_eq!(told.as_ref(), Some(&moved));
                }
                other => panic!("an update answered {other:?}"),
            }
        }
        assert_eq!(written, 1, "one state, one successor");
        current = moved;
    }
}

fn the_sessions_are_held_by_one(store: &dyn LedgerStore) {
    let entered = AtomicBool::new(false);
    let kept = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let first = store.transfers().expect("held");
        first.put(&session(1)).expect("kept");
        scope.spawn(|| {
            let second = store.transfers().expect("held after the first");
            entered.store(true, Ordering::SeqCst);
            kept.store(second.list().expect("listed").len(), Ordering::SeqCst);
        });
        // Long enough for a second holder that does not wait to be seen.
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !entered.load(Ordering::SeqCst),
            "a second holder entered while the first held"
        );
        first.put(&session(2)).expect("kept");
        drop(first);
    });
    assert!(entered.load(Ordering::SeqCst));
    assert_eq!(
        kept.load(Ordering::SeqCst),
        2,
        "it read what the first left"
    );
}
