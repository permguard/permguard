// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`IdentityStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. The suite's records are plain bytes: the
//! store keeps what it is given and trusts none of it, and what a record must be is
//! [`Identity`](super::Identity)'s, proven by its own tests on a store that passes this suite. A
//! backend proves what only it can, that its records survive its own restart and what it
//! completes of an interrupted write, in its own tests.
//!
//! | Case                                   | Rule of the contract                                    |
//! | -------------------------------------- | ------------------------------------------------------- |
//! | `nothing_is_held`                      | no record, no key, no start, no reset, no retired       |
//! | `the_provisioning_record_is_written_once` | the same again is the first; another is refused      |
//! | `a_document_is_replaced`               | the last one written is the one read                    |
//! | `successions_are_added_in_order`       | oldest first, each the item it was added as             |
//! | `a_public_key_is_published_once`       | per epoch; removed, its epoch holds nothing             |
//! | `a_start_is_recorded`                  | an identity that was opened says so                     |
//! | `a_reset_is_marked_and_cleared`        | the mark names the identity it retires                  |
//! | `a_retired_identity_keeps_its_evidence` | with the record of its reset; what is held stays       |
//! | `clear_leaves_what_is_not_the_identitys` | the provisioning record, the mark and the retired stay |
//! | `records_together_are_written_once`    | of those that arrive together one is written            |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use permguard_objects::cbor::{self, Value};

use super::record::uuid_text;
use super::store::{HeldEpoch, IdentityStore, Retired};
use crate::operations::mutation::Applying;

/// How a suite runs something inside one operation of the mutation engine: the token it is
/// given is one the engine built, a new operation at every call.
pub type Operate<'a> = &'a dyn Fn(&mut dyn FnMut(&Applying<'_>));

const OLD: [u8; 16] = [0x0a; 16];
const OLDER: [u8; 16] = [0x0b; 16];

fn item(n: i64) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Int(n),
        Value::Text("succession".to_owned()),
    ]))
    .expect("an item encodes")
}

fn public(epoch: u64) -> HeldEpoch {
    HeldEpoch {
        epoch,
        public: true,
        private: false,
    }
}

/// Runs every case, each on a store `make` has just made empty; `operate` runs what it is given
/// inside one operation of the identity's domain.
pub fn run<S: IdentityStore + ?Sized>(make: &dyn Fn() -> Arc<S>, operate: Operate<'_>) {
    nothing_is_held(&*make());
    the_provisioning_record_is_written_once(&*make());
    a_document_is_replaced(&*make());
    successions_are_added_in_order(&*make());
    a_public_key_is_published_once(&*make());
    a_start_is_recorded(&*make());
    a_reset_is_marked_and_cleared(&*make(), operate);
    a_retired_identity_keeps_its_evidence(&*make(), operate);
    clear_leaves_what_is_not_the_identitys(&*make(), operate);
    records_together_are_written_once(&*make());
}

fn nothing_is_held<S: IdentityStore + ?Sized>(store: &S) {
    assert_eq!(store.init().expect("reads"), None);
    assert_eq!(store.document().expect("reads"), None);
    assert!(store.successions().expect("reads").is_empty());
    assert_eq!(store.public(1).expect("reads"), None);
    assert!(store.held_epochs().expect("reads").is_empty());
    assert!(!store.started().expect("reads"));
    assert_eq!(store.resetting().expect("reads"), None);
    assert!(store.retired().expect("reads").is_empty());
    // Removing what is not there is no error.
    store.remove_init().expect("nothing to remove");
    store.remove_public(1).expect("nothing to remove");
    store.clear_resetting().expect("nothing to clear");
    store.clear().expect("nothing to clear");
}

fn the_provisioning_record_is_written_once<S: IdentityStore + ?Sized>(store: &S) {
    store.publish_init(b"the first record").expect("written");
    assert_eq!(
        store.init().expect("reads").as_deref(),
        Some(&b"the first record"[..])
    );
    store
        .publish_init(b"the first record")
        .expect("the same record again is the first");
    assert!(
        store.publish_init(b"another record").is_err(),
        "a provisioning record is never replaced"
    );
    assert_eq!(
        store.init().expect("reads").as_deref(),
        Some(&b"the first record"[..])
    );
    store.remove_init().expect("removed");
    assert_eq!(store.init().expect("reads"), None);
    store.remove_init().expect("twice");
    // A reset's next identity writes its own.
    store.publish_init(b"another record").expect("written");
    assert_eq!(
        store.init().expect("reads").as_deref(),
        Some(&b"another record"[..])
    );
}

fn a_document_is_replaced<S: IdentityStore + ?Sized>(store: &S) {
    store.replace_document(b"epoch 1").expect("written");
    assert_eq!(
        store.document().expect("reads").as_deref(),
        Some(&b"epoch 1"[..])
    );
    store
        .replace_document(b"epoch 2, longer")
        .expect("replaced");
    assert_eq!(
        store.document().expect("reads").as_deref(),
        Some(&b"epoch 2, longer"[..])
    );
}

fn successions_are_added_in_order<S: IdentityStore + ?Sized>(store: &S) {
    for n in 1..=3 {
        store.append_succession(&item(n)).expect("added");
    }
    let held: Vec<Vec<u8>> = store
        .successions()
        .expect("reads")
        .iter()
        .map(|value| cbor::encode(value).expect("encodes"))
        .collect();
    assert_eq!(held, vec![item(1), item(2), item(3)]);
}

fn a_public_key_is_published_once<S: IdentityStore + ?Sized>(store: &S) {
    store.publish_public(1, &[1; 32]).expect("published");
    store.publish_public(3, &[3; 32]).expect("published");
    store
        .publish_public(1, &[1; 32])
        .expect("the same key again is the first");
    assert!(
        store.publish_public(1, &[9; 32]).is_err(),
        "an epoch's key is never replaced"
    );
    assert_eq!(
        store.public(1).expect("reads").as_deref(),
        Some(&[1; 32][..])
    );
    assert_eq!(store.public(2).expect("reads"), None);
    assert_eq!(
        store.held_epochs().expect("reads"),
        vec![public(1), public(3)]
    );
    store.remove_public(3).expect("removed");
    store.remove_public(3).expect("twice");
    assert_eq!(store.public(3).expect("reads"), None);
    assert_eq!(store.held_epochs().expect("reads"), vec![public(1)]);
    // The rotation that found it publishes its own.
    store.publish_public(3, &[4; 32]).expect("published");
    assert_eq!(
        store.public(3).expect("reads").as_deref(),
        Some(&[4; 32][..])
    );
}

fn a_start_is_recorded<S: IdentityStore + ?Sized>(store: &S) {
    store.record_start(b"boot 1").expect("recorded");
    assert!(store.started().expect("reads"));
    store.record_start(b"boot 2").expect("replaced");
    assert!(store.started().expect("reads"));
}

fn a_reset_is_marked_and_cleared<S: IdentityStore + ?Sized>(store: &S, operate: Operate<'_>) {
    operate(&mut |applying| store.mark_resetting(applying, &OLD).expect("marked"));
    assert_eq!(store.resetting().expect("reads").as_deref(), Some(&OLD[..]));
    store.clear_resetting().expect("cleared");
    assert_eq!(store.resetting().expect("reads"), None);
    store.clear_resetting().expect("twice");
}

fn a_retired_identity_keeps_its_evidence<S: IdentityStore + ?Sized>(
    store: &S,
    operate: Operate<'_>,
) {
    store.publish_init(b"record").expect("written");
    store.replace_document(b"document").expect("written");
    store.append_succession(&item(1)).expect("added");
    store.publish_public(1, &[1; 32]).expect("published");
    store.publish_public(2, &[2; 32]).expect("published");
    operate(&mut |applying| {
        store
            .retire(applying, &OLD, b"the reset of OLD")
            .expect("retired");
    });
    assert_eq!(
        store.retired().expect("reads"),
        vec![Retired {
            host_id: uuid_text(&OLD),
            reset: Some(b"the reset of OLD".to_vec()),
            init: true,
        }]
    );
    // Retiring keeps evidence and removes nothing: the identity held is still there.
    assert_eq!(
        store.init().expect("reads").as_deref(),
        Some(&b"record"[..])
    );
    assert_eq!(
        store.document().expect("reads").as_deref(),
        Some(&b"document"[..])
    );
    assert_eq!(store.successions().expect("reads").len(), 1);
    assert_eq!(
        store.held_epochs().expect("reads"),
        vec![public(1), public(2)]
    );
    // An identity retired before it is kept beside, each with its own record.
    operate(&mut |applying| {
        store
            .retire(applying, &OLDER, b"the reset of OLDER")
            .expect("retired");
    });
    let mut retired = store.retired().expect("reads");
    retired.sort_by(|a, b| a.host_id.cmp(&b.host_id));
    assert_eq!(
        retired
            .iter()
            .map(|retired| (retired.host_id.clone(), retired.reset.clone()))
            .collect::<Vec<_>>(),
        vec![
            (uuid_text(&OLD), Some(b"the reset of OLD".to_vec())),
            (uuid_text(&OLDER), Some(b"the reset of OLDER".to_vec())),
        ]
    );
}

fn clear_leaves_what_is_not_the_identitys<S: IdentityStore + ?Sized>(
    store: &S,
    operate: Operate<'_>,
) {
    store.publish_init(b"record").expect("written");
    store.replace_document(b"document").expect("written");
    store.append_succession(&item(1)).expect("added");
    store.publish_public(1, &[1; 32]).expect("published");
    store.publish_public(2, &[2; 32]).expect("published");
    store.record_start(b"boot").expect("recorded");
    operate(&mut |applying| {
        store.retire(applying, &OLD, b"reset").expect("retired");
        store.mark_resetting(applying, &OLD).expect("marked");
    });
    store.clear().expect("cleared");
    assert_eq!(store.document().expect("reads"), None);
    assert!(store.successions().expect("reads").is_empty());
    assert!(store.held_epochs().expect("reads").is_empty());
    assert_eq!(store.public(1).expect("reads"), None);
    assert!(!store.started().expect("reads"));
    // What a reset run again reads to complete itself stays.
    assert_eq!(
        store.init().expect("reads").as_deref(),
        Some(&b"record"[..])
    );
    assert_eq!(store.resetting().expect("reads").as_deref(), Some(&OLD[..]));
    assert_eq!(store.retired().expect("reads").len(), 1);
    // The next identity is written where the last one was.
    store.replace_document(b"next").expect("written");
    store.publish_public(1, &[7; 32]).expect("published");
    store.append_succession(&item(9)).expect("added");
    assert_eq!(store.successions().expect("reads").len(), 1);
}

fn records_together_are_written_once<S: IdentityStore + ?Sized>(store: &S) {
    const THREADS: u8 = 8;
    const ROUNDS: u64 = 6;
    for round in 1..=ROUNDS {
        let wrote = AtomicUsize::new(0);
        let together = Barrier::new(usize::from(THREADS));
        std::thread::scope(|scope| {
            for thread in 1..=THREADS {
                let (wrote, together) = (&wrote, &together);
                scope.spawn(move || {
                    together.wait();
                    if store.publish_public(round, &[thread; 32]).is_ok() {
                        wrote.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(
            wrote.load(Ordering::Relaxed),
            1,
            "one key is published for an epoch, the others are refused"
        );
        assert!(store.public(round).expect("reads").is_some());
    }
    // And the provisioning record alike.
    let wrote = AtomicUsize::new(0);
    let together = Barrier::new(usize::from(THREADS));
    std::thread::scope(|scope| {
        for thread in 1..=THREADS {
            let (wrote, together) = (&wrote, &together);
            scope.spawn(move || {
                together.wait();
                if store.publish_init(&[thread; 8]).is_ok() {
                    wrote.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(wrote.load(Ordering::Relaxed), 1, "one record is written");
}
