// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`AccountStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! its accounts survive its own restart, in its own tests.
//!
//! | Case                         | Rule of the contract                                          |
//! | ---------------------------- | ------------------------------------------------------------- |
//! | `an_empty_store`             | nothing held, revision 0                                      |
//! | `what_is_written_is_read`    | every read answers what the last change wrote                 |
//! | `the_revision_counts_changes`| it rises by one with every change, and never otherwise        |
//! | `the_invalid_is_refused`     | [`validate`](super::validate) first, and nothing written      |
//! | `a_key_names_one_account`    | an access key of one account is refused to another            |
//! | `a_change_follows_its_read`  | a change from a revision that is not the account's conflicts  |
//! | `the_administrator_stays`    | `admin` is never deleted; what is not held is not found       |
//! | `a_deletion_takes_the_keys`  | a deleted account's keys name nothing                         |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use permguard_core::authz::{Selector, TokenScope, operations};
use permguard_host::operations::journal::OperationId;

use super::{
    ADMIN, AccessKey, Account, AccountStore, AccountsError, MAX_LIVE_KEYS, Status, admin_scopes,
};

fn scope(operations: &[&str], selector: &str) -> TokenScope {
    TokenScope {
        operations: operations.iter().map(|op| (*op).to_owned()).collect(),
        selector: Selector::parse(selector).expect("a selector"),
    }
}

fn key(id: &str) -> AccessKey {
    AccessKey {
        access_key: id.to_owned(),
        secret_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
        created_at: 10,
        expires_at: None,
    }
}

fn revision<S: AccountStore + ?Sized>(store: &S) -> u64 {
    store.revision().expect("the revision reads")
}

fn held<S: AccountStore + ?Sized>(store: &S, name: &str) -> Option<Account> {
    store.get(name).expect("the account reads")
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: AccountStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    an_empty_store(&*make());
    what_is_written_is_read(&*make());
    the_revision_counts_changes(&*make());
    the_invalid_is_refused(&*make());
    a_key_names_one_account(&*make());
    a_change_follows_its_read(&*make());
    the_administrator_stays(&*make());
    a_deletion_takes_the_keys(&*make());
}

fn an_empty_store<S: AccountStore + ?Sized>(store: &S) {
    assert_eq!(revision(store), 0);
    assert_eq!(store.count().expect("the count reads"), 0);
    assert!(store.list().expect("the list reads").is_empty());
    assert!(held(store, "billing").is_none());
    assert!(
        store
            .by_access_key("pgak_AAAAAAAAAAAAAAAAAAAA")
            .expect("the key reads")
            .is_none()
    );
    assert!(
        store
            .operation(&OperationId::from_bytes([7; 16]))
            .expect("the operation reads")
            .is_none()
    );
}

fn what_is_written_is_read<S: AccountStore + ?Sized>(store: &S) {
    let billing = Account::new(
        "billing",
        "the billing service",
        vec![scope(&[operations::DECISION_EVALUATE], "plane/data/*")],
        10,
    );
    let written = store.put(None, billing, "test", 10).expect("written");
    assert_eq!(written.revision, 1);
    assert_eq!(written.created_at, 10);
    assert_eq!(written.updated_at, 10);
    assert_eq!(held(store, "billing").as_ref(), Some(&written));

    let mut changed = written.clone();
    changed.status = Status::Suspended;
    changed.keys.push(key("pgak_AAAAAAAAAAAAAAAAAAAA"));
    let changed = store.put(None, changed, "test", 20).expect("changed");
    assert_eq!(changed.revision, 2);
    assert_eq!(changed.created_at, 10, "a change keeps when it was made");
    assert_eq!(changed.updated_at, 20);
    assert_eq!(changed.status, Status::Suspended);

    let read = held(store, "billing").expect("held");
    assert_eq!(read, changed);
    assert_eq!(store.count().expect("the count reads"), 1);
    assert_eq!(store.list().expect("the list reads"), vec![changed.clone()]);
    let (account, found) = store
        .by_access_key("pgak_AAAAAAAAAAAAAAAAAAAA")
        .expect("the key reads")
        .expect("the key is held");
    assert_eq!(account, changed);
    assert_eq!(found.access_key, "pgak_AAAAAAAAAAAAAAAAAAAA");
}

fn the_revision_counts_changes<S: AccountStore + ?Sized>(store: &S) {
    for (at, name) in ["one", "two", "three"].into_iter().enumerate() {
        let written = store
            .put(None, Account::new(name, "", Vec::new(), 1), "test", 1)
            .expect("written");
        assert_eq!(written.revision, at as u64 + 1);
        assert_eq!(revision(store), at as u64 + 1);
    }
    store.delete(None, "two", "test", 2).expect("deleted");
    assert_eq!(revision(store), 4);
    // A refusal changes nothing, the revision included.
    assert!(store.delete(None, "two", "test", 3).is_err());
    assert!(
        store
            .put(None, Account::new("Upper", "", Vec::new(), 3), "test", 3)
            .is_err()
    );
    assert_eq!(revision(store), 4);
    let names: Vec<String> = store
        .list()
        .expect("the list reads")
        .into_iter()
        .map(|account| account.name)
        .collect();
    assert_eq!(names, vec!["one", "three"], "the list is by name");
}

fn the_invalid_is_refused<S: AccountStore + ?Sized>(store: &S) {
    let long = "a".repeat(64);
    for bad in ["", "Upper", "-dash", long.as_str(), "sp ace"] {
        assert!(
            matches!(
                store.put(None, Account::new(bad, "", Vec::new(), 1), "t", 1),
                Err(AccountsError::Invalid(_))
            ),
            "the name {bad:?}"
        );
    }
    assert!(matches!(
        store.put(
            None,
            Account::new("a", &"d".repeat(1_025), Vec::new(), 1),
            "t",
            1
        ),
        Err(AccountsError::Invalid(_))
    ));
    // An operation outside the registry, one that never applies where it is placed, none.
    for scopes in [
        vec![scope(&["nothing.at.all"], "plane/data/*")],
        vec![scope(&[operations::DECISION_EVALUATE], "plane/control/*")],
        vec![scope(&[], "plane/data/*")],
    ] {
        assert!(matches!(
            store.put(None, Account::new("a", "", scopes, 1), "t", 1),
            Err(AccountsError::Invalid(_))
        ));
    }
    let mut crowded = Account::new("crowded", "", Vec::new(), 1);
    crowded.keys = (0..=MAX_LIVE_KEYS)
        .map(|at| key(&format!("pgak_{}", ["A", "B", "C", "D"][at % 4].repeat(20))))
        .collect();
    assert!(matches!(
        store.put(None, crowded, "t", 1),
        Err(AccountsError::Conflict(_))
    ));
    assert_eq!(revision(store), 0, "a refusal writes nothing");
    assert_eq!(store.count().expect("the count reads"), 0);
}

fn a_key_names_one_account<S: AccountStore + ?Sized>(store: &S) {
    let mut one = Account::new("one", "", Vec::new(), 1);
    one.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
    let one = store.put(None, one, "t", 1).expect("written");
    let mut other = Account::new("other", "", Vec::new(), 1);
    other.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
    assert!(matches!(
        store.put(None, other, "t", 1),
        Err(AccountsError::Conflict(_))
    ));
    assert!(held(store, "other").is_none());
    // The account that holds the key keeps it through its own changes.
    let mut again = one;
    again.description = "still its key".to_owned();
    store
        .put(None, again, "t", 2)
        .expect("its own key is no conflict");
}

fn a_change_follows_its_read<S: AccountStore + ?Sized>(store: &S) {
    let first = store
        .put(None, Account::new("billing", "", Vec::new(), 1), "t", 1)
        .expect("written");
    let mut later = first.clone();
    later.description = "changed".to_owned();
    let later = store.put(None, later, "t", 2).expect("changed");

    // Made from the revision before the last change: the change it did not see would be lost.
    let mut stale = first;
    stale.description = "lost".to_owned();
    assert!(matches!(
        store.put(None, stale, "t", 3),
        Err(AccountsError::Conflict(_))
    ));
    // A new account of a name that is held.
    assert!(matches!(
        store.put(None, Account::new("billing", "", Vec::new(), 3), "t", 3),
        Err(AccountsError::Conflict(_))
    ));
    // A change of an account that is not held.
    let mut gone = Account::new("gone", "", Vec::new(), 3);
    gone.revision = 9;
    assert!(matches!(
        store.put(None, gone, "t", 3),
        Err(AccountsError::Conflict(_))
    ));
    assert_eq!(held(store, "billing"), Some(later));
    assert_eq!(revision(store), 2);
    assert!(held(store, "gone").is_none());
}

fn the_administrator_stays<S: AccountStore + ?Sized>(store: &S) {
    store
        .put(None, Account::new(ADMIN, "", admin_scopes(), 1), "t", 1)
        .expect("the administrator");
    assert!(matches!(
        store.delete(None, ADMIN, "t", 2),
        Err(AccountsError::Conflict(_))
    ));
    assert!(held(store, ADMIN).is_some());
    assert!(matches!(
        store.delete(None, "nobody", "t", 2),
        Err(AccountsError::NotFound(_))
    ));
    assert_eq!(revision(store), 1);
}

fn a_deletion_takes_the_keys<S: AccountStore + ?Sized>(store: &S) {
    let mut one = Account::new("one", "", Vec::new(), 1);
    one.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
    store.put(None, one, "t", 1).expect("written");
    store.delete(None, "one", "t", 2).expect("deleted");
    assert!(held(store, "one").is_none());
    assert!(
        store
            .by_access_key("pgak_AAAAAAAAAAAAAAAAAAAA")
            .expect("the key reads")
            .is_none()
    );
    // The name is free again, and the account made under it is a new one.
    let again = store
        .put(None, Account::new("one", "", Vec::new(), 3), "t", 3)
        .expect("written again");
    assert_eq!(again.revision, 3);
    assert_eq!(again.created_at, 3);
}
