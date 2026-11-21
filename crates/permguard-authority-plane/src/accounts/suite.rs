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
//! | `a_change_reads_its_account` | a change is given the account as it stands, and replaces that |
//! | `changes_together_all_hold`  | changes of one account from several threads are all applied   |
//! | `the_administrator_stays`    | `admin` is never deleted; what is not held is not found       |
//! | `a_deletion_asks_first`      | a deletion its guard refuses deletes nothing                  |
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

/// A guard that lets every deletion go.
fn allowed(_: &Account) -> Result<(), AccountsError> {
    Ok(())
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
    a_change_reads_its_account(&*make());
    changes_together_all_hold(&*make());
    the_administrator_stays(&*make());
    a_deletion_asks_first(&*make());
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
    let written = store.create(None, billing, "test", 10).expect("written");
    assert_eq!(written.revision, 1);
    assert_eq!(written.created_at, 10);
    assert_eq!(written.updated_at, 10);
    assert_eq!(held(store, "billing").as_ref(), Some(&written));

    let changed = store
        .update(
            None,
            "billing",
            &|held| {
                let mut changed = held.clone();
                changed.status = Status::Suspended;
                changed.keys.push(key("pgak_AAAAAAAAAAAAAAAAAAAA"));
                Ok(changed)
            },
            "test",
            20,
        )
        .expect("changed");
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
            .create(None, Account::new(name, "", Vec::new(), 1), "test", 1)
            .expect("written");
        assert_eq!(written.revision, at as u64 + 1);
        assert_eq!(revision(store), at as u64 + 1);
    }
    store
        .delete(None, "two", &allowed, "test", 2)
        .expect("deleted");
    assert_eq!(revision(store), 4);
    // A refusal changes nothing, the revision included.
    assert!(store.delete(None, "two", &allowed, "test", 3).is_err());
    assert!(
        store
            .create(None, Account::new("Upper", "", Vec::new(), 3), "test", 3)
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
                store.create(None, Account::new(bad, "", Vec::new(), 1), "t", 1),
                Err(AccountsError::Invalid(_))
            ),
            "the name {bad:?}"
        );
    }
    assert!(matches!(
        store.create(
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
            store.create(None, Account::new("a", "", scopes, 1), "t", 1),
            Err(AccountsError::Invalid(_))
        ));
    }
    let mut crowded = Account::new("crowded", "", Vec::new(), 1);
    crowded.keys = (0..=MAX_LIVE_KEYS)
        .map(|at| key(&format!("pgak_{}", ["A", "B", "C", "D"][at % 4].repeat(20))))
        .collect();
    assert!(matches!(
        store.create(None, crowded, "t", 1),
        Err(AccountsError::Conflict(_))
    ));
    assert_eq!(revision(store), 0, "a refusal writes nothing");
    assert_eq!(store.count().expect("the count reads"), 0);
}

fn a_key_names_one_account<S: AccountStore + ?Sized>(store: &S) {
    let mut one = Account::new("one", "", Vec::new(), 1);
    one.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
    store.create(None, one, "t", 1).expect("written");
    let mut other = Account::new("other", "", Vec::new(), 1);
    other.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
    assert!(matches!(
        store.create(None, other, "t", 1),
        Err(AccountsError::Conflict(_))
    ));
    assert!(held(store, "other").is_none());
    // Nor by a change of an account that is held.
    store
        .create(None, Account::new("other", "", Vec::new(), 2), "t", 2)
        .expect("written");
    assert!(matches!(
        store.update(
            None,
            "other",
            &|held| {
                let mut changed = held.clone();
                changed.keys.push(key("pgak_AAAAAAAAAAAAAAAAAAAA"));
                Ok(changed)
            },
            "t",
            3
        ),
        Err(AccountsError::Conflict(_))
    ));
    assert!(
        held(store, "other").expect("held").keys.is_empty(),
        "a refused change writes nothing"
    );
    // The account that holds the key keeps it through its own changes.
    store
        .update(
            None,
            "one",
            &|held| {
                let mut changed = held.clone();
                changed.description = "still its key".to_owned();
                Ok(changed)
            },
            "t",
            4,
        )
        .expect("its own key is no conflict");
}

fn a_change_reads_its_account<S: AccountStore + ?Sized>(store: &S) {
    let first = store
        .create(None, Account::new("billing", "", Vec::new(), 1), "t", 1)
        .expect("written");
    // Two changes decided from one read of the account: each is given the account as it
    // stands when it is applied, so the second does not undo the first.
    let add_key = |held: &Account| {
        let mut changed = held.clone();
        changed.keys.push(key("pgak_AAAAAAAAAAAAAAAAAAAA"));
        Ok(changed)
    };
    let describe = |held: &Account| {
        let mut changed = held.clone();
        changed.description = "described".to_owned();
        Ok(changed)
    };
    let keyed = store
        .update(None, "billing", &add_key, "t", 2)
        .expect("a key added");
    assert_eq!(keyed.revision, first.revision + 1);
    let described = store
        .update(None, "billing", &describe, "t", 3)
        .expect("described");
    assert_eq!(described.keys.len(), 1, "the key added before is kept");
    assert_eq!(described.description, "described");
    assert_eq!(described.revision, first.revision + 2);
    assert_eq!(described.updated_at, 3);
    assert_eq!(held(store, "billing"), Some(described.clone()));

    // What a change refuses is refused of the account as it is, and nothing is written.
    let seen = std::cell::Cell::new(0);
    let refused = store.update(
        None,
        "billing",
        &|held| {
            seen.set(held.revision);
            Err(AccountsError::Conflict("not this time".to_owned()))
        },
        "t",
        4,
    );
    assert!(matches!(refused, Err(AccountsError::Conflict(detail)) if detail == "not this time"));
    assert_eq!(seen.get(), described.revision, "the account as it stands");
    assert_eq!(revision(store), described.revision);

    // An account keeps its name and when it was made, whatever a change answers.
    let renamed = store
        .update(
            None,
            "billing",
            &|held| {
                let mut changed = held.clone();
                changed.name = "payroll".to_owned();
                changed.created_at = 99;
                Ok(changed)
            },
            "t",
            5,
        )
        .expect("changed");
    assert_eq!(renamed.name, "billing");
    assert_eq!(renamed.created_at, 1);
    assert!(held(store, "payroll").is_none());

    // What a change answers is valid, or it is not written.
    assert!(matches!(
        store.update(
            None,
            "billing",
            &|held| {
                let mut changed = held.clone();
                changed.description = "d".repeat(1_025);
                Ok(changed)
            },
            "t",
            6
        ),
        Err(AccountsError::Invalid(_))
    ));
    assert_eq!(held(store, "billing"), Some(renamed.clone()));

    // An account that is not held is not changed, and one that is held is not made again.
    assert!(matches!(
        store.update(None, "nobody", &describe, "t", 7),
        Err(AccountsError::NotFound(_))
    ));
    assert!(matches!(
        store.create(None, Account::new("billing", "", Vec::new(), 7), "t", 7),
        Err(AccountsError::Conflict(_))
    ));
    assert_eq!(revision(store), renamed.revision);
}

/// Several threads change one account at once, each change counting one up from what it is
/// given. A store that gave a change a copy read before another change landed would lose
/// counts; one that reads and writes the account as one step loses none.
fn changes_together_all_hold<S: AccountStore + ?Sized>(store: &S) {
    const THREADS: u64 = 8;
    const EACH: u64 = 25;
    let made = store
        .create(None, Account::new("counter", "0", Vec::new(), 1), "t", 1)
        .expect("written");
    let count_up = |held: &Account| {
        let count: u64 = held
            .description
            .parse()
            .map_err(|_| AccountsError::Invalid("the count does not read".to_owned()))?;
        let mut changed = held.clone();
        changed.description = (count + 1).to_string();
        Ok(changed)
    };
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for _ in 0..EACH {
                    store
                        .update(None, "counter", &count_up, "t", 2)
                        .expect("a change that arrives with others is applied");
                }
            });
        }
    });
    let counted = held(store, "counter").expect("held");
    assert_eq!(
        counted.description,
        (THREADS * EACH).to_string(),
        "every change is applied to the account the one before it left"
    );
    assert_eq!(counted.revision, made.revision + THREADS * EACH);
    assert_eq!(revision(store), made.revision + THREADS * EACH);
}

fn the_administrator_stays<S: AccountStore + ?Sized>(store: &S) {
    store
        .create(None, Account::new(ADMIN, "", admin_scopes(), 1), "t", 1)
        .expect("the administrator");
    assert!(matches!(
        store.delete(None, ADMIN, &allowed, "t", 2),
        Err(AccountsError::Conflict(_))
    ));
    assert!(held(store, ADMIN).is_some());
    assert!(matches!(
        store.delete(None, "nobody", &allowed, "t", 2),
        Err(AccountsError::NotFound(_))
    ));
    assert_eq!(revision(store), 1);
}

fn a_deletion_asks_first<S: AccountStore + ?Sized>(store: &S) {
    let written = store
        .create(None, Account::new("billing", "", Vec::new(), 1), "t", 1)
        .expect("written");
    let seen = std::cell::Cell::new(0);
    let refused = store.delete(
        None,
        "billing",
        &|held| {
            seen.set(held.revision);
            Err(AccountsError::Conflict("not this one".to_owned()))
        },
        "t",
        2,
    );
    assert!(matches!(refused, Err(AccountsError::Conflict(detail)) if detail == "not this one"));
    assert_eq!(seen.get(), written.revision, "the account as it stands");
    assert_eq!(held(store, "billing"), Some(written));
    assert_eq!(revision(store), 1);
}

fn a_deletion_takes_the_keys<S: AccountStore + ?Sized>(store: &S) {
    let mut one = Account::new("one", "", Vec::new(), 1);
    one.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
    store.create(None, one, "t", 1).expect("written");
    store
        .delete(None, "one", &allowed, "t", 2)
        .expect("deleted");
    assert!(held(store, "one").is_none());
    assert!(
        store
            .by_access_key("pgak_AAAAAAAAAAAAAAAAAAAA")
            .expect("the key reads")
            .is_none()
    );
    // The name is free again, and the account made under it is a new one.
    let again = store
        .create(None, Account::new("one", "", Vec::new(), 3), "t", 3)
        .expect("written again");
    assert_eq!(again.revision, 3);
    assert_eq!(again.created_at, 3);
}
