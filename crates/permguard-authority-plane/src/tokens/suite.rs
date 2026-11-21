// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`TokenStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! its tokens survive its own restart, in its own tests.
//!
//! | Case                            | Rule of the contract                                       |
//! | ------------------------------- | ---------------------------------------------------------- |
//! | `an_empty_store`                | nothing held, revision 0                                   |
//! | `a_token_draws_an_entry`        | an issue opens the list it needs and draws a free entry    |
//! | `the_invalid_is_refused`        | a token expires after it is issued and carries a scope     |
//! | `a_status_changes_and_ends`     | a change is counted and shown in the list; `INVALID` ends  |
//! | `an_expired_token_is_left`      | past a clock skew after its expiry a token is not changed  |
//! | `the_open_list_never_retires`   | whatever expired in it                                     |
//! | `the_newest_token_reads_first`  | live tokens newest first; a key's last use                 |
//!
//! The suite does not retire a closed list: closing one takes [`OPEN_UNTIL`](super::OPEN_UNTIL)
//! issues.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use permguard_core::authz::{Selector, TokenScope};
use permguard_host::authz::access_tokens::CLOCK_SKEW;
use permguard_host::operations::journal::OperationId;
use permguard_objects::status_list::ENTRIES;

use super::{IssuedToken, TokenDraft, TokenError, TokenStore, status};

const NOW: u64 = 1_800_000_000;
const KEY: &str = "pgak_AAAAAAAAAAAAAAAAAAAA";

fn draft(account: &str) -> TokenDraft {
    TokenDraft {
        account: account.to_owned(),
        access_key: KEY.to_owned(),
        scopes: vec![TokenScope {
            operations: std::iter::once("decision.evaluate".to_owned()).collect(),
            selector: Selector::parse("plane/data/*").expect("a selector"),
        }],
        expires_at: NOW + 3_600,
    }
}

fn revision<S: TokenStore + ?Sized>(store: &S) -> u64 {
    store.revision().expect("the revision reads")
}

fn held<S: TokenStore + ?Sized>(store: &S, token: &IssuedToken) -> IssuedToken {
    store
        .token(&token.jti)
        .expect("the token reads")
        .expect("the token is held")
}

/// The value of the list entry `token` reads its status from.
fn entry<S: TokenStore + ?Sized>(store: &S, token: &IssuedToken) -> u8 {
    store
        .list(&token.list_id)
        .expect("the list reads")
        .expect("the list is held")
        .list
        .get(usize::try_from(token.index).expect("an index"))
        .expect("the entry is in the list")
}

fn of<'a>(account: &'a str) -> impl Fn(&IssuedToken) -> bool + 'a {
    move |token| token.account == account
}

/// Runs every case, each on a store `make` has just made empty.
pub fn run<S: TokenStore + ?Sized>(make: &dyn Fn() -> Arc<S>) {
    an_empty_store(&*make());
    a_token_draws_an_entry(&*make());
    the_invalid_is_refused(&*make());
    a_status_changes_and_ends(&*make());
    an_expired_token_is_left(&*make());
    the_open_list_never_retires(&*make());
    the_newest_token_reads_first(&*make());
}

fn an_empty_store<S: TokenStore + ?Sized>(store: &S) {
    assert_eq!(revision(store), 0);
    assert!(store.list_ids().expect("the lists read").is_empty());
    assert!(store.live_tokens(NOW).expect("the tokens read").is_empty());
    assert!(store.token(&[1; 16]).expect("the token reads").is_none());
    assert!(store.list(&[1; 16]).expect("the list reads").is_none());
    assert!(
        store
            .changed_at(&[1; 16])
            .expect("the list reads")
            .is_none()
    );
    assert!(store.last_used(KEY).expect("the key reads").is_none());
    assert!(
        store
            .operation(&OperationId::from_bytes([7; 16]))
            .expect("the operation reads")
            .is_none()
    );
}

fn a_token_draws_an_entry<S: TokenStore + ?Sized>(store: &S) {
    let first = store.issue(draft("billing"), NOW).expect("issued");
    let after_first = revision(store);
    assert!(after_first > 0, "an issue is a change");
    let second = store.issue(draft("payroll"), NOW).expect("issued");
    assert!(revision(store) > after_first, "and so is the next");
    assert_eq!(first.list_id, second.list_id, "one open list");
    assert_ne!(first.index, second.index, "an entry is drawn once");
    assert_ne!(first.jti, second.jti);
    for token in [&first, &second] {
        assert!(usize::try_from(token.index).expect("an index") < ENTRIES);
        assert_eq!(token.status, status::VALID);
        assert_eq!(token.issued_at, NOW);
        assert_eq!(token.expires_at, NOW + 3_600);
        assert_eq!(token.access_key, KEY);
        assert_eq!(&held(store, token), token);
        assert_eq!(entry(store, token), status::VALID);
    }
    assert_eq!(first.account, "billing");
    assert_eq!(
        store.list_ids().expect("the lists read"),
        vec![first.list_id]
    );
    assert!(
        store
            .changed_at(&first.list_id)
            .expect("the list reads")
            .is_some()
    );
}

fn the_invalid_is_refused<S: TokenStore + ?Sized>(store: &S) {
    let mut expired = draft("billing");
    expired.expires_at = NOW;
    assert!(matches!(
        store.issue(expired, NOW),
        Err(TokenError::Invalid(_))
    ));
    let mut bare = draft("billing");
    bare.scopes.clear();
    assert!(matches!(
        store.issue(bare, NOW),
        Err(TokenError::Invalid(_))
    ));
    assert_eq!(revision(store), 0, "a refusal writes nothing");
    assert!(store.list_ids().expect("the lists read").is_empty());
}

fn a_status_changes_and_ends<S: TokenStore + ?Sized>(store: &S) {
    let billing = store.issue(draft("billing"), NOW).expect("issued");
    let payroll = store.issue(draft("payroll"), NOW).expect("issued");
    let before = revision(store);
    let listed = store
        .changed_at(&billing.list_id)
        .expect("the list reads")
        .expect("the list is held");

    let set = |value: u8| store.set_status(None, &of("billing"), value, "t", NOW);
    assert_eq!(set(status::SUSPENDED).expect("set"), 1);
    let suspended = revision(store);
    assert!(suspended > before, "a status changed is a change");
    assert_eq!(held(store, &billing).status, status::SUSPENDED);
    assert_eq!(entry(store, &billing), status::SUSPENDED);
    assert!(
        store
            .changed_at(&billing.list_id)
            .expect("the list reads")
            .expect("the list is held")
            > listed,
        "a status change is a change of its list"
    );
    assert_eq!(
        set(status::SUSPENDED).expect("nothing"),
        0,
        "the status it holds"
    );
    assert_eq!(set(status::INVALID).expect("set"), 1);
    assert_eq!(entry(store, &billing), status::INVALID);
    assert_eq!(
        set(status::VALID).expect("nothing"),
        0,
        "INVALID is terminal"
    );
    assert_eq!(set(status::SUSPENDED).expect("nothing"), 0);
    assert_eq!(held(store, &billing).status, status::INVALID);
    let ended = revision(store);
    assert!(ended > suspended);

    // The other account's token was never selected.
    assert_eq!(held(store, &payroll).status, status::VALID);
    assert_eq!(entry(store, &payroll), status::VALID);
    assert_eq!(
        store
            .set_status(None, &of("nobody"), status::INVALID, "t", NOW)
            .expect("nothing"),
        0
    );
    assert!(matches!(
        store.set_status(None, &of("payroll"), 9, "t", NOW),
        Err(TokenError::Invalid(_))
    ));
    assert_eq!(
        revision(store),
        ended,
        "what changes nothing leaves the revision"
    );
}

fn an_expired_token_is_left<S: TokenStore + ?Sized>(store: &S) {
    let token = store.issue(draft("billing"), NOW).expect("issued");
    let before = revision(store);
    // A Plane accepts a token until a clock skew past its expiry: until then it is revocable.
    let past = token.expires_at + CLOCK_SKEW;
    assert_eq!(
        store
            .set_status(None, &of("billing"), status::INVALID, "t", past)
            .expect("nothing"),
        0
    );
    assert_eq!(revision(store), before);
    assert_eq!(
        store
            .set_status(None, &of("billing"), status::INVALID, "t", past - 1)
            .expect("set"),
        1
    );
    assert_eq!(held(store, &token).status, status::INVALID);
}

fn the_open_list_never_retires<S: TokenStore + ?Sized>(store: &S) {
    let token = store.issue(draft("billing"), NOW).expect("issued");
    let later = token.expires_at + CLOCK_SKEW + 1;
    let before = revision(store);
    assert_eq!(store.retire_expired("t", later).expect("retired"), 0);
    assert_eq!(revision(store), before);
    assert_eq!(
        store.list_ids().expect("the lists read"),
        vec![token.list_id]
    );
    assert!(
        store
            .live_tokens(later)
            .expect("the tokens read")
            .is_empty()
    );
    // Expired, and still held with its list.
    assert_eq!(held(store, &token).status, status::VALID);
}

fn the_newest_token_reads_first<S: TokenStore + ?Sized>(store: &S) {
    let first = store.issue(draft("billing"), NOW).expect("issued");
    let mut later = draft("payroll");
    later.expires_at = NOW + 7_200;
    let second = store.issue(later, NOW + 10).expect("issued");
    let live: Vec<[u8; 16]> = store
        .live_tokens(NOW + 10)
        .expect("the tokens read")
        .into_iter()
        .map(|token| token.jti)
        .collect();
    assert_eq!(live, vec![second.jti, first.jti]);
    assert_eq!(store.last_used(KEY).expect("the key reads"), Some(NOW + 10));
    // Not yet expired is live; at its expiry a token is not.
    let live = store
        .live_tokens(first.expires_at)
        .expect("the tokens read");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].jti, second.jti);
}
