// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Two Authority Planes over one database (iteration 03, WP-28.2): what one instance signs, the
//! other signs past, and a revocation either commits is in every list signed after it.
//!
//! The tests need a server, as `permguard-postgres`'s `foundations.rs` says, and are skipped
//! without one.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use base64::Engine as _;
use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Selector, TokenScope};
use permguard_host::authz::Authorization;
use permguard_host::composition::{
    AUTHORITY_TOKENS, AccessTokenV1, Declaration, Host, StatusListTokenV1,
};
use permguard_host::identity::record::uuid_text;
use permguard_host::time::TimeGuard;
use permguard_postgres::testing::{Cases, server};

use crate::PLANE;
use crate::accounts::postgres::PostgresAccounts;
use crate::authority::{Authority, Parts};
use crate::marks::MarkStore;
use crate::tokens::postgres::{PostgresMarks, PostgresTokens};
use crate::tokens::{TokenDraft, TokenStore, status};

/// An Authority Plane of one instance over `database`, signing lists with the keys at `keys`.
fn instance(database: &permguard_postgres::Database, keys: &std::path::Path) -> Authority {
    instance_feeding(database, keys, None)
}

/// [`instance`], also signing tokens, feeding the trust `trust` of its Host when one is given.
fn instance_feeding(
    database: &permguard_postgres::Database,
    keys: &std::path::Path,
    trust: Option<Arc<permguard_host::authz::authority::AuthorityTrust>>,
) -> Authority {
    let ring: Arc<dyn permguard_core::KeyManager> =
        Arc::new(permguard_std::keys::DirectoryKeyManager::new(
            keys.to_path_buf(),
            permguard_std::keys::KeyPolicy {
                publish_ahead: std::time::Duration::ZERO,
                rotate_every: std::time::Duration::from_secs(3600),
                retain: std::time::Duration::from_secs(3600),
                verify_retain: std::time::Duration::from_secs(3600),
            },
        ));
    ring.maintain().expect("the ring publishes");
    ring.maintain().expect("the ring activates");
    let registration = Host::builder()
        .ring(AUTHORITY_TOKENS, ring)
        .build()
        .register(
            Declaration::new(PLANE)
                .signs::<AccessTokenV1>()
                .signs::<StatusListTokenV1>(),
        )
        .expect("the declaration registers");
    let lists = registration
        .signer::<StatusListTokenV1>()
        .expect("a signer")
        .expect("the ring is composed");
    let tokens = registration
        .signer::<AccessTokenV1>()
        .expect("a signer")
        .expect("the ring is composed");
    Authority::new(Parts {
        accounts: Arc::new(PostgresAccounts::new(database.clone())),
        registry: Arc::new(PostgresTokens::new(database.clone())),
        tokens: Some(tokens),
        lists: Some(lists),
        issuer: "https://authority.example:8443".to_owned(),
        audience: "permguard".to_owned(),
        profile: AssuranceProfile::Development,
        authorization: Arc::new(Authorization::permissive()),
        mutations: None,
        audit: None,
        trust,
        time: Arc::new(TimeGuard::system(std::time::Duration::from_secs(30))),
        marks: Some(Arc::new(PostgresMarks::new(database.clone())) as Arc<dyn MarkStore>),
    })
    .expect("the Authority is made")
}

/// What a signed list says: its `iat` and its bits.
fn read(compact: &str) -> (u64, serde_json::Value) {
    let payload = compact.split('.').nth(1).expect("a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url");
    let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    (
        payload["iat"].as_u64().expect("an iat"),
        payload["status_list"]["lst"].clone(),
    )
}

/// An instance that read the marks before another signed past them signs past that one (X84),
/// and the revocation the other instance committed is in what it signs.
#[test]
fn instances_sign_one_list_past_each_other_and_lose_no_revocation_on_postgresql() {
    let Some(server) =
        server("instances_sign_one_list_past_each_other_and_lose_no_revocation_on_postgresql")
    else {
        return;
    };
    let cases = Cases::new(server);
    let database = cases.next();
    let keys = std::env::temp_dir().join(format!("pg-authority-instances-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    // Both made before either signs: each read the marks as they were then, none.
    let (one, other) = (instance(&database, &keys), instance(&database, &keys));
    let registry = PostgresTokens::new(database.clone());
    let now = permguard_core::time::unix_now();
    let draft = || TokenDraft {
        account: "billing".to_owned(),
        access_key: "pgak_AAAAAAAAAAAAAAAAAAAA".to_owned(),
        scopes: vec![TokenScope {
            operations: std::iter::once("decision.evaluate".to_owned()).collect(),
            selector: Selector::parse("plane/data/*").expect("a selector"),
        }],
        expires_at: now + 3_600,
    };
    let first = registry.issue(draft(), now).expect("issued");
    let second = registry.issue(draft(), now).expect("issued");
    assert_eq!(first.list_id, second.list_id);
    let list = uuid_text(&first.list_id);

    let (signed, _) = read(&one.list_token(&list).expect("signed"));
    // Revoked, then signed again by the same instance: its `iat` strictly after.
    registry
        .set_status(
            None,
            &|token| token.jti == first.jti,
            status::INVALID,
            "operator",
            now,
        )
        .expect("revoked");
    let (revoked_at, revoked) = read(&one.list_token(&list).expect("signed"));
    assert!(revoked_at > signed);
    // The other instance, behind on the mark, signs past it and with the revocation in.
    let (later, bits) = read(&other.list_token(&list).expect("signed past the mark"));
    assert!(later > revoked_at, "{later} after {revoked_at}");
    assert_eq!(
        bits, revoked,
        "the revocation is in what the other instance signs"
    );
    // A second revocation, committed through the other instance's store, reaches the first.
    registry
        .set_status(
            None,
            &|token| token.jti == second.jti,
            status::INVALID,
            "operator",
            now,
        )
        .expect("revoked");
    let (last, both) = read(&one.list_token(&list).expect("signed"));
    assert!(last > later);
    assert_ne!(both, bits, "the second revocation is in the list");
    let _ = std::fs::remove_dir_all(keys);
}

/// An instance that read the marks at its start signs a list after another instance signed
/// another list past what it read: the marks it keeps are every list's as the store holds them,
/// not the ones it read (X84, the reviewer's finding of WP-28.2).
#[test]
fn an_instance_behind_on_another_list_still_signs_on_postgresql() {
    let Some(server) = server("an_instance_behind_on_another_list_still_signs_on_postgresql")
    else {
        return;
    };
    let cases = Cases::new(server);
    let database = cases.next();
    let keys = std::env::temp_dir().join(format!("pg-authority-behind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    // Another list the tokens hold, signed up to 10 when this instance starts.
    let other_list = [9_u8; 16];
    database
        .write(|unit| {
            unit.execute(
                "INSERT INTO permguard_authority_lists
                     (list_id, open, drawn, latest_expiry, changed_at)
                 VALUES ($1, false, 0, 0, 0)",
                &[&other_list.as_slice()],
            )
        })
        .expect("a list");
    let marks = PostgresMarks::new(database.clone());
    marks
        .keep(&std::collections::BTreeMap::from([(other_list, 10)]))
        .expect("kept");
    let behind = instance(&database, &keys);
    // Another instance signs that list past it.
    marks
        .keep(&std::collections::BTreeMap::from([(other_list, 20)]))
        .expect("kept");
    let registry = PostgresTokens::new(database.clone());
    let now = permguard_core::time::unix_now();
    let issued = registry
        .issue(
            TokenDraft {
                account: "billing".to_owned(),
                access_key: "pgak_AAAAAAAAAAAAAAAAAAAA".to_owned(),
                scopes: vec![TokenScope {
                    operations: std::iter::once("decision.evaluate".to_owned()).collect(),
                    selector: Selector::parse("plane/data/*").expect("a selector"),
                }],
                expires_at: now + 3_600,
            },
            now,
        )
        .expect("issued");
    behind
        .list_token(&uuid_text(&issued.list_id))
        .expect("signed, the other list's mark taken as the store holds it");
    assert_eq!(
        marks.held().get(&other_list),
        Some(&20),
        "and never lowered"
    );
    let _ = std::fs::remove_dir_all(keys);
}

/// WP-28.7: a token another instance issued names a list it opened a moment ago. This instance's
/// Host does not hold it, and the token's want of it makes the feed due at once: what the feed
/// hands over is the list, from the store both instances keep.
#[test]
fn a_list_another_instance_opened_is_fed_when_a_token_wants_it_on_postgresql() {
    use permguard_host::authz::access_tokens::Trust as _;

    let Some(server) =
        server("a_list_another_instance_opened_is_fed_when_a_token_wants_it_on_postgresql")
    else {
        return;
    };
    let cases = Cases::new(server);
    let database = cases.next();
    let keys =
        std::env::temp_dir().join(format!("pg-authority-instances-fed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    let issuer = "https://authority.example:8443";
    let trust = Arc::new(permguard_host::authz::authority::AuthorityTrust::in_memory(
        Some(issuer),
        "permguard",
    ));
    let this = instance_feeding(&database, &keys, Some(Arc::clone(&trust)));
    this.feed_trust();
    assert!(!this.trust_wanted(), "nothing wanted yet");
    // Another instance issues, through the store both keep, from a list it opens.
    let now = permguard_core::time::unix_now();
    let issued = PostgresTokens::new(database.clone())
        .issue(
            TokenDraft {
                account: "billing".to_owned(),
                access_key: "pgak_AAAAAAAAAAAAAAAAAAAA".to_owned(),
                scopes: vec![TokenScope {
                    operations: std::iter::once("decision.evaluate".to_owned()).collect(),
                    selector: Selector::parse("plane/data/*").expect("a selector"),
                }],
                expires_at: now + 3_600,
            },
            now,
        )
        .expect("issued");
    let uri = this.list_uri(&issued.list_id);
    assert!(trust.lists().list(issuer, &uri).is_none(), "not held here");
    // The token names it: the verifier asks, and the feed is due at once, once.
    trust.unknown_list(&uri);
    assert!(this.trust_wanted(), "a token wants the list");
    assert!(!this.trust_wanted(), "taken once");
    this.feed_trust();
    assert!(
        trust.lists().list(issuer, &uri).is_some(),
        "the feed hands the list over"
    );
    let _ = std::fs::remove_dir_all(keys);
}
