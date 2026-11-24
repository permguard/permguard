// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's store contracts kept on PostgreSQL: each passes the conformance suite its file
//! backend passes, every change of an operation inside a transaction of the mutation engine.
//!
//! The tests need a server, as `foundations.rs` says, and are skipped without one.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_postgres::audit::PostgresTrails;
use permguard_postgres::bootstrap::PostgresBootstrap;
use permguard_postgres::catalog::PostgresCatalog;
use permguard_postgres::delivered::PostgresDeliveredKeys;
use permguard_postgres::held::PostgresHeld;
use permguard_postgres::holds::PostgresHolds;
use permguard_postgres::identity::PostgresIdentity;
use permguard_postgres::members::PostgresMembers;
use permguard_postgres::peers::PostgresSeen;
use permguard_postgres::replay::PostgresReplay;
use permguard_postgres::ring::PostgresRing;
use permguard_postgres::slots::PostgresSlots;
use permguard_postgres::testing::{Cases, server};
use permguard_postgres::witnesses::{PostgresVersionWitnesses, PostgresWitnesses};

#[test]
fn the_holds_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_holds_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::holds::suite::run(&|| Arc::new(PostgresHolds::new(cases.next())), &|work| {
        cases.operate(permguard_host::holds::DOMAIN, work)
    });
}

#[test]
fn the_seen_epochs_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_seen_epochs_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::session::peers::suite::run(&|| Arc::new(PostgresSeen::new(cases.next())));
}

#[test]
fn the_bootstrap_commitment_keeps_its_contract_on_postgresql() {
    let Some(server) = server("the_bootstrap_commitment_keeps_its_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::authz::store::suite::run(
        &|| Arc::new(PostgresBootstrap::new(cases.next())),
        &|work| cases.operate("authz.bootstrap", work),
    );
}

#[test]
fn the_witnesses_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_witnesses_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::secrets::suite::run_witnesses(&|| {
        Arc::new(PostgresWitnesses::new(cases.next()))
    });
}

#[test]
fn the_version_witnesses_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_version_witnesses_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::identity::witness::suite::run(&|| {
        Arc::new(PostgresVersionWitnesses::new(cases.next()))
    });
}

#[test]
fn what_a_host_holds_of_the_authority_keeps_its_contract_on_postgresql() {
    let Some(server) =
        server("what_a_host_holds_of_the_authority_keeps_its_contract_on_postgresql")
    else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::authz::held::suite::run(&|| Arc::new(PostgresHeld::new(cases.next())));
}

#[test]
fn the_plans_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_plans_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::api::replay::suite::run(
        &|| Arc::new(PostgresReplay::new(cases.next())),
        &|work| cases.operate("host.plans", work),
    );
}

#[test]
fn the_identity_keeps_its_contract_on_postgresql() {
    let Some(server) = server("the_identity_keeps_its_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::identity::suite::run(
        &|| Arc::new(PostgresIdentity::new(cases.next())),
        &|work| cases.operate("host.identity", work),
    );
}

#[test]
fn a_ring_keeps_its_contract_on_postgresql() {
    let Some(server) = server("a_ring_keeps_its_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::keys::ring::suite::run(
        &|| Arc::new(PostgresRing::new(cases.next(), "host-signing")),
        &|work| cases.operate("host.keys", work),
    );
}

#[test]
fn the_rings_of_one_database_are_apart_on_postgresql() {
    use permguard_host::keys::ring::store::RingStore;

    let Some(server) = server("the_rings_of_one_database_are_apart_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    let database = cases.next();
    let (one, other) = (
        PostgresRing::new(database.clone(), "one"),
        PostgresRing::new(database, "other"),
    );
    one.append(1, &[0x01]).expect("added");
    one.replace_view(b"the view of one").expect("written");
    one.publish_public("thumb", b"a key of one")
        .expect("published");
    assert!(other.entries().expect("reads").is_empty());
    assert_eq!(other.view().expect("reads"), None);
    assert_eq!(other.public("thumb").expect("reads"), None);
    other.append(1, &[0x02]).expect("its own first entry");
    other.clear().expect("cleared");
    other.forget_entries().expect("forgotten");
    assert_eq!(one.entries().expect("reads").len(), 1);
    assert!(one.view().expect("reads").is_some());
    assert!(one.public("thumb").expect("reads").is_some());
}

#[test]
fn the_memberships_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_memberships_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::membership::suite::run(&|| Arc::new(PostgresMembers::new(cases.next())));
}

#[test]
fn the_catalog_keeps_its_contract_on_postgresql() {
    let Some(server) = server("the_catalog_keeps_its_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_core::catalog::suite::run(&|| Arc::new(PostgresCatalog::new(cases.next())));
}

#[test]
fn the_audit_trails_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_audit_trails_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::audit::suite::run(&|| Arc::new(PostgresTrails::new(cases.next())));
}

#[test]
fn the_key_slots_keep_their_contract_on_postgresql() {
    let Some(server) = server("the_key_slots_keep_their_contract_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::keys::slots::suite::run(&|| {
        Arc::new(PostgresSlots::new(cases.next(), "host.operations"))
    });
}

#[test]
fn the_delivered_keys_keep_their_contract_sealed_on_postgresql() {
    let Some(server) = server("the_delivered_keys_keep_their_contract_sealed_on_postgresql") else {
        return;
    };
    let cases = Cases::new(server);
    permguard_host::secrets::suite::run_delivered(&|| {
        Arc::new(PostgresDeliveredKeys::new(
            cases.next(),
            permguard_postgres::testing::sealer(),
        ))
    });
    // What the last case kept: every key sealed, none in the clear.
    let rows: Vec<Vec<u8>> = cases
        .current()
        .write(|unit| {
            Ok(unit
                .query("SELECT wrapped FROM permguard_delivered_keys", &[])?
                .into_iter()
                .map(|row| row.get(0))
                .collect())
        })
        .expect("read");
    assert!(!rows.is_empty());
    for row in rows {
        for byte in 1..=4u8 {
            assert!(
                !row.windows(32).any(|window| window == [byte; 32]),
                "a key is in the clear"
            );
        }
    }
}
