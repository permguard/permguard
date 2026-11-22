// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's store contracts kept on PostgreSQL: each passes the conformance suite its file
//! backend passes, every change of an operation inside a transaction of the mutation engine.
//!
//! The tests need a server, as `foundations.rs` says, and are skipped without one.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_postgres::bootstrap::PostgresBootstrap;
use permguard_postgres::held::PostgresHeld;
use permguard_postgres::holds::PostgresHolds;
use permguard_postgres::peers::PostgresSeen;
use permguard_postgres::replay::PostgresReplay;
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
