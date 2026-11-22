// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's store contracts kept on PostgreSQL: each passes the conformance suite its file
//! backend passes, every change of an operation inside a transaction of the mutation engine.
//!
//! The tests need a server, as `foundations.rs` says, and are skipped without one.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_postgres::bootstrap::PostgresBootstrap;
use permguard_postgres::holds::PostgresHolds;
use permguard_postgres::peers::PostgresSeen;
use permguard_postgres::testing::{Cases, server};

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
