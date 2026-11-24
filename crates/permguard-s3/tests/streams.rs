// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A stream consumer's runs kept on PostgreSQL and S3: they pass the conformance suite the file
//! backend passes.
//!
//! The tests need both servers, as `permguard_postgres::testing` and `permguard_s3::testing`
//! say, and are skipped without them.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_postgres::testing::{Cases, server};
use permguard_s3::streams::PostgresRuns;

#[test]
fn a_consumers_runs_keep_their_contract_on_postgresql_and_s3() {
    let test = "a_consumers_runs_keep_their_contract_on_postgresql_and_s3";
    let Some(server) = server(test) else {
        return;
    };
    let cases = Cases::new(server);
    permguard_stream::engine::consumer::suite::run(&|| {
        let bucket = permguard_s3::testing::scratch(test).expect("the run names a bucket");
        Arc::new(PostgresRuns::new(cases.next(), bucket, "data/decisions/1"))
    });
}
