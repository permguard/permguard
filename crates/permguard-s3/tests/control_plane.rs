// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Control Plane's stores kept on PostgreSQL and S3: each passes the conformance suite its
//! file backend passes.
//!
//! The tests need both servers, as `permguard_postgres::testing` and `permguard_s3::testing`
//! say, and are skipped without them. `scripts/test-s3.sh --then scripts/test-postgres.sh`
//! starts both and runs them.

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use permguard_control_plane::catalog::archives::{ArchiveError, ArchiveStore, Keeping, Requested};
use permguard_control_plane::catalog::imports::ArchiveRecord;
use permguard_control_plane::store::{Ledgers as _, REFS_DOMAIN};
use permguard_postgres::testing::{Cases, server};
use permguard_s3::control_plane::{PostgresArchives, PostgresLedgers};
use permguard_s3::testing::scratch;

/// The ledger store passes the contract's suite, each case on a ledger of its own, every ref
/// update inside an operation of the mutation engine.
#[test]
fn the_ledgers_keep_their_contract_on_postgresql_and_s3() {
    let test = "the_ledgers_keep_their_contract_on_postgresql_and_s3";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let cases = Cases::new(server);
    let made = AtomicUsize::new(0);
    permguard_control_plane::store::suite::run(
        &|| {
            let ledger = made.fetch_add(1, Ordering::Relaxed);
            PostgresLedgers::new(cases.next(), bucket.clone())
                .ledger("zone", &format!("ledger-{ledger}"))
        },
        &|work| cases.operate(REFS_DOMAIN, work),
    );
}

/// The archive store passes the contract's suite, each case in a database and under a prefix
/// of the bucket of its own; and whatever the requests of a case were answered, the bucket
/// holds the bytes of the archives the zone keeps and no others.
#[test]
fn the_archives_keep_their_contract_on_postgresql_and_s3() {
    let test = "the_archives_keep_their_contract_on_postgresql_and_s3";
    let Some(server) = server(test) else {
        return;
    };
    let cases = Cases::new(server);
    let made = Mutex::new(Vec::new());
    permguard_control_plane::catalog::archives::suite::run(&|| {
        let bucket = scratch(test).expect("the run names a bucket");
        let database = cases.next();
        made.lock()
            .expect("the stores")
            .push((database.clone(), bucket.clone()));
        Arc::new(PostgresArchives::new(database, bucket))
    });
    let made = made.into_inner().expect("the stores");
    assert!(made.len() > 4, "every case made a store");
    for (database, bucket) in &made {
        let mut bytes: Vec<String> = bucket
            .list("")
            .expect("listed")
            .into_iter()
            .map(|object| object.key)
            .collect();
        bytes.sort();
        let mut rows: Vec<String> = database
            .write(|unit| {
                Ok(unit
                    .query("SELECT zone, id FROM permguard_archives", &[])?
                    .iter()
                    .map(|row| {
                        format!(
                            "zones/{}/archives/{}",
                            row.get::<_, String>(0),
                            row.get::<_, String>(1)
                        )
                    })
                    .collect())
            })
            .expect("read");
        rows.sort();
        assert_eq!(bytes, rows, "one object an archive, and no other");
    }
}

/// Bytes a keeping that stopped left under an archive's key give way to the archive; the bytes
/// of an archive that is kept are never replaced.
#[test]
fn bytes_no_row_names_give_way_on_postgresql_and_s3() {
    let test = "bytes_no_row_names_give_way_on_postgresql_and_s3";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let cases = Cases::new(server);
    let store = PostgresArchives::new(cases.next(), bucket.clone());
    let record = |name: &str| ArchiveRecord {
        id: "0190a000-0000-7000-8000-000000000001".to_owned(),
        name: name.to_owned(),
        imported_at: 1,
        manifest_digest: "sha256:00".to_owned(),
        source_host_id: "host".to_owned(),
        source_zone_id: "zone".to_owned(),
        source_zone_name: "source".to_owned(),
        ledgers: Vec::new(),
    };
    let asked = |request_id: &str, name: &str| Requested {
        request_id: request_id.to_owned(),
        name: name.to_owned(),
        manifest_digest: "sha256:00".to_owned(),
    };
    let key = "zones/z1/archives/0190a000-0000-7000-8000-000000000001";
    bucket
        .put_new(key, b"left by a keeping that stopped")
        .expect("published");
    let kept = store
        .keep(
            "z1",
            b"the archive",
            &asked("import-1", "backup"),
            &record("backup"),
        )
        .expect("answered");
    assert_eq!(kept, Keeping::Kept);
    assert_eq!(
        bucket.get(key, 64).expect("read").as_deref(),
        Some(&b"the archive"[..])
    );
    // Another request, another name, the id of the archive that is kept.
    let refused = store.keep(
        "z1",
        b"another archive",
        &asked("import-2", "audit"),
        &record("audit"),
    );
    assert!(
        matches!(refused, Err(ArchiveError::Record(_))),
        "{refused:?}"
    );
    assert_eq!(
        bucket.get(key, 64).expect("read").as_deref(),
        Some(&b"the archive"[..])
    );
    assert_eq!(store.archived("z1").expect("listed").len(), 1);
}
