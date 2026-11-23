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

/// The deep verification on PostgreSQL and S3 reads each object through its ledger's store
/// (WP-28.2): an object whose bytes are not what its digest names is found, named by its place,
/// and left as it is; the others are read.
#[test]
fn the_deep_verification_finds_an_object_altered_in_the_bucket() {
    use permguard_core::catalog::{Catalog as _, Selector};
    use permguard_host::storage::verify::{Budget, Mode};

    let test = "the_deep_verification_finds_an_object_altered_in_the_bucket";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let cases = Cases::new(server);
    let database = cases.next();
    let catalog = permguard_postgres::catalog::PostgresCatalog::new(database.clone());
    let zone = catalog.create_zone("payments").expect("created");
    let ledger = catalog
        .create_ledger(&Selector::Id(zone.id.clone()), "orders")
        .expect("created");
    let ledgers = PostgresLedgers::new(database, bucket.clone());
    let store = ledgers.ledger(&zone.id, &ledger.id);
    let digests: Vec<_> = ["one", "two", "three"]
        .iter()
        .map(|text| {
            store
                .put_object(
                    &permguard_objects::object::Blob {
                        media_type: permguard_core::domains::media::POLICY_CEDAR.to_owned(),
                        data: text.as_bytes().to_vec(),
                    }
                    .encode()
                    .expect("a blob"),
                )
                .expect("landed")
                .0
        })
        .collect();
    // The bytes of one object replaced in the bucket, behind the store.
    let hex = digests[1]
        .to_string()
        .trim_start_matches("sha256:")
        .to_owned();
    let (fan, rest) = hex.split_at(2);
    let key = format!(
        "zones/{}/ledgers/{}/objects/{fan}/{rest}",
        zone.id, ledger.id
    );
    bucket.delete(&key).expect("removed");
    bucket
        .put_new(&key, b"not what the digest names")
        .expect("put");

    let report = permguard_control_plane::verify::pass_stores(
        &catalog,
        &ledgers,
        Mode::Full,
        &mut Budget::unbounded(),
    );
    assert!(report.complete);
    assert_eq!(report.files_checked, 3);
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    assert!(
        report.findings[0]
            .path
            .to_string_lossy()
            .ends_with(&digests[1].to_string()),
        "{:?}",
        report.findings
    );
    // Left as it is: the store still refuses it.
    assert!(store.get_object(&digests[1]).is_err());
}

/// The bytes a keeping of an archive left without its record are removed past the grace, and
/// those of an archive kept stay (WP-28.2).
#[test]
fn the_bytes_no_archive_record_names_are_swept() {
    let test = "the_bytes_no_archive_record_names_are_swept";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let cases = Cases::new(server);
    let archives = PostgresArchives::new(cases.next(), bucket.clone());
    let zone = "01a00000-0000-7000-8000-00000000000a";
    let record = ArchiveRecord {
        id: "01c00000-0000-7000-8000-000000000001".to_owned(),
        name: "kept".to_owned(),
        imported_at: 1_800_000_000,
        manifest_digest: format!("sha256:{}", "ab".repeat(32)),
        source_host_id: "11".repeat(16),
        source_zone_id: "01d00000-0000-7000-8000-00000000000a".to_owned(),
        source_zone_name: "delivery".to_owned(),
        ledgers: Vec::new(),
    };
    let asked = Requested {
        request_id: "request-1".to_owned(),
        name: record.name.clone(),
        manifest_digest: record.manifest_digest.clone(),
    };
    assert_eq!(
        archives
            .keep(zone, b"a kept archive", &asked, &record)
            .expect("kept"),
        Keeping::Kept
    );
    let orphan = format!("zones/{zone}/archives/01c00000-0000-7000-8000-000000000002");
    bucket
        .put_new(&orphan, b"left by a keeping that stopped")
        .expect("put");
    // Within the grace a keeping may still be writing its record: nothing goes.
    assert_eq!(
        archives
            .sweep_unnamed(zone, std::time::Duration::from_secs(3_600))
            .expect("swept"),
        0
    );
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert_eq!(
        archives
            .sweep_unnamed(zone, std::time::Duration::ZERO)
            .expect("swept"),
        1
    );
    assert_eq!(bucket.get(&orphan, 1024).expect("read"), None);
    assert_eq!(
        bucket
            .get(&format!("zones/{zone}/archives/{}", record.id), 1024)
            .expect("read"),
        Some(b"a kept archive".to_vec())
    );
}
