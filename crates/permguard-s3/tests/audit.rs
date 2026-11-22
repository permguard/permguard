// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The audit trails kept on PostgreSQL, their sealed days settled to S3 (iteration 03,
//! WP-27.4): a settled day reads as it did, a trail copied out of the two verifies offline as
//! one of a volume does, and a day retention deletes takes its object with it.
//!
//! The tests need both servers, as `permguard_postgres::testing` and `permguard_s3::testing`
//! say, and are skipped without them.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_host::audit::checkpoint::Keys;
use permguard_host::audit::record::{AuditRecord, genesis};
use permguard_host::audit::store::{Trails, export};
use permguard_host::audit::{Class, HOST, trail, verify};
use permguard_host::keys::ring::{HOST_OPERATIONS, Policy, Ring};
use permguard_host::storage::Dir;
use permguard_host::storage::volume::Volume;
use permguard_host::time::TimeGuard;
use permguard_objects::digest::Digest;
use permguard_postgres::audit::PostgresTrails;
use permguard_postgres::testing::{scratch, server};

/// 2026-11-20T12:00:00Z.
const DAY_1: u64 = 1_795_176_000;
const DAY: u64 = 86_400;

fn record(at: u64, target: &str) -> AuditRecord {
    AuditRecord {
        trail: format!("security:{HOST}"),
        seq: 0,
        operation_id: None,
        phase: None,
        host_id: [1; 16],
        boot_id: [2; 16],
        component: "host".to_owned(),
        action: "server.start".to_owned(),
        principal: "system:test".to_owned(),
        resource: HOST.to_owned(),
        target: Some(target.to_owned()),
        outcome: "ok".to_owned(),
        facts: BTreeMap::new(),
        build: "9.9.9".to_owned(),
        config_revision: Digest::compute(b"settings"),
        at,
        monotonic_offset: 0,
        previous: genesis(),
    }
}

/// The `host.operations` ring of a scratch volume, which signs the checkpoints, and the keys an
/// operator would export of it.
fn ring(root: &std::path::Path) -> (Arc<Ring>, Keys) {
    use permguard_core::KeyManager as _;

    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let ring = Arc::new(
        Ring::open(
            &volume,
            HOST_OPERATIONS,
            permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
            Policy {
                publish_ahead: Duration::from_secs(600),
                rotate_every: Duration::from_secs(3650 * DAY),
                retain: Duration::from_secs(3650 * DAY),
            },
            Arc::new(TimeGuard::system(Duration::from_secs(30))),
        )
        .expect("the ring opens"),
    );
    ring.maintain().expect("the first key");
    let directory = permguard_host::keys::ring::directory(&volume, HOST_OPERATIONS)
        .expect("the ring's directory");
    let document = permguard_host::keys::ring::export(directory.path()).expect("the keys export");
    (ring, Keys::from_document(&document).expect("the keys read"))
}

#[test]
fn sealed_days_settle_to_s3_and_the_trail_verifies_offline() {
    let test = "sealed_days_settle_to_s3_and_the_trail_verifies_offline";
    let (Some(server), Some(bucket)) = (server(test), permguard_s3::testing::scratch(test)) else {
        return;
    };
    let database = scratch(&server);
    let root = std::env::temp_dir().join(format!("permguard-s3-audit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (ring, keys) = ring(&root.join("volume"));
    let trails =
        PostgresTrails::new((*database.database).clone()).with_objects(Arc::new(bucket.clone()));

    // Three days of records, the first two sealed when the third starts.
    // A day kept: the first day is past it once the third begins.
    let retention = Some(Duration::from_secs(DAY));
    let mut targets = 0;
    for day in 0..3u64 {
        for _ in 0..3 {
            targets += 1;
            trails
                .hold(Class::Security, HOST, retention, &mut |trail| {
                    let new_day = trail
                        .append(record(DAY_1 + day * DAY + targets, &format!("t{targets}")))
                        .expect("appended");
                    if new_day {
                        let today = trail.last_day().expect("a day").to_owned();
                        trail
                            .seal_before(&today, ring.as_ref(), [1; 16], DAY_1 + day * DAY)
                            .expect("sealed");
                    }
                    true
                })
                .expect("held");
        }
    }
    let view = trails
        .view(Class::Security, HOST)
        .expect("answered")
        .expect("held");
    let days = view.days().expect("days");
    assert_eq!(days.len(), 3);
    let before: Vec<Vec<u8>> = days
        .iter()
        .map(|day| view.day(day).expect("read"))
        .collect();

    // The two sealed days go to the bucket; the day still written stays in its rows.
    assert_eq!(trails.settle().expect("settled"), 2);
    assert_eq!(
        trails.settle().expect("settled again"),
        0,
        "a day settles once"
    );
    let digest = trail::resource_digest(HOST);
    let mut objects: Vec<String> = bucket
        .list("")
        .expect("listed")
        .into_iter()
        .map(|object| object.key)
        .collect();
    objects.sort();
    assert_eq!(
        objects,
        [
            format!("audit/trails/security/{digest}/{}", days[0]),
            format!("audit/trails/security/{digest}/{}", days[1]),
        ]
    );
    let rows: i64 = database
        .database
        .write(|unit| {
            Ok(unit
                .query_one("SELECT count(*) FROM permguard_audit_records", &[])?
                .get(0))
        })
        .expect("counted");
    assert_eq!(rows, 3, "only the open day's records are rows");
    let after: Vec<Vec<u8>> = days
        .iter()
        .map(|day| view.day(day).expect("read"))
        .collect();
    assert_eq!(after, before, "a settled day reads as it did");

    // Copied out of the two, the trail verifies as one of a volume does.
    let copied = root.join("copied");
    std::fs::create_dir_all(&copied).expect("a directory");
    let into = Dir::open(&copied).expect("opened");
    assert_eq!(export(&trails, &into).expect("exported"), 1);
    let today = trail::period_of(&days[2]);
    let report = verify::verify_trail_on(
        &trail::directory(&into, Class::Security, HOST, false).expect("the trail"),
        Class::Security,
        &digest,
        &keys,
        &today,
    );
    assert!(report.problems.is_empty(), "{report:?}");
    assert_eq!(report.records, 9);
    assert_eq!(report.checkpoints, 2);
    assert_eq!(
        report.sealed_through.as_deref(),
        Some(trail::period_of(&days[1]).as_str())
    );

    // Retention deletes the oldest sealed day; its object goes at the next settlement.
    let mut anchored = None;
    trails
        .hold(Class::Security, HOST, retention, &mut |trail| {
            anchored = trail.prune(&days[2], None).expect("pruned");
            true
        })
        .expect("held");
    let anchor = anchored.expect("a day past the retention went");
    assert_eq!(view.days().expect("days"), days[1..]);
    assert_eq!(trails.settle().expect("settled"), 1);
    assert_eq!(
        bucket
            .list("")
            .expect("listed")
            .into_iter()
            .map(|object| object.key)
            .collect::<Vec<_>>(),
        [format!("audit/trails/security/{digest}/{}", days[1])]
    );
    assert_eq!(trail::anchor(view.as_ref()).expect("read"), Some(anchor));
    let _ = std::fs::remove_dir_all(root);
}
