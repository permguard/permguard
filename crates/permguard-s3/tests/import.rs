// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The import of a volume into PostgreSQL and S3 (iteration 03, WP-27.6): a ledger, the archives
//! of a zone and a consumer's runs, written as a volume kept them, read back through the stores
//! of this backend as they read on files.
//!
//! The tests need both servers, as `control_plane.rs` says, and are skipped without them.

#![allow(clippy::expect_used)]

use permguard_control_plane::catalog::archives::{ArchiveStore, FileArchives, Keeping, Requested};
use permguard_control_plane::catalog::imports::{ArchiveRecord, ArchivedLedger};
use permguard_control_plane::store::{FileObjectStore, LedgerStore, Ledgers as _, copy_objects};
use permguard_host::operations::mutation::Applying;
use permguard_host::storage::Dir;
use permguard_objects::object::Blob;
use permguard_postgres::testing::{Cases, server};
use permguard_s3::control_plane::{PostgresArchives, PostgresLedgers};
use permguard_s3::streams::PostgresRuns;
use permguard_s3::testing::scratch;
use permguard_stream::engine::consumer::export;
use permguard_stream::engine::consumer::store::{FileRuns, Runs};

const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";
const LEDGER: &str = "01a00000-0000-7000-8000-00000000000b";

fn temporary(name: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("permguard-s3-import-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch");
    root
}

fn blob(text: &str) -> Vec<u8> {
    Blob {
        media_type: permguard_core::domains::media::POLICY_CEDAR.to_owned(),
        data: text.as_bytes().to_vec(),
    }
    .encode()
    .expect("a blob")
}

/// A ledger with objects, refs, one written before the transaction, statements, a root and a
/// transfer session: read back on PostgreSQL and S3 as the file backend held it.
#[test]
fn a_ledger_is_imported_as_it_was() {
    let test = "a_ledger_is_imported_as_it_was";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let root = temporary("ledger");
    let mutations =
        permguard_control_plane::store::testing::offline_ref_mutations(&root.join("volume"))
            .expect("the engine opens");
    let operate = |work: &mut dyn FnMut(&Applying<'_>)| {
        permguard_control_plane::store::testing::operation(&mutations, work);
    };
    let files = FileObjectStore::new(root.join("ledger"));
    let digests: Vec<_> = ["one", "two", "three"]
        .iter()
        .map(|text| files.put_object(&blob(text)).expect("landed").0)
        .collect();
    operate(&mut |applying| {
        files
            .update_ref(applying, "main", None, &digests[0])
            .expect("created");
    });
    let first = files.read_ref("main").expect("read").expect("held");
    let expected = permguard_notp::ExpectedRef {
        counter: first.counter,
        digest: permguard_control_plane::store::ref_digest(&first).expect("a digest"),
    };
    operate(&mut |applying| {
        files
            .update_ref(applying, "main", Some(&expected), &digests[1])
            .expect("moved");
    });
    files.write_signature("main", b"a statement").expect("kept");
    files.keep_roots(&[digests[2].clone()]).expect("kept");
    // A ref a build before the transaction wrote, and a transfer session, as files hold them.
    std::fs::write(
        root.join("ledger/refs/legacy"),
        format!(
            "{{\"version\":1,\"head\":\"{}\",\"counter\":4}}\n",
            digests[2]
        ),
    )
    .expect("written");
    std::fs::create_dir_all(root.join("ledger/transfers")).expect("a directory");
    std::fs::write(
        root.join("ledger/transfers")
            .join(format!("{}.cbor", "07".repeat(16))),
        b"a session",
    )
    .expect("written");

    let cases = Cases::new(server);
    let ledgers = PostgresLedgers::new(cases.next(), bucket);
    let target = ledgers.ledger(ZONE, LEDGER);
    assert_eq!(copy_objects(&files, target.as_ref()).expect("copied"), 3);
    ledgers
        .import(ZONE, LEDGER, &files.export().expect("exported"))
        .expect("imported");
    for digest in &digests {
        assert_eq!(
            target.get_object(digest).expect("read"),
            files.get_object(digest).expect("read")
        );
    }
    assert_eq!(
        target.list_refs().expect("read"),
        files.list_refs().expect("read")
    );
    assert_eq!(target.list_refs().expect("read").len(), 2);
    for name in ["main", "legacy"] {
        assert_eq!(
            target.ref_operation(name).expect("read"),
            files.ref_operation(name).expect("read")
        );
    }
    assert_eq!(target.ref_operation("legacy").expect("read"), None);
    assert_eq!(
        target.read_signature("main").expect("read"),
        Some(b"a statement".to_vec())
    );
    assert_eq!(target.roots().expect("read"), files.roots().expect("read"));
    let sessions: Vec<(Vec<u8>, Vec<u8>)> = cases
        .current()
        .write(|unit| {
            Ok(unit
                .query(
                    "SELECT transfer_id, record FROM permguard_ledger_transfers",
                    &[],
                )?
                .into_iter()
                .map(|row| (row.get(0), row.get(1)))
                .collect())
        })
        .expect("read");
    assert_eq!(sessions, vec![(vec![7; 16], b"a session".to_vec())]);
    assert_eq!(target.verify_at_load().expect("verified"), 2);
    // The ref moves on from where it was: the counter follows the one carried.
    let held = target.read_ref("main").expect("read").expect("held");
    let expected = permguard_notp::ExpectedRef {
        counter: held.counter,
        digest: permguard_control_plane::store::ref_digest(&held).expect("a digest"),
    };
    cases.operate(
        permguard_control_plane::store::REFS_DOMAIN,
        &mut |applying| {
            target
                .update_ref(applying, "main", Some(&expected), &digests[2])
                .expect("moved");
        },
    );
    assert_eq!(
        target
            .read_ref("main")
            .expect("read")
            .expect("held")
            .counter,
        held.counter + 1
    );
    let _ = std::fs::remove_dir_all(root);
}

/// The archives of a zone, read back on PostgreSQL and S3 as the file backend held them.
#[test]
fn the_archives_of_a_zone_are_imported_as_they_were() {
    let test = "the_archives_of_a_zone_are_imported_as_they_were";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let root = temporary("archives");
    let files = FileArchives::new(&root);
    let record = |n: usize, name: &str| ArchiveRecord {
        id: format!("01c00000-0000-7000-8000-{n:012x}"),
        name: name.to_owned(),
        imported_at: 1_800_000_000,
        manifest_digest: format!("sha256:{}", "ab".repeat(32)),
        source_host_id: "11".repeat(16),
        source_zone_id: "01d00000-0000-7000-8000-00000000000a".to_owned(),
        source_zone_name: "delivery".to_owned(),
        ledgers: vec![ArchivedLedger {
            id: "01d00000-0000-7000-8000-00000000000b".to_owned(),
            name: "policies".to_owned(),
            refs: 1,
            objects: 2,
            statements: 1,
        }],
    };
    for (n, name) in [(1, "first"), (2, "second")] {
        let record = record(n, name);
        let asked = Requested {
            request_id: format!("request-{n}"),
            name: record.name.clone(),
            manifest_digest: record.manifest_digest.clone(),
        };
        assert_eq!(
            files
                .keep(ZONE, format!("archive {n}").as_bytes(), &asked, &record)
                .expect("kept"),
            Keeping::Kept
        );
    }
    let cases = Cases::new(server);
    let target = PostgresArchives::new(cases.next(), bucket.clone());
    for (record, asked, archive) in files.export(ZONE).expect("exported") {
        assert_eq!(
            target.keep(ZONE, &archive, &asked, &record).expect("kept"),
            Keeping::Kept
        );
        assert_eq!(
            bucket
                .get(&format!("zones/{ZONE}/archives/{}", record.id), 1024)
                .expect("read"),
            Some(archive)
        );
    }
    let mut held = target.archived(ZONE).expect("read");
    held.sort_by(|left, right| left.id.cmp(&right.id));
    let mut kept = files.archived(ZONE).expect("read");
    kept.sort_by(|left, right| left.id.cmp(&right.id));
    assert_eq!(held, kept);
    assert_eq!(
        target.kept_by(ZONE, "request-2").expect("read"),
        files.kept_by(ZONE, "request-2").expect("read")
    );
    let _ = std::fs::remove_dir_all(root);
}

/// A consumer's runs, a deleted prefix among them, read back on PostgreSQL and S3 as the file
/// backend held them: every frame at its own index.
#[test]
fn a_consumers_runs_are_imported_as_they_were() {
    let test = "a_consumers_runs_are_imported_as_they_were";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let root = temporary("runs");
    let files = FileRuns::new(Dir::create_root(&root).expect("a directory"), 1, 64);
    let (component, producer) = ("a1".repeat(32), "b2".repeat(16));
    for run in ["c3".repeat(16), "d4".repeat(16)] {
        let mut held = files
            .open(&component, &producer, &run, true)
            .expect("opened")
            .expect("created");
        for n in 0..6u8 {
            held.append(1, &[n; 40]).expect("appended");
        }
        held.drop_prefix(2).expect("dropped");
        held.replace_view("STATE", b"state").expect("kept");
        held.replace_view("signers.cbor", b"signers").expect("kept");
        held.publish("batches", "1-6.jws", b"a batch")
            .expect("kept");
        held.publish("statements", "ab.cbor", b"a statement")
            .expect("kept");
    }
    files
        .replace_producer_view(&component, &producer, "FORKED", b"forked")
        .expect("kept");
    files
        .replace_resource_view(&component, "IMPORT", b"import")
        .expect("kept");
    let exported = export(&files).expect("exported");
    assert_eq!(exported.runs.len(), 2);
    assert!(exported.runs.iter().all(|run| run.first_index > 0));

    let cases = Cases::new(server);
    let target = PostgresRuns::new(cases.next(), bucket, "data/decisions/1");
    target.import(&exported).expect("imported");
    let mut read = export(&target).expect("read back");
    // A frame's claim is the writer's on files; the database keeps none.
    let mut carried = exported.clone();
    for runs in [&mut read, &mut carried] {
        for run in &mut runs.runs {
            for frame in &mut run.frames {
                frame.claim = 0;
            }
        }
    }
    assert_eq!(read, carried);
    // The next frame follows the last one carried.
    let mut held = target
        .open(&component, &producer, &"c3".repeat(16), false)
        .expect("opened")
        .expect("held");
    assert_eq!(held.append(1, &[9; 40]).expect("appended"), 6);
    let _ = std::fs::remove_dir_all(root);
}
