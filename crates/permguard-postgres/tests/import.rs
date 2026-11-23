// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The import of a volume into PostgreSQL (iteration 03, WP-27.6): each store's state, written as
//! a volume kept it, reads back through the store of this backend as it read on files.
//!
//! The tests need a server, as `foundations.rs` says, and are skipped without one.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::catalog::{Catalog, Selector};
use permguard_host::audit::checkpoint::{Checkpoint, CheckpointSigner};
use permguard_host::audit::record::{AuditRecord, genesis};
use permguard_host::audit::store::{FileTrails, Trails};
use permguard_host::audit::{Class, HOST, trail};
use permguard_host::authz::authority::carry_held;
use permguard_host::authz::held::files::FileHeld;
use permguard_host::authz::held::{HeldStore, KeptKeys, Named};
use permguard_host::authz::testing::TestAuthority;
use permguard_host::identity::files::FileIdentity;
use permguard_host::identity::record::uuid_text;
use permguard_host::identity::store::IdentityStore;
use permguard_host::identity::witness::VersionWitnesses;
use permguard_host::identity::witness::files::FileVersionWitnesses;
use permguard_host::keys::ring::files::FileRing;
use permguard_host::keys::ring::store::RingStore;
use permguard_host::membership::files::FileMembers;
use permguard_host::membership::store::{Doc, Listing, MemberStore};
use permguard_host::membership::zone::Receipt;
use permguard_host::operations::journal::Initiator;
use permguard_host::operations::mutation::{
    Applied, Applying, Begin, Failure as MutationFailure, Mutations,
};
use permguard_host::secrets::files::{FileDeliveredKeys, FileWitnesses};
use permguard_host::secrets::{DeliveredKeys, KeyVersion, WitnessStore, ZonePurpose, ZoneTuple};
use permguard_host::session::peers::files::FileSeen;
use permguard_host::session::peers::{Seen, SeenStore};
use permguard_host::storage::volume::Volume;
use permguard_host::storage::write::replace_bytes;
use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;
use permguard_postgres::audit::PostgresTrails;
use permguard_postgres::catalog::PostgresCatalog;
use permguard_postgres::delivered::PostgresDeliveredKeys;
use permguard_postgres::held::PostgresHeld;
use permguard_postgres::identity::PostgresIdentity;
use permguard_postgres::members::PostgresMembers;
use permguard_postgres::peers::PostgresSeen;
use permguard_postgres::ring::PostgresRing;
use permguard_postgres::testing::{Cases, server};
use permguard_postgres::witnesses::{PostgresVersionWitnesses, PostgresWitnesses};
use permguard_std::catalog::FileCatalog;

/// 2026-11-20T12:00:00Z.
const DAY_1: u64 = 1_795_176_000;
const DAY: u64 = 86_400;

struct Signer;

impl CheckpointSigner for Signer {
    fn seal(&self, checkpoint: &mut Checkpoint) -> Result<Vec<u8>, String> {
        checkpoint.key_set_epoch = 1;
        let payload = checkpoint.encode().map_err(|error| error.to_string())?;
        permguard_objects::cose::Sign1::sign_with(
            permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
            permguard_core::domains::protected::AUDIT_CHECKPOINT,
            b"test",
            payload,
            |_| Ok::<_, String>(vec![0; 64]),
        )
        .map_err(|error| error.to_string())?
        .encode()
        .map_err(|error| error.to_string())
    }
}

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

/// A trail written on files, sealed and pruned, imported: every day, record, checkpoint and the
/// anchor read back the same, and the trail continues from where it was on files.
#[test]
fn an_audit_trail_is_imported_as_it_was_on_postgresql() {
    let Some(server) = server("an_audit_trail_is_imported_as_it_was_on_postgresql") else {
        return;
    };
    let root = std::env::temp_dir().join(format!("permguard-import-trail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (files, _) = FileTrails::open(&volume, "2026-11-20.cborseq").expect("opens");
    let retention = Some(Duration::from_secs(DAY));
    for day in 0..4u64 {
        for n in 0..3u64 {
            files
                .hold(Class::Security, HOST, retention, &mut |trail| {
                    if trail
                        .append(record(DAY_1 + day * DAY + n, &format!("d{day}n{n}")))
                        .expect("appended")
                        && let Some(today) = trail.last_day().map(ToOwned::to_owned)
                    {
                        trail
                            .seal_before(&today, &Signer, [1; 16], DAY_1 + day * DAY)
                            .expect("sealed");
                        trail.prune(&today, None).expect("pruned");
                    }
                    true
                })
                .expect("held");
        }
    }
    let source = files
        .view(Class::Security, HOST)
        .expect("answered")
        .expect("held");

    let cases = Cases::new(server);
    let trails = PostgresTrails::new(cases.next());
    let imported = trails
        .import(Class::Security, HOST, source.as_ref())
        .expect("imported");
    assert!(imported > 0);
    let target = trails
        .view(Class::Security, HOST)
        .expect("answered")
        .expect("held");
    assert_eq!(target.days().expect("days"), source.days().expect("days"));
    for day in source.days().expect("days") {
        assert_eq!(
            target.day(&day).expect("read"),
            source.day(&day).expect("read")
        );
    }
    let mut names = source.checkpoint_names().expect("names");
    names.sort();
    let mut imported_names = target.checkpoint_names().expect("names");
    imported_names.sort();
    assert_eq!(imported_names, names);
    for name in &names {
        assert_eq!(
            target.checkpoint(name).expect("read"),
            source.checkpoint(name).expect("read")
        );
    }
    assert_eq!(
        target.anchor().expect("read"),
        source.anchor().expect("read")
    );
    assert!(
        target.anchor().expect("read").is_some(),
        "retention left an anchor"
    );
    assert_eq!(
        trail::state_of(target.as_ref()).expect("a state"),
        trail::state_of(source.as_ref()).expect("a state")
    );
    // And it continues where it was: the next record takes the next sequence and chains.
    let mut given = None;
    trails
        .hold(Class::Security, HOST, retention, &mut |trail| {
            trail
                .append(record(DAY_1 + 3 * DAY + 9, "after the import"))
                .expect("appended");
            given = Some(trail.next_seq() - 1);
            true
        })
        .expect("held");
    assert_eq!(
        given,
        Some(trail::state_of(source.as_ref()).expect("a state").next_seq)
    );
    assert!(trail::verify(target.as_ref()).expect("one chain") > 0);
    let _ = std::fs::remove_dir_all(root);
}

/// A volume of its own below the temporary directory, claimed, and its root.
fn claimed(name: &str) -> (std::path::PathBuf, Volume) {
    let root = std::env::temp_dir().join(format!("permguard-import-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    (root, volume)
}

/// Runs `work` inside one operation of the file mutation engine of `volume`.
fn on_files(volume: &Volume, work: &mut dyn FnMut(&Applying<'_>)) {
    let mutations = Mutations::open_offline(volume, "import").expect("the engine opens");
    mutations
        .run(
            Begin {
                domain: permguard_host::identity::DOMAIN,
                operation: permguard_host::identity::reset::RESET_RUN,
                action: permguard_host::identity::reset::AUDIT_RESET,
                initiator: Initiator::System("import".to_owned()),
                request: None,
                target: Some("import".to_owned()),
            },
            |applying| {
                work(applying);
                Ok::<_, MutationFailure<String>>(Applied {
                    revision: 1,
                    target: None,
                    value: (),
                })
            },
        )
        .expect("the operation ran");
}

fn item(text: &str, n: i64) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Int(n),
        Value::Text(text.to_owned()),
    ]))
    .expect("an item encodes")
}

/// The identity, with a retired one's evidence, and a ring, with a retired Host's records, read
/// back on PostgreSQL as the file backend held them.
#[test]
fn the_identity_and_a_ring_are_imported_as_they_were() {
    let Some(server) = server("the_identity_and_a_ring_are_imported_as_they_were") else {
        return;
    };
    let (root, volume) = claimed("identity");
    let identity = FileIdentity::open(&volume).expect("opens");
    let ring_name = "host-signing";
    let ring = FileRing::open(
        permguard_host::keys::ring::files::directory(&volume, ring_name).expect("a directory"),
        ring_name,
    )
    .expect("opens");
    // A first identity and its ring, retired by a reset.
    identity.publish_init(b"old init").expect("kept");
    identity.replace_document(b"old document").expect("kept");
    identity
        .append_succession(&item("old succession", 1))
        .expect("kept");
    identity.publish_public(1, b"old key 1").expect("kept");
    ring.append(1, &item("old entry", 1)).expect("kept");
    ring.replace_view(b"old view").expect("kept");
    ring.keep_binding(1, b"old binding").expect("kept");
    ring.publish_public("old-thumbprint", b"old jwk")
        .expect("kept");
    on_files(&volume, &mut |applying| {
        identity
            .retire(applying, &[0x0a; 16], b"the reset")
            .expect("retired");
        ring.retire(applying, &[0x0a; 16]).expect("retired");
    });
    identity.clear().expect("cleared");
    identity.remove_init().expect("removed");
    ring.forget_entries().expect("forgotten");
    ring.clear().expect("cleared");
    // The identity held now, and its ring.
    identity.publish_init(b"init").expect("kept");
    identity.replace_document(b"document").expect("kept");
    for n in 1..=3 {
        identity
            .append_succession(&item("succession", n))
            .expect("kept");
    }
    identity.publish_public(1, b"key 1").expect("kept");
    identity.publish_public(2, b"key 2").expect("kept");
    identity.record_start(b"the start").expect("kept");
    for seq in 1..=3 {
        ring.append(seq, &item("entry", i64::try_from(seq).expect("small")))
            .expect("kept");
    }
    ring.replace_view(b"view").expect("kept");
    ring.replace_binding(b"binding").expect("kept");
    ring.keep_binding(2, b"binding 2").expect("kept");
    ring.keep_binding(3, b"binding 3").expect("kept");
    ring.publish_public("thumbprint-a", b"jwk a").expect("kept");
    ring.publish_public("thumbprint-b", b"jwk b").expect("kept");

    let cases = Cases::new(server);
    let database = cases.next();
    let target = PostgresIdentity::new(database.clone());
    target
        .import(&identity.export().expect("exported"))
        .expect("imported");
    assert_eq!(target.init().expect("read"), identity.init().expect("read"));
    assert_eq!(
        target.document().expect("read"),
        identity.document().expect("read")
    );
    assert_eq!(
        target.successions().expect("read"),
        identity.successions().expect("read")
    );
    assert_eq!(target.successions().expect("read").len(), 3);
    for epoch in [1, 2, 3] {
        assert_eq!(
            target.public(epoch).expect("read"),
            identity.public(epoch).expect("read")
        );
    }
    assert!(target.started().expect("read"));
    let retired = target.retired().expect("read");
    assert_eq!(retired, identity.retired().expect("read"));
    assert_eq!(retired.len(), 1);
    // The evidence itself, row by row.
    let evidence: Vec<(String, i64, Vec<u8>)> = database
        .write(|unit| {
            Ok(unit
                .query(
                    "SELECT kind, position, record FROM permguard_identity_evidence
                     ORDER BY kind, position",
                    &[],
                )?
                .into_iter()
                .map(|row| (row.get(0), row.get(1), row.get(2)))
                .collect())
        })
        .expect("read");
    assert_eq!(
        evidence,
        vec![
            ("document".to_owned(), 0, b"old document".to_vec()),
            ("init".to_owned(), 0, b"old init".to_vec()),
            ("public".to_owned(), 1, b"old key 1".to_vec()),
            ("succession".to_owned(), 1, item("old succession", 1)),
        ]
    );
    // A reset under way is not carried: the start on files completes it first.
    on_files(&volume, &mut |applying| {
        identity
            .mark_resetting(applying, &[0x0c; 16])
            .expect("marked");
    });
    let refused = identity.export().expect_err("a reset under way");
    assert!(
        refused.to_string().contains("reset is under way"),
        "{refused}"
    );
    identity.clear_resetting().expect("cleared");

    let target = PostgresRing::new(database.clone(), ring_name);
    target
        .import(&ring.export().expect("exported"))
        .expect("imported");
    assert_eq!(
        target.entries().expect("read"),
        ring.entries().expect("read")
    );
    assert_eq!(target.view().expect("read"), ring.view().expect("read"));
    assert_eq!(
        target.binding().expect("read"),
        ring.binding().expect("read")
    );
    assert_eq!(
        target.kept_bindings().expect("read"),
        ring.kept_bindings().expect("read")
    );
    for thumbprint in ["thumbprint-a", "thumbprint-b", "old-thumbprint"] {
        assert_eq!(
            target.public(thumbprint).expect("read"),
            ring.public(thumbprint).expect("read")
        );
    }
    // The next entry follows the last one carried.
    target.append(4, &item("entry", 4)).expect("follows");
    let kept: Vec<(String, String, Vec<u8>)> = database
        .write(|unit| {
            Ok(unit
                .query(
                    "SELECT kind, name, record FROM permguard_ring_evidence
                     WHERE ring = $1 AND host_id = $2 ORDER BY kind, name",
                    &[&ring_name, &uuid_text(&[0x0a; 16])],
                )?
                .into_iter()
                .map(|row| (row.get(0), row.get(1), row.get(2)))
                .collect())
        })
        .expect("read");
    assert_eq!(
        kept,
        vec![
            ("entry".to_owned(), "1".to_owned(), item("old entry", 1)),
            (
                "kept binding".to_owned(),
                "1".to_owned(),
                b"old binding".to_vec()
            ),
            (
                "public key".to_owned(),
                "old-thumbprint".to_owned(),
                b"old jwk".to_vec()
            ),
            ("record".to_owned(), "view".to_owned(), b"old view".to_vec()),
        ]
    );
    let _ = std::fs::remove_dir_all(root);
}

/// The memberships, every kind of document among them, read back on PostgreSQL as the file
/// backend held them.
#[test]
fn the_memberships_are_imported_as_they_were() {
    let Some(server) = server("the_memberships_are_imported_as_they_were") else {
        return;
    };
    let (root, volume) = claimed("members");
    let files = FileMembers::open(&volume).expect("opens");
    const M: [u8; 16] = [0x21; 16];
    const OP: [u8; 16] = [0x31; 16];
    let task = "events.ship";
    let trail = "security:host";
    let receipt = Receipt {
        epoch: 1,
        confirmed_at: 2,
        transcript_digest: [3; 32],
        tuples: Vec::new(),
        resource: "plane/control/zone/z1".to_owned(),
    }
    .encode()
    .expect("encodes");
    for seq in 1..=2 {
        files
            .append(seq, &item("entry", i64::try_from(seq).expect("small")))
            .expect("kept");
    }
    files.replace_summary(b"summary").expect("kept");
    files
        .keep_manifest(&M, 1, "d1", b"manifest 1")
        .expect("kept");
    files
        .keep_manifest(&M, 2, "d2", b"manifest 2")
        .expect("kept");
    files
        .keep_invitation(&[0x41; 16], b"invitation")
        .expect("kept");
    let docs: Vec<(Doc<'_>, Vec<u8>)> = vec![
        (
            Doc::Lease {
                membership: &M,
                task,
            },
            b"lease".to_vec(),
        ),
        (
            Doc::Progress {
                membership: &M,
                task,
            },
            b"progress".to_vec(),
        ),
        (
            Doc::Session {
                membership: &M,
                task,
            },
            b"session".to_vec(),
        ),
        (Doc::Delivered { membership: &M }, b"delivered".to_vec()),
        (
            Doc::ZoneReceipt {
                membership: &M,
                task,
                resource: "plane/control/zone/z1",
            },
            receipt.clone(),
        ),
        (
            Doc::ReplaySlot {
                membership: &M,
                task,
                slot: 7,
            },
            b"slot".to_vec(),
        ),
        (
            Doc::Verification { membership: &M },
            b"verification".to_vec(),
        ),
        (
            Doc::VerificationResult { operation: &OP },
            b"result".to_vec(),
        ),
        (
            Doc::Acks {
                membership: &M,
                task,
            },
            b"acks".to_vec(),
        ),
        (
            Doc::TrailName {
                membership: &M,
                trail,
            },
            trail.as_bytes().to_vec(),
        ),
        (
            Doc::TrailLast {
                membership: &M,
                trail,
            },
            b"last".to_vec(),
        ),
        (
            Doc::TrailAnchor {
                membership: &M,
                trail,
            },
            b"anchor".to_vec(),
        ),
        (
            Doc::TrailFork {
                membership: &M,
                trail,
            },
            b"fork".to_vec(),
        ),
    ];
    for (doc, bytes) in &docs {
        files.keep(doc, bytes).expect("kept");
    }
    files
        .publish_checkpoint(&M, trail, 1, b"checkpoint 1")
        .expect("kept");
    files
        .publish_checkpoint(&M, trail, 2, b"checkpoint 2")
        .expect("kept");

    let cases = Cases::new(server);
    let target = PostgresMembers::new(cases.next());
    let carried = files.copy_into(&target).expect("imported");
    // Two entries, the summary, two manifests, an invitation, the documents, two checkpoints.
    assert_eq!(carried, 2 + 1 + 2 + 1 + docs.len() + 2);
    assert_eq!(
        target.entries().expect("read"),
        files.entries().expect("read")
    );
    for (doc, bytes) in &docs {
        assert_eq!(target.doc(doc).expect("read").as_deref(), Some(&bytes[..]));
    }
    for count in [1, 2] {
        assert_eq!(
            target.checkpoint(&M, trail, count).expect("read"),
            files.checkpoint(&M, trail, count).expect("read")
        );
    }
    let receipts = target
        .list(&Listing::ZoneReceipts {
            membership: &M,
            task,
        })
        .expect("listed");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].bytes.as_deref().ok(), Some(&receipt[..]));
    // The next entry follows the last one carried.
    target.append(3, &item("entry", 3)).expect("follows");
    let _ = std::fs::remove_dir_all(root);
}

/// The catalog, a deleted ledger's tombstone and the marks of the names among it, read back on
/// PostgreSQL as the file backend held it: a name taken again starts above what it reached.
#[test]
fn the_catalog_is_imported_as_it_was() {
    let Some(server) = server("the_catalog_is_imported_as_it_was") else {
        return;
    };
    let root =
        std::env::temp_dir().join(format!("permguard-import-catalog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let files = FileCatalog::new(&root);
    let zone = files.create_zone("payments").expect("created");
    let by_id = Selector::Id(zone.id.clone());
    files.create_ledger(&by_id, "orders").expect("created");
    let gone = files.create_ledger(&by_id, "refunds").expect("created");
    files
        .rename_ledger(&by_id, &Selector::Name("orders".to_owned()), "purchases")
        .expect("renamed");
    files
        .delete_ledger(&by_id, &Selector::Name("refunds".to_owned()))
        .expect("deleted");
    let doomed = files.create_zone("scratch").expect("created");
    files
        .delete_zone(&Selector::Id(doomed.id.clone()))
        .expect("deleted");
    files.create_zone("billing").expect("created");

    let cases = Cases::new(server);
    let target = PostgresCatalog::new(cases.next());
    target
        .import(&files.export().expect("exported"))
        .expect("imported");
    assert_eq!(
        target.list_zones().expect("listed"),
        files.list_zones().expect("listed")
    );
    assert_eq!(
        target.list_ledgers(&by_id).expect("listed"),
        files.list_ledgers(&by_id).expect("listed")
    );
    assert_eq!(
        target.ledger_tombstone(&zone.id, &gone.id).expect("read"),
        files.ledger_tombstone(&zone.id, &gone.id).expect("read")
    );
    assert!(
        target
            .ledger_tombstone(&zone.id, &gone.id)
            .expect("read")
            .is_some()
    );
    assert_eq!(
        target.zone_tombstone(&doomed.id).expect("read"),
        files.zone_tombstone(&doomed.id).expect("read")
    );
    // A name a record left starts above what it reached, on both.
    let again = target.create_ledger(&by_id, "orders").expect("created");
    let on_files = files.create_ledger(&by_id, "orders").expect("created");
    assert_eq!(again.revision, on_files.revision);
    assert!(again.revision > 1);
    let _ = std::fs::remove_dir_all(root);
}

/// The witnesses, the delivered keys, the seen peers, the versions' witnesses, the key slots
/// and what a Host held of the Authority Plane, read back on PostgreSQL as the file backend held
/// them.
#[test]
fn the_host_secrets_and_trust_are_imported_as_they_were() {
    let Some(server) = server("the_host_secrets_and_trust_are_imported_as_they_were") else {
        return;
    };
    let (root, volume) = claimed("secrets");
    let cases = Cases::new(server);
    let database = cases.next();

    let witnesses = FileWitnesses::open(&volume).expect("opens");
    let names = [
        vec!["root".to_owned(), "v1".to_owned()],
        vec!["zone-use".to_owned(), "a".to_owned(), "v2".to_owned()],
    ];
    for (n, name) in names.iter().enumerate() {
        witnesses
            .first(name, &[u8::try_from(n).expect("small") + 1; 32])
            .expect("kept");
    }
    let target = PostgresWitnesses::new(database.clone());
    assert_eq!(
        target
            .import(&witnesses.export().expect("exported"))
            .expect("imported"),
        2
    );
    for (n, name) in names.iter().enumerate() {
        // What is kept is the first: a later witness is answered the one carried.
        assert_eq!(
            target.first(name, &[9; 32]).expect("read"),
            vec![u8::try_from(n).expect("small") + 1; 32]
        );
    }

    let delivered = FileDeliveredKeys::open(&volume).expect("opens");
    let tuple = ZoneTuple {
        authority: [1; 16],
        zone: [2; 16],
        purpose: ZonePurpose::AuditPseudonym,
        scope: [3; 16],
        version: KeyVersion::new(2).expect("a version"),
    };
    delivered.keep(&tuple, &[5; 32]).expect("kept");
    let target =
        PostgresDeliveredKeys::new(database.clone(), permguard_postgres::testing::sealer());
    for (tuple, key) in delivered.export().expect("exported") {
        target.keep(&tuple, &key).expect("kept");
    }
    assert_eq!(target.key(&tuple).expect("read").as_deref(), Some(&[5; 32]));

    let seen = Seen {
        host_id: [7; 16],
        epoch: 3,
        fingerprint: "sha256:seen".to_owned(),
        at: DAY_1,
    };
    let peers = volume.host().subdir("peers", true).expect("a directory");
    replace_bytes(
        &peers,
        &format!("{}.cbor", uuid_text(&seen.host_id)),
        &seen.encode().expect("encodes"),
    )
    .expect("written");
    let files = FileSeen::open(&volume).expect("opens");
    let target = PostgresSeen::new(database.clone());
    target
        .import(&files.export().expect("exported"))
        .expect("imported");
    assert_eq!(target.seen(&seen.host_id).expect("read"), Some(seen));

    let versions = FileVersionWitnesses::new(&root);
    for realm in [None, Some("acme")] {
        versions
            .update(realm, &mut |entries| {
                entries.push(("v1".to_owned(), format!("{realm:?} one")));
                entries.push(("v2".to_owned(), format!("{realm:?} two")));
                true
            })
            .expect("kept");
    }
    let target = PostgresVersionWitnesses::new(database.clone());
    for (realm, entries) in versions.export().expect("exported") {
        target.import(realm.as_deref(), &entries).expect("imported");
    }
    for realm in [None, Some("acme")] {
        let read = |store: &dyn VersionWitnesses| {
            let mut held = Vec::new();
            store
                .update(realm, &mut |entries| {
                    held.clone_from(entries);
                    false
                })
                .expect("read");
            held
        };
        assert_eq!(read(&target), read(&versions));
        assert_eq!(read(&target).len(), 2);
    }

    let authority = TestAuthority::new();
    let keys = KeptKeys {
        issuer: permguard_host::authz::testing::ISSUER.to_owned(),
        keys: authority.key_set()["keys"]
            .as_array()
            .expect("an array")
            .clone(),
    };
    let held = FileHeld::open(&volume).expect("opens");
    held.keep_keys(&keys).expect("kept");
    let token = authority.list_token();
    let named = Named {
        issuer: keys.issuer.clone(),
        uri: format!(
            "{}/authority/v1/status-lists/{}",
            keys.issuer,
            permguard_host::authz::testing::LIST_ID
        ),
        iat: 1,
    };
    held.keep_list(&named, &token).expect("kept");
    let target = PostgresHeld::new(database.clone());
    let (carried, left) = carry_held(
        held.keys().expect("read").as_ref(),
        &held.export().expect("exported"),
        &target,
        permguard_core::time::unix_now(),
    )
    .expect("carried");
    assert_eq!((carried, left), (1, 0));
    assert_eq!(target.keys().expect("read"), Some(keys));
    assert_eq!(
        target
            .restore(&|kept| (kept == token).then(|| named.clone()))
            .expect("restored"),
        vec![token]
    );
    let _ = std::fs::remove_dir_all(root);
}
