// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::time::Duration;

use permguard_core::authz::{Resource, Selector};
use permguard_objects::cose::Sign1;

use super::*;
use crate::api::grants::CreateGrant;
use crate::api::keys::KeyBundleQuery;
use crate::api::testing::{Recording, actor, admin, reopen_with, scratch};
use crate::operations::backup::{Consistency, SnapshotManifest};

fn code(refusal: &Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

/// A facade over a fresh volume that keeps its backups, its barriers lasting `lifetime`; the
/// volume's root and its audit trail with it.
fn backed(tag: &str, lifetime: Option<Duration>) -> (HostApi, std::path::PathBuf, Arc<Recording>) {
    let root = scratch(tag);
    let trail = Arc::new(Recording::default());
    let (api, _, volume) = reopen_with(
        &root,
        vec![HOST_OPERATIONS, crate::keys::ring::DATA_ATTEST],
        Arc::clone(&trail),
    );
    let backups = Backups::open(&volume).expect("the backups open");
    assert!(
        backups
            .cut(crate::authz::store::now())
            .expect("cut")
            .is_empty()
    );
    let backups = match lifetime {
        Some(lifetime) => backups.with_lifetime(lifetime),
        None => backups,
    };
    // The volume stays claimed for the facade's life, as a server's does.
    std::mem::forget(volume);
    (
        api.with_backups(
            Arc::new(backups),
            Some("kms:backups/recovery-1".to_owned()),
            Some("aes-256-gcm".to_owned()),
        ),
        root,
        trail,
    )
}

/// A grant creation: a mutation of the Host.
async fn grant(api: &HostApi, request_id: &str) -> Result<crate::api::grants::Created, Refusal> {
    api.create_grant(
        &admin(),
        CreateGrant {
            request_id: request_id.to_owned(),
            expected_revision: None,
            principal: format!("spiffe://acme/{request_id}"),
            operations: vec![operations::CATALOG_READ.to_owned()],
            selector: Selector::under(Resource::host()).to_string(),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            expires_at: None,
        },
    )
    .await
}

fn manifest_of(prepared: &BackupPrepared) -> (Vec<u8>, SnapshotManifest) {
    let bytes = URL_SAFE_NO_PAD
        .decode(&prepared.manifest)
        .expect("base64url");
    let manifest = SnapshotManifest::decode(
        Sign1::decode(&bytes)
            .expect("an envelope")
            .payload_unverified(),
    )
    .expect("a manifest");
    (bytes, manifest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Every action and phase the trail recorded.
fn recorded(trail: &Recording) -> Vec<(String, String, Option<&'static str>)> {
    trail
        .events
        .lock()
        .expect("the trail")
        .iter()
        .map(|(action, subject, _, phase)| (action.clone(), subject.clone(), *phase))
        .collect()
}

/// WP-7.8: a prepare raises the barrier and answers a manifest naming the backup, the volume, the
/// Host, the roots and the recovery labels, and the token once; while it holds, a mutation is
/// refused `unavailable`, a second prepare `conflict`, another token `not_found`; the finalize
/// binds the snapshot id, spends the token and lowers the barrier; the list shows it; every step
/// is audited.
#[tokio::test]
async fn a_prepared_backup_holds_mutations_until_it_is_finalized() {
    let (api, _root, trail) = backed("backup-hold", None);
    let prepared = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect("prepared");
    let (_, manifest) = manifest_of(&prepared);
    assert_eq!(hex(&manifest.operation_id), prepared.operation_id);
    assert_eq!(
        manifest.host_id,
        api.identity.as_ref().expect("an identity").host_id()
    );
    assert_eq!(
        manifest
            .roots
            .iter()
            .map(|root| root.name.as_str())
            .collect::<Vec<_>>(),
        vec!["host", "data", "operations"]
    );
    assert!(manifest.roots[0].files > 0, "the Host's files are bound");
    assert!(manifest.revisions.contains_key("mutations"));
    assert_eq!(
        manifest.recovery_key_id.as_deref(),
        Some("kms:backups/recovery-1")
    );
    assert_eq!(manifest.encryption_profile.as_deref(), Some("aes-256-gcm"));
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&prepared.token).expect("b64").len(),
        32
    );
    // The token is a secret: no `Debug` prints it.
    for printed in [
        format!("{prepared:?}"),
        format!(
            "{:?}",
            FinalizeBackup {
                token: prepared.token.clone(),
                snapshot_id: "s".to_owned()
            }
        ),
        format!(
            "{:?}",
            AbortBackup {
                token: prepared.token.clone()
            }
        ),
    ] {
        assert!(!printed.contains(&prepared.token), "{printed}");
    }

    api.list_backups(&admin())
        .expect("reads go on under the barrier");
    api.ring(HOST_OPERATIONS)
        .expect("reads go on under the barrier");
    let held = grant(&api, "during").await.expect_err("mutations are held");
    assert_eq!(code(&held), codes::common::UNAVAILABLE);
    let busy = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect_err("one backup at a time");
    assert_eq!(code(&busy), codes::common::CONFLICT);
    let unknown = api
        .finalize_backup(
            &admin(),
            FinalizeBackup {
                token: URL_SAFE_NO_PAD.encode([7u8; 32]),
                snapshot_id: "csi:snap-1".to_owned(),
            },
        )
        .expect_err("another token");
    assert_eq!(code(&unknown), codes::common::NOT_FOUND);
    let invalid = api
        .finalize_backup(
            &admin(),
            FinalizeBackup {
                token: prepared.token.clone(),
                snapshot_id: "a snapshot".to_owned(),
            },
        )
        .expect_err("not a snapshot id");
    assert_eq!(code(&invalid), codes::common::INVALID_ARGUMENT);
    assert_eq!(
        code(&grant(&api, "still").await.expect_err("still held")),
        codes::common::UNAVAILABLE,
        "a refused finalize leaves the barrier up"
    );

    let ended = api
        .finalize_backup(
            &admin(),
            FinalizeBackup {
                token: prepared.token.clone(),
                snapshot_id: "csi:snap-0001".to_owned(),
            },
        )
        .expect("finalized");
    assert_eq!(ended.backup, prepared.operation_id);
    assert_eq!(ended.state, "finalized");
    assert_eq!(ended.snapshot_id.as_deref(), Some("csi:snap-0001"));
    assert_ne!(
        ended.receipt.operation_id, prepared.operation_id,
        "its own operation"
    );
    let spent = api
        .abort_backup(
            &admin(),
            AbortBackup {
                token: prepared.token.clone(),
            },
        )
        .expect_err("the token is spent");
    assert_eq!(code(&spent), codes::common::NOT_FOUND);
    grant(&api, "after").await.expect("mutations resume");

    let listed = api.list_backups(&admin()).expect("listed");
    assert_eq!(listed.backups.len(), 1);
    let backup = &listed.backups[0];
    assert_eq!(backup.operation_id, prepared.operation_id);
    assert_eq!(backup.state, "finalized");
    assert_eq!(backup.snapshot_id.as_deref(), Some("csi:snap-0001"));
    assert!(backup.ended_at.is_some());

    let records = recorded(&trail);
    for action in ["host.backup.prepared", "host.backup.finalized"] {
        for phase in ["intent", "applied"] {
            assert!(
                records
                    .iter()
                    .any(|(held, subject, held_phase)| held == action
                        && subject.ends_with(crate::api::testing::ADMIN)
                        && *held_phase == Some(phase)),
                "{action} {phase}: {records:?}"
            );
        }
    }
}

/// WP-7.8: a prepare nobody ends lets mutations through once its barrier expires, and is recorded
/// aborted by the Host itself at the next call; an abort with its token ends one at once.
#[tokio::test]
async fn an_abandoned_backup_aborts_when_its_barrier_expires() {
    let (api, _root, trail) = backed("backup-expiry", Some(Duration::from_secs(2)));
    let prepared = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect("prepared");
    assert_eq!(
        code(&grant(&api, "held").await.expect_err("held")),
        codes::common::UNAVAILABLE
    );
    std::thread::sleep(Duration::from_millis(2200));
    grant(&api, "expired")
        .await
        .expect("past its lifetime the barrier holds nothing");
    // The timer records the abort with nobody calling: the store itself says so.
    std::thread::sleep(Duration::from_millis(300));
    let held = api
        .backups
        .as_ref()
        .expect("backups")
        .list()
        .expect("listed");
    assert_eq!(held[0].state, "aborted", "the timer aborted it");
    let listed = api.list_backups(&admin()).expect("listed");
    assert_eq!(listed.backups[0].operation_id, prepared.operation_id);
    assert_eq!(listed.backups[0].state, "aborted");
    assert!(
        recorded(&trail)
            .iter()
            .any(|(action, subject, phase)| action == "host.backup.aborted"
                && subject == "system:backup"
                && *phase == Some("applied")),
        "the Host recorded the abort"
    );
    let expired = api
        .finalize_backup(
            &admin(),
            FinalizeBackup {
                token: prepared.token,
                snapshot_id: "late".to_owned(),
            },
        )
        .expect_err("too late");
    assert_eq!(code(&expired), codes::common::NOT_FOUND);

    // A second within the same second still lists after the first.
    std::thread::sleep(Duration::from_millis(1100));
    let second = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect("another backup");
    let ended = api
        .abort_backup(
            &admin(),
            AbortBackup {
                token: second.token,
            },
        )
        .expect("aborted");
    assert_eq!(ended.state, "aborted");
    assert_eq!(ended.snapshot_id, None);
    grant(&api, "after-abort").await.expect("resumed");
    // Newest first, each with its manifest.
    let listed = api.list_backups(&admin()).expect("listed").backups;
    assert_eq!(
        listed
            .iter()
            .map(|backup| backup.operation_id.as_str())
            .collect::<Vec<_>>(),
        vec![second.operation_id.as_str(), prepared.operation_id.as_str()]
    );
    assert!(listed.iter().all(|backup| backup.manifest.is_some()));
    assert_eq!(
        listed[0].manifest.as_deref(),
        Some(second.manifest.as_str())
    );
}

/// WP-7.8: prepare, finalize and abort need `backup.manage`, the list `backup.read`.
#[tokio::test]
async fn backups_need_their_grants() {
    let (api, _root, _) = backed("backup-grants", None);
    let reader = "spiffe://acme/operators/reader";
    api.create_grant(
        &admin(),
        CreateGrant {
            request_id: "reader".to_owned(),
            expected_revision: None,
            principal: reader.to_owned(),
            operations: vec![operations::BACKUP_READ.to_owned()],
            selector: Selector::under(Resource::host()).to_string(),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            expires_at: None,
        },
    )
    .await
    .expect("granted");
    api.list_backups(&actor(reader)).expect("a reader lists");
    let refused = api
        .prepare_backup(&actor(reader), PrepareBackup {})
        .expect_err("a reader manages nothing");
    assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
    let nobody = api
        .list_backups(&actor("spiffe://acme/nobody"))
        .expect_err("no grant");
    assert!(matches!(nobody, Refusal::Denied(_)), "{nobody:?}");
    assert!(
        api.list_backups(&admin())
            .expect("listed")
            .backups
            .is_empty()
    );
}

/// Every file below `from`, copied to `to`: what a storage driver's snapshot holds.
fn copy(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("the copy");
    for entry in std::fs::read_dir(from).expect("lists").flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copied");
        }
    }
}

/// The Host's keys bundle for `host`, every page, and the identity pin: what the operator keeps
/// outside the snapshot.
fn bundle(api: &HostApi) -> (Vec<u8>, Vec<Vec<u8>>, String) {
    let query = |frontier: Option<&str>, cursor: Option<&str>| KeyBundleQuery {
        resource: "host".to_owned(),
        frontier: frontier.map(str::to_owned),
        cursor: cursor.map(str::to_owned),
        limit: None,
    };
    let first = api
        .key_bundle(&admin(), &query(None, None))
        .expect("a bundle");
    let mut items = first.items.clone();
    let mut cursor = first.next_cursor.clone();
    while let Some(next) = cursor {
        let page = api
            .key_bundle(&admin(), &query(Some(&first.manifest), Some(&next)))
            .expect("a page");
        items.extend(page.items);
        cursor = page.next_cursor;
    }
    (
        URL_SAFE_NO_PAD.decode(&first.manifest).expect("b64"),
        items
            .iter()
            .map(|item| URL_SAFE_NO_PAD.decode(item).expect("b64"))
            .collect(),
        api.keys
            .identity()
            .expect("the identity")
            .first_fingerprint()
            .to_owned(),
    )
}

/// WP-7.8, done when: a snapshot taken inside the barrier verifies against its external bundle
/// as application-consistent; a copy of the live volume after a mutation is labelled
/// crash-consistent only, naming what differs; a wrong pin, a changed manifest or another volume
/// is refused, never labelled.
#[tokio::test]
async fn a_snapshot_inside_the_barrier_verifies_and_one_outside_is_crash_consistent() {
    let (api, root, _) = backed("backup-verify", None);
    // A volume holds more than `host/`: a wrapped key of the operations root.
    std::fs::create_dir_all(root.join("operations/keys")).expect("the root");
    std::fs::write(root.join("operations/keys/wrapped"), b"sealed").expect("a key");
    let prepared = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect("prepared");
    let inside = scratch("backup-verify-inside");
    copy(&root, &inside);
    api.finalize_backup(
        &admin(),
        FinalizeBackup {
            token: prepared.token.clone(),
            snapshot_id: "copy:inside".to_owned(),
        },
    )
    .expect("finalized");
    grant(&api, "outside").await.expect("a mutation after it");
    let outside = scratch("backup-verify-outside");
    copy(&root, &outside);
    let (manifest, _) = manifest_of(&prepared);
    let (bundle_manifest, items, pin) = bundle(&api);

    let verdict = backup::verify(&inside, &manifest, &bundle_manifest, &items, &pin)
        .expect("the snapshot verifies");
    assert_eq!(verdict.consistency, Consistency::ApplicationConsistent);
    assert_eq!(hex(&verdict.manifest.operation_id), prepared.operation_id);
    // The transaction's journal took the prepare's own commit after the inventory: a prefix grown.
    assert_eq!(
        verdict.grown,
        vec!["host/audit/mutations/journal.cborseq".to_owned()]
    );

    let verdict = backup::verify(&outside, &manifest, &bundle_manifest, &items, &pin)
        .expect("verified, and labelled");
    let Consistency::CrashConsistent(differences) = verdict.consistency else {
        panic!("a copy outside the barrier is not application-consistent");
    };
    assert!(!differences.is_empty());

    // A file of the snapshot changed in place is a difference too.
    let changed = scratch("backup-verify-changed");
    copy(&inside, &changed);
    let victim = std::fs::read_dir(changed.join("host"))
        .expect("lists")
        .flatten()
        .find(|entry| entry.file_name() == "VOLUME-CLAIM" || entry.file_name() == "FORMAT")
        .expect("a view of the volume");
    let mut bytes = std::fs::read(victim.path()).expect("reads");
    bytes.push(0);
    std::fs::write(victim.path(), bytes).expect("changed");
    assert!(matches!(
        backup::verify(&changed, &manifest, &bundle_manifest, &items, &pin)
            .expect("labelled")
            .consistency,
        Consistency::CrashConsistent(_)
    ));

    let refused = backup::verify(&inside, &manifest, &bundle_manifest, &items, "not-the-pin")
        .expect_err("another pin");
    assert!(refused.contains("bundle"), "{refused}");
    let mut forged = manifest.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let refused = backup::verify(&inside, &forged, &bundle_manifest, &items, &pin)
        .expect_err("a changed manifest");
    assert!(refused.contains("signature"), "{refused}");
    let (other, other_root, _) = backed("backup-verify-other", None);
    let _ = other;
    let refused = backup::verify(&other_root, &manifest, &bundle_manifest, &items, &pin)
        .expect_err("another volume");
    assert!(refused.contains("volume"), "{refused}");

    // A file the snapshot holds beyond the manifest is state past the barrier.
    let extra = scratch("backup-verify-extra");
    copy(&inside, &extra);
    std::fs::write(extra.join("data").join("late"), b"after").unwrap_or_else(|_| {
        std::fs::create_dir_all(extra.join("data")).expect("data");
        std::fs::write(extra.join("data").join("late"), b"after").expect("written");
    });
    let Consistency::CrashConsistent(differences) =
        backup::verify(&extra, &manifest, &bundle_manifest, &items, &pin)
            .expect("labelled")
            .consistency
    else {
        panic!("an extra file is a difference");
    };
    assert_eq!(
        differences,
        vec!["data/late: not in the manifest".to_owned()]
    );

    // An inventory changed in the snapshot is refused, never read.
    let tampered = scratch("backup-verify-inventory");
    copy(&inside, &tampered);
    let inventory = tampered
        .join("host/backups")
        .join(&prepared.operation_id)
        .join(backup::INVENTORY);
    let mut bytes = std::fs::read(&inventory).expect("reads");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&inventory, bytes).expect("written");
    assert!(
        backup::verify(&tampered, &manifest, &bundle_manifest, &items, &pin).is_err(),
        "a changed inventory"
    );

    // The same files reordered across the roots: each root's digest holds, the inventory the
    // manifest signed does not, and it is refused.
    let reordered = scratch("backup-verify-reordered");
    copy(&inside, &reordered);
    let path = reordered
        .join("host/backups")
        .join(&prepared.operation_id)
        .join(backup::INVENTORY);
    let dir = crate::storage::Dir::open(path.parent().expect("a parent")).expect("opens");
    let inventory_items = crate::storage::sequence::read(&dir, backup::INVENTORY, 1 << 16)
        .expect("reads")
        .items;
    // Every `host/` item moved after the `operations/` ones: each root keeps its order.
    let is_host = |item: &permguard_objects::cbor::Value| {
        matches!(item, permguard_objects::cbor::Value::Map(pairs)
            if matches!(&pairs[0].1, permguard_objects::cbor::Value::Text(path) if path.starts_with("host/")))
    };
    let (host, rest): (Vec<_>, Vec<_>) = inventory_items.into_iter().partition(is_host);
    assert!(!host.is_empty() && rest.iter().any(|item| !is_host(item)));
    let inventory_items: Vec<_> = rest.into_iter().chain(host).collect();
    let mut bytes = Vec::new();
    for item in &inventory_items {
        bytes.extend(permguard_objects::cbor::encode(item).expect("encodes"));
    }
    std::fs::write(&path, bytes).expect("written");
    let refused = backup::verify(&reordered, &manifest, &bundle_manifest, &items, &pin)
        .expect_err("another inventory");
    assert_eq!(refused, "the inventory is not the one the manifest binds");

    // Signed by this Host's key and naming another Host, or other roots: refused.
    let ring = api.keys.ring(HOST_OPERATIONS).expect("the ring");
    let (_, held) = manifest_of(&prepared);
    let other_host = backup::sign(
        ring,
        &SnapshotManifest {
            host_id: [0xee; 16],
            ..held.clone()
        },
    )
    .expect("signed");
    let refused = backup::verify(&inside, &other_host, &bundle_manifest, &items, &pin)
        .expect_err("another Host");
    assert!(refused.contains("another Host"), "{refused}");
    let mut roots = held.roots.clone();
    roots[0].files += 1;
    let other_roots = backup::sign(
        ring,
        &SnapshotManifest {
            roots,
            ..held.clone()
        },
    )
    .expect("signed");
    let refused = backup::verify(&inside, &other_roots, &bundle_manifest, &items, &pin)
        .expect_err("other roots");
    assert!(refused.contains("roots"), "{refused}");
    let too_large = vec![0u8; backup::MAX_MANIFEST_BYTES + 1];
    let refused =
        backup::verify(&inside, &too_large, &bundle_manifest, &items, &pin).expect_err("too large");
    assert!(refused.contains("at most"), "{refused}");
    // Only `host.operations` signs a manifest.
    let attest = api
        .keys
        .ring(crate::keys::ring::DATA_ATTEST)
        .expect("another ring");
    assert!(backup::sign(attest, &held).is_err());
}

/// WP-7.8: a manifest whose `host.operations` key the bundle revokes verifies nothing.
#[tokio::test]
async fn a_manifest_under_a_revoked_key_is_refused() {
    use crate::api::keys::{PlanKeyRevoke, RotateRing, RunKeyRevoke};

    let (api, root, _) = backed("backup-revoked", None);
    let prepared = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect("prepared");
    let inside = scratch("backup-revoked-inside");
    copy(&root, &inside);
    api.finalize_backup(
        &admin(),
        FinalizeBackup {
            token: prepared.token.clone(),
            snapshot_id: "copy:revoked".to_owned(),
        },
    )
    .expect("finalized");
    let (manifest, _) = manifest_of(&prepared);
    let kid = String::from_utf8(
        Sign1::decode(&manifest)
            .expect("an envelope")
            .header()
            .expect("a header")
            .kid,
    )
    .expect("text");
    let epoch = api.ring(HOST_OPERATIONS).expect("the ring").epoch;
    api.rotate_ring(
        &admin(),
        HOST_OPERATIONS,
        RotateRing {
            request_id: "rotate".to_owned(),
            expected_epoch: epoch.expect("an epoch"),
        },
    )
    .await
    .expect("rotated");
    let planned = api
        .plan_key_revoke(
            &admin(),
            HOST_OPERATIONS,
            PlanKeyRevoke {
                request_id: "plan".to_owned(),
                kid: kid.clone(),
                reason: "compromise".to_owned(),
                compromised_at: Some("2026-10-08T10:00:00Z".to_owned()),
                expected_epoch: None,
            },
        )
        .await
        .expect("planned");
    api.run_key_revoke(
        &admin(),
        HOST_OPERATIONS,
        RunKeyRevoke {
            request_id: "run".to_owned(),
            receipt: planned.receipt,
        },
    )
    .await
    .expect("revoked");
    let (bundle_manifest, items, pin) = bundle(&api);
    let refused = backup::verify(&inside, &manifest, &bundle_manifest, &items, &pin)
        .expect_err("a revoked key");
    assert!(refused.contains("revoked"), "{refused}");
}

/// WP-7.8: an inventory that outlasts its barrier — here a barrier of no time at all — aborts the
/// backup rather than answering a manifest taken while mutations had resumed.
#[tokio::test]
async fn a_prepare_that_outlasts_its_barrier_is_aborted() {
    let (api, _root, _) = backed("backup-outlasted", Some(Duration::ZERO));
    let refused = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect_err("outlasted");
    assert!(
        refused
            .error()
            .is_some_and(|error| error.code() == codes::common::UNAVAILABLE),
        "{refused:?}"
    );
    let listed = api.list_backups(&admin()).expect("listed").backups;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, "aborted");
    grant(&api, "after").await.expect("mutations go on");
}

/// WP-7.10: an export manifest signed by the Host under `host.operations` verifies from the
/// source Host's keys bundle and identity pin; a wrong pin, a changed manifest, a manifest of
/// another protected type, or one under a revoked key is refused.
#[tokio::test]
async fn an_export_manifest_verifies_from_the_sources_bundle_and_pin() {
    use crate::api::keys::{PlanKeyRevoke, RotateRing, RunKeyRevoke};
    use crate::composition::Payload as _;
    use crate::exports::{self, ExportedLedger, Manifest};

    let (api, _root, _) = backed("export-verify", None);
    let host_id = api.keys.identity().expect("the identity").host_id();
    let held = Manifest {
        host_id,
        exported_at: 1_800_000_000,
        zone_id: "zone-id".to_owned(),
        zone_name: "delivery".to_owned(),
        ledgers: vec![ExportedLedger {
            id: "ledger-id".to_owned(),
            name: "release".to_owned(),
            default_ref: "main".to_owned(),
            refs: Vec::new(),
            objects: 0,
            statements: 0,
        }],
        bundle_digest: exports::bundle_digest(b""),
        bundle_bytes: 0,
    };
    let ring = api.keys.ring(HOST_OPERATIONS).expect("the operations ring");
    let envelope = held.sign_with(ring.as_ref()).expect("signed");
    let (bundle_manifest, items, pin) = bundle(&api);

    let verified = exports::verify(&envelope, &bundle_manifest, &items, &pin).expect("it verifies");
    assert_eq!(verified.manifest, held);
    assert_eq!(verified.host_id, host_id);

    assert!(exports::verify(&envelope, &bundle_manifest, &items, "not-the-pin").is_err());
    let mut forged = envelope.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    assert!(exports::verify(&forged, &bundle_manifest, &items, &pin).is_err());
    let snapshot = crate::operations::backup::sign(ring, &manifest_for(host_id)).expect("signed");
    let refused = exports::verify(&snapshot, &bundle_manifest, &items, &pin)
        .expect_err("another protected type");
    assert!(refused.contains("signature"), "{refused}");
    let mut stranger = held.clone();
    stranger.host_id = [9; 16];
    let other = stranger.sign_with(ring.as_ref()).expect("signed");
    let refused =
        exports::verify(&other, &bundle_manifest, &items, &pin).expect_err("another Host");
    assert!(refused.contains("another Host"), "{refused}");

    let kid = String::from_utf8(
        Sign1::decode(&envelope)
            .expect("an envelope")
            .header()
            .expect("a header")
            .kid,
    )
    .expect("text");
    let epoch = api.ring(HOST_OPERATIONS).expect("the ring").epoch;
    api.rotate_ring(
        &admin(),
        HOST_OPERATIONS,
        RotateRing {
            request_id: "rotate".to_owned(),
            expected_epoch: epoch.expect("an epoch"),
        },
    )
    .await
    .expect("rotated");
    let planned = api
        .plan_key_revoke(
            &admin(),
            HOST_OPERATIONS,
            PlanKeyRevoke {
                request_id: "plan".to_owned(),
                kid,
                reason: "compromise".to_owned(),
                compromised_at: Some("2026-10-08T10:00:00Z".to_owned()),
                expected_epoch: None,
            },
        )
        .await
        .expect("planned");
    api.run_key_revoke(
        &admin(),
        HOST_OPERATIONS,
        RunKeyRevoke {
            request_id: "run".to_owned(),
            receipt: planned.receipt,
        },
    )
    .await
    .expect("revoked");
    let (bundle_manifest, items, pin) = bundle(&api);
    let refused =
        exports::verify(&envelope, &bundle_manifest, &items, &pin).expect_err("a revoked key");
    assert!(refused.contains("revoked"), "{refused}");
}

/// A snapshot manifest of `host_id`, signed under the same ring as an export.
fn manifest_for(host_id: [u8; 16]) -> SnapshotManifest {
    SnapshotManifest {
        operation_id: [1; 16],
        volume_id: [2; 16],
        host_id,
        revisions: std::collections::BTreeMap::new(),
        roots: Vec::new(),
        at: 1_800_000_000,
        inventory_digest: [5; 32],
        recovery_key_id: None,
        encryption_profile: None,
    }
}

/// `8-architecture-storage-operations.md` (application-consistent snapshot): every root is
/// flushed, every directory of it, before the prepare answers. A directory deep in a root whose
/// flush fails refuses the prepare: no token is answered for a snapshot the disk did not make
/// durable, the operation is aborted rather than left `prepared`, and mutations go on.
#[tokio::test]
async fn a_root_that_cannot_be_flushed_refuses_the_prepare() {
    let (api, root, _) = backed("backup-unflushed", None);
    let deep = root.join("data").join("deep").join("deeper");
    std::fs::create_dir_all(&deep).expect("created");
    {
        let _failing =
            permguard_core::fault::inject_exact(&deep, permguard_core::fault::Fault::Fsync);
        let refused = api
            .prepare_backup(&admin(), PrepareBackup {})
            .expect_err("a root was not flushed");
        assert!(
            refused
                .error()
                .is_some_and(|error| error.code() == codes::common::UNAVAILABLE),
            "{refused:?}"
        );
    }
    // Nothing is left `prepared` without a barrier behind it.
    let listed = api.list_backups(&admin()).expect("listed").backups;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, "aborted", "{listed:?}");
    grant(&api, "after-unflushed")
        .await
        .expect("mutations go on");
    let prepared = api
        .prepare_backup(&admin(), PrepareBackup {})
        .expect("the disk flushes again");
    let (_, manifest) = manifest_of(&prepared);
    assert_eq!(hex(&manifest.operation_id), prepared.operation_id);
}
