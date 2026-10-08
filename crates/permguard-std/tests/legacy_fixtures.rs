// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog, the key ring and the audit trail as this release writes them, kept so that every
//! later layout can prove it still reads them.
//!
//! Each fixture under `tests/fixtures/legacy/v1/` is a volume fragment written by the current code.
//! In CI a fixture is copied aside and opened by the current store, which must find the same
//! zones, keys and records. Setting `PERMGUARD_CAPTURE_LEGACY_FIXTURES=1` rewrites the fixtures
//! from the current code instead; that is done once per layout version and reviewed, never to
//! make a failing test pass.
//!
//! These fixtures are the v1 compatibility baseline: every later migration of the catalog, the key
//! ring or the audit trail must read them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use permguard_core::keys::{PublicSet as _, Sign as _};
use permguard_core::{AuditEvent, AuditSink, Catalog, KeyManager, Maintenance, Selector};
use permguard_std::audit::{FileAuditSink, verify};
use permguard_std::catalog::FileCatalog;
use permguard_std::keys::{Clock, DirectoryKeyManager, KeyPolicy, verify_signature};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/legacy/v1");

/// One instant, so that a fixture captured today and verified next year see the same clock.
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        1_759_276_800
    }
}

fn policy() -> KeyPolicy {
    KeyPolicy {
        publish_ahead: Duration::from_secs(600),
        rotate_every: Duration::from_secs(30 * 86_400),
        retain: Duration::from_secs(60 * 86_400),
        verify_retain: Duration::from_secs(365 * 86_400),
    }
}

fn capturing() -> bool {
    std::env::var_os("PERMGUARD_CAPTURE_LEGACY_FIXTURES").is_some()
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("permguard-legacy-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// Removes the empty directories under `directory`, deepest first. Git keeps no empty directory, so
/// a fixture holding one would read differently from a clean checkout than from the capture.
fn prune_empty(directory: &Path) {
    for entry in fs::read_dir(directory).expect("the directory is listed") {
        let entry = entry.expect("an entry is read");
        if entry.file_type().expect("a file type").is_dir() {
            prune_empty(&entry.path());
            if fs::read_dir(entry.path())
                .expect("the directory is listed")
                .next()
                .is_none()
            {
                fs::remove_dir(entry.path()).expect("the empty directory is removed");
            }
        }
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the target directory is created");
    for entry in fs::read_dir(from).expect("the source directory is listed") {
        let entry = entry.expect("an entry is read");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("a file is copied");
        }
    }
}

/// Builds into `work` when capturing and publishes it as the fixture; otherwise restores the
/// fixture into `work`. Either way `work` is what the verification reads.
fn stage(name: &str, work: &Path, build: impl FnOnce(&Path)) {
    let fixture = Path::new(FIXTURES).join(name);
    if capturing() {
        build(work);
        let _ = fs::remove_dir_all(&fixture);
        copy_dir(work, &fixture);
        prune_empty(&fixture);
    } else {
        copy_dir(&fixture, work);
    }
}

#[test]
fn test_the_v1_catalog_fixture_is_read_by_the_current_code() {
    let work = scratch("catalog");
    stage("catalog", &work, |directory| {
        let catalog = FileCatalog::new(directory);
        catalog.create_zone("billing").expect("the zone is created");
        catalog
            .create_ledger(&Selector::parse("billing"), "invoices")
            .expect("the ledger is created");
    });

    let catalog = FileCatalog::new(&work);
    let zones = catalog.list_zones().expect("the zones list");
    assert_eq!(
        zones
            .iter()
            .map(|zone| zone.name.as_str())
            .collect::<Vec<_>>(),
        ["billing"]
    );
    let ledgers = catalog
        .list_ledgers(&Selector::parse("billing"))
        .expect("the ledgers list");
    assert_eq!(
        ledgers
            .iter()
            .map(|ledger| ledger.name.as_str())
            .collect::<Vec<_>>(),
        ["invoices"]
    );
    assert!(work.join("zones.json").exists());
    assert!(work.join(&zones[0].id).join("ledgers.json").exists());
}

#[test]
fn test_the_v1_key_ring_fixture_is_read_and_signs_with_the_current_code() {
    let work = scratch("keys");
    stage("keys", &work, |directory| {
        let manager = DirectoryKeyManager::with_clock(directory, policy(), Box::new(FixedClock));
        manager.maintain().expect("the first key is minted");
    });

    // The key is named from the bytes on disk, not from the manager, so that a manager which minted
    // a fresh key instead of reading the captured one cannot agree with itself and pass.
    let captured = captured_kid(&work.join("ring.json"));

    let manager = DirectoryKeyManager::with_clock(&work, policy(), Box::new(FixedClock));
    let keys = manager.public_keys().expect("the public set reads");
    assert_eq!(keys.len(), 1, "one key, as captured");
    assert_eq!(keys[0].kid, captured);
    let active = manager.active_key_id().expect("one key is active");
    assert_eq!(active.as_str(), captured);
    assert_eq!(
        manager.maintain().expect("maintenance runs"),
        Maintenance::default(),
        "the captured ring needs nothing at the captured instant"
    );

    // The private half on disk still signs, and the published half verifies what it signed.
    let signature = manager.sign(b"legacy fixture").expect("the ring signs");
    assert_eq!(signature.key_id().as_str(), captured);
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&keys[0].x)
        .expect("the published key is base64url");
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
        .verify(b"legacy fixture", signature.bytes())
        .expect("the signature verifies under the published key");
    assert!(work.join("ring.json").exists());
}

#[tokio::test]
async fn test_the_v1_audit_trail_fixture_is_verified_by_the_current_code() {
    let work = scratch("audit");
    let fixture = Path::new(FIXTURES).join("audit");
    if capturing() {
        let keys = Arc::new(DirectoryKeyManager::with_clock(
            work.join("keys"),
            policy(),
            Box::new(FixedClock),
        ));
        keys.maintain().expect("the sealing key is minted");
        let sink = FileAuditSink::new(
            work.join("trail"),
            "permguard-fixture",
            "0.1.0",
            Duration::from_secs(30 * 86_400),
        )
        .sealed_by(keys);
        sink.prepare().expect("the trail directory is prepared");
        for action in [
            "fixture.created",
            "fixture.zone.created",
            "fixture.key.minted",
        ] {
            sink.record(&AuditEvent::system(action, "legacy-fixture"), None)
                .await
                .expect("the record is written");
        }
        sink.shutdown().await.expect("the day is sealed");
        let _ = fs::remove_dir_all(&fixture);
        copy_dir(&work, &fixture);
        prune_empty(&fixture);
    } else {
        copy_dir(&fixture, &work);
    }

    let verification = verify(&work.join("trail")).expect("the trail verifies");
    assert_eq!(verification.records, 3);
    assert_eq!(verification.days, 1);
    assert_ne!(verification.head, "0".repeat(64));

    // `verify` checks the chain under each seal but leaves the signature to a caller holding a key
    // it trusts: here, the sealing key captured beside the trail.
    assert_eq!(verification.seals.len(), 1, "one day, one seal");
    let seal = &verification.seals[0];
    assert_eq!(seal.body.head, verification.head);
    let sealer = captured_kid(&work.join("keys").join("ring.json"));
    assert_eq!(seal.kid.as_deref(), Some(sealer.as_str()));
    let keys = DirectoryKeyManager::with_clock(work.join("keys"), policy(), Box::new(FixedClock))
        .public_keys()
        .expect("the sealing key set reads");
    let jwk = keys
        .iter()
        .find(|key| key.kid == sealer)
        .expect("the sealing key is published");
    let signature = from_hex(seal.signature.as_deref().expect("the seal is signed"));
    assert!(
        verify_signature(
            jwk,
            &seal.signed_bytes().expect("the seal body encodes"),
            &signature
        ),
        "the seal signature verifies under the captured sealing key"
    );
}

/// The `kid` of the only key in a captured `ring.json`, read as plain JSON.
fn captured_kid(ring: &Path) -> String {
    let ring: serde_json::Value =
        serde_json::from_slice(&fs::read(ring).expect("ring.json is present")).expect("JSON");
    let keys = ring["keys"].as_array().expect("the ring lists keys");
    assert_eq!(keys.len(), 1, "one key, as captured");
    keys[0]["kid"]
        .as_str()
        .expect("the key has a kid")
        .to_owned()
}

fn from_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex has an even length");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// WP-3.1: the v1 key ring fixture and the audit fixture's sealing ring migrate once through the
/// WP-1.9 framework into `host/keys/host.operations`; the carried key signs with the same
/// material under its ring-prefixed kid, and the seal made under the bare thumbprint still
/// verifies against the migrated ring through the legacy alias.
#[test]
fn test_the_v1_key_rings_migrate_to_the_host_ring_and_old_seals_keep_verifying() {
    use permguard_core::assurance::AssuranceProfile;
    use permguard_host::keys::migration::{Laid, lay_out};
    use permguard_host::keys::ring::{HOST_OPERATIONS, Policy, Ring};
    use permguard_host::keys::selects;
    use permguard_host::storage::volume::Volume;

    let ring_policy = Policy {
        publish_ahead: Duration::from_secs(600),
        rotate_every: Duration::from_secs(30 * 86_400),
        retain: Duration::from_secs(365 * 86_400),
    };
    let time = || {
        Arc::new(permguard_host::time::TimeGuard::system(
            Duration::from_secs(30),
        ))
    };

    // The keys fixture: the active key is carried and signs as before.
    let root = scratch("keys-migrated");
    let legacy = root.join("operations/keys/operations");
    copy_dir(&Path::new(FIXTURES).join("keys"), &legacy);
    let captured = captured_kid(&legacy.join("ring.json"));
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        assert_eq!(
            lay_out(
                &volume,
                HOST_OPERATIONS,
                Some(&legacy),
                AssuranceProfile::Development,
                None,
                1_759_276_900,
            )
            .expect("migrated"),
            Laid::Migrated
        );
        let ring = Ring::open(
            &volume,
            HOST_OPERATIONS,
            permguard_host::identity::Suite::Ed25519Sha256V1,
            ring_policy,
            time(),
        )
        .expect("the migrated ring opens");
        let keys = ring.public_keys().expect("published");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, format!("{HOST_OPERATIONS}:{captured}"));
        assert!(selects(&keys[0], &captured), "the legacy kid selects it");
        let signature = ring.sign(b"after the migration").expect("signs");
        assert_eq!(signature.key_id().as_str(), keys[0].kid);
        assert!(verify_signature(
            &keys[0],
            b"after the migration",
            signature.bytes()
        ));
        assert!(
            legacy.join("ring.json").exists(),
            "the old generation is kept"
        );
    }
    let _ = fs::remove_dir_all(&root);

    // The audit fixture: its seal names the bare thumbprint and verifies after the migration.
    let root = scratch("seal-migrated");
    let fixture = Path::new(FIXTURES).join("audit");
    copy_dir(&fixture, &root.join("trail-fixture"));
    let legacy = root.join("operations/keys/operations");
    copy_dir(&fixture.join("keys"), &legacy);
    let verification = verify(&root.join("trail-fixture").join("trail")).expect("verifies");
    let seal = &verification.seals[0];
    let sealer = seal.kid.clone().expect("the seal names its key");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    lay_out(
        &volume,
        HOST_OPERATIONS,
        Some(&legacy),
        AssuranceProfile::Development,
        None,
        1_759_276_900,
    )
    .expect("migrated");
    let keys = Ring::open(
        &volume,
        HOST_OPERATIONS,
        permguard_host::identity::Suite::Ed25519Sha256V1,
        ring_policy,
        time(),
    )
    .expect("opens")
    .public_keys()
    .expect("published");
    let jwk = keys
        .iter()
        .find(|key| selects(key, &sealer))
        .expect("the sealing key is selected by its bare thumbprint");
    assert_ne!(jwk.kid, sealer, "published under its ring-prefixed kid");
    assert!(verify_signature(
        jwk,
        &seal.signed_bytes().expect("the seal body encodes"),
        &from_hex(seal.signature.as_deref().expect("the seal is signed"))
    ));
    drop(volume);
    let _ = fs::remove_dir_all(&root);
}
