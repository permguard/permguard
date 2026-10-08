// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::KeyManager as _;
use permguard_core::keys::Sign as _;
use permguard_objects::crypto::suite::SigningKey;

use super::*;
use crate::keys::KeyProvider as _;
use crate::keys::ring::{DATA_ATTEST, Policy, Ring, journal_entries};
use crate::storage::migrate::Phase;
use crate::time::TimeGuard;

const NOW: u64 = 1_800_000_000;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-legacy-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("created");
    path
}

fn pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = "-----BEGIN PRIVATE KEY-----\n".to_owned();
    for line in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out
}

/// A legacy ring as the directory key manager wrote it: one key per state given.
fn legacy_ring(directory: &Path, states: &[&str]) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(directory).expect("created");
    let mut keys = Vec::new();
    let mut described = Vec::new();
    for (index, state) in states.iter().enumerate() {
        let pkcs8 = SigningKey::generate_pkcs8(Suite::Ed25519Sha256V1).expect("generated");
        let key = SigningKey::from_pkcs8(Suite::Ed25519Sha256V1, &pkcs8).expect("reads");
        let public = key.public_key().to_vec();
        let kid = thumbprint::jwk_thumbprint(Suite::Ed25519Sha256V1, &public).expect("thumbprint");
        if *state != "archived" {
            std::fs::write(directory.join(format!("{kid}.pem")), pem(&pkcs8)).expect("written");
        }
        let at = 1_759_276_800 + 100 * index as u64;
        let mut entry = serde_json::json!({
            "kid": kid,
            "state": state,
            "algorithm": "EdDSA",
            "public_key": URL_SAFE_NO_PAD.encode(&public),
            "created_at": at,
        });
        if *state != "published" {
            entry["activated_at"] = serde_json::json!(at + 10);
        }
        if matches!(*state, "retired" | "archived") {
            entry["retired_at"] = serde_json::json!(at + 50);
        }
        described.push(entry);
        keys.push((kid, public));
    }
    std::fs::write(
        directory.join(LEGACY_RING),
        serde_json::to_vec_pretty(&serde_json::json!({ "version": 1, "keys": described }))
            .expect("json"),
    )
    .expect("written");
    keys
}

fn ring(volume: &Volume) -> Ring {
    Ring::open(
        volume,
        DATA_ATTEST,
        Suite::Ed25519Sha256V1,
        Policy {
            publish_ahead: Duration::from_secs(600),
            rotate_every: Duration::from_secs(30 * 86_400),
            retain: Duration::from_secs(365 * 86_400),
        },
        Arc::new(TimeGuard::system(Duration::from_secs(30))),
    )
    .expect("the migrated ring opens")
}

#[test]
fn a_legacy_ring_migrates_to_its_journal_keeping_every_key_and_the_old_generation() {
    let root = scratch("migrate");
    let legacy = root.join("operations/keys/data");
    let keys = legacy_ring(&legacy, &["archived", "retired", "active", "published"]);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert!(needs_migration(&volume, DATA_ATTEST, Some(&legacy)).expect("read"));

    let laid = lay_out(
        &volume,
        DATA_ATTEST,
        Some(&legacy),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect("migrated");
    assert_eq!(laid, Laid::Migrated);
    assert!(!needs_migration(&volume, DATA_ATTEST, Some(&legacy)).expect("read"));
    let layout = Layout::open(&volume, &subsystem(DATA_ATTEST)).expect("opens");
    let status = layout.status().expect("status").expect("laid out");
    assert_eq!(status.manifest.active.version, TARGET_VERSION);
    assert_eq!(status.manifest.active.directory, "host/keys/data.attest");
    assert_eq!(status.phase, Phase::Committed);
    assert!(
        legacy.join(LEGACY_RING).exists(),
        "the old generation is kept"
    );

    let ring = ring(&volume);
    let statement = ring.statement().expect("a statement");
    assert_eq!(statement.epoch, 4, "one epoch per key the set ever took");
    let published: Vec<String> = statement.keys.iter().map(|key| key.kid.clone()).collect();
    for (kid, public) in &keys {
        let canonical = thumbprint::kid(DATA_ATTEST, kid);
        assert!(published.contains(&canonical), "{canonical}");
        let jwk = statement
            .keys
            .iter()
            .find(|key| key.kid == canonical)
            .expect("published");
        assert_eq!(URL_SAFE_NO_PAD.decode(&jwk.x).expect("x"), *public);
        assert!(
            super::super::selects(jwk, kid),
            "the legacy kid still selects it"
        );
    }
    assert_eq!(
        ring.active_key_id().expect("active").as_str(),
        thumbprint::kid(DATA_ATTEST, &keys[2].0)
    );
    let signature = ring.sign(b"after").expect("the carried key signs");
    Suite::Ed25519Sha256V1
        .verify(&keys[2].1, b"after", signature.bytes())
        .expect("under the same material");
    let slots = FileKeyProvider::new(
        volume
            .host()
            .subdir("keys", false)
            .and_then(|dir| dir.subdir(DATA_ATTEST, false))
            .and_then(|dir| dir.subdir(PRIVATE, false))
            .expect("private"),
    )
    .slots()
    .expect("listed");
    let mut expected = vec![keys[2].0.clone(), keys[3].0.clone()];
    expected.sort();
    let mut slots = slots;
    slots.sort();
    assert_eq!(
        slots, expected,
        "only the active and the waiting key's private halves"
    );
    let kinds: Vec<Kind> =
        journal_entries(&crate::keys::ring::directory(&volume, DATA_ATTEST).expect("dir"))
            .expect("journal")
            .into_iter()
            .map(|entry| entry.kind)
            .collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == Kind::Destroyed)
            .count(),
        2
    );
    assert_eq!(ring.maintain().expect("maintained").published, 0);

    layout.finalize(NOW + 1).expect("finalized");
    assert!(!legacy.exists(), "finalize removes the legacy directory");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_volume_without_a_legacy_ring_declares_the_ring_at_once() {
    let root = scratch("fresh");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let legacy = root.join("operations/keys/data");
    assert!(!needs_migration(&volume, DATA_ATTEST, Some(&legacy)).expect("read"));
    assert_eq!(
        lay_out(
            &volume,
            DATA_ATTEST,
            Some(&legacy),
            AssuranceProfile::Development,
            None,
            NOW
        )
        .expect("declared"),
        Laid::Fresh
    );
    assert_eq!(
        lay_out(
            &volume,
            DATA_ATTEST,
            Some(&legacy),
            AssuranceProfile::Development,
            None,
            NOW
        )
        .expect("again"),
        Laid::Current
    );
    let manifest = Layout::open(&volume, &subsystem(DATA_ATTEST))
        .expect("opens")
        .manifest()
        .expect("read")
        .expect("declared");
    assert_eq!(manifest.active.version, TARGET_VERSION);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_legacy_ring_that_cannot_migrate_is_refused_before_anything_switches() {
    // Outside the volume.
    let root = scratch("refused");
    let outside = scratch("refused-outside");
    legacy_ring(&outside, &["active"]);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let refused = lay_out(
        &volume,
        DATA_ATTEST,
        Some(&outside),
        AssuranceProfile::Development,
        None,
        NOW,
    )
    .expect_err("outside the volume");
    assert!(
        format!("{refused}").contains("outside the volume"),
        "{refused}"
    );

    // Production declares a backup first: the preflight takes the profile.
    let legacy = root.join("operations/keys/data");
    legacy_ring(&legacy, &["active"]);
    assert!(
        lay_out(
            &volume,
            DATA_ATTEST,
            Some(&legacy),
            AssuranceProfile::Production,
            None,
            NOW
        )
        .is_err()
    );
    assert!(
        needs_migration(&volume, DATA_ATTEST, Some(&legacy)).expect("read"),
        "still to migrate"
    );
    assert_eq!(
        lay_out(
            &volume,
            DATA_ATTEST,
            Some(&legacy),
            AssuranceProfile::Production,
            Some("snapshot-2026-10-08".to_owned()),
            NOW,
        )
        .expect("with a declared backup"),
        Laid::Migrated
    );
    drop(volume);

    // A kid that is not the thumbprint of its key.
    let root = scratch("refused-kid");
    let legacy = root.join("operations/keys/data");
    legacy_ring(&legacy, &["active"]);
    let text = std::fs::read_to_string(legacy.join(LEGACY_RING)).expect("read");
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["keys"][0]["public_key"] = serde_json::json!(URL_SAFE_NO_PAD.encode([7u8; 32]));
    std::fs::write(legacy.join(LEGACY_RING), value.to_string()).expect("written");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    assert!(
        lay_out(
            &volume,
            DATA_ATTEST,
            Some(&legacy),
            AssuranceProfile::Development,
            None,
            NOW
        )
        .is_err()
    );
    assert!(
        !root.join("host/keys/data.attest/journal.cborseq").exists(),
        "nothing switched"
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(outside);
}

#[test]
fn only_a_rings_own_directory_is_a_generation_under_host() {
    use crate::storage::migrate::host_target_admitted;
    assert!(host_target_admitted(
        "keys-data-attest",
        "host/keys/data.attest"
    ));
    assert!(!host_target_admitted(
        "keys-data-attest",
        "host/keys/control.attest"
    ));
    assert!(!host_target_admitted(
        "keys-data-attest",
        "host/keys/data.attest/x"
    ));
    assert!(!host_target_admitted("keys-data-attest", "host/keys/"));
    assert!(!host_target_admitted("notes", "host/keys/notes"));
    assert!(!host_target_admitted("keys-data-attest", "host/layout/x"));
}

#[test]
fn the_declared_layouts_are_the_rings_subsystems() {
    use crate::keys::ring::{CONTROL_ATTEST, HOST_OPERATIONS};
    let names: Vec<&str> = layouts().into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        names,
        vec![
            subsystem(HOST_OPERATIONS),
            subsystem(CONTROL_ATTEST),
            subsystem(DATA_ATTEST)
        ]
    );
}

#[test]
fn a_migration_a_crash_left_between_its_declaration_and_its_intent_is_carried_out() {
    let root = scratch("declared");
    let legacy = root.join("operations/keys/data");
    legacy_ring(&legacy, &["active"]);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    // Version 1 declared where the legacy ring is, and nothing after it.
    Layout::open(&volume, &subsystem(DATA_ATTEST))
        .expect("opens")
        .declare(SOURCE_VERSION, "operations/keys/data", NOW)
        .expect("declared");
    assert!(needs_migration(&volume, DATA_ATTEST, Some(&legacy)).expect("read"));
    assert_eq!(
        lay_out(&volume, DATA_ATTEST, Some(&legacy), AssuranceProfile::Development, None, NOW)
            .expect("migrated"),
        Laid::Migrated
    );
    ring(&volume).active_key_id().expect("the carried key is active");
    let _ = std::fs::remove_dir_all(root);
}
