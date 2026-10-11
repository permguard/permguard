// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `audit verify --directory <volume> [--keys <bundle>]` over the Host's trails (WP-3.7): the
//! verifier every server binary registers, driven through the command line of an app.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use permguard_core::assurance::AssuranceProfile;
use permguard_core::{AuditEvent, BuildSettings, KeyManager as _, ProductIdentity, Subject};
use permguard_host::audit::{Engine, Stamp, config_revision};
use permguard_host::identity::Suite;
use permguard_host::keys::ring::{self, HOST_OPERATIONS, Policy, Ring};
use permguard_host::storage::volume::Volume;
use permguard_host::time::{ManualClock, ManualMonotonic, TimeGuard};
use permguard_server::{App, Cli, DefaultServerHost};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;

const START: i64 = 1_800_000_000;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-audit-verify-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn operations(volume: &Volume, time: Arc<TimeGuard>) -> Arc<Ring> {
    let ring = Arc::new(
        Ring::open(
            volume,
            HOST_OPERATIONS,
            Suite::Ed25519Sha256V1,
            Policy {
                publish_ahead: Duration::from_secs(600),
                rotate_every: Duration::from_secs(3650 * 86_400),
                retain: Duration::from_secs(3650 * 86_400),
            },
            time,
        )
        .expect("the ring opens"),
    );
    ring.maintain().expect("the first key");
    ring
}

/// A volume whose `security` and `operations` trails hold two days, the first sealed under the
/// volume's `host.operations` key; answers the root and that key's export, written beside it.
fn sealed_volume(tag: &str) -> (PathBuf, PathBuf) {
    let root = scratch(tag);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let wall = Arc::new(ManualClock::at(START));
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        Arc::new(ManualMonotonic::default()),
        Duration::from_secs(30),
    ));
    let stamp = Stamp {
        host_id: [1; 16],
        boot_id: [2; 16],
        build: "9.9.9".to_owned(),
        config_revision: config_revision([("PERMGUARD_TEST", Some("on"))]),
    };
    let engine = Engine::open(&volume, stamp, Arc::clone(&time), None).expect("the engine opens");
    engine.seal_with(operations(&volume, time));
    let both = |engine: &Engine| {
        engine
            .append(
                &AuditEvent::new("zone.created", Subject::System("catalog")).on("z1"),
                None,
            )
            .expect("a security record");
        engine
            .append(
                &AuditEvent::new("server.start", Subject::System("host")),
                None,
            )
            .expect("an operations record");
    };
    both(&engine);
    wall.jump(86_400);
    both(&engine);
    engine.close();
    let ring_dir = ring::directory(&volume, HOST_OPERATIONS).expect("the ring directory");
    let keys = root.with_extension("keys.json");
    std::fs::write(&keys, ring::export(ring_dir.path()).expect("exported")).expect("written");
    (root, keys)
}

fn app() -> App {
    App::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Box::new(DefaultServerHost::new()),
        Box::new(MemoryStorage::new()),
        Box::new(RecordingAuditSink::new()),
    )
    .with_audit_verifier(permguard_server::checkpoints::verify)
}

async fn verify(directory: &Path, keys: Option<&Path>) -> anyhow::Result<String> {
    verify_from(directory, keys, None).await
}

async fn verify_from(
    directory: &Path,
    keys: Option<&Path>,
    checkpoint: Option<&Path>,
) -> anyhow::Result<String> {
    let mut argv = vec![
        "demo-x".to_owned(),
        "audit".to_owned(),
        "verify".to_owned(),
        "--directory".to_owned(),
        directory.display().to_string(),
    ];
    if let Some(keys) = keys {
        argv.extend(["--keys".to_owned(), keys.display().to_string()]);
    }
    if let Some(checkpoint) = checkpoint {
        argv.extend(["--checkpoint".to_owned(), checkpoint.display().to_string()]);
    }
    let action = Cli::try_parse_from(argv)
        .expect("the command parses")
        .action()
        .expect("an action");
    let mut out = Vec::new();
    app().dispatch_to(&action, &mut out).await?;
    Ok(String::from_utf8(out).expect("text"))
}

#[tokio::test]
async fn verify_with_independent_keys_reports_every_trail() {
    let (root, keys) = sealed_volume("independent");
    let report = verify(&root, Some(&keys)).await.expect("the trails verify");
    assert!(report.contains("keys: independent"), "{report}");
    assert!(report.contains("security:plane/control ok"), "{report}");
    assert!(report.contains("operations:host ok"), "{report}");
    assert!(report.contains("2 trails verified, 0 failed"), "{report}");

    // Without `--keys`, the volume's own keys, and the report says so; the trails directory
    // itself is accepted as well as the volume.
    let report = verify(&root.join("host/audit/trails"), None)
        .await
        .expect("the trails verify");
    assert!(report.contains("not independent"), "{report}");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_file(&keys);
}

#[tokio::test]
async fn a_checkpoint_signed_by_another_key_fails_with_independent_keys() {
    let (root, keys) = sealed_volume("another-key");
    // The keys of another Host's `host.operations`, kept apart: no checkpoint of this volume is
    // signed by them.
    let (other, other_keys) = sealed_volume("another-key-other");
    let refused = verify(&root, Some(&other_keys))
        .await
        .expect_err("signed by a key outside the set");
    let message = format!("{refused:#}");
    assert!(message.contains("FAILED"), "{message}");
    assert!(message.contains("a key the set lacks"), "{message}");
    assert!(message.contains("2 trails verified, 2 failed"), "{message}");
    for path in [&root, &other] {
        let _ = std::fs::remove_dir_all(path);
    }
    for path in [&keys, &other_keys] {
        let _ = std::fs::remove_file(path);
    }
}

/// The seal of the first day of the `security` trail, as a verifier copies it off the volume.
fn held_seal(root: &Path) -> PathBuf {
    let trail = root
        .join("host/audit/trails/security")
        .join(permguard_host::audit::trail::resource_digest(
            "plane/control",
        ))
        .join("checkpoints");
    let seal = std::fs::read_dir(&trail)
        .expect("the checkpoints")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "cose"))
        .expect("a seal");
    let held = root.with_extension("held.cose");
    std::fs::copy(seal, &held).expect("copied");
    held
}

#[tokio::test]
async fn a_checkpoint_held_outside_the_volume_verifies_its_trail_and_finds_a_rewrite() {
    let (root, keys) = sealed_volume("held");
    let held = held_seal(&root);
    let report = verify_from(&root, Some(&keys), Some(&held))
        .await
        .expect("the trails verify");
    assert!(
        report.contains("verified from the checkpoint held"),
        "{report}"
    );
    // The whole volume is replaced by another history sealed under its own key: the held
    // checkpoint is not in it.
    let (other, other_keys) = sealed_volume("held-other");
    let refused = verify_from(&other, Some(&other_keys), Some(&held))
        .await
        .expect_err("the held checkpoint is not in that history");
    let message = format!("{refused:#}");
    assert!(message.contains("from the checkpoint held"), "{message}");
    assert!(message.contains("rewritten"), "{message}");
    for path in [&root, &other] {
        let _ = std::fs::remove_dir_all(path);
    }
    for path in [&keys, &other_keys, &held] {
        let _ = std::fs::remove_file(path);
    }
}

#[tokio::test]
async fn a_directory_holding_no_trail_is_refused() {
    let (root, keys) = sealed_volume("empty");
    let empty = scratch("empty-directory");
    std::fs::create_dir_all(&empty).expect("created");
    let refused = verify(&empty, Some(&keys))
        .await
        .expect_err("nothing to verify is not a success");
    assert!(
        format!("{refused:#}").contains("holds no audit trail"),
        "{refused:#}"
    );
    for path in [&root, &empty] {
        let _ = std::fs::remove_dir_all(path);
    }
    let _ = std::fs::remove_file(&keys);
}
