// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The composition of a Host with no server in the build (the crate boundaries refactoring,
//! RD-15): it opens the Host on its volume and runs the server host it was handed, on the caller's
//! runtime, and what reaches outside the process is refused by name until an adapter is composed.
//!
//! | What is composed                                  | What the start does                        |
//! | ------------------------------------------------- | ------------------------------------------ |
//! | a shutdown signal, a server host that binds none  | opens the Host, runs the host once, stops  |
//! | no shutdown signal and no process signal          | refuses before it touches the volume       |
//! | an Authority Plane named elsewhere, no client     | refuses: no token could ever be verified   |
//!
//! The server's own suites prove the same start with a server's adapters composed.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use permguard_core::planes::settings::SETTING_AUTHORITY_URL;
use permguard_core::{BoxFuture, BuildSettings, ProductIdentity, ServerContext, ServerHost};
use permguard_runtime::Composition;
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;

/// A server host that binds nothing: it counts its runs and returns when it is asked to stop.
struct Headless(Arc<AtomicUsize>);

impl ServerHost for Headless {
    fn name(&self) -> &'static str {
        "headless"
    }

    fn run<'a>(
        &'a self,
        _context: &'a ServerContext<'a>,
        shutdown: BoxFuture<'a, ()>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            shutdown.await;
            Ok(())
        })
    }
}

fn composition(runs: &Arc<AtomicUsize>) -> Composition {
    Composition::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Box::new(Headless(Arc::clone(runs))),
        Box::new(MemoryStorage::new()),
        Box::new(RecordingAuditSink::new()),
    )
}

/// A configuration file and the volume it names, each the test's own.
fn fixture(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "permguard-runtime-test-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the fixture directory");
    let volume = dir.join("volume");
    let file = dir.join("config.yml");
    std::fs::write(
        &file,
        format!(
            "assurance:\n  profile: development\nworking_dir: {}\npublic:\n  http: 127.0.0.1:0\n",
            volume.to_str().expect("a UTF-8 path")
        ),
    )
    .expect("the configuration file");
    (file, volume)
}

async fn start(composition: &Composition, file: &Path, inputs: &[(&str, &str)]) -> Result<()> {
    let config = composition.config_from(
        Some(file),
        inputs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    )?;
    let mut out = Vec::new();
    composition.serve(&config, file, &mut out).await
}

#[tokio::test]
async fn test_a_headless_host_opens_on_its_volume_and_runs_the_host_it_was_handed() {
    let runs = Arc::new(AtomicUsize::new(0));
    let composition = composition(&runs).with_shutdown_signal(|| Box::pin(std::future::ready(())));
    let (file, volume) = fixture("opens");

    start(&composition, &file, &[])
        .await
        .expect("the Host starts and stops");

    assert_eq!(runs.load(Ordering::SeqCst), 1, "the server host ran once");
    // The Host was opened on the volume: it is claimed, and holds the identity the start
    // provisioned under `development`.
    let claimed = permguard_host::storage::volume::Volume::claim(
        &volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume is released once the start returns");
    assert!(
        permguard_host::identity::witness_of(&claimed)
            .expect("the identity is read")
            .is_some(),
        "the start provisioned no identity"
    );
}

#[tokio::test]
async fn test_a_start_nothing_can_stop_is_refused_before_the_volume_is_touched() {
    let runs = Arc::new(AtomicUsize::new(0));
    let composition = composition(&runs);
    let (file, volume) = fixture("unstoppable");

    let refused = start(&composition, &file, &[])
        .await
        .expect_err("no shutdown signal and no process signal");

    assert!(
        format!("{refused:#}").contains("no way to be stopped"),
        "{refused:#}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0, "the server host never ran");
    assert!(!volume.exists(), "the volume was created");
}

#[tokio::test]
async fn test_an_authority_plane_named_elsewhere_is_refused_without_a_client_to_fetch_its_keys() {
    let runs = Arc::new(AtomicUsize::new(0));
    let composition = composition(&runs)
        .with_declared_settings([SETTING_AUTHORITY_URL])
        .with_shutdown_signal(|| Box::pin(std::future::ready(())));
    let (file, _) = fixture("authority");

    let refused = start(
        &composition,
        &file,
        &[(SETTING_AUTHORITY_URL, "https://authority.example")],
    )
    .await
    .expect_err("no adapter fetches the key set");

    assert!(
        format!("{refused:#}").contains("no client to fetch its key set and status lists"),
        "{refused:#}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0, "the server host never ran");
}

/// A configuration that grants a write without a credential is refused before anything binds
/// under `production`, naming the entry (BUG-0318), and an administrative operation under any
/// profile (BUG-0202); under `development` the write stands and is published as relaxed.
#[test]
fn test_a_public_write_is_refused_from_production_and_published_under_development() {
    let runs = Arc::new(AtomicUsize::new(0));
    let composition = composition(&runs);
    let (file, volume) = fixture("public-grants");
    let grants = |profile: &str, operations: &str| {
        std::fs::write(
            &file,
            format!(
                "assurance:\n  profile: {profile}\nworking_dir: {}\npublic:\n  http: 127.0.0.1:0\n\
                 host:\n  authz:\n    public:\n      - operations: [catalog.read]\n        \
                 selector: plane/control/*\n      - operations: [{operations}]\n        \
                 selector: plane/control/*\n",
                volume.to_str().expect("a UTF-8 path")
            ),
        )
        .expect("the configuration file");
        composition.config_from(Some(&file), Vec::<(String, String)>::new())
    };

    let refused = grants("production", "catalog.write, policy.push")
        .expect_err("production refuses a public write")
        .to_string();
    assert!(
        refused.contains("host.authz.public[1]") && refused.contains("catalog.write"),
        "{refused}"
    );
    for profile in ["development", "production", "regulated"] {
        let refused = grants(profile, "keys.admin")
            .expect_err("an administrative operation is never public")
            .to_string();
        assert!(refused.contains("never public"), "{profile}: {refused}");
    }

    let development = grants("development", "catalog.write, policy.push")
        .expect("development permits a public write");
    let relaxed = development.relaxations_in_force();
    for relaxation in [
        permguard_core::assurance::Relaxation::AuthzPublic,
        permguard_core::assurance::Relaxation::AuthzPublicWrite,
    ] {
        assert!(relaxed.contains(&relaxation), "{relaxation}: {relaxed:?}");
    }
    assert_eq!(runs.load(Ordering::SeqCst), 0, "nothing ran");
}
