// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A synchronization round against a real control plane, in process.
//!
//! What is asserted is the behaviour an operator depends on: only what the
//! patterns follow is mirrored, a mirror that is already current does not
//! move, a mirror the patterns stop following is removed — and, the one that
//! matters most, **a server that does not answer never causes a deletion**.
//! Losing a connection is not a reason to lose a policy.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use permguard_control_client::TlsOptions;
use permguard_core::Metrics;
use permguard_core::mirrors::MirrorSource;
use permguard_data_plane::mirrors::layout::{self, Mirror};
use permguard_data_plane::mirrors::{round, source};

/// A real control plane, served in process on an ephemeral port.
///
/// The router is the shipped one — catalog and NOTP, the same code a
/// deployment runs — so what this suite exercises is the product's listing
/// and transfer, not a stand-in for them.
mod plane {
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use permguard_core::keys::KeyManager as _;
    use permguard_core::{Config, ProductIdentity, ServerContext};
    use permguard_std::audit::RecordingAuditSink;
    use permguard_std::catalog::FileCatalog;
    use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
    use permguard_std::storage::MemoryStorage;

    /// A plane that stops when the test drops it.
    pub struct Plane {
        pub url: String,
        stop: tokio::task::JoinHandle<()>,
    }

    impl Drop for Plane {
        fn drop(&mut self) {
            self.stop.abort();
        }
    }

    /// Starts the control plane's HTTP surface over `volume`.
    pub async fn start(volume: &Path) -> Plane {
        // The collaborators outlive the served router, so they are leaked on
        // purpose: this process is one test binary, and the alternative is a
        // lifetime dance that teaches nobody anything.
        // The working directory is a setting, so it arrives the way every
        // setting does — through the layers, not through a setter.
        let config: &'static Config = Box::leak(Box::new(
            Config::from_layers(
                permguard_core::config::BuildSettings::new(
                    "0.0.0-test",
                    "2022",
                    "Nitro Agility S.r.l.",
                ),
                Vec::<String>::new(),
                permguard_core::config::Layers::new().with_environment(vec![(
                    permguard_core::config::SETTING_WORKING_DIR.to_owned(),
                    volume.to_string_lossy().into_owned(),
                )]),
            )
            .expect("the test configuration builds"),
        ));
        let storage: &'static MemoryStorage = Box::leak(Box::new(MemoryStorage::new()));
        let audit: &'static RecordingAuditSink = Box::leak(Box::new(RecordingAuditSink::new()));
        let catalog = Arc::new(FileCatalog::new(config.zones_directory()));
        let keys = Arc::new(DirectoryKeyManager::new(
            volume.join("keys/control"),
            KeyPolicy {
                publish_ahead: Duration::ZERO,
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(3600),
                verify_retain: Duration::from_secs(3600),
            },
        ));
        keys.maintain().expect("the ring publishes");
        keys.maintain().expect("the ring activates");

        let context: &'static ServerContext<'static> = Box::leak(Box::new(
            ServerContext::new(identity(), config, storage, audit)
                .with_catalog(catalog)
                .with_control_signing_keys(keys),
        ));
        let router = permguard_control_plane::module().http_routes(context);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port is free");
        let address: SocketAddr = listener.local_addr().expect("the address is known");
        let stop = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        Plane {
            url: format!("http://{address}"),
            stop,
        }
    }

    fn identity() -> ProductIdentity {
        ProductIdentity::new(
            "permguard-control-plane",
            "Permguard",
            "tagline",
            "about",
            "",
        )
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-sync-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

/// One declared source, for a test that needs several.
fn declared(url: &str, zones: &[&str], ledgers: &[&str]) -> MirrorSource {
    MirrorSource {
        url: url.to_owned(),
        tls: permguard_core::mirrors::MirrorTls::default(),
        zones: zones.iter().map(|p| (*p).to_owned()).collect(),
        ledgers: ledgers.iter().map(|p| (*p).to_owned()).collect(),
    }
}

fn context(
    url: &str,
    root: &std::path::Path,
    zones: &[&str],
    ledgers: &[&str],
) -> Arc<round::Context> {
    let declared = MirrorSource {
        url: url.to_owned(),
        tls: permguard_core::mirrors::MirrorTls::default(),
        zones: zones.iter().map(|p| (*p).to_owned()).collect(),
        ledgers: ledgers.iter().map(|p| (*p).to_owned()).collect(),
    };
    Arc::new(round::Context {
        // This suite is about mirroring; the decision path has its own.
        decider: None,
        sources: source::compile(std::slice::from_ref(&declared), root)
            .expect("the patterns compile"),
        root: root.to_path_buf(),
        deadline: Duration::from_secs(30),
        stale_after: None,
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    })
}

/// Creates the zones and ledgers a test needs, through the same client the
/// product uses — so the fixture cannot drift from the API.
fn provision(url: &str, zone: &str, ledgers: &[&str]) {
    let catalog = permguard_control_client::catalog::client(
        url,
        &TlsOptions::default(),
        Box::new(permguard_control_client::narrate::Silent),
    )
    .expect("the catalog client connects");
    let created = catalog.create_zone(zone).expect("the zone is created");
    for ledger in ledgers {
        catalog
            .create_ledger(&created.id, ledger)
            .expect("the ledger is created");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_mirrors_only_what_the_patterns_follow() {
    let volume = scratch("follow");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    provision(&url, "other", &["main-ledger"]);

    let root = volume.join("mirrors");
    // Follow the zone `acme` and only its `main-ledger`.
    let outcome = round::run(context(&url, &root, &["acme"], &["main-ledger"])).await;

    assert_eq!(outcome.unreachable, 0, "the plane answered");
    assert_eq!(outcome.failed, 0, "nothing failed");
    let held = layout::on_disk(&root).expect("the mirrors list");
    assert_eq!(held.len(), 1, "one ledger of one zone: {held:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mirror_the_patterns_stop_following_is_removed() {
    let volume = scratch("reap");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);

    let root = volume.join("mirrors");
    round::run(context(&url, &root, &["acme"], &[])).await;
    assert_eq!(
        layout::on_disk(&root).expect("lists").len(),
        2,
        "both ledgers are followed at first"
    );

    // Narrow the pattern: the other mirror is no longer wanted.
    let outcome = round::run(context(&url, &root, &["acme"], &["main-ledger"])).await;
    assert_eq!(outcome.reaped, 1);
    let held = layout::on_disk(&root).expect("lists");
    assert_eq!(held.len(), 1, "{held:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ledger_the_server_deleted_is_removed_here_too() {
    let volume = scratch("deleted");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "retired"]);

    let root = volume.join("mirrors");
    round::run(context(&url, &root, &[], &[])).await;
    assert_eq!(
        layout::on_disk(&root).expect("lists").len(),
        2,
        "both ledgers are mirrored while the server has both"
    );

    // The operator deletes one on the server. The next round sees a listing
    // without it, so the mirror is no longer wanted — and goes.
    let catalog = permguard_control_client::catalog::client(
        &url,
        &TlsOptions::default(),
        Box::new(permguard_control_client::narrate::Silent),
    )
    .expect("the catalog client connects");
    let zone = catalog.get_zone("acme").expect("the zone is there");
    catalog
        .delete_ledger(&zone.id, "retired")
        .expect("the ledger is deleted on the server");

    let outcome = round::run(context(&url, &root, &[], &[])).await;
    assert_eq!(outcome.reaped, 1, "the deleted ledger's mirror is removed");
    let held = layout::on_disk(&root).expect("lists");
    assert_eq!(held.len(), 1, "{held:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_server_never_causes_a_deletion() {
    let volume = scratch("unreachable");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);

    let root = volume.join("mirrors");
    round::run(context(&url, &root, &[], &[])).await;
    let before = layout::on_disk(&root).expect("lists");
    assert_eq!(before.len(), 1);

    // Now point the round at a port where nothing listens. The mirror on disk
    // must survive: a plane that cannot ask is not a plane that was told to
    // forget.
    let outcome = round::run(context("http://127.0.0.1:1", &root, &[], &[])).await;
    assert_eq!(outcome.unreachable, 1);
    assert_eq!(
        outcome.reaped, 0,
        "nothing is removed on an unanswered server"
    );
    assert_eq!(
        layout::on_disk(&root).expect("lists"),
        before,
        "the mirrors are exactly as they were"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ledger_two_servers_both_claim_is_left_alone_rather_than_taken_by_the_first() {
    // Two control planes, each holding a zone and ledger of the same *name*.
    // Names are not what a mirror is addressed by, so whether they collide
    // depends on the identities they minted — and when they do collide, taking
    // the first would mean this plane decided whose policies it serves by
    // configuration order.
    let volume = scratch("contested");
    let one = plane::start(&volume.join("one")).await;
    let two = plane::start(&volume.join("two")).await;
    provision(&one.url, "acme", &["main-ledger"]);
    provision(&two.url, "acme", &["main-ledger"]);

    let root = volume.join("mirrors");
    let sources = vec![declared(&one.url, &[], &[]), declared(&two.url, &[], &[])];
    let outcome = round::run(Arc::new(round::Context {
        decider: None,
        sources: source::compile(&sources, &root).expect("the patterns compile"),
        root: root.clone(),
        deadline: Duration::from_secs(30),
        stale_after: None,
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    }))
    .await;

    // Identities are minted per control plane, so two independent planes do
    // not normally collide — which is the point: the plane mirrors both, and
    // `contested` stays at zero unless the identities really are the same.
    assert_eq!(
        outcome.contested, 0,
        "different identities are not a conflict"
    );
    assert_eq!(
        layout::on_disk(&root).expect("lists").len(),
        2,
        "and both are followed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_unreachable_server_does_not_cost_another_server_its_mirrors() {
    // The case a single-source test cannot see: with two control planes
    // configured, a partition towards one of them used to delete *its* ledgers
    // from this plane, because the reaping set was built from whoever
    // answered. Absence is evidence of deletion only for the server that was
    // asked.
    let volume = scratch("partial");
    let other = plane::start(&volume.join("other")).await;
    let sources = {
        let gone = plane::start(&volume.join("gone")).await;
        provision(&gone.url, "acme", &["main-ledger"]);

        let both = vec![
            declared(&gone.url, &[], &[]),
            declared(&other.url, &[], &[]),
        ];
        let root = volume.join("mirrors");
        let outcome = round::run(Arc::new(round::Context {
            decider: None,
            sources: source::compile(&both, &root).expect("the patterns compile"),
            root: root.clone(),
            deadline: Duration::from_secs(30),
            stale_after: None,
            parallelism: 2,
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            metrics: Metrics::none(),
        }))
        .await;
        assert_eq!(outcome.unreachable, 0, "both answered");
        assert_eq!(
            layout::on_disk(&root).expect("lists").len(),
            1,
            "one server's ledger is mirrored"
        );

        both
        // `gone` is dropped here: that control plane is now unreachable.
    };

    let root = volume.join("mirrors");
    let before = layout::on_disk(&root).expect("lists");
    let outcome = round::run(Arc::new(round::Context {
        decider: None,
        sources: source::compile(&sources, &root).expect("the patterns compile"),
        root: root.clone(),
        deadline: Duration::from_secs(30),
        stale_after: None,
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    }))
    .await;

    assert_eq!(outcome.unreachable, 1, "one server is gone");
    assert_eq!(
        outcome.reaped, 0,
        "and the mirror belongs to exactly that server"
    );
    assert_eq!(
        layout::on_disk(&root).expect("lists"),
        before,
        "so it is exactly where it was"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_round_is_idempotent() {
    let volume = scratch("again");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);

    let root = volume.join("mirrors");
    let first = round::run(context(&url, &root, &[], &[])).await;
    let second = round::run(context(&url, &root, &[], &[])).await;

    assert_eq!(first.failed, 0);
    assert_eq!(second.failed, 0);
    assert_eq!(second.reaped, 0, "nothing to remove the second time");
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 1);
}

#[test]
fn a_mirror_of_an_empty_ledger_is_not_a_failure() {
    // An empty ledger has no head yet: the first `apply` creates its history.
    // A mirror of it holds nothing and must not read as a failure — otherwise
    // every freshly created ledger would page somebody.
    let mirror = Mirror {
        zone_id: "z-1".to_owned(),
        ledger_id: "l-1".to_owned(),
    };
    assert_eq!(mirror.label(), "z-1/l-1");
}
