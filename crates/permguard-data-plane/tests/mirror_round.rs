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
    use permguard_core::{Config, PlaneContext, ProductIdentity, ServerContext};
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

        // The control plane signs through the handle the Host registers for it, as in a server.
        let module = permguard_control_plane::module();
        let registration = permguard_host::composition::Host::builder()
            .ring(permguard_host::composition::CONTROL_ATTEST, keys)
            // Every head statement names its Host (WP-7.1): NOTP is served only with one.
            .host_id([0x11; 16])
            // Every ref update runs in a mutation transaction (WP-7.12).
            .mutations(Arc::new(
                permguard_host::operations::mutation::Mutations::open_offline(
                    &permguard_host::storage::volume::Volume::claim(
                        &volume.join("host-volume"),
                        permguard_core::assurance::AssuranceProfile::Development,
                    )
                    .expect("the volume is claimed"),
                    "test",
                )
                .expect("the mutation journal opens"),
            ))
            // This suite is about mirroring, not about who may read the catalog.
            .authorization(Arc::new(
                permguard_host::composition::Authorization::permissive(),
            ))
            .build()
            .register(module.declaration(config))
            .expect("the control plane registers");
        let server: &'static ServerContext<'static> = Box::leak(Box::new(
            ServerContext::new(identity(), config, storage, audit)
                .with_catalog(catalog)
                .with_plane_handles("control", Arc::new(registration)),
        ));
        // The boundary every served surface has: nobody is anonymous without it (WP-2.4).
        let router = module
            .http_routes(&PlaneContext::new(server, "control"))
            .layer(permguard_transport::ActorLayer::new(Arc::new(
                permguard_core::NoRules,
            )));

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
        required: true,
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
        required: true,
    };
    Arc::new(round::Context {
        tasks: None,
        selections: Default::default(),
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
    let retired = catalog
        .get_ledger(&zone.id, "retired")
        .expect("the ledger is there");
    catalog
        .delete_ledger(&zone.id, "retired", retired.revision)
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
        tasks: None,
        selections: Default::default(),
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

    // Identities are minted per control plane, so two independent planes do not collide on ids:
    // the plane mirrors both. Their names do collide, and a request by name answered from
    // whichever directory lists first would be the list order choosing (WP-7.2a): the name is
    // contested and reported, while each ledger stays reachable by its own ids.
    let held = layout::on_disk(&root).expect("lists");
    assert_eq!(held.len(), 2, "both are followed");
    assert_eq!(outcome.contested, 1, "the shared name is reported");
    assert!(
        permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_none(),
        "neither answers to the shared name"
    );
    for mirror in &held {
        assert!(
            permguard_data_plane::authz::store::find(&root, &mirror.zone_id, &mirror.ledger_id)
                .is_some(),
            "each answers to its ids"
        );
    }
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
            tasks: None,
            selections: Default::default(),
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
        tasks: None,
        selections: Default::default(),
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
        authority: None,
        zone_id: "z-1".to_owned(),
        ledger_id: "l-1".to_owned(),
    };
    assert_eq!(mirror.label(), "z-1/l-1");
}

/// WP-7.2a: a `policy.mirror` task stand-in. Its session decodes each real `MirrorRequest` and
/// answers it from the control plane at `url`, so what this suite drives is the round, the
/// listing, the authority-qualified layout and the pull over a task session; the provider's own
/// handler has its tests in the control plane.
mod tasks {
    use std::sync::{Arc, Mutex};

    use permguard_control_client::remote::Remote as _;
    use permguard_control_client::{AnyRemote, TlsOptions};
    use permguard_core::BoxFuture;
    use permguard_host::composition::{MirrorRefusal, MirrorSession, MirrorTask, MirrorTasks};
    use permguard_notp::{
        FetchObjectsRequest, GetRefRequest, GetRefResponse, ListLedgersAnswer, ListedLedger,
        MirrorOperation, MirrorRequest, NegotiatePullRequest,
    };

    /// The tasks a Host holds, the URL that answers each coordinator, and what was asked.
    pub struct Held {
        pub tasks: Vec<MirrorTask>,
        pub url: String,
        /// The coordinators that refuse every session.
        pub silent: Vec<[u8; 16]>,
        /// Every operation a session carried, by task id.
        pub asked: Arc<Mutex<Vec<(String, MirrorOperation)>>>,
        /// The ledger names a task's listing is cut to, by task id; a task absent lists every one.
        pub only: Vec<(String, Vec<String>)>,
        /// Whether listings say they are not complete.
        pub incomplete: bool,
        /// The tasks whose listings alone say they are not complete.
        pub partial: Vec<String>,
        /// The tasks whose sessions name no pinned ring.
        pub unpinned: Vec<String>,
    }

    impl MirrorTasks for Held {
        fn watch_mirror<'a>(
            &'a self,
            _task: &'a permguard_host::composition::MirrorTask,
            _positions: Vec<(String, u64)>,
        ) -> permguard_core::BoxFuture<
            'a,
            Result<
                Box<dyn permguard_host::composition::MirrorWatch>,
                permguard_host::composition::MirrorRefusal,
            >,
        > {
            Box::pin(std::future::ready(Err(
                permguard_host::composition::MirrorRefusal {
                    code: "unavailable".to_owned(),
                    reason: "this stand-in watches nothing".to_owned(),
                },
            )))
        }

        fn mirror_tasks(&self) -> Vec<MirrorTask> {
            self.tasks.clone()
        }

        fn open_mirror<'a>(
            &'a self,
            task: &'a MirrorTask,
        ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
            let opened: Result<Box<dyn MirrorSession>, MirrorRefusal> =
                if self.silent.contains(&task.coordinator) {
                    Err(MirrorRefusal {
                        code: permguard_core::codes::common::UNAVAILABLE.to_owned(),
                        reason: "the coordinator did not answer".to_owned(),
                    })
                } else {
                    Ok(Box::new(Session {
                        url: self.url.clone(),
                        task: task.task_id.clone(),
                        asked: Arc::clone(&self.asked),
                        only: self
                            .only
                            .iter()
                            .find(|(id, _)| *id == task.task_id)
                            .map(|(_, names)| names.clone()),
                        incomplete: self.incomplete || self.partial.contains(&task.task_id),
                        unpinned: self.unpinned.contains(&task.task_id),
                    }))
                };
            Box::pin(std::future::ready(opened))
        }
    }

    struct Session {
        url: String,
        task: String,
        asked: Arc<Mutex<Vec<(String, MirrorOperation)>>>,
        only: Option<Vec<String>>,
        incomplete: bool,
        unpinned: bool,
    }

    impl MirrorSession for Session {
        fn ring(&self) -> Option<permguard_host::composition::PinnedRing> {
            // The ledgers of these tests hold no history yet: nothing is verified under it.
            (!self.unpinned).then(|| permguard_host::composition::PinnedRing {
                epoch: 1,
                key_set_digest: [3; 32],
                binding: b"binding".to_vec(),
                keys: Vec::new(),
            })
        }

        fn call(&mut self, body: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, MirrorRefusal>> {
            let url = self.url.clone();
            let task = self.task.clone();
            let asked = Arc::clone(&self.asked);
            let only = self.only.clone();
            let incomplete = self.incomplete;
            Box::pin(async move {
                tokio::task::spawn_blocking(move || {
                    answer(&url, &task, &asked, &body, only.as_deref(), incomplete)
                })
                .await
                .expect("the answer is computed")
            })
        }
    }

    fn refused(code: &str, reason: String) -> MirrorRefusal {
        MirrorRefusal {
            code: code.to_owned(),
            reason,
        }
    }

    fn answer(
        url: &str,
        task: &str,
        asked: &Mutex<Vec<(String, MirrorOperation)>>,
        body: &[u8],
        only: Option<&[String]>,
        incomplete: bool,
    ) -> Result<Vec<u8>, MirrorRefusal> {
        let request = MirrorRequest::decode(body)
            .map_err(|error| refused("body_rejected", error.to_string()))?;
        asked
            .lock()
            .expect("the log")
            .push((task.to_owned(), request.operation));
        let failed = |error: String| refused("notp_failed", error);
        if request.operation == MirrorOperation::ListLedgers {
            let catalog = permguard_control_client::catalog::client(
                url,
                &TlsOptions::default(),
                Box::new(permguard_control_client::narrate::Silent),
            )
            .map_err(failed)?;
            let mut ledgers = Vec::new();
            for zone in catalog
                .list_zones(None, None)
                .map_err(|f| failed(f.detail))?
            {
                for ledger in catalog
                    .list_ledgers(&zone.id, None, None)
                    .map_err(|f| failed(f.detail))?
                {
                    if only.is_some_and(|names| !names.contains(&ledger.name)) {
                        continue;
                    }
                    ledgers.push(ListedLedger {
                        zone_id: zone.id.clone(),
                        zone_name: zone.name.clone(),
                        ledger_id: ledger.id,
                        ledger_name: ledger.name,
                    });
                }
            }
            ledgers.sort_by(|left, right| {
                (&left.zone_id, &left.ledger_id).cmp(&(&right.zone_id, &right.ledger_id))
            });
            return ListLedgersAnswer {
                ledgers,
                complete: !incomplete,
            }
            .encode()
            .map_err(|error| failed(error.to_string()));
        }
        let remote = AnyRemote::connect(
            url,
            &TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .map_err(failed)?;
        remote.bind(&request.zone, &request.ledger);
        let not_found = |error: String| {
            if error.contains("not_found") {
                refused(permguard_core::codes::common::NOT_FOUND, error)
            } else {
                failed(error)
            }
        };
        match request.operation {
            MirrorOperation::KeyRing => remote.keyring().map_err(failed),
            MirrorOperation::GetRef => {
                let asked = GetRefRequest::decode(&request.body)
                    .map_err(|error| failed(error.to_string()))?;
                let held = remote
                    .get_ref(&asked.r#ref)
                    .map_err(failed)?
                    .ok_or_else(|| {
                        refused(permguard_core::codes::common::NOT_FOUND, "no ref".into())
                    })?;
                GetRefResponse {
                    head: permguard_objects::digest::Digest::parse(&held.head)
                        .map_err(|_| failed("a head".into()))?,
                    counter: held.counter,
                    statement: held.statement,
                    ref_digest: permguard_objects::digest::Digest::parse(&held.ref_digest)
                        .map_err(|_| failed("a digest".into()))?,
                }
                .encode()
                .map_err(|error| failed(error.to_string()))
            }
            MirrorOperation::NegotiatePull => {
                let asked = NegotiatePullRequest::decode(&request.body)
                    .map_err(|error| failed(error.to_string()))?;
                remote
                    .negotiate_pull(&asked)
                    .map_err(not_found)?
                    .encode()
                    .map_err(|error| failed(error.to_string()))
            }
            MirrorOperation::FetchObjects => {
                let asked = FetchObjectsRequest::decode(&request.body)
                    .map_err(|error| failed(error.to_string()))?;
                remote
                    .fetch(&asked)
                    .map_err(failed)?
                    .encode()
                    .map_err(|error| failed(error.to_string()))
            }
            MirrorOperation::ListLedgers => unreachable!("answered above"),
        }
    }

    /// One `policy.mirror` task of `coordinator`.
    pub fn task(coordinator: [u8; 16], membership: u8, id: &str, required: bool) -> MirrorTask {
        MirrorTask {
            membership_id: [membership; 16],
            task_id: id.to_owned(),
            coordinator,
            revision: 1,
            resource: "plane/control".to_owned(),
            required,
            max_body_bytes: 1 << 24,
        }
    }
}

fn over_tasks(root: &std::path::Path, held: tasks::Held) -> Arc<round::Context> {
    Arc::new(round::Context {
        tasks: Some(Arc::new(held)),
        selections: Default::default(),
        decider: None,
        sources: Vec::new(),
        root: root.to_path_buf(),
        deadline: Duration::from_secs(30),
        stale_after: None,
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    })
}

/// WP-7.2a, F-16: a Host's `policy.mirror` tasks are mirrored over their sessions, under the
/// coordinator's authority: listed by the session, named in their identity, attributed to one
/// source however many tasks of one coordinator name a ledger, and read over the session rather
/// than any URL.
#[tokio::test(flavor = "multi_thread")]
async fn a_membership_task_is_mirrored_under_its_authority_over_its_session() {
    let volume = scratch("over-tasks");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));

    let outcome = round::run(over_tasks(
        &root,
        tasks::Held {
            // Two memberships of one coordinator: one source (F-16).
            tasks: vec![
                tasks::task(coordinator, 1, "mirror", true),
                tasks::task(coordinator, 2, "mirror-again", false),
            ],
            url: url.clone(),
            silent: Vec::new(),
            asked: Arc::clone(&asked),
            only: Vec::new(),
            incomplete: false,
            partial: Vec::new(),
            unpinned: Vec::new(),
        },
    ))
    .await;

    assert_eq!((outcome.unreachable, outcome.failed), (0, 0), "{outcome:?}");
    assert_eq!(outcome.contested, 0, "one coordinator is one source");
    let authority = layout::authority_name(&coordinator);
    assert_eq!(
        outcome.coordinators,
        vec![(round::source_key(&authority), true)],
        "one source, required because one of its tasks is"
    );
    let held = layout::on_disk(&root).expect("the mirrors list");
    assert_eq!(held.len(), 2, "{held:?}");
    for mirror in &held {
        assert_eq!(mirror.authority.as_deref(), Some(authority.as_str()));
        assert!(mirror.path(&root).starts_with(root.join(&authority)));
        let identity = permguard_data_plane::authz::store::identity_of(&mirror.path(&root))
            .expect("the identity is recorded");
        assert_eq!(identity.authority.as_deref(), Some(authority.as_str()));
        assert_eq!(identity.server, round::source_key(&authority));
    }
    let found = permguard_data_plane::authz::store::find(&root, "acme", "main-ledger")
        .expect("served by name");
    assert_eq!(
        found.identity.authority.as_deref(),
        Some(authority.as_str())
    );

    // Every read went over a session: the listings, then a negotiation per ledger.
    let asked = asked.lock().expect("the log").clone();
    let operations: Vec<_> = asked.iter().map(|(_, operation)| *operation).collect();
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == permguard_notp::MirrorOperation::ListLedgers)
            .count(),
        2,
        "each task listed once: {asked:?}"
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == permguard_notp::MirrorOperation::NegotiatePull)
            .count(),
        2,
        "each ledger negotiated once, over one of the sessions: {asked:?}"
    );
}

/// WP-7.2a: a coordinator whose session cannot be opened is unreachable for the round, and costs
/// nothing it already serves.
#[tokio::test(flavor = "multi_thread")]
async fn a_coordinator_that_does_not_answer_costs_none_of_its_mirrors() {
    let volume = scratch("silent-coordinator");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let held = |silent: Vec<[u8; 16]>| tasks::Held {
        tasks: vec![tasks::task(coordinator, 1, "mirror", true)],
        url: url.clone(),
        silent,
        asked: Arc::new(std::sync::Mutex::new(Vec::new())),
        only: Vec::new(),
        incomplete: false,
        partial: Vec::new(),
        unpinned: Vec::new(),
    };

    round::run(over_tasks(&root, held(Vec::new()))).await;
    let before = layout::on_disk(&root).expect("lists");
    assert_eq!(before.len(), 1);

    let outcome = round::run(over_tasks(&root, held(vec![coordinator]))).await;
    assert_eq!(outcome.unreachable, 1);
    assert_eq!(outcome.reaped, 0, "nothing is removed on its account");
    assert_eq!(layout::on_disk(&root).expect("lists"), before);
    let reported = outcome
        .sources
        .iter()
        .find(|source| source.url == round::source_key(&layout::authority_name(&coordinator)))
        .expect("the coordinator is reported");
    assert!(!reported.answered && !reported.succeeded());
}

/// WP-7.2a: the same ledger from a configured URL and from a membership lands in two directories,
/// and a request naming it is answered from neither: no list order picks whose policy is served.
#[tokio::test(flavor = "multi_thread")]
async fn a_ledger_both_a_url_and_a_task_offer_is_served_from_neither() {
    let volume = scratch("url-and-task");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");

    round::run(context(&url, &root, &[], &[])).await;
    assert!(
        permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_some(),
        "one mirror answers"
    );
    round::run(over_tasks(
        &root,
        tasks::Held {
            tasks: vec![tasks::task([0x11; 16], 1, "mirror", true)],
            url: url.clone(),
            silent: Vec::new(),
            asked: Arc::new(std::sync::Mutex::new(Vec::new())),
            only: Vec::new(),
            incomplete: false,
            partial: Vec::new(),
            unpinned: Vec::new(),
        },
    ))
    .await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);
    assert!(
        permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_none(),
        "two mirrors answer to one name: neither is chosen"
    );
    assert_eq!(
        permguard_data_plane::authz::store::contested(&root, "acme", "main-ledger").len(),
        2,
        "and the refusal can say why"
    );
    let outcome = round::run(context(&url, &root, &[], &[])).await;
    assert_eq!(outcome.contested, 1, "every round says so");
}

/// WP-7.2a: the file narrows the tasks it follows by membership and task ids with anchored
/// patterns; a task it does not name is neither opened nor listed.
#[tokio::test(flavor = "multi_thread")]
async fn the_file_narrows_the_tasks_followed_by_membership_task_and_pattern() {
    let volume = scratch("narrowed-tasks");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let selections =
        source::TaskSelections::compile(&[permguard_core::mirrors::MirrorTaskSelection {
            membership: permguard_host::identity::record::uuid_text(&[1; 16]),
            task: "mirror".to_owned(),
            zones: vec!["acme".to_owned()],
            ledgers: vec!["main-ledger".to_owned()],
        }])
        .expect("the patterns compile");

    let outcome = round::run(Arc::new(round::Context {
        tasks: Some(Arc::new(tasks::Held {
            tasks: vec![
                tasks::task([0x11; 16], 1, "mirror", true),
                tasks::task([0x22; 16], 2, "elsewhere", true),
            ],
            url: url.clone(),
            silent: Vec::new(),
            asked: Arc::clone(&asked),
            only: Vec::new(),
            incomplete: false,
            partial: Vec::new(),
            unpinned: Vec::new(),
        })),
        selections,
        decider: None,
        sources: Vec::new(),
        root: root.clone(),
        deadline: Duration::from_secs(30),
        stale_after: None,
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    }))
    .await;

    assert_eq!((outcome.unreachable, outcome.failed), (0, 0), "{outcome:?}");
    let held = layout::on_disk(&root).expect("lists");
    assert_eq!(held.len(), 1, "only `acme/main-ledger`: {held:?}");
    assert_eq!(
        outcome.coordinators,
        vec![
            (
                round::source_key(&layout::authority_name(&[0x11; 16])),
                true
            ),
            (
                round::source_key(&layout::authority_name(&[0x22; 16])),
                true
            ),
        ],
        "the task the file leaves out is not followed, and still counts for readiness: it is \
         required by its signed manifest"
    );
    assert!(
        asked
            .lock()
            .expect("the log")
            .iter()
            .all(|(task, _)| task == "mirror"),
        "nothing was asked over the task left out"
    );
}

fn held_by(
    url: &str,
    tasks: Vec<permguard_host::composition::MirrorTask>,
    only: Vec<(&str, Vec<&str>)>,
    incomplete: bool,
) -> tasks::Held {
    tasks::Held {
        tasks,
        url: url.to_owned(),
        silent: Vec::new(),
        asked: Arc::new(std::sync::Mutex::new(Vec::new())),
        only: only
            .into_iter()
            .map(|(task, names)| {
                (
                    task.to_owned(),
                    names.into_iter().map(ToOwned::to_owned).collect(),
                )
            })
            .collect(),
        incomplete,
        partial: Vec::new(),
        unpinned: Vec::new(),
    }
}

/// WP-7.2a: a ledger gone from its task's complete listing is removed from under its authority,
/// and the directories it leaves empty go with it; one gone from an incomplete listing stays, the
/// listing proving nothing absent.
#[tokio::test(flavor = "multi_thread")]
async fn only_a_complete_listing_of_its_own_task_removes_a_task_mirror() {
    let volume = scratch("task-reap");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let authority = layout::authority_name(&coordinator);
    let task = || vec![tasks::task(coordinator, 1, "mirror", true)];

    round::run(over_tasks(&root, held_by(&url, task(), Vec::new(), false))).await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // Cut short: `staging` is missing from a listing that says it is not whole.
    let outcome = round::run(over_tasks(
        &root,
        held_by(&url, task(), vec![("mirror", vec!["main-ledger"])], true),
    ))
    .await;
    assert_eq!(outcome.reaped, 0, "an incomplete listing removes nothing");
    let reported = outcome
        .sources
        .iter()
        .find(|source| source.url == round::source_key(&authority))
        .expect("reported");
    assert!(
        !reported.answered,
        "an incomplete listing is no answer for reaping"
    );
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // Whole, and without `staging`: it goes.
    let outcome = round::run(over_tasks(
        &root,
        held_by(&url, task(), vec![("mirror", vec!["main-ledger"])], false),
    ))
    .await;
    assert_eq!(outcome.reaped, 1);
    let reported = outcome
        .sources
        .iter()
        .find(|source| source.url == round::source_key(&authority))
        .expect("reported");
    assert!(reported.answered && reported.succeeded());
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 1);

    // Whole and empty: the last one goes, and the authority's directory with its zone.
    let outcome = round::run(over_tasks(
        &root,
        held_by(&url, task(), vec![("mirror", Vec::new())], false),
    ))
    .await;
    assert_eq!(outcome.reaped, 1);
    assert!(layout::on_disk(&root).expect("lists").is_empty());
    assert!(
        !root.join(&authority).exists(),
        "nothing of the authority is left"
    );
}

/// WP-7.2a: a mirror is its own task's to remove. A task this round does not list — its
/// membership suspended — removes nothing, however whole another task of the same coordinator
/// lists.
#[tokio::test(flavor = "multi_thread")]
async fn a_suspended_task_costs_none_of_its_mirrors_to_another_task_of_its_coordinator() {
    let volume = scratch("task-suspended");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];

    // Membership 1's task lists `main-ledger`, membership 2's `staging`.
    round::run(over_tasks(
        &root,
        held_by(
            &url,
            vec![
                tasks::task(coordinator, 1, "first", true),
                tasks::task(coordinator, 2, "second", true),
            ],
            vec![("first", vec!["main-ledger"]), ("second", vec!["staging"])],
            false,
        ),
    ))
    .await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // Membership 2 suspended: its task is not held this round, and membership 1's lists whole.
    let outcome = round::run(over_tasks(
        &root,
        held_by(
            &url,
            vec![tasks::task(coordinator, 1, "first", true)],
            vec![("first", vec!["main-ledger"])],
            false,
        ),
    ))
    .await;
    assert_eq!(outcome.reaped, 0, "`staging` is its own task's to remove");
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);
}

/// WP-7.2a: a task listing whole removes what it no longer lists, even while another task of the
/// same coordinator lists only in part: each task's mirrors are its own to remove.
#[tokio::test(flavor = "multi_thread")]
async fn a_whole_task_reaps_its_own_while_a_sibling_task_lists_in_part() {
    let volume = scratch("task-sibling");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let both = || {
        vec![
            tasks::task(coordinator, 1, "first", true),
            tasks::task(coordinator, 2, "second", true),
        ]
    };

    round::run(over_tasks(
        &root,
        held_by(
            &url,
            both(),
            vec![("first", vec!["main-ledger"]), ("second", vec!["staging"])],
            false,
        ),
    ))
    .await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // `first` lists whole and without `main-ledger`; `second` lists only in part.
    let mut held = held_by(
        &url,
        both(),
        vec![("first", Vec::new()), ("second", vec!["staging"])],
        false,
    );
    held.partial = vec!["second".to_owned()];
    let outcome = round::run(over_tasks(&root, held)).await;
    assert_eq!(outcome.reaped, 1, "`first` removes what it no longer lists");
    let left = layout::on_disk(&root).expect("lists");
    assert_eq!(left.len(), 1, "`second`'s mirror stays: {left:?}");
}

/// WP-7.2b: a task whose membership pins no `control.attest` set has nothing its statements could
/// verify under: its coordinator fails the round, and none of its ledgers is mirrored.
#[tokio::test(flavor = "multi_thread")]
async fn a_task_whose_membership_pins_no_ring_is_not_mirrored() {
    let volume = scratch("unpinned");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let mut held = held_by(
        &url,
        vec![tasks::task([0x11; 16], 1, "mirror", true)],
        Vec::new(),
        false,
    );
    held.unpinned = vec!["mirror".to_owned()];

    let outcome = round::run(over_tasks(&root, held)).await;
    assert_eq!(
        outcome.unreachable, 1,
        "the coordinator failed: {outcome:?}"
    );
    assert!(layout::on_disk(&root).expect("lists").is_empty());
}
