// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A catalog change interrupted at every step is applied once or not at all, and its retry is
//! answered.
//!
//! The test binary runs itself as the child: an ignored test runs a script of catalog changes
//! through the catalog's facade, a zone created, a ledger created, renamed and deleted, the zone
//! renamed, on the directory the parent names, and aborts at the crash point and pass the parent
//! chose (`PERMGUARD_CRASH_AT`, `PERMGUARD_CRASH_HIT`): every phase of the mutation transaction
//! a change runs in, and every step of the writes of the catalog's records. The parent resolves
//! what the crash left open, as a starting Control Plane does, then runs the same script with
//! the same request ids, as a client that retries does, and requires every step answered, the
//! catalog as the script leaves it with each change applied once, and no operation left open.
//!
//! One answer is a refusal, and the test holds it to exactly that: a deletion that landed and
//! whose answer the crash lost is answered `not_found` at its retry, because the record that
//! would answer it is the one it deleted. The ledger is then required deleted once, by that
//! attempt. Built with the `crash-points` feature only.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use permguard_control_plane::catalog::{self, CatalogFacade, ledgers, zones};
use permguard_control_plane::refusal::Refusal;
use permguard_core::authz::{Actor, ActorContext, Credential, Principal};
use permguard_core::catalog::{Catalog, Selector};
use permguard_core::{Disclosure, Zone, codes};
use permguard_host::composition::{Authorization, MutationHandle};
use permguard_host::operations::mutation::Mutations;
use permguard_std::catalog::FileCatalog;

const CHILD_DIRECTORY: &str = "PERMGUARD_CATALOG_CRASH_DIRECTORY";

/// The crash points a catalog change passes through: the transaction's phases and the atomic
/// writes of the records.
const POINTS: &[&str] = &[
    "mutation.intent_written",
    "mutation.intent_audited",
    "mutation.applied",
    "mutation.committed",
    "mutation.applied_audited",
    "mutation.projected",
    "view.temp_written",
    "view.temp_flushed",
    "view.renamed",
    "view.parent_flushed",
    "journal.frame_written",
    "journal.frame_flushed",
];

/// The passes tried at each point: the script is five changes, each a pass of a phase and
/// several of a write.
const HITS: u64 = 8;

fn actor() -> Actor {
    Actor::Authenticated(ActorContext::new(
        Principal::new("spiffe://acme/operator").expect("a principal"),
        Credential::Certificate,
        None,
    ))
}

/// The catalog of a Control Plane on `root` and the transaction its changes run in.
struct Plane {
    facade: CatalogFacade,
    engine: Arc<Mutations>,
}

impl Plane {
    /// Opens the plane as a start does: the changes a crash left open are resolved against the
    /// catalog before it takes one.
    fn open(root: &Path) -> Self {
        let volume = permguard_host::storage::volume::Volume::claim(
            &root.join("volume"),
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("the volume is claimed");
        let engine = Arc::new(Mutations::open_offline(&volume, "crash").expect("it opens"));
        std::mem::forget(volume);
        let catalog: Arc<dyn Catalog> = Arc::new(FileCatalog::new(root.join("zones")));
        let mutations = catalog::recovered(
            MutationHandle::new(Arc::clone(&engine), catalog::CATALOG_DOMAIN),
            &catalog,
        )
        .expect("the changes a crash left open are resolved");
        Self {
            facade: CatalogFacade {
                catalog,
                recorder: None,
                disclosure: Disclosure::Full,
                audit_refusals: false,
                metrics: permguard_core::metrics::Metrics::none(),
                authorization: Arc::new(Authorization::permissive()),
                host: None,
                mutations: Some(mutations),
                exports: None,
            },
            engine,
        }
    }

    /// The script, each change under a request id of its own: the zone as it ends, the id of
    /// the ledger it deleted, and whether the deletion was answered with the ledger. A `retry`
    /// accepts `not_found` for it: the first attempt's deletion landed and its answer was lost.
    async fn script(&self, retry: bool) -> Result<(Zone, String, bool), String> {
        let (facade, actor) = (&self.facade, actor());
        let said = |step: &str, refused: Refusal| format!("{step}: {refused:?}");
        let zone = zones::create(facade, &actor, "delivery", "request-1")
            .await
            .map_err(|refused| said("the zone's creation", refused))?;
        let ledger = ledgers::create(facade, &actor, &zone.id, "policies", "request-2")
            .await
            .map_err(|refused| said("the ledger's creation", refused))?;
        let renamed = ledgers::rename(
            facade,
            &actor,
            &zone.id,
            &ledger.id,
            "rules",
            ledger.revision,
            "request-3",
        )
        .await
        .map_err(|refused| said("the ledger's rename", refused))?;
        let answered = match ledgers::delete(
            facade,
            &actor,
            &zone.id,
            &ledger.id,
            renamed.revision,
            "request-4",
        )
        .await
        {
            Ok(deleted) => {
                if (deleted.id.as_str(), deleted.name.as_str()) != (ledger.id.as_str(), "rules") {
                    return Err(format!("the deletion answered {deleted:?}"));
                }
                true
            }
            Err(Refusal::Api(error)) if retry && error.code() == codes::common::NOT_FOUND => false,
            Err(refused) => return Err(said("the ledger's deletion", refused)),
        };
        let zone = zones::rename(
            facade,
            &actor,
            &zone.id,
            "delivery-eu",
            zone.revision,
            "request-5",
        )
        .await
        .map_err(|refused| said("the zone's rename", refused))?;
        Ok((zone, ledger.id, answered))
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

/// The child: runs the script until the crash point the parent chose aborts it.
#[test]
#[ignore = "the crash test's child, run by `a_catalog_change_interrupted_at_every_step_recovers`"]
fn child_changes_the_catalog_until_it_crashes() {
    let Ok(root) = std::env::var(CHILD_DIRECTORY) else {
        return;
    };
    let plane = Plane::open(Path::new(&root));
    let _ = runtime().block_on(plane.script(false));
}

fn crash(root: &Path, point: &str, hit: u64) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("the test binary is known"))
        .args([
            "--ignored",
            "--exact",
            "child_changes_the_catalog_until_it_crashes",
            "--nocapture",
        ])
        .env(CHILD_DIRECTORY, root)
        .env(permguard_host::storage::crash::CRASH_AT, point)
        .env(permguard_host::storage::crash::CRASH_HIT, hit.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the child runs")
}

#[cfg(unix)]
fn aborted(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal() == Some(6)
}

#[cfg(not(unix))]
fn aborted(status: std::process::ExitStatus) -> bool {
    matches!(status.code(), Some(3) | Some(-1_073_740_791))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pg-catalog-crash-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory");
    dir
}

#[test]
fn a_catalog_change_interrupted_at_every_step_recovers() {
    let (mut crashed, mut answered, mut lost) = (0, 0, 0);
    for point in POINTS {
        for hit in 1..=HITS {
            let root = scratch(&format!("{}-{hit}", point.replace('.', "-")));
            let status = crash(&root, point, hit);
            if !aborted(status) {
                // The script passes the point fewer times than `hit`: it finished whole.
                assert!(
                    status.success(),
                    "{point} pass {hit}: the child failed otherwise"
                );
                let _ = std::fs::remove_dir_all(&root);
                continue;
            }
            crashed += 1;

            // What a starting Control Plane does: resolve the changes the crash left open.
            let plane = Plane::open(&root);
            assert!(
                plane.engine.open_intents().is_empty(),
                "{point} pass {hit}: an operation is left open"
            );

            // The client retries the script with the same request ids: every step is answered.
            let (zone, deleted, with_the_ledger) = runtime()
                .block_on(plane.script(true))
                .unwrap_or_else(|refused| {
                    panic!("{point} pass {hit}: the retry was refused: {refused}")
                });
            assert_eq!(
                (zone.name.as_str(), zone.revision),
                ("delivery-eu", 2),
                "{point} pass {hit}: the zone was renamed once"
            );
            if with_the_ledger {
                answered += 1;
            } else {
                lost += 1;
            }
            let catalog = &plane.facade.catalog;
            let zones = catalog.list_zones().expect("the zones read");
            assert_eq!(zones.len(), 1, "{point} pass {hit}: one zone");
            assert_eq!(
                (zones[0].id.as_str(), zones[0].revision),
                (zone.id.as_str(), 2)
            );
            assert!(
                catalog
                    .list_ledgers(&Selector::Id(zone.id.clone()))
                    .expect("the ledgers read")
                    .is_empty(),
                "{point} pass {hit}: the ledger was deleted"
            );
            let tombstone = catalog
                .ledger_tombstone(&zone.id, &deleted)
                .expect("the tombstone reads")
                .unwrap_or_else(|| panic!("{point} pass {hit}: the deleted ledger left none"));
            assert_eq!(
                (tombstone.name.as_str(), tombstone.revision),
                ("rules", 2),
                "{point} pass {hit}: the ledger was renamed once before it was deleted"
            );
            assert!(
                tombstone.operation.is_some(),
                "{point} pass {hit}: the deletion ran in an operation"
            );
            assert!(
                plane.engine.open_intents().is_empty(),
                "{point} pass {hit}: the retry left an operation open"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }
    assert!(
        crashed >= POINTS.len() * 3,
        "only {crashed} rounds crashed: the points are not on the script's path"
    );
    // The lost answer is the window of one change among five, never the rule.
    assert!(
        answered > lost,
        "the deletion was answered {answered} times and refused {lost}"
    );
}
