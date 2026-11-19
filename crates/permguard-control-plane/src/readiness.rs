// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the Control Plane verifies before it reports ready (BUG-0255), and keeps verifying.
//!
//! | Requirement      | Satisfied when                                                                  |
//! | ---------------- | ------------------------------------------------------------------------------- |
//! | `ledgers`        | every ledger of the catalog has this build's `FORMAT`, or holds nothing yet,    |
//! |                  | and every ref of it parses and names a head the store holds                     |
//! | `control.attest` | the head-statement signer has an active key, when the git-like store is served  |
//!
//! Checked when the plane's services start, before the Host settles it, so a plane holding an
//! incompatible or damaged ledger, or a signing ring with no active key, stays in Load with the
//! reason instead of answering ready and failing the first request that touches it. Checked again
//! every [`EVERY`]: a repair promotes the plane without a restart, and a ledger damaged after the
//! plane serves is reported as degraded on that requirement, the phases never going back. A
//! catalog that cannot be listed is a failed check too. Reads only: nothing is written, no pin
//! included.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use permguard_core::catalog::{Catalog, Selector};
use permguard_core::{BoxFuture, PlaneContext, PlaneHealth, PlaneTask, ready};
use tokio::task::JoinHandle;

use crate::store::FileObjectStore;

/// How often the requirements are checked again.
pub const EVERY: Duration = Duration::from_secs(60);

/// The requirement on the catalog's ledgers.
pub const LEDGERS: &str = "ledgers";

/// The requirement on the head-statement signer's active key.
pub const ATTEST: &str = "control.attest";

/// The most damaged ledgers a reason names; the rest are counted.
const NAMED: usize = 5;

/// Why the catalog's ledgers do not all verify, or `Ok` with how many did.
pub fn ledgers(catalog: &dyn Catalog, zones_root: &Path) -> Result<usize, String> {
    let zones = catalog
        .list_zones()
        .map_err(|error| format!("the catalog could not be listed: {error}"))?;
    let mut verified = 0;
    let mut failed = Vec::new();
    for zone in &zones {
        let ledgers = match catalog.list_ledgers(&Selector::Id(zone.id.clone())) {
            Ok(ledgers) => ledgers,
            Err(error) => {
                failed.push(format!(
                    "zone {}: its ledgers could not be listed: {error}",
                    zone.id
                ));
                continue;
            }
        };
        for ledger in &ledgers {
            let directory = zones_root.join(&zone.id).join("ledgers").join(&ledger.id);
            match FileObjectStore::new(directory).verify_at_load() {
                Ok(_) => verified += 1,
                Err(error) => failed.push(format!("ledger {}/{}: {error}", zone.id, ledger.id)),
            }
        }
    }
    if failed.is_empty() {
        return Ok(verified);
    }
    let more = failed.len().saturating_sub(NAMED);
    Err(format!(
        "{} ledger(s) do not verify: {}{}",
        failed.len(),
        failed
            .iter()
            .take(NAMED)
            .cloned()
            .collect::<Vec<_>>()
            .join("; "),
        if more > 0 {
            format!("; and {more} more")
        } else {
            String::new()
        }
    ))
}

/// What one check needs, taken from the plane's context when its services start.
struct Checks {
    health: PlaneHealth,
    catalog: Option<Arc<dyn Catalog>>,
    zones_root: PathBuf,
    signer:
        Option<permguard_host::composition::Signer<permguard_host::composition::HeadStatementV1>>,
    /// The last reason the ledgers were said not to verify.
    said: Mutex<Option<String>>,
}

impl Checks {
    /// Checks every requirement once and reports it to the plane's lifecycle.
    fn run(&self) {
        let now = SystemTime::now();
        if let Some(catalog) = &self.catalog {
            match ledgers(catalog.as_ref(), &self.zones_root) {
                Ok(_) => {
                    *self
                        .said
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                    self.health.satisfy(LEDGERS);
                }
                Err(reason) => {
                    // Said once per reason, not once a minute.
                    let mut said = self
                        .said
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if said.as_deref() != Some(reason.as_str()) {
                        *said = Some(reason.clone());
                        tracing::warn!(
                            event.name = "control.ledgers_unverified",
                            component = "control-plane",
                            reason = %reason,
                            "a ledger of the catalog does not verify: the plane is not ready on it"
                        );
                    }
                    drop(said);
                    self.health.wait(LEDGERS, reason, now);
                }
            }
        }
        if let Some(signer) = &self.signer {
            match signer.ready() {
                Ok(()) => self.health.satisfy(ATTEST),
                Err(error) => self.health.wait(
                    ATTEST,
                    format!("the head statements cannot be signed: {error}"),
                    now,
                ),
            }
        }
    }
}

/// The service the plane mounts.
#[derive(Default)]
pub struct ReadinessService {
    running: Mutex<Option<JoinHandle<()>>>,
}

impl ReadinessService {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PlaneTask for ReadinessService {
    fn name(&self) -> &'static str {
        "readiness"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let catalog = context.catalog().cloned();
            // The ring is a requirement where the git-like store is served: a catalog to resolve
            // ledgers and a signer to attest heads.
            let signer = catalog
                .as_ref()
                .and_then(|_| crate::handles::head_signer(context));
            let checks = Arc::new(Checks {
                health: context.health(),
                catalog,
                zones_root: context.config().zones_directory(),
                signer,
                said: Mutex::new(None),
            });
            // Before the Host settles the plane: what does not verify keeps it in Load.
            let first = Arc::clone(&checks);
            tokio::task::spawn_blocking(move || first.run()).await?;
            let looping = Arc::clone(&checks);
            let handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(EVERY);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let checks = Arc::clone(&looping);
                    if tokio::task::spawn_blocking(move || checks.run())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            *self
                .running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        if let Some(handle) = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            handle.abort();
        }
        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::lifecycle::{Kind, Phase};

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "permguard-cp-readiness-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// A catalog with one zone and one ledger, and that ledger's directory.
    fn catalog(root: &Path) -> (Arc<dyn Catalog>, PathBuf) {
        let catalog = permguard_std::catalog::FileCatalog::new(root.join("zones"));
        let zone = catalog.create_zone("delivery").expect("a zone");
        let ledger = catalog
            .create_ledger(&Selector::Id(zone.id.clone()), "policies")
            .expect("a ledger");
        let directory = root
            .join("zones")
            .join(&zone.id)
            .join("ledgers")
            .join(&ledger.id);
        (Arc::new(catalog), directory)
    }

    /// A `control.attest` ring under `root`, with an active key or none.
    fn signer(
        root: &Path,
        active: bool,
    ) -> permguard_host::composition::Signer<permguard_host::composition::HeadStatementV1> {
        use permguard_core::keys::KeyManager as _;

        let keys = Arc::new(permguard_std::keys::DirectoryKeyManager::new(
            root.join("keys"),
            permguard_std::keys::KeyPolicy {
                publish_ahead: Duration::ZERO,
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(3600),
                verify_retain: Duration::from_secs(3600),
            },
        ));
        if active {
            keys.maintain().expect("an active key");
        }
        crate::handles::head_signer_for_tests(keys)
    }

    /// A Control Plane in Load, and its checks.
    fn plane(
        catalog: Option<Arc<dyn Catalog>>,
        zones_root: PathBuf,
        signer: Option<
            permguard_host::composition::Signer<permguard_host::composition::HeadStatementV1>,
        >,
    ) -> (permguard_core::Health, Checks) {
        let health = permguard_core::Health::default();
        health
            .lifecycle()
            .enter("control", Kind::Plane, true, Phase::Load);
        let checks = Checks {
            health: PlaneHealth::new(health.clone(), "control"),
            catalog,
            zones_root,
            signer,
            said: Mutex::new(None),
        };
        (health, checks)
    }

    /// BUG-0255: every ledger of the catalog verifies before the plane is ready: an empty one, or
    /// one pinned to this build's `FORMAT` whose refs parse and name heads the store holds.
    /// Another `FORMAT`, an unpinned store with content, or a ref that does not read names the
    /// ledger.
    #[test]
    fn a_ledger_that_does_not_verify_is_named() {
        let root = scratch("ledgers");
        let (catalog, directory) = catalog(&root);
        let zones = root.join("zones");
        assert_eq!(ledgers(catalog.as_ref(), &zones), Ok(1), "an empty ledger");

        std::fs::create_dir_all(&directory).expect("the directory");
        std::fs::write(directory.join("FORMAT"), "1\n").expect("pinned");
        assert_eq!(
            ledgers(catalog.as_ref(), &zones),
            Ok(1),
            "a pinned, empty ledger"
        );

        let ledger = directory
            .file_name()
            .and_then(|name| name.to_str())
            .expect("its id")
            .to_owned();
        std::fs::write(directory.join("FORMAT"), "9\n").expect("another format");
        let why = ledgers(catalog.as_ref(), &zones).expect_err("another format");
        assert!(why.contains(&ledger), "{why}");

        std::fs::remove_file(directory.join("FORMAT")).expect("unpinned");
        std::fs::create_dir_all(directory.join("objects")).expect("content");
        let why = ledgers(catalog.as_ref(), &zones).expect_err("unpinned with content");
        assert!(
            why.contains(&ledger) && why.contains("unversioned"),
            "{why}"
        );

        std::fs::write(directory.join("FORMAT"), "1\n").expect("pinned");
        std::fs::create_dir_all(directory.join("refs")).expect("refs");
        std::fs::write(directory.join("refs").join("main"), "not a ref").expect("a broken ref");
        let why = ledgers(catalog.as_ref(), &zones).expect_err("a ref that does not read");
        assert!(why.contains(&ledger), "{why}");
    }

    /// BUG-0255: a plane holding a ledger that does not verify stays in Load with the reason, not
    /// ready; repaired, the next check promotes it, with no restart.
    #[test]
    fn a_plane_is_ready_only_once_its_ledgers_verify() {
        let root = scratch("promote");
        let (catalog, directory) = catalog(&root);
        std::fs::create_dir_all(&directory).expect("the directory");
        std::fs::write(directory.join("FORMAT"), "9\n").expect("another format");
        let (health, checks) = plane(Some(catalog), root.join("zones"), None);

        checks.run();
        health.lifecycle().settle("control");
        assert_eq!(health.lifecycle().phase("control"), Some(Phase::Load));
        let reason = health
            .lifecycle()
            .component("control")
            .and_then(|component| component.reason)
            .unwrap_or_default();
        assert!(reason.contains("do not verify"), "{reason}");

        std::fs::write(directory.join("FORMAT"), "1\n").expect("repaired");
        checks.run();
        assert_eq!(health.lifecycle().phase("control"), Some(Phase::Ready));
    }

    /// BUG-0255: where the git-like store is served the plane needs an active `control.attest`
    /// key: without one it stays in Load naming it; with one it is ready.
    #[test]
    fn the_head_signer_needs_an_active_key() {
        for (active, expected) in [(false, Phase::Load), (true, Phase::Ready)] {
            let root = scratch(&format!("attest-{active}"));
            let (catalog, _) = catalog(&root);
            let (health, checks) = plane(
                Some(catalog),
                root.join("zones"),
                Some(signer(&root, active)),
            );
            checks.run();
            health.lifecycle().settle("control");
            assert_eq!(
                health.lifecycle().phase("control"),
                Some(expected),
                "{active}"
            );
            if !active {
                let reason = health
                    .lifecycle()
                    .component("control")
                    .and_then(|component| component.reason)
                    .unwrap_or_default();
                assert!(reason.contains("cannot be signed"), "{reason}");
            }
        }
    }
}
