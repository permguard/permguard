// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The background pass of deep verification over this control plane's objects (WP-1.6).
//!
//! Startup reads no object: serving does not wait on a store of any size. What startup leaves is
//! checked here instead, off every request path: a sample of the objects every few minutes, each
//! inflated and hashed against its name, within a byte budget per pass. Consecutive passes sample
//! different objects, so the whole store is read every [`EVERY`] × `1000 / PER_MILLE`.
//!
//! A finding is logged and counted, never repaired: the file is left byte for byte as it was, for
//! the operator and `volume verify` to look at. A request that reads the object already refuses it
//! ([`crate::store::FileObjectStore::get_object`]).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use permguard_core::metrics::Metric;
use permguard_core::{BoxFuture, PlaneContext, PlaneTask, ready};
use permguard_host::storage::verify::{self, Background, Budget, Mode, Report};
use tracing::{debug, error, warn};

const COMPONENT: &str = "control-plane";

/// How often a sampled pass runs.
pub const EVERY: Duration = Duration::from_secs(10 * 60);

/// The share of objects one pass reads, per thousand: twenty passes read them all.
pub const PER_MILLE: u16 = 50;

/// The bytes one pass may read.
pub const BUDGET_BYTES: u64 = 256 * 1024 * 1024;

/// Objects the background pass found corrupted.
pub const CORRUPTED: Metric = Metric::counter(
    "permguard_store_objects_corrupted",
    "Objects deep verification found not to hold what their names say.",
);

/// The service the plane mounts.
pub struct VerifyService {
    every: Duration,
    running: Mutex<Option<Background>>,
}

impl Default for VerifyService {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyService {
    /// The service, on its ordinary cadence.
    pub fn new() -> Self {
        Self {
            every: EVERY,
            running: Mutex::new(None),
        }
    }
}

/// One sampled pass over the objects below `zones`.
pub fn pass(zones: &Path, mode: Mode, budget: &mut Budget) -> Report {
    let mut report = Report::new();
    if zones.is_dir()
        && let Err(failed) = verify::objects(
            zones,
            &crate::store::object_check,
            mode,
            budget,
            &mut report,
        )
    {
        warn!(
            event.name = "verify.failed",
            component = COMPONENT,
            error = %failed,
            "the objects could not all be walked: this pass is incomplete"
        );
        report.complete = false;
    }

    report
}

impl PlaneTask for VerifyService {
    fn name(&self) -> &'static str {
        "verify"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let zones = context.config().zones_directory();
            let metrics = context.metrics().clone();
            let pass_over = zones.clone();
            let background = Background::spawn(
                self.every,
                PER_MILLE,
                BUDGET_BYTES,
                Arc::new(move |mode, budget: &mut Budget| pass(&pass_over, mode, budget)),
                Arc::new(move |report: &Report| {
                    for finding in &report.findings {
                        error!(
                            event.name = "verify.object_corrupted",
                            component = COMPONENT,
                            path = %finding.path.display(),
                            what = %finding.what,
                            "an object does not hold what its name says; it is left as it is"
                        );
                        metrics.add(&CORRUPTED, &[], 1.0);
                    }
                    debug!(
                        event.name = "verify.pass",
                        component = COMPONENT,
                        files = report.files_checked,
                        bytes = report.bytes_read,
                        complete = report.complete,
                        "a sampled verification pass finished"
                    );
                }),
            )
            .map_err(|failed| anyhow!("starting the verification pass: {failed}"))?;
            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the verification service lock is poisoned"))? =
                Some(background);

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the verification service lock is poisoned"))),
        };

        Box::pin(async move {
            if let Some(background) = running {
                // Waits for a pass under way: blocking, so off the runtime's threads.
                let _ = tokio::task::spawn_blocking(move || background.stop()).await;
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::store::FileObjectStore;
    use permguard_objects::object::Blob;

    fn blob(text: &str) -> Vec<u8> {
        Blob {
            media_type: "application/vnd.permguard.policy.cedar".into(),
            data: text.as_bytes().to_vec(),
        }
        .encode()
        .expect("encoded")
    }

    fn ledger(tag: &str) -> (std::path::PathBuf, FileObjectStore) {
        let zones = std::env::temp_dir().join(format!(
            "permguard-control-verify-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&zones);
        let store = FileObjectStore::new(zones.join("zone-a").join("ledger-1"));
        (zones, store)
    }

    #[test]
    fn the_background_pass_finds_a_corrupted_historical_object_and_leaves_it() {
        let (zones, store) = ledger("background");
        let mut digests = Vec::new();
        for index in 0..20 {
            let object = blob(&format!("permit(principal, action, resource); // {index}"));
            digests.push(store.put_object(&object).expect("stored").0);
        }
        let damaged = digests[7].to_string();
        let hex = &damaged["sha256:".len()..];
        let file = zones
            .join("zone-a/ledger-1/objects")
            .join(&hex[..2])
            .join(&hex[2..]);
        std::fs::write(&file, b"rot").expect("corrupted");

        let reports = Arc::new(Mutex::new(Vec::<Report>::new()));
        let seen = Arc::clone(&reports);
        let over = zones.clone();
        // Every object each pass, quickly: the cadence is the only thing a test shortens.
        let background = Background::spawn(
            Duration::from_millis(10),
            1000,
            BUDGET_BYTES,
            Arc::new(move |mode, budget: &mut Budget| pass(&over, mode, budget)),
            Arc::new(move |report: &Report| seen.lock().expect("lock").push(report.clone())),
        )
        .expect("spawned");
        let started = std::time::Instant::now();
        while reports.lock().expect("lock").is_empty() {
            assert!(started.elapsed() < Duration::from_secs(10), "a pass ran");
            std::thread::sleep(Duration::from_millis(5));
        }
        background.stop();

        let report = reports.lock().expect("lock")[0].clone();
        assert_eq!(report.files_checked, 20, "every object, nothing else");
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].path, file);
        assert_eq!(
            std::fs::read(&file).expect("read"),
            b"rot",
            "never repaired"
        );
    }

    #[test]
    fn volume_verify_reads_the_tree_the_plane_declares() {
        let (zones, store) = ledger("volume");
        let object = blob("permit(principal, action, resource);");
        let digest = store.put_object(&object).expect("stored").0.to_string();
        let hex = &digest["sha256:".len()..];
        let root = zones.join("volume");
        let file = root
            .join("data/zones/zone-a/ledger-1/objects")
            .join(&hex[..2])
            .join(&hex[2..]);
        std::fs::create_dir_all(file.parent().expect("fan")).expect("tree");
        std::fs::write(&file, b"rot").expect("a corrupted copy on the volume");
        let trees: Vec<permguard_server::VerifiedTree> = crate::module().verified_trees();
        let report = verify::volume(&root, None, &trees, Mode::Full, &mut Budget::unbounded())
            .expect("verified");
        assert_eq!(report.files_checked, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, file);
    }

    #[test]
    fn the_check_judges_objects_and_ignores_everything_else() {
        let (zones, store) = ledger("check");
        let object = blob("permit(principal, action, resource);");
        let digest = store.put_object(&object).expect("stored").0.to_string();
        let hex = &digest["sha256:".len()..];
        let relative = Path::new("zone-a/ledger-1/objects")
            .join(&hex[..2])
            .join(&hex[2..]);
        let stored = std::fs::read(zones.join(&relative)).expect("read");
        assert_eq!(crate::store::object_check(&relative, &stored), Some(true));
        assert_eq!(crate::store::object_check(&relative, b"rot"), Some(false));
        assert_eq!(
            crate::store::object_check(Path::new("zone-a/ledger-1/FORMAT"), b"1\n"),
            None,
            "not an object"
        );
    }
}
