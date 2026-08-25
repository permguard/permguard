// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Re-reading transport material without dropping a connection.
//!
//! A certificate is renewed on a schedule nobody controls from inside this process. The alternatives
//! to noticing are a restart every ninety days, or — far more often, because nobody wants the
//! restart — a certificate that quietly expires on a Sunday.
//!
//! Two things can ask for a re-read, and both end up here:
//!
//! * a **watcher** per surface, comparing modification times at the configured interval;
//! * **SIGHUP**, which is what an operator and every certificate-renewal hook already know to send.
//!
//! # Nothing breaks on a bad reload
//!
//! The new material is built into a complete `ServerConfig` *before* anything is swapped. If it does
//! not build — half-written file, mismatched pair, revoked list that will not parse — the live
//! configuration is untouched and the surface keeps serving with what it had. A reload that failed
//! is a warning, never an outage.
//!
//! # Why the watcher reads the bytes, not the clock
//!
//! What is compared between ticks is a digest of each file's contents. Modification times would be
//! cheaper, and wrong twice: a filesystem with one-second granularity can absorb a rewrite into the
//! same stamp, and a `cp` that preserves times changes the material without changing the time. The
//! files are a few kilobytes read every thirty seconds — the digest costs nothing and answers the
//! actual question, which is whether the *material* changed.
//!
//! Certificate and key are two files, written one after the other. A watcher that reloaded the
//! instant it saw the first change would regularly read a new certificate beside an old key. So a
//! change is noticed, allowed to settle, and only then acted on — and the state is recorded whether
//! the reload succeeded or not, so a genuinely broken file warns once instead of every tick.
//!
//! # A registry, and why it is process-wide
//!
//! SIGHUP is a process-wide event with no argument, so the thing it acts on is every surface in the
//! process. The registry holds weak references: a surface that has stopped is dropped from it the
//! next time anything walks it, so nothing here keeps a listener alive.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;
use tracing::{debug, info, warn};

use permguard_core::{Metrics, TlsSettings};

/// The `component` every record of a reload carries.
const COMPONENT: &str = "transport";

/// How long a change is allowed to settle before it is acted on.
const SETTLE: Duration = Duration::from_secs(1);

/// One live surface, in the form a reload needs it.
pub struct Reloadable {
    address: SocketAddr,
    settings: TlsSettings,
    config: RustlsConfig,
    seen: Mutex<Vec<Option<String>>>,
    surface: &'static str,
    metrics: Metrics,
}

impl Reloadable {
    /// Records a surface that is serving `settings` through `config`.
    pub fn new(address: SocketAddr, settings: TlsSettings, config: RustlsConfig) -> Self {
        let seen = fingerprints(&settings);

        Self {
            address,
            settings,
            config,
            seen: Mutex::new(seen),
            surface: "surface",
            metrics: Metrics::none(),
        }
    }

    /// Records what the reloaded material says about itself, under the name `surface`.
    ///
    /// This is what makes the expiry a *current* number rather than a description of whatever this
    /// process started with: a renewal that swaps the file moves the gauge, and one that quietly did
    /// not leaves it where it was — which is the alert.
    pub fn measured(mut self, surface: &'static str, metrics: Metrics) -> Self {
        self.surface = surface;
        self.metrics = metrics;

        self
    }
}

/// What a pass over every surface did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reloaded {
    /// Surfaces now serving newly read material.
    pub reloaded: usize,
    /// Surfaces whose material could not be read, and which kept what they had.
    pub failed: usize,
}

/// The surfaces this process is serving, weakly.
fn registry() -> &'static Mutex<Vec<Weak<Reloadable>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Weak<Reloadable>>>> = OnceLock::new();

    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Adds a surface to the set SIGHUP acts on.
pub fn register(surface: &Arc<Reloadable>) {
    if let Ok(mut surfaces) = registry().lock() {
        surfaces.retain(|entry| entry.strong_count() > 0);
        surfaces.push(Arc::downgrade(surface));
    }
}

/// Asks every live surface in this process to re-read its material.
///
/// This is what SIGHUP means. It reloads unconditionally rather than checking modification times
/// first: an operator who sends the signal is stating that the material changed, and a reload that
/// finds the same material simply installs the same thing again.
pub fn reload_all() -> Reloaded {
    let surfaces: Vec<Arc<Reloadable>> = match registry().lock() {
        Ok(mut surfaces) => {
            surfaces.retain(|entry| entry.strong_count() > 0);
            surfaces.iter().filter_map(Weak::upgrade).collect()
        }
        Err(_) => Vec::new(),
    };

    let mut outcome = Reloaded::default();

    for surface in &surfaces {
        // The times are recorded either way, so a watcher does not immediately repeat the work.
        remember(surface);

        match reload(surface) {
            Ok(fingerprint) => {
                outcome.reloaded += 1;
                info!(
                    event.name = "transport.tls_reloaded",
                    component = COMPONENT,
                    address = %surface.address,
                    reason = "signal",
                    tls.certificate.fingerprint = %fingerprint,
                    "re-read the transport material"
                );
            }
            Err(error) => {
                outcome.failed += 1;
                warn!(
                    event.name = "transport.tls_reload_failed",
                    component = COMPONENT,
                    address = %surface.address,
                    reason = "signal",
                    error = %format!("{error:#}"),
                    "kept the material already in use"
                );
            }
        }
    }

    outcome
}

/// Watches one surface's material until the surface goes away.
///
/// Holds a [`Weak`], so the task ends on its own if the surface is dropped without being stopped.
pub async fn watch(surface: Weak<Reloadable>, interval: Duration) {
    // A change has to be seen twice, `settle` apart, before it is acted on — but the settle must
    // never be longer than the interval itself, or a test that polls quickly would never act.
    let settle = SETTLE.min(interval / 2).max(Duration::from_millis(1));

    loop {
        tokio::time::sleep(interval).await;

        let Some(surface) = surface.upgrade() else {
            return;
        };

        if !changed(&surface) {
            continue;
        }

        debug!(
            event.name = "transport.tls_changed",
            component = COMPONENT,
            address = %surface.address,
            "the transport material changed on disk"
        );

        tokio::time::sleep(settle).await;

        // Recorded before the attempt, so material that is genuinely broken warns once per change
        // rather than once per tick for as long as it stays broken.
        remember(&surface);

        match reload(&surface) {
            Ok(fingerprint) => info!(
                event.name = "transport.tls_reloaded",
                component = COMPONENT,
                address = %surface.address,
                reason = "changed",
                tls.certificate.fingerprint = %fingerprint,
                "re-read the transport material"
            ),
            Err(error) => warn!(
                event.name = "transport.tls_reload_failed",
                component = COMPONENT,
                address = %surface.address,
                reason = "changed",
                error = %format!("{error:#}"),
                "kept the material already in use"
            ),
        }
    }
}

/// Builds the material afresh and installs it, leaving the live configuration alone if it cannot.
fn reload(surface: &Reloadable) -> anyhow::Result<String> {
    let (config, fingerprint) = crate::material::build(&surface.settings)?;

    surface.config.reload_from_config(config);
    crate::measure::record_certificate_expiry(surface.surface, &surface.metrics, &surface.settings);

    Ok(fingerprint)
}

/// Reports whether any file this surface is made of has been touched since it was last looked at.
fn changed(surface: &Reloadable) -> bool {
    let Ok(seen) = surface.seen.lock() else {
        return false;
    };

    fingerprints(&surface.settings) != *seen
}

/// Records the current material as the state that has been accounted for.
fn remember(surface: &Reloadable) {
    if let Ok(mut seen) = surface.seen.lock() {
        *seen = fingerprints(&surface.settings);
    }
}

/// Returns the digest of every file the material is made of.
///
/// A file that cannot be read yields `None` rather than an error: mid-renewal a file is briefly
/// absent, and that *is* a change — it belongs in the comparison, not in a failure.
fn fingerprints(settings: &TlsSettings) -> Vec<Option<String>> {
    settings.files().map(fingerprint_of).collect()
}

fn fingerprint_of(path: &Path) -> Option<String> {
    std::fs::read(path)
        .map(|bytes| crate::digest::digest(&bytes))
        .ok()
}
