// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The part of the key ring that has to keep happening.
//!
//! Rotation is a schedule, and a schedule nobody runs is a comment. This is the thing that runs it:
//! one pass at startup, and one every tick after that.
//!
//! Startup is deliberately not "best effort". A deployment whose key ring cannot be read or written
//! is a deployment that will fail to sign later, at a moment nobody chose, and it is far better to
//! fail while somebody is watching the server start.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use permguard_core::metrics::Metric;
use permguard_core::{BoxFuture, KeyManager, Metrics, ServerContext, Service, ready};

/// Whether an issuer currently has a key that will sign — 1 or 0, labelled by realm and role.
///
/// The one number worth alerting on per issuer: a ring sitting at 0 publishes a key set nothing can
/// verify a signature against. `realm=server` is the control plane's own ring. `role` separates the
/// `operations` ring (seals the trail) from the `tokens` ring (signs issued tokens), so a realm with
/// both does not collapse into one gauge. The label set is the configured realms times two roles,
/// which is bounded, so this cannot grow without bound the way a path label would.
const KEYS_ACTIVE: Metric = Metric::gauge(
    "permguard_keys_active",
    "Whether an issuer has an active signing key (1) or not (0), by realm and role.",
);

// The manager is taken from the context rather than from a constructor, because which manager
// exists is a question the configuration answers and this service is registered before any
// configuration has been read.

/// The `component` every record of the key ring carries.
const COMPONENT: &str = "keys";

/// Advances the key lifecycle, at startup and on a timer.
pub struct KeyService {
    /// An explicit cadence override. `None` — the ordinary case — takes the deployment's configured
    /// `keys.maintenance_interval`. `Some` is for a test that wants a cadence of its own.
    tick: Option<Duration>,
    running: Mutex<Option<Running>>,
}

/// The ticking task, and the way to ask it to stop.
struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Default for KeyService {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyService {
    /// Builds the service that maintains whichever key rings the context carries.
    ///
    /// The cadence comes from the configuration at start; nothing needs to be chosen here.
    pub fn new() -> Self {
        Self {
            tick: None,
            running: Mutex::new(None),
        }
    }

    /// Advances the lifecycle at a fixed cadence regardless of configuration, which is what a test
    /// that cannot wait for a configured minute wants.
    pub fn every(mut self, tick: Duration) -> Self {
        self.tick = Some(tick);

        self
    }

    /// Runs one pass over one ring, recording only what it actually changed.
    ///
    /// Silence when nothing happened is the point: a rotation is rare and worth noticing, and a
    /// record every minute saying that nothing rotated is how the one that mattered gets missed. Every
    /// record names the ring — `server`, or the realm — so one process maintaining many issuers stays
    /// readable in the log.
    fn pass(ring: &Ring) -> Result<()> {
        let report = ring
            .keys
            .maintain()
            .with_context(|| format!("advancing the key lifecycle for {}", ring.label()))?;

        if report.is_empty() {
            return Ok(());
        }

        info!(
            event.name = "keys.maintained",
            component = COMPONENT,
            realm = ring.realm.as_deref(),
            keys.role = ring.role,
            keys.published = report.published,
            keys.activated = report.activated,
            keys.retired = report.retired,
            keys.archived = report.archived,
            keys.forgotten = report.forgotten,
            "the key ring changed"
        );

        Ok(())
    }

    /// Publishes whether a ring currently has a key that will sign, labelled by its issuer.
    fn record_active(metrics: &Metrics, ring: &Ring) {
        let realm = ring.realm.as_deref().unwrap_or("server");
        let active = f64::from(u8::from(ring.keys.active_key_id().is_ok()));

        metrics.set(
            &KEYS_ACTIVE,
            &[("realm", realm), ("role", ring.role)],
            active,
        );
    }
}

/// One key ring this service maintains, which issuer it belongs to, and what it is for.
///
/// `realm` is `None` for the server's own ring and the realm name otherwise. `role` is `operations`
/// for the ring that seals a trail or `tokens` for the ring that signs issued tokens — a realm has
/// both, so the two must be told apart. Together they let a single sequential loop maintain every
/// ring without a task apiece, and name each one in the log.
struct Ring {
    realm: Option<String>,
    role: &'static str,
    keys: Arc<dyn KeyManager>,
}

impl Ring {
    /// How this ring is named in a record and an error.
    fn label(&self) -> String {
        match &self.realm {
            Some(name) => format!("the {} ring of the realm `{name}`", self.role),
            None => format!("the {} ring of the server", self.role),
        }
    }
}

impl Service for KeyService {
    fn name(&self) -> &'static str {
        COMPONENT
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Every ring this deployment maintains, in one list: the server's first, then each
            // realm's. One list is what makes the loop below a single sequential pass rather than a
            // task per issuer — the whole reason many realms cost a loop and not many threads.
            let mut rings: Vec<Ring> = Vec::new();
            if let Some(keys) = context.keys() {
                rings.push(Ring {
                    realm: None,
                    role: "operations",
                    keys: Arc::clone(keys),
                });
            }
            // The plane signing rings: separate rings from the one sealing
            // the trail, maintained by the same pass. The control plane's
            // signs what it serves; the data plane's will sign decisions.
            if let Some(keys) = context.control_signing_keys() {
                rings.push(Ring {
                    realm: None,
                    role: "control-signing",
                    keys: Arc::clone(keys),
                });
            }
            if let Some(keys) = context.data_signing_keys() {
                rings.push(Ring {
                    realm: None,
                    role: "data-signing",
                    keys: Arc::clone(keys),
                });
            }
            // Each realm brings up to two rings, maintained the same way in this one loop: its
            // operations ring, which seals its trail, and its token ring, which signs the tokens it
            // issues. A realm may have either, both, or neither.
            for realm in context.realms().all() {
                if let Some(keys) = realm.operations_keys() {
                    rings.push(Ring {
                        realm: Some(realm.name().to_owned()),
                        role: "operations",
                        keys: Arc::clone(keys),
                    });
                }
                if let Some(keys) = realm.token_keys() {
                    rings.push(Ring {
                        realm: Some(realm.name().to_owned()),
                        role: "tokens",
                        keys: Arc::clone(keys),
                    });
                }
            }

            if rings.is_empty() {
                info!(
                    event.name = "keys.disabled",
                    component = COMPONENT,
                    "this deployment publishes no signing keys"
                );

                return Ok(());
            }

            // The startup pass. The server's ring failing is fatal — it is this server's identity and
            // it signs the system trail, so a deployment that cannot prepare it should fail while
            // somebody is watching. A realm's ring failing is loud but not fatal: a broken realm must
            // not keep the server and the other realms from starting.
            for ring in &rings {
                if let Err(error) = Self::pass(ring) {
                    match &ring.realm {
                        None => {
                            return Err(error).context("the server key ring could not be prepared");
                        }
                        Some(name) => warn!(
                            event.name = "keys.realm_unavailable",
                            component = COMPONENT,
                            realm = name.as_str(),
                            keys.role = ring.role,
                            error = %format!("{error:#}"),
                            "this realm's key ring could not be prepared; it will not sign until it can"
                        ),
                    }

                    Self::record_active(context.metrics(), ring);
                    continue;
                }

                info!(
                    event.name = "keys.ready",
                    component = COMPONENT,
                    realm = ring.realm.as_deref(),
                    keys.role = ring.role,
                    keys.manager = ring.keys.name(),
                    keys.active = ring
                        .keys
                        .active_key_id()
                        .map(|id| id.to_string())
                        .unwrap_or_else(|_| "none yet".to_owned()),
                    "signing"
                );
                Self::record_active(context.metrics(), ring);
            }

            let (stop, mut stopped) = watch::channel(false);
            let tick = self
                .tick
                .unwrap_or_else(|| context.config().keys_maintenance_interval());
            let metrics = context.metrics().clone();

            let task = tokio::spawn(async move {
                let mut timer = tokio::time::interval(tick);
                // The first tick of an interval fires immediately, and the pass it would run has
                // just been run above.
                timer.tick().await;

                loop {
                    tokio::select! {
                        _ = timer.tick() => {
                            // Every ring, in sequence, each isolated: a pass that fails leaves that
                            // ring on disk unchanged and its active key still signing, and must not
                            // stop the others being advanced. What is not acceptable is failing
                            // quietly.
                            for ring in &rings {
                                if let Err(error) = Self::pass(ring) {
                                    warn!(
                                        event.name = "keys.maintenance_failed",
                                        component = COMPONENT,
                                        realm = ring.realm.as_deref(),
                                        keys.role = ring.role,
                                        error = %format!("{error:#}"),
                                        "the key lifecycle did not advance"
                                    );
                                }

                                Self::record_active(&metrics, ring);
                            }
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the key service lock is poisoned"))? =
                Some(Running { task, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the key service lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(running) = running else {
                return Ok(());
            };

            // The receiver lives in the task, so this only fails if the task is already gone.
            let _ = running.stop.send(true);

            match running.task.await {
                Ok(()) => debug!(
                    event.name = "keys.stopped",
                    component = COMPONENT,
                    "no longer maintaining the key ring"
                ),
                Err(error) => warn!(
                    event.name = "keys.stop_failed",
                    component = COMPONENT,
                    error = %error,
                    "the key maintenance task did not finish"
                ),
            }

            Ok(())
        })
    }
}
