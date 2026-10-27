// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The loops beside the decision log: measuring its pressure, and shipping a legacy spool.
//!
//! # Why these are a service and not tasks on the decision path
//!
//! Because the decision path may never wait on them. The Host's producer ships the log over
//! `decisions.ship` (WP-6.1); what runs here is what the plane still owns:
//!
//! - **the pressure measure**, once a second: each stream's unacknowledged bytes and age against
//!   the bounds, read from memory by every decision, which never reads a journal itself;
//! - **the legacy shipper**, only on an upgraded plane whose version 1 spool still holds records:
//!   it ships them to the configured destination until the spool is empty, and stops.
//!
//! # What stops the legacy shipper
//!
//! An empty spool, or a refusal on the merits — a signature that does not verify, a chain that
//! does not hold, a stream the store has closed. Those are incidents, and a loop that retried
//! them would spin forever while hiding the one thing an operator needed to see. Everything else
//! is retried with backoff, because the records are still on this plane's own disk.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use permguard_control_client::decisions;
use permguard_core::{BoxFuture, PlaneContext, PlaneTask, future::ready};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info};

use super::shipper::{Round, Shipper, backoff};

const COMPONENT: &str = "data-plane";

/// How often the decision log's pressure is measured.
const MEASURE_EVERY: Duration = Duration::from_secs(1);

/// The running loops, and the way to ask them to stop.
struct Running {
    tasks: Vec<JoinHandle<()>>,
    stop: watch::Sender<bool>,
}

/// Measures the decision log, and ships a legacy spool until it is empty.
pub struct DecisionService {
    tick: Option<Duration>,
    running: Mutex<Option<Running>>,
}

impl Default for DecisionService {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionService {
    /// Builds the service beside this plane's decision log.
    pub fn new() -> Self {
        Self {
            tick: None,
            running: Mutex::new(None),
        }
    }

    /// Ships a legacy spool at a fixed cadence regardless of configuration.
    pub fn every(mut self, tick: Duration) -> Self {
        self.tick = Some(tick);

        self
    }
}

impl PlaneTask for DecisionService {
    fn name(&self) -> &'static str {
        "decisions"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.log_enabled() {
                // Records an earlier release left are shipped only while the log is on: said, so
                // turning it off is never how they are lost unnoticed.
                let spool = config.working_dir().join(config.log_spool_directory());
                if super::holds_segments(&spool).unwrap_or(true) {
                    tracing::warn!(
                        event.name = "decisions.legacy_stranded",
                        component = COMPONENT,
                        spool = %spool.display(),
                        "the decision log is off and a legacy decision spool is on the volume: \
                         what it holds unshipped is shipped only while the log is on"
                    );
                }
                return Ok(());
            }
            let Some(log) = super::host_log(context) else {
                // Reported in detail where it was decided. Fatal here, and deliberately: a plane
                // configured to record and unable to would refuse every decision, `required`
                // being the only mode written. Refusing to start is the honest failure.
                return Err(anyhow!(
                    "the decision log is enabled and this plane cannot write it: refusing to \
                     start rather than refuse every decision"
                ));
            };
            // Pseudonymisation is not optional once records leave this plane.
            // `docs/decision-logs.md` states that subject and principal
            // identifiers are tokenised **at the source**, so that the control
            // plane — a different trust domain, with a different set of readers
            // — never holds a raw one. A plane that shipped them raw would make
            // that sentence false, and it would do so silently.
            if crate::handles::zone_key(
                context,
                permguard_host::secrets::ZonePurpose::AuditPseudonym,
            )
            .is_none()
            {
                return Err(anyhow!(
                    "the decision log is enabled and the Host holds no zone keys for pseudonyms \
                     (operations.secrets.coordinator_root_ref): subject and principal identifiers \
                     are tokenised under the zone's key before a record leaves this plane, and \
                     there is nothing here to tokenise them with"
                ));
            }
            // The stream is sealed under the plane's `data.attest` ring, and nothing unsealed is
            // ever shipped or acknowledged: a log without it would grow unbounded and reach no
            // coordinator. Refused, as records that leave unattributable always were.
            if crate::handles::decision_signer(context).is_none() {
                error!(
                    event.name = "decisions.unsigned",
                    component = COMPONENT,
                    "the decision log is on and no signing ring is composed (dataPlane.keys)"
                );
                return Err(anyhow!(
                    "the decision log is enabled and no signing ring is composed \
                     (dataPlane.keys): its records would never be sealed or shipped"
                ));
            }
            let (stop, stopped) = watch::channel(false);
            let mut tasks = vec![tokio::spawn(measure(log, stopped.clone()))];
            match super::legacy_spool(context).map_err(|error| anyhow!(error))? {
                Some(journal) => tasks.push(self.ship_legacy(context, journal, stopped)?),
                None => drop(stopped),
            }

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the decision service lock is poisoned"))? =
                Some(Running { tasks, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the decision service lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(running) = running else {
                return Ok(());
            };
            let _ = running.stop.send(true);
            for task in running.tasks {
                let _ = task.await;
            }

            Ok(())
        })
    }
}

impl DecisionService {
    /// Starts shipping the legacy spool `journal` to the configured destination until it is
    /// empty (WP-6.1, owner decision of 2026-10-16).
    fn ship_legacy(
        &self,
        context: &PlaneContext<'_>,
        journal: Arc<super::Journal>,
        mut stopped: watch::Receiver<bool>,
    ) -> Result<JoinHandle<()>> {
        let config = context.config();
        let Some(keys) = crate::handles::decision_signer(context) else {
            // Records that leave unattributable are records nobody can act on.
            error!(
                event.name = "decisions.unsigned",
                component = COMPONENT,
                "a legacy decision spool holds records and no signing ring is composed \
                 (dataPlane.keys)"
            );

            return Err(anyhow!(
                "a legacy decision spool holds records and no signing ring is composed \
                 (dataPlane.keys): they would leave unattributable"
            ));
        };
        // Where records go: the server the file names, and nothing inferred (WP-7.7: a mirror names
        // no server to infer one from).
        let (url, tls) = destination(context)?;
        // Whichever transport the URL names: a deployment that terminates gRPC and one behind an
        // HTTP proxy ship the same records.
        let sink = decisions::client(
            &url,
            &tls,
            Box::new(permguard_control_client::narrate::Silent),
        )
        .map_err(|error| anyhow!("reaching the decision log at {url}: {error}"))?;

        let interval = self.tick.unwrap_or_else(|| config.log_batch_interval());
        let shipper = Arc::new(Shipper::new(
            Arc::clone(&journal),
            sink,
            keys,
            config.log_batch_bytes(),
            super::rate(config.log_sample_permits()),
            context.metrics().clone(),
        ));
        info!(
            event.name = "decisions.legacy_shipping",
            component = COMPONENT,
            server = url.as_str(),
            interval.seconds = interval.as_secs(),
            "a legacy decision spool is shipped until it is empty; new decisions are recorded on \
             the Host's stream"
        );

        Ok(tokio::spawn(async move {
            let mut failures = 0u32;
            loop {
                let wait = if failures == 0 {
                    interval
                } else {
                    backoff(interval, failures)
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {
                        // Blocking: the spool is files, and a round reads and flushes them. Off
                        // the runtime's threads.
                        let shipper = Arc::clone(&shipper);
                        let outcome = tokio::task::spawn_blocking(move || shipper.round()).await;
                        match outcome {
                            Ok(Round::Shipped { .. }) => failures = 0,
                            Ok(Round::Idle) => {
                                info!(
                                    event.name = "decisions.legacy_drained",
                                    component = COMPONENT,
                                    "the legacy decision spool is empty: nothing more is shipped \
                                     from it"
                                );
                                break;
                            }
                            Ok(Round::Deferred(_)) | Err(_) => failures = failures.saturating_add(1),
                            Ok(Round::Stopped { .. }) => break,
                        }
                    }
                    _ = stopped.changed() => break,
                }
            }
        }))
    }
}

/// Measures `log`'s pressure every [`MEASURE_EVERY`] until stopped, off the runtime's threads:
/// the measure reads journals.
async fn measure(log: Arc<super::HostLog>, mut stopped: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(MEASURE_EVERY) => {
                let log = Arc::clone(&log);
                let _ = tokio::task::spawn_blocking(move || log.measure()).await;
            }
            _ = stopped.changed() => break,
        }
    }
}

/// Where records go, and how that server is trusted.
/// Where a plane ships what it produced.
///
/// Shared with the event shipper: one deployment ships both to one control plane, and asking it to
/// name that plane twice would be asking it to keep two settings in step.
pub fn destination(
    context: &PlaneContext<'_>,
) -> Result<(String, permguard_control_client::TlsOptions)> {
    let config = context.config();
    if let Some(destination) = config.log_destination() {
        return Ok((
            destination.url.clone(),
            tls_of(&destination.tls, config.working_dir()),
        ));
    }

    // No server named: mirrors name none since WP-7.7, so there is nothing to take one from.
    Err(anyhow!(
        "the decision log is on and names no server: say where records go under \
         `dataPlane.decisions.log.server`"
    ))
}

/// The trust material for the log's server, resolved against the volume.
///
/// A relative path in a configuration file means "next to the volume this
/// process was given", exactly as it does for a listener's certificate and for
/// a mirror source.
fn tls_of(
    tls: &permguard_core::mirrors::MirrorTls,
    working_dir: &std::path::Path,
) -> permguard_control_client::TlsOptions {
    permguard_control_client::TlsOptions {
        ca_file: tls.ca_file.as_ref().map(Into::into),
        cert_file: tls.cert.as_ref().map(Into::into),
        key_file: tls.key.as_ref().map(Into::into),
        server_name: tls.server_name.clone(),
        // Never: see `permguard_core::mirrors::MirrorTls`.
        skip_verify: false,
        // A shipper or a mirror presents mutual TLS, never an operator's token (TC-1).
        key_pem: None,
        token: None,
    }
    .rooted_at(working_dir)
}
