// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shipping loop, running beside the listeners it drains.
//!
//! # Why this is a service and not a task on the decision path
//!
//! Because the decision path may never wait on it. A plane answering ten
//! thousand decisions a second and a control plane that is down for an hour
//! are the same situation from here: records accumulate on disk, this loop
//! keeps trying, and nothing upstream notices.
//!
//! # What stops it
//!
//! Only a refusal on the merits — a signature that does not verify, a chain
//! that does not hold, a stream the store has closed. Those are incidents, and
//! a loop that retried them would spin forever while hiding the one thing an
//! operator needed to see. Everything else is retried with backoff, because
//! the records are still on this plane's own disk.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use permguard_control_client::decisions;
use permguard_core::{BoxFuture, ServerContext, Service, future::ready};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info};

use super::shipper::{Round, Shipper, backoff};

const COMPONENT: &str = "data-plane";

/// The running loop, and the way to ask it to stop.
struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

/// Ships what this plane decided, on a cadence.
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
    /// Builds the service that drains this plane's spool.
    pub fn new() -> Self {
        Self {
            tick: None,
            running: Mutex::new(None),
        }
    }

    /// Ships at a fixed cadence regardless of configuration.
    pub fn every(mut self, tick: Duration) -> Self {
        self.tick = Some(tick);

        self
    }
}

impl Service for DecisionService {
    fn name(&self) -> &'static str {
        "decisions"
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.log_enabled() {
                return Ok(());
            }
            let Some(journal) = super::journal(context) else {
                // Reported in detail where it was decided. Fatal here, and
                // deliberately: a plane configured to record and unable to
                // would answer every decision unrecorded — which is the exact
                // outcome `on_full: closed` exists to prevent, arrived at by
                // a different route. Refusing to start is the honest failure.
                return Err(anyhow!(
                    "the decision log is enabled and this plane cannot write it: refusing to \
                     start rather than answer decisions it cannot record"
                ));
            };
            // Pseudonymisation is not optional once records leave this plane.
            // `docs/decision-logs.md` states that subject and principal
            // identifiers are tokenised **at the source**, so that the control
            // plane — a different trust domain, with a different set of readers
            // — never holds a raw one. A plane that shipped them raw would make
            // that sentence false, and it would do so silently.
            if context
                .recorder()
                .and_then(permguard_core::AuditRecorder::pseudonymizer)
                .is_none()
            {
                return Err(anyhow!(
                    "the decision log is enabled and no pseudonymizer is composed \
                     (operations.audit.pseudonym): subject and principal identifiers are \
                     tokenised before a record leaves this plane, and there is nothing here to \
                     tokenise them with"
                ));
            }
            let Some(keys) = context.data_signing_keys() else {
                // Same reasoning: records that leave unattributable are records
                // nobody can act on, and a plane that keeps deciding while
                // producing them is worse than one that will not start.
                error!(
                    event.name = "decisions.unsigned",
                    component = COMPONENT,
                    "the decision log is on and no signing ring is composed (dataPlane.keys)"
                );

                return Err(anyhow!(
                    "the decision log is enabled and no signing ring is composed \
                     (dataPlane.keys): records would leave unattributable"
                ));
            };

            // Where records go. A plane that mirrors exactly one server ships
            // there when the file names none, because that is the only
            // unambiguous inference; anything else is refused rather than
            // guessed.
            let (url, tls) = destination(context)?;
            // Whichever transport the URL names: a deployment that terminates
            // gRPC and one behind an HTTP proxy ship the same records.
            let sink = decisions::client(
                &url,
                &tls,
                Box::new(permguard_control_client::narrate::Silent),
            )
            .map_err(|error| anyhow!("reaching the decision log at {url}: {error}"))?;

            let interval = self.tick.unwrap_or_else(|| config.log_batch_interval());
            let shipper = Arc::new(Shipper::new(
                journal,
                sink,
                Arc::clone(keys),
                config.log_batch_bytes(),
                super::rate(config.log_sample_permits()),
                context.metrics().clone(),
            ));
            info!(
                event.name = "decisions.shipping",
                component = COMPONENT,
                server = url.as_str(),
                interval.seconds = interval.as_secs(),
                "decisions are recorded here and shipped from here"
            );

            let (stop, mut stopped) = watch::channel(false);
            let task = tokio::spawn(async move {
                let mut failures = 0u32;
                loop {
                    let wait = if failures == 0 {
                        interval
                    } else {
                        backoff(interval, failures)
                    };
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {
                            // Blocking: the spool is files, and a round reads
                            // and flushes them. Off the runtime's threads.
                            let shipper = Arc::clone(&shipper);
                            let outcome = tokio::task::spawn_blocking(move || shipper.round()).await;
                            match outcome {
                                Ok(Round::Shipped { .. }) | Ok(Round::Idle) => failures = 0,
                                Ok(Round::Deferred(_)) | Err(_) => failures = failures.saturating_add(1),
                                Ok(Round::Stopped { .. }) => break,
                            }
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the decision service lock is poisoned"))? =
                Some(Running { task, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the decision service lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(running) = running else {
                return Ok(());
            };
            let _ = running.stop.send(true);
            let _ = running.task.await;

            Ok(())
        })
    }
}

/// Where records go, and how that server is trusted.
/// Where a plane ships what it produced.
///
/// Shared with the event shipper: one deployment ships both to one control plane, and asking it to
/// name that plane twice would be asking it to keep two settings in step.
pub fn destination(
    context: &ServerContext<'_>,
) -> Result<(String, permguard_control_client::TlsOptions)> {
    let config = context.config();
    if let Some(destination) = config.log_destination() {
        return Ok((
            destination.url.clone(),
            tls_of(&destination.tls, config.working_dir()),
        ));
    }

    // No server named. Exactly one mirror source is unambiguous; anything else
    // is refused at startup rather than guessed at runtime.
    let sources = config.mirror_sources();
    match sources.len() {
        1 => {
            let source = &sources[0];
            Ok((
                source.url.clone(),
                tls_of(&source.tls, config.working_dir()),
            ))
        }
        0 => Err(anyhow!(
            "the decision log is on and names no server, and this plane mirrors none either: say \
             where records go under `dataPlane.decisions.log.server`"
        )),
        many => Err(anyhow!(
            "the decision log is on and names no server, and this plane mirrors {many} of them: \
             which one receives the records is not something to guess — name it under \
             `dataPlane.decisions.log.server`"
        )),
    }
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
    }
    .rooted_at(working_dir)
}
