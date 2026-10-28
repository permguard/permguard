// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shipping loop for events, and the eviction that follows it.
//!
//! # Why this is a service and not a task on the submission path
//!
//! Because a submission may never wait on it. A plane recording ten thousand events a second and a
//! control plane that is down for an hour are the same situation from here: records accumulate on
//! disk, this loop keeps trying, and nothing upstream notices — **until** the journal's capacity or
//! its retention safety is threatened, at which point submissions fail closed rather than events
//! being dropped.
//!
//! # Two watermarks, and why eviction is not the acknowledgement
//!
//! A decision record acknowledged may be deleted. An event record acknowledged may be deleted only
//! if no loaded policy could still read it: it is also the history this plane decides against. So
//! this loop advances the acknowledgement and then evicts by
//!
//! ```text
//! min(control_plane_acked_through, dogwood_retention_safe_through)
//! ```
//!
//! where the second is derived from the effective `max_window` plus the configured allowed
//! lateness and clock skew. Deleting on the first alone would silently change what this plane's
//! future decisions mean.
//!
//! # What stops it
//!
//! Only a refusal on the merits — a signature that does not verify, a chain that does not hold, a
//! stream the store has closed. Those are incidents, and a loop that retried them would spin for
//! ever while hiding the one thing an operator needed to see. Everything else is retried with
//! bounded, jittered backoff, because the records are still on this plane's own disk.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use permguard_core::{BoxFuture, PlaneContext, PlaneTask, future::ready};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::shipper::{Backoff, Round, Shipper};

const COMPONENT: &str = "temporal";

/// How often a round runs when nothing is failing.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);
/// The most bytes one batch carries.
pub const DEFAULT_BATCH_BYTES: u64 = 4 * 1024 * 1024;

/// The running loop, and the way to ask it to stop.
struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

/// Ships what this plane recorded, and evicts what nothing needs any more.
pub struct EventService {
    tick: Option<Duration>,
    running: Mutex<Option<Running>>,
}

impl Default for EventService {
    fn default() -> Self {
        Self::new()
    }
}

impl EventService {
    /// Builds the service that drains this plane's event journals.
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

impl PlaneTask for EventService {
    fn name(&self) -> &'static str {
        "events"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !super::served(config) {
                return Ok(());
            }
            let Some(submitter) = super::submitter(context) else {
                // Reported in detail where it was decided. Fatal here, and deliberately: a plane
                // configured to record history and unable to would answer every submission by
                // failing closed, which is a plane that refuses every request while appearing to
                // be running.
                return Err(anyhow!(
                    "the temporal interface is enabled and this plane cannot write its event \
                     journals: refusing to start rather than fail every submission closed"
                ));
            };
            // The stream is sealed under the plane's `data.attest` ring, and nothing unsealed is
            // ever shipped: a log without it would grow until its bounds refused every
            // submission and reach no coordinator.
            let Some(keys) = crate::handles::event_signer(context) else {
                return Err(anyhow!(
                    "the temporal interface is enabled and no signing ring is composed \
                     (dataPlane.keys): event records would leave this plane unattributable, and \
                     an unattributable history is one nobody can act on"
                ));
            };

            let interval = self.tick.unwrap_or(DEFAULT_INTERVAL);
            let streams = Arc::clone(submitter.streams());
            // The origins the member Host imports, whose floor this loop keeps too (WP-6.2c2b1).
            let imported = submitter.imported().cloned();
            let retention = streams.bounds().retention_minimum;
            // Recorded on the Host's producer and shipped by it over `events.ship` (WP-6.2a); this
            // loop keeps the floor the producer deletes above current. The old shipper runs only
            // while a legacy journal holds anything unshipped, which it sends until it is empty.
            let legacy_pending = legacy_unshipped(&streams);
            // An event-specific destination wins. Only its absence falls back to the decision
            // log's endpoint, so a value written under `events.destination` can never be accepted
            // by configuration and then ignored by the running service.
            // The HTTP pull is retired (WP-6.2c2b2): only a legacy journal still draining reaches
            // the Control Plane over it.
            let remote = if legacy_pending {
                Some(destination(context)?)
            } else {
                None
            };
            let shipper = match (&remote, legacy_pending) {
                (Some((url, tls)), true) => {
                    info!(
                        event.name = "events.legacy_shipping",
                        component = COMPONENT,
                        server = url.as_str(),
                        "a legacy event journal is shipped until it is empty; new events are \
                         recorded on the Host's stream"
                    );
                    Some(Arc::new(Shipper::new(
                        Arc::clone(&streams),
                        event_sink(url, tls)?,
                        keys,
                        DEFAULT_BATCH_BYTES,
                        context.metrics().clone(),
                    )))
                }
                _ => None,
            };
            info!(
                event.name = "events.recording",
                component = COMPONENT,
                interval.seconds = interval.as_secs(),
                retention.seconds = retention.as_secs(),
                "events are recorded on the Host's stream and shipped over events.ship"
            );

            let (stop, mut stopped) = watch::channel(false);
            let backoff = Backoff::default();
            let task = tokio::spawn(async move {
                let mut ship_failures = 0u32;
                let mut next_ship = tokio::time::Instant::now() + interval;
                loop {
                    let deadline = next_ship;
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => {
                            let now = tokio::time::Instant::now();
                            if now >= next_ship {
                                // Blocking: a round reads and flushes files. Off the runtime's threads.
                                let shipper = shipper.clone();
                                let streams = Arc::clone(&streams);
                                let imported = imported.clone();
                                let outcome = tokio::task::spawn_blocking(move || {
                                    keep_floors(&streams, imported.as_deref(), retention);
                                    let rounds = shipper
                                        .map(|shipper| shipper.round())
                                        .unwrap_or_default();
                                    evict(&streams, retention);
                                    rounds
                                }).await;
                                match outcome {
                                    Ok(rounds) => {
                                        if rounds.iter().any(|(_, round)| {
                                            matches!(round, Round::Stopped { .. })
                                        }) {
                                            break;
                                        }
                                        ship_failures = match rounds
                                            .iter()
                                            .any(|(_, round)| matches!(round, Round::Deferred(_)))
                                        {
                                            true => ship_failures.saturating_add(1),
                                            false => 0,
                                        };
                                    }
                                    Err(_) => ship_failures = ship_failures.saturating_add(1),
                                }
                                let wait = match ship_failures {
                                    0 => interval,
                                    held => backoff.wait(held, jitter()),
                                };
                                next_ship = tokio::time::Instant::now() + wait;
                            }

                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the event service lock is poisoned"))? =
                Some(Running { task, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the event service lock is poisoned"))),
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

/// Where this plane exchanges event records, using the event destination when one is declared and
/// the decision-log endpoint otherwise for deployments that send both streams to one control
/// plane.
fn destination(
    context: &PlaneContext<'_>,
) -> Result<(String, permguard_control_client::TlsOptions)> {
    let config = context.config();
    if let Some(destination) = config.events_destination() {
        return Ok((
            destination.url.clone(),
            tls_of(&destination.tls, config.working_dir()),
        ));
    }

    crate::decisions::service::destination(context)
}

fn tls_of(
    tls: &permguard_core::mirrors::MirrorTls,
    working_dir: &std::path::Path,
) -> permguard_control_client::TlsOptions {
    permguard_control_client::TlsOptions {
        ca_file: tls.ca_file.as_ref().map(Into::into),
        cert_file: tls.cert.as_ref().map(Into::into),
        key_file: tls.key.as_ref().map(Into::into),
        server_name: tls.server_name.clone(),
        skip_verify: false,
        // A shipper or a mirror presents mutual TLS, never an operator's token (TC-1).
        key_pem: None,
        token: None,
    }
    .rooted_at(working_dir)
}

/// Evicts what the control plane holds and no loaded policy could still read.
///
/// The retention-safe boundary is computed from the records themselves: the highest sequence whose
/// occurrence is older than `now - required_retention`. Read from the journal rather than tracked
/// in memory, because it is the *events'* own times that decide it and a counter kept beside them
/// could drift from what they say.
fn evict(streams: &Arc<super::streams::Streams>, retention: Duration) {
    let bounds = streams.bounds();
    // What the policies need, plus what a late or skewed clock may add on top of it. An event
    // inside that span could still land inside a window a policy is looking at.
    let required = bounds.required_retention(retention);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();
    let horizon = now.saturating_sub(required.as_secs() as i64);

    for (zone, ledger) in streams.ledgers() {
        let Ok(state) = streams.state(&zone, &ledger) else {
            continue;
        };
        // Only what has been acknowledged is a candidate at all; among those, only what is older
        // than the horizon. The stricter of the two, always.
        let mut safe = state.oldest_retained.saturating_sub(1);
        let Ok(records) = streams.legacy_read_from(&zone, &ledger, safe, 100_000) else {
            continue;
        };
        for record in records {
            let Some(seq) = record.get("seq").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            if seq > state.acked_through {
                break;
            }
            let occurred = record
                .get("occurred_at")
                .and_then(serde_json::Value::as_str)
                .and_then(permguard_events::index::epoch_seconds)
                .unwrap_or(i64::MAX);
            if occurred >= horizon {
                break;
            }
            safe = seq;
        }
        match streams.evict(&zone, &ledger, safe) {
            Ok(0) => {}
            Ok(removed) => info!(
                event.name = "events.evicted",
                component = COMPONENT,
                removed,
                through = safe,
                "event records the control plane holds and no loaded policy can still read were \
                 removed"
            ),
            Err(error) => warn!(
                event.name = "events.eviction_failed",
                component = COMPONENT,
                error = %error,
                "event records could not be evicted: the journal keeps them, which is the safe \
                 direction"
            ),
        }
    }
}

/// Whether a legacy journal holds anything its shipper has still to send.
fn legacy_unshipped(streams: &super::streams::Streams) -> bool {
    streams.ledgers().iter().any(|(zone, ledger)| {
        streams
            .state(zone, ledger)
            .map_or(true, |state| state.acked_through < state.durable_through)
    })
}

/// Keeps the floor the Host's producer deletes above current: what no loaded window reads, plus
/// what lateness and skew may add (WP-6.2a); and the one its consumer deletes the imported
/// origins' runs above (WP-6.2c2b1).
fn keep_floors(
    streams: &super::streams::Streams,
    imported: Option<&super::imported::Imported>,
    retention: Duration,
) {
    let required = streams.bounds().required_retention(retention);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();
    let horizon = now.saturating_sub(required.as_secs() as i64);
    if let Some(imported) = imported
        && let Err(error) = imported.refresh_floors(horizon)
    {
        warn!(
            event.name = "events.import_floor_unmeasured",
            component = COMPONENT,
            error = %error,
            "the imported runs' retention floor could not be measured: they are kept"
        );
    }
    if let Err(error) = streams.refresh_floors(horizon) {
        // The floor last measured stays, and a run never measured is kept whole: the safe
        // direction.
        warn!(
            event.name = "events.floor_unmeasured",
            component = COMPONENT,
            error = %error,
            "the event stream's retention floor could not be measured"
        );
    }
}

/// The client for whichever transport the URL names.
fn event_sink(
    url: &str,
    tls: &permguard_control_client::TlsOptions,
) -> Result<Box<dyn permguard_control_client::events::EventSink>> {
    let narrator = || Box::new(permguard_control_client::narrate::Silent);
    let sink: Box<dyn permguard_control_client::events::EventSink> = if url.starts_with("grpc") {
        Box::new(
            permguard_control_client::events_grpc::GrpcEventSink::connect(url, tls, narrator())
                .map_err(|error| anyhow!("reaching the event store at {url}: {error}"))?,
        )
    } else {
        Box::new(
            permguard_control_client::events::HttpEventSink::connect(url, tls, narrator())
                .map_err(|error| anyhow!("reaching the event store at {url}: {error}"))?,
        )
    };

    Ok(sink)
}

/// A fresh jitter fraction for one backoff.
///
/// From the same source the instance identifiers come from, so a fleet does not share a sequence:
/// a deterministic jitter would be no jitter at all once every plane ran the same build.
fn jitter() -> f64 {
    use ring::rand::SecureRandom as _;

    let mut bytes = [0u8; 2];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        // No randomness is a reason to wait the full window rather than to hammer.
        return 1.0;
    }

    f64::from(u16::from_be_bytes(bytes)) / f64::from(u16::MAX)
}
