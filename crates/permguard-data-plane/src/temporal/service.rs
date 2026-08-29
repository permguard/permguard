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

use anyhow::{Context as _, Result, anyhow};
use permguard_core::{BoxFuture, ServerContext, Service, future::ready};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::pull::{Puller, Round as PullRound, Subscription};
use super::shipper::{Backoff, Round, Shipper};

const COMPONENT: &str = "temporal";

/// How often a round runs when nothing is failing.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);
/// The most bytes one batch carries.
pub const DEFAULT_BATCH_BYTES: u64 = 4 * 1024 * 1024;
/// How often the local copy of imported history is compacted.
const IMPORT_EVICTION_INTERVAL: Duration = Duration::from_secs(60 * 60);

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

impl Service for EventService {
    fn name(&self) -> &'static str {
        "events"
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
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
            let Some(keys) = context.data_signing_keys() else {
                return Err(anyhow!(
                    "the temporal interface is enabled and no signing ring is composed \
                     (dataPlane.keys): event records would leave this plane unattributable, and \
                     an unattributable history is one nobody can act on"
                ));
            };

            // An event-specific destination wins. Only its absence falls back to the decision
            // log's endpoint, so a value written under `events.destination` can never be accepted
            // by configuration and then ignored by the running service.
            let (url, tls) = destination(context)?;
            let sink = event_sink(&url, &tls)?;

            let interval = self.tick.unwrap_or(DEFAULT_INTERVAL);
            let pull_interval = self.tick.unwrap_or(config.events_pull_interval());
            let shipper = Arc::new(Shipper::new(
                Arc::clone(submitter.streams()),
                sink,
                Arc::clone(keys),
                DEFAULT_BATCH_BYTES,
                context.metrics().clone(),
            ));
            let streams = Arc::clone(submitter.streams());
            let retention = streams.bounds().retention_minimum;
            let imported_retention = streams.bounds().required_retention(retention);
            info!(
                event.name = "events.shipping",
                component = COMPONENT,
                server = url.as_str(),
                interval.seconds = interval.as_secs(),
                retention.seconds = retention.as_secs(),
                "events are recorded here and shipped from here"
            );

            // The pull worker, when this deployment reads history other planes recorded. Built
            // here so it shares the loop's cadence and its shutdown: a second loop would be a
            // second thing to stop, and one of the two would be the one that is not stopped.
            let puller = puller(context, &url, &tls)?;
            let (stop, mut stopped) = watch::channel(false);
            let backoff = Backoff::default();
            let task = tokio::spawn(async move {
                let mut ship_failures = 0u32;
                let mut pull_failures = 0u32;
                let mut next_ship = tokio::time::Instant::now() + interval;
                let mut next_pull = tokio::time::Instant::now() + pull_interval;
                let mut next_import_eviction = tokio::time::Instant::now();
                loop {
                    let deadline = if puller.is_some() {
                        next_ship.min(next_pull).min(next_import_eviction)
                    } else {
                        next_ship
                    };
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => {
                            let now = tokio::time::Instant::now();
                            if now >= next_ship {
                                // Blocking: a round reads and flushes files. Off the runtime's threads.
                                let shipper = Arc::clone(&shipper);
                                let streams = Arc::clone(&streams);
                                let outcome = tokio::task::spawn_blocking(move || {
                                    let rounds = shipper.round();
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

                            if puller.is_some() && now >= next_pull {
                                let puller = puller.clone();
                                let outcome = tokio::task::spawn_blocking(move || {
                                    puller.map(|held| held.round()).unwrap_or_default()
                                }).await;
                                match outcome {
                                    Ok(rounds) => {
                                        let deferred = rounds.iter().any(|(_, round)| {
                                            matches!(round, PullRound::Deferred(_))
                                        });
                                        for (subscription, round) in rounds {
                                            if let PullRound::Quarantined { records, reason } = round {
                                                warn!(
                                                    event.name = "events.import_quarantined",
                                                    component = COMPONENT,
                                                    zone = subscription.zone.as_str(),
                                                    ledger = subscription.ledger.as_str(),
                                                    records,
                                                    reason = reason.as_str(),
                                                    "imported records were refused and not applied"
                                                );
                                            }
                                        }
                                        pull_failures = if deferred {
                                            pull_failures.saturating_add(1)
                                        } else {
                                            0
                                        };
                                    }
                                    Err(_) => pull_failures = pull_failures.saturating_add(1),
                                }
                                let wait = match pull_failures {
                                    0 => pull_interval,
                                    held => backoff.wait(held, jitter()),
                                };
                                next_pull = tokio::time::Instant::now() + wait;
                            }

                            if puller.is_some() && now >= next_import_eviction {
                                let puller = puller.clone();
                                let outcome = tokio::task::spawn_blocking(move || {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|held| held.as_secs() as i64)
                                        .unwrap_or_default();
                                    let horizon = now.saturating_sub(
                                        imported_retention.as_secs() as i64
                                    );
                                    puller
                                        .map(|held| held.evict_before(horizon))
                                        .unwrap_or_default()
                                }).await;
                                match outcome {
                                    Ok(results) => {
                                        for (subscription, result) in results {
                                            match result {
                                                Ok(0) => {}
                                                Ok(removed) => info!(
                                                    event.name = "events.import_evicted",
                                                    component = COMPONENT,
                                                    zone = subscription.zone.as_str(),
                                                    ledger = subscription.ledger.as_str(),
                                                    removed,
                                                    "imported copies no temporal policy can still read were removed"
                                                ),
                                                Err(error) => warn!(
                                                    event.name = "events.import_eviction_failed",
                                                    component = COMPONENT,
                                                    zone = subscription.zone.as_str(),
                                                    ledger = subscription.ledger.as_str(),
                                                    error = error.as_str(),
                                                    "imported history could not be compacted; keeping it is the safe direction"
                                                ),
                                            }
                                        }
                                    }
                                    Err(error) => warn!(
                                        event.name = "events.import_eviction_failed",
                                        component = COMPONENT,
                                        error = %error,
                                        "the imported-history compaction worker failed"
                                    ),
                                }
                                next_import_eviction = tokio::time::Instant::now()
                                    + IMPORT_EVICTION_INTERVAL;
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

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
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

/// The pull worker, when this deployment reads history other planes recorded.
///
/// `None` for `local`, which is the default and the ordinary case. A plane that reads only its own
/// events has nothing to import and nothing to verify, and building a worker for it would be
/// building something that runs and finds nothing for ever.
fn puller(
    context: &ServerContext<'_>,
    url: &str,
    tls: &permguard_control_client::TlsOptions,
) -> Result<Option<Arc<Puller>>> {
    let config = context.config();
    if !config.events_pull_mode().is_shared() {
        return Ok(None);
    }
    let reader = permguard_control_client::events::client(
        url,
        tls,
        Box::new(permguard_control_client::narrate::Silent),
    )
    .map_err(|error| anyhow!("reaching the event store at {url}: {error}"))?;

    // Whose signatures this plane accepts on imported records. Its own ring is deliberately not
    // among them: an imported record was produced by somebody else, and a plane that verified
    // against itself would accept anything it could have written.
    let keys = producer_keys(config);
    if keys.is_empty() {
        anyhow::bail!(
            "`dataPlane.events.pull.mode` is `{}` and this plane knows no producer's keys: name \
             them with producer and tenant bindings under \
             `dataPlane.events.pull.producer_keys`. Imported history would otherwise be applied \
             without authority to say who produced it",
            config.events_pull_mode().as_str()
        );
    }

    // Canonicalised against the mirrors this plane holds, for the same reason the submission path
    // is: a ledger answers to its identifiers and to its display names, and an operator may have
    // configured either. Imported history is keyed by identifier, so a subscription left as the
    // operator spelled it would ask for a stream nobody publishes and import nothing — silently,
    // because "no records" and "no such stream" look alike from a cursor.
    //
    // A pair this plane does not mirror is left as configured and named in the log: it may be a
    // ledger whose first synchronization has not landed yet, and refusing to start over that would
    // make an ordering problem into an outage.
    let mirrors = config.mirrors_directory();
    let canonical = |zone: &str, ledger: &str| -> (String, String) {
        match crate::authz::store::find(&mirrors, zone, ledger) {
            Some(mirror) => (
                mirror.identity.zone_id.clone(),
                mirror.identity.ledger_id.clone(),
            ),
            None => {
                warn!(
                    event.name = "events.subscription_unresolved",
                    component = COMPONENT,
                    zone,
                    ledger,
                    "a pull subscription names a ledger this plane does not mirror yet: it is used                      as written, and will import nothing until the mirror arrives"
                );

                (zone.to_owned(), ledger.to_owned())
            }
        }
    };
    let subscriptions: Vec<Subscription> = config
        .events_pull_ledgers()
        .iter()
        .map(|held| {
            let (zone, ledger) = canonical(&held.zone, &held.ledger);

            Subscription {
                zone,
                ledger,
                event_types: match held.event_types.is_empty() {
                    // Absent means the one type this build validates, stated rather than left open:
                    // the type set is part of the filter the read cursor is bound to, and a cursor
                    // bound to "everything" would keep meaning something different as types are added.
                    true => vec![permguard_languages::event::EVENT_TYPE.to_owned()],
                    false => held.event_types.clone(),
                },
            }
        })
        .collect();

    let imports = super::imports(config);
    for subscription in &subscriptions {
        imports
            .bind(
                &subscription.zone,
                &subscription.ledger,
                &subscription.event_types,
            )
            .with_context(|| {
                format!(
                    "binding the import cursor for `{}/{}` to its event types",
                    subscription.zone, subscription.ledger
                )
            })?;
    }

    let key_files = config
        .events_pull_producer_keys()
        .iter()
        .map(|source| super::pull::ProducerFile {
            path: config.working_dir().join(&source.path),
            producer: source.producer.clone(),
            zone: source.zone.clone(),
            ledger: source.ledger.clone(),
        })
        .collect();

    Ok(Some(Arc::new(
        Puller::new(
            reader,
            imports,
            subscriptions,
            keys,
            config.events_pull_mode(),
            context.metrics().clone(),
        )
        .with_key_files(key_files),
    )))
}

/// Where this plane exchanges event records, using the event destination when one is declared and
/// the decision-log endpoint otherwise for deployments that send both streams to one control
/// plane.
fn destination(
    context: &ServerContext<'_>,
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
    }
    .rooted_at(working_dir)
}

/// The producers' published key sets, from the paths the file names.
fn producer_keys(config: &permguard_core::Config) -> Vec<super::pull::ProducerTrust> {
    let mut keys = Vec::new();
    for source in config.events_pull_producer_keys() {
        let resolved = config.working_dir().join(&source.path);
        let Ok(text) = std::fs::read_to_string(&resolved) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        keys.extend(
            parsed
                .get("keys")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|value| serde_json::from_value::<permguard_core::Jwk>(value).ok())
                .map(|key| super::pull::ProducerTrust {
                    key,
                    producer: source.producer.clone(),
                    zone: source.zone.clone(),
                    ledger: source.ledger.clone(),
                }),
        );
    }

    keys
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
        let Ok(records) = streams.read_from(&zone, &ledger, safe, 100_000) else {
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
                zone = zone.as_str(),
                ledger = ledger.as_str(),
                removed,
                through = safe,
                "event records the control plane holds and no loaded policy can still read were \
                 removed"
            ),
            Err(error) => warn!(
                event.name = "events.eviction_failed",
                component = COMPONENT,
                zone = zone.as_str(),
                ledger = ledger.as_str(),
                error = %error,
                "event records could not be evicted: the journal keeps them, which is the safe \
                 direction"
            ),
        }
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
