// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One round of synchronization: ask each server what it has, keep what is
//! followed, mirror it, and remove what is no longer wanted.
//!
//! # The order matters
//!
//! Discovery first, then mirroring, then reaping — and reaping only for
//! servers that **answered**. A control plane that is unreachable must not
//! look like a control plane that deleted everything: an unanswered server
//! contributes nothing to the desired set, and nothing on disk is removed
//! because of it. Losing a connection is not a reason to lose a policy.
//!
//! # What a timeout can and cannot do
//!
//! Each mirror runs with a deadline, and the transports carry it into their
//! socket timeouts, which is where a stuck exchange actually gets cut. A
//! blocking thread cannot be killed in Rust — nothing can — so the honest
//! guarantee is this: a mirror that exceeds its deadline is **abandoned for
//! this round** (the round moves on and reports it), and the work it was
//! doing ends when its socket times out. Objects already fetched stay: they
//! are immutable and the next round reuses them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use permguard_control_client::pull::{self, TrackedRef};
use permguard_control_client::{AnyRemote, FsStore, TlsOptions};
use permguard_core::Metrics;

use crate::authz::store::Identity;
use tracing::{debug, info, warn};

use crate::mirrors::layout::{self, Mirror};
use crate::mirrors::measure;
use crate::mirrors::source::Source;

const COMPONENT: &str = "data-plane";

/// What one round did, for the log line, the audit record and the gauges.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Mirrors that advanced or were already current.
    pub synchronized: usize,
    /// Mirrors this engine may not serve: synchronized, and refused by the
    /// load gate. Counted apart from failures, because nothing went wrong
    /// here — the ledger simply asks for an engine this one is not.
    pub blocked: usize,
    /// Mirrors that failed or ran out of their deadline.
    pub failed: usize,
    /// Mirrors removed: no longer followed, or gone from the server.
    pub reaped: usize,
    /// Servers that did not answer at all — the reason nothing was reaped
    /// for them.
    pub unreachable: usize,
    /// Ledgers more than one answering server claimed, and which were
    /// therefore left untouched rather than taken from whichever was
    /// configured first.
    pub contested: usize,
}

impl Outcome {
    /// How the round ended, in one word, for the counter and the record.
    pub fn label(&self) -> &'static str {
        if self.failed == 0 && self.unreachable == 0 && self.contested == 0 {
            "ok"
        } else {
            "partial"
        }
    }
}

/// Everything a round needs, resolved once at start.
pub struct Context {
    pub sources: Vec<Source>,
    pub root: std::path::PathBuf,
    /// The decision path, so a ledger that just arrived is checked and
    /// compiled here — off the request path, where it belongs. `None` in a
    /// test that is only about mirroring.
    pub decider: Option<Arc<crate::authz::decide::Decider>>,
    pub deadline: Duration,
    pub parallelism: usize,
    /// The deployment's staleness bound, when it set one: a mirror whose last
    /// verified synchronization is older than this is alarmed on, per round.
    pub stale_after: Option<Duration>,
    /// The bound on work that is **physically** outstanding.
    ///
    /// A deadline abandons a mirror logically; the blocking task it started
    /// keeps running until its socket gives up, and a blocking task cannot be
    /// killed. So the permit is held by the work itself and released when the
    /// work ends, not when the round stops waiting for it. Without this, a
    /// pathological endpoint accumulates threads across rounds while
    /// `parallelism` reports a number nobody is enforcing.
    pub permits: Arc<tokio::sync::Semaphore>,
    pub metrics: Metrics,
}

/// Runs one round to completion.
///
/// Sequential across servers (there are a handful, and one slow server must
/// not hide another's failure in a race), concurrent across ledgers up to the
/// configured parallelism — because that is where the work is.
pub async fn run(context: Arc<Context>) -> Outcome {
    let started = Instant::now();
    let mut outcome = Outcome::default();
    let mut served: Vec<Served> = Vec::new();
    let mut answered = Vec::new();

    for source in &context.sources {
        match discover(source).await {
            Ok(found) => {
                let (zones, ledgers) = source.patterns();
                debug!(
                    event.name = "sync.discovered",
                    component = COMPONENT,
                    server = source.url(),
                    zone.patterns = zones.as_str(),
                    ledger.patterns = ledgers.as_str(),
                    mirrors = found.len(),
                    "the server listed what it has"
                );
                answered.push(source.url().to_owned());
                served.extend(found);
            }
            Err(error) => {
                outcome.unreachable += 1;
                warn!(
                    event.name = "sync.server_unreachable",
                    component = COMPONENT,
                    server = source.url(),
                    error = %error,
                    "the server did not answer: nothing it holds is removed on its account"
                );
            }
        }
    }

    served.sort_by(|left, right| left.mirror.cmp(&right.mirror));
    // Two servers offering one ledger is not a duplicate to fold away: it is
    // two authorities claiming the same policies, and taking the first is
    // deciding whose policies this plane serves by configuration order.
    outcome.contested = contested(&mut served);
    served.dedup_by(|left, right| left.mirror == right.mirror);
    let mut wanted: Vec<Mirror> = served.iter().map(|held| held.mirror.clone()).collect();
    wanted.sort();
    wanted.dedup();

    // Mirror what is wanted, a bounded number at a time.
    let mut running = Vec::new();
    let parallelism = context.parallelism.max(1);
    for held in served.clone() {
        let carried = Arc::clone(&context);
        running.push(tokio::spawn(async move {
            let mirror = held.mirror.clone();
            let outcome = mirror_one(&carried, &held).await;
            (mirror, outcome)
        }));
        if running.len() >= parallelism {
            outcome.absorb(join(&mut running).await);
        }
    }
    outcome.absorb(join(&mut running).await);

    // Reap, but only what a server that *answered this round* no longer wants.
    if !answered.is_empty() {
        outcome.reaped = reap(&context, &wanted, &answered);
    }

    context
        .metrics
        .count(&measure::ROUNDS, &[("outcome", outcome.label())]);
    context.metrics.observe(
        &measure::ROUND_SECONDS,
        &[],
        started.elapsed().as_secs_f64(),
    );
    holdings(&context, &wanted);

    outcome
}

impl Context {
    /// The trust material configured for the server that offered a mirror.
    ///
    /// Each server carries its own: two control planes in one file may sit
    /// behind two different authorities, and trusting one because the other
    /// was named would be exactly the confusion an exact URL exists to avoid.
    fn tls_for(&self, url: &str) -> TlsOptions {
        self.sources
            .iter()
            .find(|source| source.url() == url)
            .map(|source| source.tls().clone())
            .unwrap_or_default()
    }
}

impl Outcome {
    fn absorb(&mut self, tally: Tally) {
        self.synchronized += tally.synchronized;
        self.blocked += tally.blocked;
        self.failed += tally.failed;
    }
}

/// Waits for the running mirrors and counts how they ended.
async fn join(running: &mut Vec<tokio::task::JoinHandle<(Mirror, Attempt)>>) -> Tally {
    let mut tally = Tally::default();
    for handle in running.drain(..) {
        match handle.await {
            Ok((_, Attempt::Current)) => tally.synchronized += 1,
            Ok((_, Attempt::Blocked)) => {
                tally.synchronized += 1;
                tally.blocked += 1;
            }
            Ok((_, Attempt::Failed)) => tally.failed += 1,
            // A panicking mirror is a bug, and it must not take the loop with it.
            Err(error) => {
                tally.failed += 1;
                warn!(
                    event.name = "sync.mirror_panicked",
                    component = COMPONENT,
                    error = %error,
                    "a mirror task ended abnormally"
                );
            }
        }
    }

    tally
}

/// What a batch of mirrors came to.
#[derive(Debug, Default)]
struct Tally {
    synchronized: usize,
    blocked: usize,
    failed: usize,
}

/// How one mirror's round ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    /// Mirrored, and serveable.
    Current,
    /// Mirrored, and this engine may not serve it.
    Blocked,
    /// Not mirrored.
    Failed,
}

/// Asks one server what it has, and keeps what this source follows.
async fn discover(source: &Source) -> Result<Vec<Served>, String> {
    let url = source.url().to_owned();
    let tls = source.tls().clone();
    let source = source.clone();

    // The client is synchronous by design: this is a background job, and a
    // dedicated thread for a few seconds costs nothing a decision path feels.
    blocking(move || {
        let admin = permguard_control_client::catalog::client(
            &url,
            &tls,
            Box::new(permguard_control_client::narrate::Silent),
        )?;
        let mut found = Vec::new();
        for zone in admin
            .list_zones(None, None)
            .map_err(|failure| failure.detail)?
        {
            if !source.follows_zone(&zone.name) {
                continue;
            }
            for ledger in admin
                .list_ledgers(&zone.id, None, None)
                .map_err(|failure| failure.detail)?
            {
                if !source.follows_ledger(&ledger.name) {
                    continue;
                }
                found.push(Served {
                    mirror: Mirror {
                        zone_id: zone.id.clone(),
                        ledger_id: ledger.id.clone(),
                    },
                    server: url.clone(),
                    identity: Identity {
                        zone_id: zone.id.clone(),
                        zone_name: zone.name.clone(),
                        ledger_id: ledger.id.clone(),
                        ledger_name: ledger.name.clone(),
                        server: url.clone(),
                    },
                });
            }
        }
        Ok(found)
    })
    .await
}

/// One ledger a server offered: where it goes, who told us, and what it is
/// called — the names are what a decision request will ask for.
#[derive(Debug, Clone)]
pub struct Served {
    pub mirror: Mirror,
    pub server: String,
    pub identity: Identity,
}

/// Drops every mirror that more than one answering server claims.
///
/// A mirror is addressed by `(zone-id, ledger-id)` with no trust domain in the
/// path, so two servers offering those identities are indistinguishable once
/// the bytes are on disk. Serving either would mean this plane decided whose
/// policies it answers from by list order — which is not a decision, it is an
/// accident. So the ledger is left exactly as it is, and the conflict is
/// reported: an operator can narrow the patterns, and until then nothing
/// silently changes hands.
///
/// Note this is checked among servers that **answered this round**. A server
/// that is silent claims nothing, so an outage cannot make a ledger look
/// contested and stop it being followed.
fn contested(served: &mut Vec<Served>) -> usize {
    let mut refused = 0;
    let mut keep = Vec::with_capacity(served.len());
    let mut index = 0;
    while index < served.len() {
        let mut end = index + 1;
        while end < served.len() && served[end].mirror == served[index].mirror {
            end += 1;
        }
        let claimants: Vec<&str> = served[index..end]
            .iter()
            .map(|held| held.server.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if claimants.len() > 1 {
            refused += 1;
            warn!(
                event.name = "sync.ledger_contested",
                component = COMPONENT,
                zone = served[index].mirror.zone_id.as_str(),
                ledger = served[index].mirror.ledger_id.as_str(),
                servers = claimants.join(", ").as_str(),
                "two control planes offer the same ledger: it is left untouched rather than \
                 taken from whichever was configured first"
            );
        } else {
            keep.extend(served[index..end].iter().cloned());
        }
        index = end;
    }
    *served = keep;

    refused
}

/// Mirrors one ledger, within its deadline, and prepares it for serving.
async fn mirror_one(context: &Context, served: &Served) -> Attempt {
    let mirror = &served.mirror;
    let server = served.server.as_str();
    let labels = [
        ("zone", mirror.zone_id.as_str()),
        ("ledger", mirror.ledger_id.as_str()),
    ];
    let started = Instant::now();
    let path = mirror.path(&context.root);
    let mirror_path = path.clone();
    let url = server.to_owned();
    let tls = context.tls_for(server);
    let tracked = TrackedRef {
        zone_id: mirror.zone_id.clone(),
        ledger_id: mirror.ledger_id.clone(),
        r#ref: "main".to_owned(),
    };

    let identity = served.identity.clone();
    // Held by the work, not by the wait: see `Context::permits`.
    let permit = match Arc::clone(&context.permits).acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return Attempt::Failed,
    };
    let work = blocking(move || {
        let _permit = permit;
        std::fs::create_dir_all(&path).map_err(|error| format!("creating the mirror: {error}"))?;
        // What this mirror is called, beside what it is. Written every round,
        // so a rename upstream reaches this plane with the next sync.
        crate::authz::store::record(&path, &identity)?;
        let store = FsStore::new(&path);
        let remote = AnyRemote::connect(
            &url,
            &tls,
            Box::new(permguard_control_client::narrate::Silent),
        )?;
        remote.bind(&tracked.zone_id, &tracked.ledger_id);
        let verified = pull::fetch_closure(&store, "objects", "refs/main", &remote, &tracked)?;
        pull::commit_checkpoint(&store, "refs/main", &verified)?;
        Ok((verified.counter, verified.fetched))
    });

    match tokio::time::timeout(context.deadline, work).await {
        Ok(Ok((counter, fetched))) => {
            context.metrics.count(
                &measure::MIRRORS,
                &[
                    ("zone", mirror.zone_id.as_str()),
                    ("ledger", mirror.ledger_id.as_str()),
                    ("outcome", if fetched > 0 { "ok" } else { "unchanged" }),
                ],
            );
            context
                .metrics
                .add(&measure::FETCHED_OBJECTS, &labels, fetched as f64);
            context
                .metrics
                .set(&measure::MIRROR_COUNTER, &labels, counter as f64);
            crate::authz::store::touch_synced(&mirror_path);
            context.metrics.set(&measure::MIRROR_AGE, &labels, 0.0);
            context.metrics.observe(
                &measure::MIRROR_SECONDS,
                &labels,
                started.elapsed().as_secs_f64(),
            );
            if fetched > 0 {
                info!(
                    event.name = "sync.mirrored",
                    component = COMPONENT,
                    server = server,
                    ledger = mirror.label().as_str(),
                    counter = counter,
                    objects = fetched,
                    "the mirror advanced"
                );
            }

            // Now that the volume holds it: may this engine serve it, and can
            // it be compiled? Done here, once, off the decision path.
            warm(context, served).await
        }
        // A ledger with no history yet is not a failure: it is a ledger
        // nobody has applied to. The mirror exists, holds nothing, and fills
        // itself on the round after the first commit — pageing somebody for
        // every freshly created ledger would train them to ignore the page.
        Ok(Err(error)) if is_empty_ledger(&error) => {
            context.metrics.count(
                &measure::MIRRORS,
                &[
                    ("zone", mirror.zone_id.as_str()),
                    ("ledger", mirror.ledger_id.as_str()),
                    ("outcome", "empty"),
                ],
            );
            // A verified "nothing yet" is still a confirmation: the server
            // answered, and the emptiness is its answer.
            crate::authz::store::touch_synced(&mirror_path);
            context.metrics.set(&measure::MIRROR_COUNTER, &labels, 0.0);
            context.metrics.set(&measure::MIRROR_AGE, &labels, 0.0);
            debug!(
                event.name = "sync.ledger_empty",
                component = COMPONENT,
                server = server,
                ledger = mirror.label().as_str(),
                "the ledger has no history yet: the mirror waits for the first commit"
            );

            Attempt::Current
        }
        Ok(Err(error)) => {
            context.metrics.count(
                &measure::MIRRORS,
                &[
                    ("zone", mirror.zone_id.as_str()),
                    ("ledger", mirror.ledger_id.as_str()),
                    ("outcome", "failed"),
                ],
            );
            warn!(
                event.name = "sync.mirror_failed",
                component = COMPONENT,
                server = server,
                ledger = mirror.label().as_str(),
                error = %error,
                "the mirror did not advance; what it already holds is still served"
            );
            report_age(context, &mirror_path, &labels, mirror, server);

            Attempt::Failed
        }
        Err(_) => {
            context.metrics.count(
                &measure::MIRRORS,
                &[
                    ("zone", mirror.zone_id.as_str()),
                    ("ledger", mirror.ledger_id.as_str()),
                    ("outcome", "timeout"),
                ],
            );
            warn!(
                event.name = "sync.mirror_timeout",
                component = COMPONENT,
                server = server,
                ledger = mirror.label().as_str(),
                deadline.seconds = context.deadline.as_secs(),
                "the mirror ran out of its deadline and is abandoned for this round"
            );
            report_age(context, &mirror_path, &labels, mirror, server);

            Attempt::Failed
        }
    }
}

/// Publishes how stale a mirror actually is, and alarms when it crossed the
/// deployment's bound.
///
/// Only a failed round grows the age — a successful one just reset it — so
/// this is where the gauge earns its name: without it, a plane cut off from
/// its control plane would report an age of zero forever, which is the exact
/// number a page must never be written against.
fn report_age(
    context: &Context,
    mirror_path: &std::path::Path,
    labels: &[(&str, &str)],
    mirror: &Mirror,
    server: &str,
) {
    let Some(age) = crate::authz::store::synced_age(mirror_path) else {
        return;
    };
    context
        .metrics
        .set(&measure::MIRROR_AGE, labels, age.as_secs_f64());
    if let Some(bound) = context.stale_after
        && age >= bound
    {
        warn!(
            event.name = "sync.mirror_stale",
            component = COMPONENT,
            server = server,
            ledger = mirror.label().as_str(),
            age.seconds = age.as_secs(),
            bound.seconds = bound.as_secs(),
            "this mirror is older than the deployment's staleness bound: it is still served, and \
             this line is the alarm"
        );
    }
}

/// Reads a mirrored ledger for serving: the load gate, then the compile, into
/// the cache the surfaces answer from.
///
/// A ledger this engine may not serve is **not** a failed mirror: the mirror is
/// exactly what the server holds. It is a ledger that answers `unavailable`
/// until it changes, and [`crate::authz::block`] is what remembers that so the
/// next round costs one file read.
async fn warm(context: &Context, served: &Served) -> Attempt {
    let Some(decider) = context.decider.clone() else {
        return Attempt::Current;
    };
    let held = crate::authz::store::Mirror {
        path: served.mirror.path(&context.root),
        identity: served.identity.clone(),
    };
    let labels = [
        ("zone", served.identity.zone_name.clone()),
        ("ledger", served.identity.ledger_name.clone()),
    ];
    let warmed = match blocking(move || Ok(decider.warm(&held))).await {
        Ok(warmed) => warmed,
        Err(error) => crate::authz::decide::Warmed::Damaged(error),
    };
    context.metrics.count(
        &measure::WARMED,
        &[
            ("zone", labels[0].1.as_str()),
            ("ledger", labels[1].1.as_str()),
            ("outcome", warmed.label()),
        ],
    );

    match &warmed {
        crate::authz::decide::Warmed::Ready { compiled } => {
            if *compiled > 0 {
                info!(
                    event.name = "sync.ledger_ready",
                    component = COMPONENT,
                    ledger = served.mirror.label().as_str(),
                    partitions = compiled,
                    "the ledger is compiled and ready to answer decisions"
                );
            }

            Attempt::Current
        }
        crate::authz::decide::Warmed::Empty => Attempt::Current,
        crate::authz::decide::Warmed::Blocked(_) => Attempt::Blocked,
        crate::authz::decide::Warmed::Damaged(detail) => {
            warn!(
                event.name = "sync.ledger_damaged",
                component = COMPONENT,
                ledger = served.mirror.label().as_str(),
                error = detail.as_str(),
                "the mirror is present and could not be read for serving"
            );

            Attempt::Failed
        }
    }
}

/// Whether a refusal means "this ledger has no history yet" rather than
/// "something went wrong" — the server says so through the not-found class of
/// the shared taxonomy, on both transports.
fn is_empty_ledger(error: &str) -> bool {
    error.contains("not_found") || error.contains("NotFound") || error.contains("no ref")
}

/// Removes mirrors on disk that no answering server wants any more.
fn reap(context: &Context, wanted: &[Mirror], answered: &[String]) -> usize {
    let Ok(present) = layout::on_disk(&context.root) else {
        return 0;
    };
    let mut removed = 0;
    for mirror in present {
        if wanted.contains(&mirror) {
            continue;
        }
        // Absence is only evidence of deletion when the observation was
        // complete — and it is complete only for the server that put this
        // mirror here. A mirror whose server did not answer this round is a
        // mirror nobody has said anything about: it stays.
        //
        // Without this, a partition towards one of several control planes
        // would delete that control plane's policies from this plane, which is
        // exactly the failure the unreachable-server rule exists to prevent.
        let source = crate::authz::store::identity_of(&mirror.path(&context.root))
            .map(|identity| identity.server);
        match &source {
            Some(server) if answered.iter().any(|answered| answered == server) => {}
            Some(server) => {
                debug!(
                    event.name = "sync.reap_skipped",
                    component = COMPONENT,
                    ledger = mirror.label().as_str(),
                    server = server.as_str(),
                    "its server did not answer this round: nothing is removed on its account"
                );
                continue;
            }
            None => {
                // No identity file: this plane cannot attribute the mirror to
                // any server, so it cannot know whether anybody still wants
                // it. Reported rather than removed — the safe direction.
                context
                    .metrics
                    .count(&measure::REAPED, &[("reason", "unattributable")]);
                warn!(
                    event.name = "sync.reap_unattributable",
                    component = COMPONENT,
                    ledger = mirror.label().as_str(),
                    "the mirror names no server: it was left in place"
                );
                continue;
            }
        }
        match layout::remove(&context.root, &mirror) {
            Ok(()) => {
                removed += 1;
                context
                    .metrics
                    .count(&measure::REAPED, &[("reason", "not_followed")]);
                info!(
                    event.name = "sync.reaped",
                    component = COMPONENT,
                    ledger = mirror.label().as_str(),
                    "the mirror is no longer followed and was removed"
                );
            }
            Err(error) => warn!(
                event.name = "sync.reap_refused",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                error = %format!("{error:#}"),
                "the mirror was left in place"
            ),
        }
    }
    removed
}

/// Refreshes the holdings gauges: how many mirrors, in how many zones, and
/// what they occupy. Read from disk rather than counted along the way, so the
/// numbers cannot drift from the volume.
fn holdings(context: &Context, wanted: &[Mirror]) {
    if !context.metrics.is_recording() {
        return;
    }
    let Ok(present) = layout::on_disk(&context.root) else {
        return;
    };
    let _ = wanted;

    let mut per_zone: std::collections::BTreeMap<String, (u64, u64)> =
        std::collections::BTreeMap::new();
    for mirror in &present {
        let bytes = layout::size_of(&context.root, mirror);
        context.metrics.set(
            &measure::MIRROR_BYTES,
            &[
                ("zone", mirror.zone_id.as_str()),
                ("ledger", mirror.ledger_id.as_str()),
            ],
            bytes as f64,
        );
        let entry = per_zone.entry(mirror.zone_id.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
    }
    for (zone, (ledgers, bytes)) in &per_zone {
        context
            .metrics
            .set(&measure::ZONE_LEDGERS, &[("zone", zone)], *ledgers as f64);
        context
            .metrics
            .set(&measure::ZONE_BYTES, &[("zone", zone)], *bytes as f64);
    }
    context
        .metrics
        .set(&measure::MIRRORS_HELD, &[], present.len() as f64);
    context
        .metrics
        .set(&measure::ZONES_HELD, &[], per_zone.len() as f64);
}

/// Runs blocking work on the blocking pool, flattening the join error: a
/// panicking mirror is a bug, and it reads as a failure of that mirror alone.
async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(outcome) => outcome,
        Err(error) => Err(format!("the task ended abnormally: {error}")),
    }
}

#[cfg(test)]
mod contested_tests {
    use super::*;
    use crate::authz::store::Identity;

    fn served(server: &str, zone_id: &str, ledger_id: &str) -> Served {
        Served {
            mirror: Mirror {
                zone_id: zone_id.to_owned(),
                ledger_id: ledger_id.to_owned(),
            },
            server: server.to_owned(),
            identity: Identity {
                zone_id: zone_id.to_owned(),
                zone_name: "acme".to_owned(),
                ledger_id: ledger_id.to_owned(),
                ledger_name: "main-ledger".to_owned(),
                server: server.to_owned(),
            },
        }
    }

    #[test]
    fn a_ledger_two_servers_claim_is_dropped_rather_than_taken_from_the_first() {
        let mut held = vec![
            served("https://one.acme.com", "zone-1", "ledger-1"),
            served("https://two.acme.com", "zone-1", "ledger-1"),
            served("https://one.acme.com", "zone-2", "ledger-2"),
        ];
        held.sort_by(|left, right| left.mirror.cmp(&right.mirror));

        assert_eq!(contested(&mut held), 1);
        assert_eq!(
            held.len(),
            1,
            "the contested ledger is gone from what this round will mirror"
        );
        assert_eq!(held[0].mirror.zone_id, "zone-2");
    }

    #[test]
    fn one_server_listing_a_ledger_twice_is_not_a_conflict_with_itself() {
        let mut held = vec![
            served("https://one.acme.com", "zone-1", "ledger-1"),
            served("https://one.acme.com", "zone-1", "ledger-1"),
        ];

        assert_eq!(contested(&mut held), 0);
        assert_eq!(held.len(), 2, "the ordinary dedup still folds these");
    }
}
