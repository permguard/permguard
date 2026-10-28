// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One round of synchronization: ask each coordinator what its `policy.mirror` tasks cover, keep
//! what is followed, mirror it, and remove what is no longer wanted. The local task of a process
//! hosting both Planes is one more coordinator: this Host (WP-7.7).
//!
//! # The order matters
//!
//! Discovery first, then mirroring, then reaping — and reaping only for
//! coordinators that **answered**. A coordinator that is unreachable must not
//! look like one that deleted everything: an unanswered coordinator
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

use permguard_control_client::FsStore;
use permguard_control_client::pull::TrackedRef;
use permguard_core::Metrics;

use crate::authz::store::Identity;
use tracing::{debug, info, warn};

use crate::mirrors::layout::{self, Mirror};
use crate::mirrors::measure;

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
    /// Coordinators that did not answer at all — the reason nothing was reaped
    /// for them.
    pub unreachable: usize,
    /// Pairs of names more than one mirror answers to, which the decision path refuses until an
    /// alias names the authority they mean.
    pub contested: usize,
    /// How each coordinator fared, by its source key: what the plane's
    /// readiness is decided from (P2, F-13).
    pub sources: Vec<SourceOutcome>,
    /// Failures by the coordinator that listed the mirror, folded into `sources`
    /// once the round is over; of no interest after that.
    pub(super) failed_by_server: std::collections::BTreeMap<String, usize>,
    /// The coordinators this round's `policy.mirror` tasks named, by source key, and whether any
    /// of their tasks is required (WP-7.2a): what readiness waits for.
    pub coordinators: Vec<(String, bool)>,
    /// What became of reap candidates this round, each `(action, mirror)`, the mirror by its label
    /// (WP-7.2d): `mirror.tombstoned`, `mirror.restored` or `mirror.reaped`, for the audit trail.
    pub candidacy: Vec<(&'static str, String)>,
    /// The mirrors past the staleness bound at the end of the round, by label, and whether the
    /// task or server they come from is required (WP-7.2d, F-14).
    pub stale: Vec<(String, bool)>,
}

/// One server's part in a round.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceOutcome {
    /// The server, exactly as configured.
    pub url: String,
    /// Whether it answered discovery at all.
    pub answered: bool,
    /// Mirrors it offered that were not mirrored this round.
    pub failed: usize,
}

impl SourceOutcome {
    /// Whether a round from this server succeeded: it answered, and every
    /// ledger it offered is mirrored.
    pub fn succeeded(&self) -> bool {
        self.answered && self.failed == 0
    }
}

impl Outcome {
    /// How the round ended, in one word, for the counter and the record.
    pub fn label(&self) -> &'static str {
        if self.label_success() {
            "ok"
        } else {
            "partial"
        }
    }

    /// Whether the round was a success for the loop's own record: nothing
    /// failed, every server answered, nothing was contested.
    pub fn label_success(&self) -> bool {
        self.failed == 0 && self.unreachable == 0 && self.contested == 0
    }
}

/// The Host's legal and incident holds as the reap reads them (WP-7.3c).
#[derive(Clone, Default)]
pub enum Holds {
    /// No Host registered this plane: nothing is held.
    #[default]
    None,
    /// The Host's hold store.
    Store(Arc<permguard_host::holds::HoldStore>),
    /// The plane reads holds and was handed none: nothing is reaped, since what a hold keeps is
    /// never guessed.
    Unavailable,
}

impl std::fmt::Debug for Holds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Store(_) => "Store",
            Self::Unavailable => "Unavailable",
        })
    }
}

/// Everything a round needs, resolved once at start.
pub struct Context {
    /// The member side of `policy.mirror` (WP-7.2a): the tasks this Host holds, snapshot every
    /// round, and a session on each. `None` where the Host holds no memberships.
    pub tasks: Option<Arc<dyn permguard_host::composition::MirrorTasks>>,
    /// How the file narrows those tasks: none, every task followed whole.
    pub selections: super::source::TaskSelections,
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
    /// How long a task mirror its task no longer lists is kept before it is reaped (WP-7.2d).
    pub reap_grace: Duration,
    /// The Host's holds: a mirror whose ledger or zone a hold in force names is never reaped.
    pub holds: Holds,
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
/// Sequential across coordinators (there are a handful, and one slow coordinator must not hide
/// another's failure in a race), concurrent across ledgers up to the configured parallelism —
/// because that is where the work is.
pub async fn run(context: Arc<Context>) -> Outcome {
    let started = Instant::now();
    let mut outcome = Outcome::default();
    let mut served: Vec<Served> = Vec::new();
    let mut answered = Vec::new();
    // The tasks whose listing was complete this round, as `<membership-id>/<task-id>` with their
    // revision: the only evidence a task mirror is no longer served (WP-7.2a).
    let mut listed_whole: Vec<(String, u64)> = Vec::new();
    // The session of every task listed this round: what its progress is reported on (WP-7.2d).
    let mut sessions = Vec::new();
    // What the staleness alarm names as required: the required tasks this Host holds, whether
    // their coordinator answered or not (WP-7.2d).
    let mut required: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // The coordinators of this Host's `policy.mirror` tasks (WP-7.2a): each its own source, its
    // ledgers under its authority.
    if let Some(tasks) = &context.tasks {
        let held = tasks.mirror_tasks();
        if held.is_empty() {
            // Not a failure: a plane not yet enrolled holds no task, and refuses every ledger as
            // one it does not serve. Said every round, so it is never mistaken for a quiet plane.
            warn!(
                event.name = "sync.no_task",
                component = COMPONENT,
                "this Host holds no `policy.mirror` task: it mirrors and serves nothing until it is \
                 enrolled with a Control Plane's Host (`permguard host members join`)"
            );
        }
        context.selections.report_unmatched(&held);
        required.extend(held.iter().filter(|task| task.required).map(task_label));
        // A required task the file leaves out still counts for readiness: the signed manifest
        // says what the plane waits for, not a local file (WP-7.2a).
        let left_out: Vec<(String, bool)> = held
            .iter()
            .filter(|task| {
                task.required
                    && !context
                        .selections
                        .follows_task(&task.membership_id, &task.task_id)
            })
            .map(|task| (source_key(&layout::authority_name(&task.coordinator)), true))
            .collect();
        let followed = held
            .into_iter()
            .filter(|task| {
                context
                    .selections
                    .follows_task(&task.membership_id, &task.task_id)
            })
            .collect();
        for coordinator in by_coordinator(followed) {
            let key = coordinator.key();
            match listed(tasks.as_ref(), &coordinator, &context.selections).await {
                Ok(Listed {
                    found,
                    complete,
                    whole,
                    sessions: opened,
                }) => {
                    listed_whole.extend(whole);
                    sessions.extend(opened);
                    debug!(
                        event.name = "sync.discovered",
                        component = COMPONENT,
                        server = key.as_str(),
                        mirrors = found.len(),
                        complete,
                        "the coordinator listed what its tasks cover"
                    );
                    // Only a complete listing of every task of the coordinator is evidence of
                    // what it no longer serves.
                    if complete {
                        answered.push(key.clone());
                    }
                    served.extend(found);
                }
                Err(error) => {
                    outcome.unreachable += 1;
                    warn!(
                        event.name = "sync.server_unreachable",
                        component = COMPONENT,
                        server = key.as_str(),
                        error = %error,
                        "the coordinator did not answer: nothing it serves is removed on its account"
                    );
                }
            }
            outcome.coordinators.push((key, coordinator.required));
        }
        for (key, required) in left_out {
            match outcome
                .coordinators
                .iter_mut()
                .find(|(known, _)| *known == key)
            {
                Some((_, known)) => *known |= required,
                None => outcome.coordinators.push((key, required)),
            }
        }
    }

    // A mirror is named by its authority (WP-7.2a): two coordinators listing one pair of ids land
    // in two mirrors, and a pair listed twice by one coordinator is one mirror.
    served.sort_by(|left, right| left.mirror.cmp(&right.mirror));
    served.dedup_by(|left, right| left.mirror == right.mirror);
    let mut wanted: Vec<Mirror> = served.iter().map(|held| held.mirror.clone()).collect();
    wanted.sort();
    wanted.dedup();

    // Mirror what is wanted, a bounded number at a time.
    let mut running = Vec::new();
    let parallelism = context.parallelism.max(1);
    for held in served.clone() {
        let carried = Arc::clone(&context);
        // The server is kept beside the task, not inside it: a mirror that panics is still
        // charged to the server that offered it, so its source cannot count as succeeded.
        let server = held.server.clone();
        running.push((
            server,
            tokio::spawn(async move {
                let mirror = held.mirror.clone();
                let outcome = mirror_one(&carried, &held).await;
                (mirror, outcome)
            }),
        ));
        if running.len() >= parallelism {
            outcome.absorb(join(&mut running).await);
        }
    }
    outcome.absorb(join(&mut running).await);

    // Reap, but only what a coordinator that *answered this round* no longer wants, and the
    // mirrors of a configured URL whatever answered (WP-7.7).
    let (reaped, candidacy) = reap(&context, &wanted, &answered, &listed_whole);
    outcome.reaped = reaped;
    outcome.candidacy = candidacy;
    // Two mirrors answering to one name are refused at the decision path: said here too, every
    // round, so the contest is seen before a request is refused over it (WP-7.2a).
    for ((zone, ledger), claimants) in crate::authz::store::contests(&context.root) {
        outcome.contested += 1;
        warn!(
            event.name = "sync.ledger_contested",
            component = COMPONENT,
            zone = zone.as_str(),
            ledger = ledger.as_str(),
            mirrors = claimants.join(", ").as_str(),
            "more than one mirror answers to this ledger's names: neither is served until one of \
             them is no longer followed, or an alias names the authority it means"
        );
    }
    outcome.stale = staleness(&context, &required);
    // What each task's mirrors came to, on its own session (WP-7.2d).
    super::progress::report(
        &context.root,
        &sessions,
        context.stale_after,
        context.deadline,
    )
    .await;
    let coordinators = outcome
        .coordinators
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    outcome.sources = coordinators
        .into_iter()
        .map(|url| SourceOutcome {
            answered: answered.iter().any(|answered| answered == &url),
            failed: outcome.failed_by_server.get(&url).copied().unwrap_or(0),
            url,
        })
        .collect();

    context.metrics.count(
        &measure::ROUNDS,
        &[(permguard_core::metrics::labels::OUTCOME, outcome.label())],
    );
    context.metrics.observe(
        &measure::ROUND_SECONDS,
        &[],
        started.elapsed().as_secs_f64(),
    );
    holdings(&context);

    outcome
}

impl Outcome {
    fn absorb(&mut self, tally: Tally) {
        self.synchronized += tally.synchronized;
        self.blocked += tally.blocked;
        self.failed += tally.failed;
        for (server, failed) in tally.failed_by_server {
            *self.failed_by_server.entry(server).or_default() += failed;
        }
    }
}

/// Waits for the running mirrors and counts how they ended, by the server that offered each.
async fn join(running: &mut Vec<(String, tokio::task::JoinHandle<(Mirror, Attempt)>)>) -> Tally {
    let mut tally = Tally::default();
    for (server, handle) in running.drain(..) {
        match handle.await {
            Ok((_, Attempt::Current)) => tally.synchronized += 1,
            Ok((_, Attempt::Blocked)) => {
                tally.synchronized += 1;
                tally.blocked += 1;
            }
            Ok((_, Attempt::Failed)) => {
                tally.failed += 1;
                *tally.failed_by_server.entry(server).or_default() += 1;
            }
            // A panicking mirror is a bug, and it must not take the loop with it; it is a
            // failure of the server's round like any other.
            Err(error) => {
                tally.failed += 1;
                *tally.failed_by_server.entry(server).or_default() += 1;
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
    failed_by_server: std::collections::BTreeMap<String, usize>,
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

/// One ledger a coordinator's task listed: where it goes, who told us, and what it is called —
/// the names are what a decision request will ask for.
#[derive(Debug, Clone)]
pub struct Served {
    pub mirror: Mirror,
    pub server: String,
    pub identity: Identity,
    /// How its reads travel: the session of the task that listed it.
    pub via: Via,
}

/// How a mirror's reads travel: a `policy.mirror` task session (WP-7.2a), the task's bound on a
/// message, the `control.attest` set its membership pins (or, for the local task, this Host's
/// own) and the coordinator the statements must name (WP-7.2b).
#[derive(Clone)]
pub struct Via {
    pub session: super::task::Shared,
    pub max_body_bytes: u64,
    pub ring: permguard_host::composition::PinnedRing,
    pub coordinator: [u8; 16],
    /// The task's revision: the epoch of the manifest it was read from (WP-7.2c).
    pub revision: u64,
}

impl std::fmt::Debug for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Via")
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

/// The `policy.mirror` tasks of one coordinator: one source, however many tasks and sessions
/// reach it (F-16).
pub(super) struct Coordinator {
    pub(super) authority: String,
    pub(super) tasks: Vec<permguard_host::composition::MirrorTask>,
    pub(super) required: bool,
}

impl Coordinator {
    /// The source key its mirrors are attributed to, in their identity and in the outcome.
    pub(super) fn key(&self) -> String {
        source_key(&self.authority)
    }
}

/// The source key of the mirrors an authority serves.
pub fn source_key(authority: &str) -> String {
    format!("host:{authority}")
}

/// `tasks`, grouped by coordinator, in a stable order.
pub(super) fn by_coordinator(
    tasks: Vec<permguard_host::composition::MirrorTask>,
) -> Vec<Coordinator> {
    let mut grouped: std::collections::BTreeMap<String, Coordinator> =
        std::collections::BTreeMap::new();
    for task in tasks {
        let authority = layout::authority_name(&task.coordinator);
        let held = grouped
            .entry(authority.clone())
            .or_insert_with(|| Coordinator {
                authority,
                tasks: Vec::new(),
                required: false,
            });
        held.required |= task.required;
        held.tasks.push(task);
    }
    let mut coordinators: Vec<Coordinator> = grouped.into_values().collect();
    for coordinator in &mut coordinators {
        coordinator.tasks.sort_by(|left, right| {
            (left.membership_id, &left.task_id).cmp(&(right.membership_id, &right.task_id))
        });
    }
    coordinators
}

/// What `coordinator`'s tasks list, and whether every listing was complete: a session per task,
/// its ledgers under the coordinator's authority. A task that cannot be opened or listed fails
/// the coordinator for this round.
async fn listed(
    tasks: &dyn permguard_host::composition::MirrorTasks,
    coordinator: &Coordinator,
    selections: &super::source::TaskSelections,
) -> Result<Listed, String> {
    let mut found = Vec::new();
    let mut complete = true;
    let mut whole = Vec::new();
    let mut sessions = Vec::new();
    for task in &coordinator.tasks {
        let session = tasks
            .open_mirror(task)
            .await
            .map_err(|refusal| format!("opening task `{}`: {refusal}", task.task_id))?;
        // The set the membership pins as the session opened, its binding verified under the
        // coordinator's identity: a task without one has nothing its statements could verify
        // under, and none of its ledgers is mirrored (WP-7.2b).
        let Some(ring) = session.ring() else {
            warn!(
                event.name = "sync.task_unpinned",
                component = COMPONENT,
                task = task.task_id.as_str(),
                "the membership pins no coordinator `control.attest` set this Host can verify: \
                 none of the task's ledgers is mirrored"
            );
            return Err(format!(
                "task `{}`: its membership pins no verifiable coordinator `control.attest` set",
                task.task_id
            ));
        };
        let session: super::task::Shared = Arc::new(tokio::sync::Mutex::new(session));
        sessions.push((task.clone(), Arc::clone(&session)));
        let listing = super::task::list(&session, task).await?;
        complete &= listing.complete;
        let label = task_label(task);
        if listing.complete {
            whole.push((label.clone(), task.revision));
        }
        for ledger in listing.ledgers {
            if !selections.follows(
                &task.membership_id,
                &task.task_id,
                &ledger.zone_name,
                &ledger.ledger_name,
            ) {
                continue;
            }
            found.push(Served {
                mirror: Mirror {
                    authority: Some(coordinator.authority.clone()),
                    zone_id: ledger.zone_id.clone(),
                    ledger_id: ledger.ledger_id.clone(),
                },
                server: coordinator.key(),
                identity: Identity {
                    zone_id: ledger.zone_id,
                    zone_name: ledger.zone_name,
                    ledger_id: ledger.ledger_id,
                    ledger_name: ledger.ledger_name,
                    server: coordinator.key(),
                    authority: Some(coordinator.authority.clone()),
                    task: Some(label.clone()),
                },
                via: Via {
                    session: Arc::clone(&session),
                    max_body_bytes: task.max_body_bytes,
                    ring: ring.clone(),
                    coordinator: task.coordinator,
                    revision: task.revision,
                },
            });
        }
    }
    Ok(Listed {
        found,
        complete,
        whole,
        sessions,
    })
}

/// What a coordinator's tasks listed: the ledgers, whether every listing was complete, the tasks
/// that listed whole with their revisions, and the session of each task, for its progress.
struct Listed {
    found: Vec<Served>,
    complete: bool,
    whole: Vec<(String, u64)>,
    sessions: Vec<(permguard_host::composition::MirrorTask, super::task::Shared)>,
}

/// How a task names the mirrors it listed: `<membership-id>/<task-id>`.
pub fn task_label(task: &permguard_host::composition::MirrorTask) -> String {
    format!(
        "{}/{}",
        permguard_host::identity::record::uuid_text(&task.membership_id),
        task.task_id
    )
}

/// Mirrors one ledger, within its deadline, and prepares it for serving.
async fn mirror_one(context: &Context, served: &Served) -> Attempt {
    let mirror = &served.mirror;
    let server = served.server.as_str();
    let started = Instant::now();
    let path = mirror.path(&context.root);
    let mirror_path = path.clone();
    let tracked = TrackedRef {
        zone_id: mirror.zone_id.clone(),
        ledger_id: mirror.ledger_id.clone(),
        r#ref: "main".to_owned(),
    };

    let identity = served.identity.clone();
    let via = served.via.clone();
    let runtime = tokio::runtime::Handle::current();
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
        // The pull and its verification on the task's session (WP-7.2a), its statements verified
        // under the pinned `control.attest` set (WP-7.2b), switched through the mirror's journal
        // (WP-7.2c).
        let Via {
            session,
            max_body_bytes,
            ring,
            coordinator,
            revision,
        } = via;
        // The state in force first: views a crash left behind the journal are rewritten.
        super::state::recover(&path)?;
        let remote = super::task::TaskRemote::new(
            session,
            runtime,
            &tracked.zone_id,
            &tracked.ledger_id,
            max_body_bytes,
            &ring,
        );
        let verified = super::task::verified_pull(&store, &tracked, &remote, &ring, coordinator)?;
        super::state::commit(
            &path,
            &super::state::MirrorState {
                revision,
                authority: verified.authority_host_id,
                zone: tracked.zone_id.clone(),
                ledger: tracked.ledger_id.clone(),
                reference: verified.reference.clone(),
                head: verified.head.clone(),
                counter: verified.counter,
                ref_digest: verified.ref_digest.clone(),
                ring_epoch: verified.ring_epoch,
                key_set_digest: ring.key_set_digest,
                verified_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|since| since.as_secs())
                    .unwrap_or_default(),
                closure_digest: super::state::closure_digest(&verified.closure),
                verified: verified.statement.clone(),
                ring_binding: ring.binding.clone(),
            },
        )?;
        Ok((verified.counter, verified.fetched))
    });

    match tokio::time::timeout(context.deadline, work).await {
        Ok(Ok((counter, fetched))) => {
            context.metrics.count(
                &measure::MIRRORS,
                &[(
                    permguard_core::metrics::labels::OUTCOME,
                    if fetched > 0 { "ok" } else { "unchanged" },
                )],
            );
            context
                .metrics
                .add(&measure::FETCHED_OBJECTS, &[], fetched as f64);
            crate::authz::store::touch_synced(&mirror_path);
            context.metrics.set_aggregated(
                &measure::MIRROR_AGE,
                permguard_core::Aggregate::Max,
                &mirror_key(mirror),
                0.0,
            );
            context.metrics.observe(
                &measure::MIRROR_SECONDS,
                &[],
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
                &[(permguard_core::metrics::labels::OUTCOME, "empty")],
            );
            // A verified "nothing yet" is still a confirmation: the server
            // answered, and the emptiness is its answer.
            crate::authz::store::touch_synced(&mirror_path);
            context.metrics.set_aggregated(
                &measure::MIRROR_AGE,
                permguard_core::Aggregate::Max,
                &mirror_key(mirror),
                0.0,
            );
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
                &[(permguard_core::metrics::labels::OUTCOME, "failed")],
            );
            warn!(
                event.name = "sync.mirror_failed",
                component = COMPONENT,
                server = server,
                ledger = mirror.label().as_str(),
                error = %error,
                "the mirror did not advance; what it already holds is still served"
            );

            Attempt::Failed
        }
        Err(_) => {
            context.metrics.count(
                &measure::MIRRORS,
                &[(permguard_core::metrics::labels::OUTCOME, "timeout")],
            );
            warn!(
                event.name = "sync.mirror_timeout",
                component = COMPONENT,
                server = server,
                ledger = mirror.label().as_str(),
                deadline.seconds = context.deadline.as_secs(),
                "the mirror ran out of its deadline and is abandoned for this round"
            );

            Attempt::Failed
        }
    }
}

/// Publishes how stale every held mirror is, and alarms on each past the deployment's bound
/// (WP-7.2d, F-14): the mirrors this round could not reach included, which is the point — a plane
/// cut off from its coordinator still measures what it holds, from its last verified
/// synchronization, and the alarm names each ledger, its task or server, and whether that is
/// required. Answers the stale mirrors by label.
fn staleness(
    context: &Context,
    required: &std::collections::BTreeSet<String>,
) -> Vec<(String, bool)> {
    let mut stale = Vec::new();
    let Ok(present) = layout::on_disk(&context.root) else {
        return stale;
    };
    for mirror in present {
        let path = mirror.path(&context.root);
        let Some(age) = crate::authz::store::synced_age(&path) else {
            continue;
        };
        context.metrics.set_aggregated(
            &measure::MIRROR_AGE,
            permguard_core::Aggregate::Max,
            &mirror_key(&mirror),
            age.as_secs_f64(),
        );
        let Some(bound) = context.stale_after else {
            continue;
        };
        if age < bound {
            continue;
        }
        let identity = crate::authz::store::identity_of(&path);
        let source = identity
            .as_ref()
            .map(|held| held.task.clone().unwrap_or_else(|| held.server.clone()))
            .unwrap_or_default();
        let is_required = required.contains(&source);
        warn!(
            event.name = "sync.mirror_stale",
            component = COMPONENT,
            ledger = mirror.label().as_str(),
            source = source.as_str(),
            required = is_required,
            age.seconds = age.as_secs(),
            bound.seconds = bound.as_secs(),
            "this mirror is older than the deployment's staleness bound: it is still served, and \
             this line is the alarm"
        );
        stale.push((mirror.label(), is_required));
    }
    context
        .metrics
        .set(&measure::MIRRORS_STALE, &[], stale.len() as f64);
    stale
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
    let warmed = match blocking(move || Ok(decider.warm(&held))).await {
        Ok(warmed) => warmed,
        Err(error) => crate::authz::decide::Warmed::Damaged(error),
    };
    context.metrics.count(
        &measure::WARMED,
        &[(permguard_core::metrics::labels::OUTCOME, warmed.label())],
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

/// Removes mirrors on disk that no answering server wants any more, and what became of each
/// task mirror's candidacy (WP-7.2d).
fn reap(
    context: &Context,
    wanted: &[Mirror],
    answered: &[String],
    listed_whole: &[(String, u64)],
) -> (usize, Vec<(&'static str, String)>) {
    let mut candidacy = Vec::new();
    let Ok(present) = layout::on_disk(&context.root) else {
        return (0, candidacy);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    let mut removed = 0;
    for mirror in present {
        let path = mirror.path(&context.root);
        // A mirror of a configured URL, in the first shape (WP-7.7): a re-pullable cache whose
        // authority a URL never proved, never served since, removed whatever answered — unless a
        // hold names its ledger.
        if mirror.authority.is_none() {
            if !held_by_a_hold(context, &mirror, now) {
                removed += remove_reaped(context, &mirror, "retired", &mut candidacy);
            }
            continue;
        }
        if wanted.contains(&mirror) {
            // Listed again: a candidacy ends, and the mirror was never touched (WP-7.2d).
            match super::tombstone::clear(&path) {
                Ok(true) => {
                    info!(
                        event.name = "sync.mirror_restored",
                        component = COMPONENT,
                        ledger = mirror.label().as_str(),
                        "its task lists the mirror again: it is no longer a reap candidate"
                    );
                    candidacy.push(("mirror.restored", mirror.label()));
                }
                Ok(false) => {}
                Err(error) => warn!(
                    event.name = "sync.tombstone_unremovable",
                    component = COMPONENT,
                    ledger = mirror.label().as_str(),
                    error = error.as_str(),
                    "the tombstone of a listed mirror could not be removed"
                ),
            }
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
        let identity = crate::authz::store::identity_of(&path);
        // A task's mirror is attributed to that task, not to its coordinator: another task of
        // the same coordinator listing whole says nothing of it, and a task this round did not
        // list — its membership suspended, its listing cut short — removes nothing (WP-7.2a).
        // Its own task's whole listing is the evidence, and the only one: what another task of
        // the coordinator listed, whole or not, decides nothing about it.
        let task_whole = match identity.as_ref().and_then(|held| held.task.as_ref()) {
            Some(task) => match listed_whole.iter().find(|(whole, _)| whole == task) {
                Some((_, revision)) => Some((task.clone(), *revision)),
                None => {
                    debug!(
                        event.name = "sync.reap_skipped",
                        component = COMPONENT,
                        ledger = mirror.label().as_str(),
                        task = task.as_str(),
                        "the task that listed it did not list whole this round: nothing is removed"
                    );
                    continue;
                }
            },
            None => None,
        };
        let source = identity.map(|identity| identity.server);
        match &source {
            _ if task_whole.is_some() => {}
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
                context.metrics.count(
                    &measure::REAPED,
                    &[(permguard_core::metrics::labels::REASON, "unattributable")],
                );
                warn!(
                    event.name = "sync.reap_unattributable",
                    component = COMPONENT,
                    ledger = mirror.label().as_str(),
                    "the mirror names no server: it was left in place"
                );
                continue;
            }
        }
        // A task mirror goes only on a second complete listing without it, the grace after the
        // first: the first writes its tombstone and the mirror keeps serving (WP-7.2d).
        if let Some((task, revision)) = task_whole {
            let first = match super::tombstone::read(&path) {
                Ok(Some(tombstone)) => Some(tombstone.first_absent_at),
                Ok(None) => None,
                Err(error) => {
                    // Unreadable: the candidacy starts again, never shortened.
                    warn!(
                        event.name = "sync.tombstone_unreadable",
                        component = COMPONENT,
                        ledger = mirror.label().as_str(),
                        error = error.as_str(),
                        "the mirror's tombstone could not be read: its grace starts again"
                    );
                    None
                }
            };
            let Some(first) = first else {
                let tombstone = super::tombstone::Tombstone {
                    first_absent_at: now,
                    task,
                    revision,
                };
                match super::tombstone::write(&path, &tombstone) {
                    Ok(()) => {
                        info!(
                            event.name = "sync.mirror_tombstoned",
                            component = COMPONENT,
                            ledger = mirror.label().as_str(),
                            grace.seconds = context.reap_grace.as_secs(),
                            "its task no longer lists the mirror: it is a reap candidate, and \
                             still served"
                        );
                        candidacy.push(("mirror.tombstoned", mirror.label()));
                    }
                    Err(error) => warn!(
                        event.name = "sync.reap_refused",
                        component = COMPONENT,
                        ledger = mirror.label().as_str(),
                        error = error.as_str(),
                        "the mirror's tombstone could not be written: it was left in place"
                    ),
                }
                continue;
            };
            if now.saturating_sub(first) < context.reap_grace.as_secs() {
                debug!(
                    event.name = "sync.reap_deferred",
                    component = COMPONENT,
                    ledger = mirror.label().as_str(),
                    "the mirror is a reap candidate within its grace"
                );
                continue;
            }
        }
        // A hold keeps the ledger: the mirror stays, a candidate, until the hold goes (WP-7.3c).
        if held_by_a_hold(context, &mirror, now) {
            continue;
        }
        removed += remove_reaped(context, &mirror, "not_followed", &mut candidacy);
    }
    (removed, candidacy)
}

/// Whether a hold keeps `mirror`'s ledger (WP-7.3c), or the holds cannot be read: either way the
/// mirror stays.
fn held_by_a_hold(context: &Context, mirror: &Mirror, now: u64) -> bool {
    let held = match &context.holds {
        Holds::None => Ok(false),
        Holds::Store(store) => store
            .keeps(&mirror.zone_id, &mirror.ledger_id, now)
            .map_err(|error| error.to_string()),
        Holds::Unavailable => Err("this plane was handed no hold store".to_owned()),
    };
    match held {
        Ok(false) => false,
        Ok(true) => {
            info!(
                event.name = "sync.reap_held",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                "a hold keeps this ledger: the mirror stays"
            );
            true
        }
        Err(error) => {
            warn!(
                event.name = "sync.reap_refused",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                error = error.as_str(),
                "the holds could not be read: nothing is removed"
            );
            true
        }
    }
}

/// Removes `mirror`, counted under `reason` and recorded as `mirror.reaped`: one when it went.
fn remove_reaped(
    context: &Context,
    mirror: &Mirror,
    reason: &'static str,
    candidacy: &mut Vec<(&'static str, String)>,
) -> usize {
    match layout::remove(&context.root, mirror) {
        Ok(()) => {
            context.metrics.count(
                &measure::REAPED,
                &[(permguard_core::metrics::labels::REASON, reason)],
            );
            info!(
                event.name = "sync.reaped",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                reason,
                "the mirror is no longer followed and was removed"
            );
            candidacy.push(("mirror.reaped", mirror.label()));
            1
        }
        Err(error) => {
            warn!(
                event.name = "sync.reap_refused",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                error = %format!("{error:#}"),
                "the mirror was left in place"
            );
            0
        }
    }
}

/// Refreshes the holdings gauges: how many mirrors, in how many zones, and
/// what they occupy. Read from disk rather than counted along the way, so the
/// numbers cannot drift from the volume.
fn holdings(context: &Context) {
    if !context.metrics.is_recording() {
        return;
    }
    let Ok(present) = layout::on_disk(&context.root) else {
        return;
    };
    // A mirror that is no longer on the volume stops counting: its age would otherwise hold the
    // oldest-mirror gauge up until the process restarts, and its blocked state would stay counted.
    let held: std::collections::BTreeSet<String> = present.iter().map(mirror_key).collect();
    for (metric, how) in [
        (&measure::MIRROR_AGE, permguard_core::Aggregate::Max),
        (
            &crate::authz::measure::BLOCKED,
            permguard_core::Aggregate::Sum,
        ),
    ] {
        context
            .metrics
            .retain_aggregated(metric, how, |resource| held.contains(resource));
    }

    // Totals only: a mirror's own size would be a series per ledger, which P10 forbids.
    let mut zones = std::collections::BTreeSet::new();
    let mut total_bytes = 0u64;
    for mirror in &present {
        total_bytes += layout::size_of(&context.root, mirror);
        zones.insert(mirror.zone_id.clone());
    }
    context
        .metrics
        .set(&measure::MIRROR_BYTES, &[], total_bytes as f64);
    context
        .metrics
        .set(&measure::MIRRORS_HELD, &[], present.len() as f64);
    context
        .metrics
        .set(&measure::ZONES_HELD, &[], zones.len() as f64);
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

/// The resource a mirror's age is kept under: the oldest mirror is the series, never the mirror.
fn mirror_key(mirror: &Mirror) -> String {
    format!("{}/{}", mirror.zone_id, mirror.ledger_id)
}
