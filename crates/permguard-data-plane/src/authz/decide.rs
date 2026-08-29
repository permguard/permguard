// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision itself: from a payload to an answer, once, whatever transport
//! carried it.
//!
//! HTTP and gRPC both land here, which is what makes them the same product
//! rather than two implementations of one idea. Everything that can go wrong
//! goes wrong here, in one place, with one taxonomy.
//!
//! # The path of one request
//!
//! ```text
//! payload ──► resolve      required fields, defaults, boxcarring    (400)
//!         ──► locate       which mirror the zone/ledger names       (404)
//!         ──► head         checkpoint, commit, manifest, load gate  (503)
//!         ──► block?       a commit this engine already refused     (503)
//!         ──► partitions   from cache, or compiled and cached
//!         ──► evaluate     every partition of the profile
//!         ──► answer       one decision, and one per evaluation
//! ```
//!
//! # How partitions combine
//!
//! A profile may name several partitions, in different languages. The
//! resolution across them is the one an authorization system can defend:
//!
//! | Any partition | Result |
//! | --- | --- |
//! | denies **explicitly** (a `forbid` matched, a `deny` rule held) | **deny**, citing it |
//! | permits, and none denied explicitly | **permit**, citing what permitted |
//! | nothing permitted | **deny** — absent means no |
//! | could not be evaluated | **deny**, with the reason in `reason_admin` |
//!
//! Fail-closed throughout: an error is a deny that says why, never a permit
//! and never a transport fault. A transport error means the request could not
//! be evaluated *at all* — that is a different sentence, and a PEP needs to
//! tell them apart.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use permguard_core::{ApiError, AuditRecorder, ErrorClass, Metrics, Subject};
use permguard_languages::request::{Asking, PartitionTarget};
use permguard_languages::{Query, resolve};
use tracing::{debug, info, warn};

use super::cache::Cache;
use super::snapshot::{self, Head, Partition, Refusal};
use super::wire::{
    CheckRequest, CheckResponse, Decision, DecisionContext, Reason, Resolved, TraceContext,
};
use super::{block, store};

const COMPONENT: &str = "data-plane";

/// What warming one mirror concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warmed {
    /// Compiled and held; `compiled` counts what this call had to build.
    Ready { compiled: usize },
    /// Nothing to serve yet: a ledger nobody has applied to.
    Empty,
    /// This engine may not serve it, and the block file says so.
    Blocked(String),
    /// The mirror is unreadable — a missing or corrupt object.
    Damaged(String),
}

impl Warmed {
    /// One word, for the log line and the metric label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::Empty => "empty",
            Self::Blocked(_) => "blocked",
            Self::Damaged(_) => "damaged",
        }
    }
}

/// Everything the decision path needs, resolved once at startup.
impl Loading {
    /// The gate for one key, created on first use.
    fn single_flight(&self, key: &str) -> Arc<Mutex<()>> {
        let mut held = match self.single_flight.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Bounded by what the cache can hold plus what is in flight: an entry is only ever created
        // for a key somebody is loading, and the map is swept when it outgrows the cache it
        // shadows. A gate map that only grew would be a slow leak keyed by ledger and commit.
        if held.len() > SINGLE_FLIGHT_CEILING {
            held.retain(|_, gate| Arc::strong_count(gate) > 1);
        }

        Arc::clone(held.entry(key.to_owned()).or_default())
    }

    /// The blocking half of [`Decider::loaded`].
    fn load(
        &self,
        root: &std::path::Path,
        zone: &str,
        ledger: &str,
        profile: &str,
    ) -> Result<Loaded, ApiError> {
        let labels = [("zone", zone), ("ledger", ledger)];

        let mirror = store::find(root, zone, ledger).ok_or_else(|| {
            self.metrics.count(
                &super::measure::REFUSALS,
                &[("reason", "ledger_not_served")],
            );
            debug!(
                event.name = "authz.ledger_not_served",
                component = COMPONENT,
                zone = zone,
                ledger = ledger,
                "a request named a ledger this plane does not mirror"
            );

            ApiError::new(
                ErrorClass::NotFound,
                "ledger_not_served",
                format!("this plane does not serve `{}/{}`", zone, ledger),
            )
        })?;

        // Freshness, before anything is read: a deployment that set a bound
        // gets a refusal, not an answer from a state that may have revoked
        // somebody since. A mirror with no marker — a volume fed by other
        // means — is not bounded here: its freshness is whoever feeds it.
        if let Some(bound) = self.expire_after
            && let Some(age) = store::synced_age(&mirror.path)
            && age >= bound
        {
            self.metrics
                .count(&super::measure::REFUSALS, &[("reason", "ledger_expired")]);
            warn!(
                event.name = "authz.ledger_expired",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                age.seconds = age.as_secs(),
                bound.seconds = bound.as_secs(),
                "this mirror is older than the deployment's expiry bound: refusing rather than \
                 deciding on it"
            );

            return Err(ApiError::new(
                ErrorClass::Unavailable,
                "ledger_expired",
                format!(
                    "`{}` was last confirmed {}s ago, which is past this deployment's expiry \
                     bound of {}s: refusing to decide on a state this old",
                    mirror.label(),
                    age.as_secs(),
                    bound.as_secs()
                ),
            ));
        }

        let head = self.head(&mirror, &labels)?;

        // A commit this engine already refused is refused again without
        // reading a single policy — and it clears itself the moment the
        // ledger moves.
        if let Some(blocked) = block::blocks(&mirror.path, &head.commit) {
            self.metrics.count(
                &super::measure::REFUSALS,
                &[("reason", "ledger_incompatible")],
            );

            return Err(ApiError::new(
                ErrorClass::Unavailable,
                "ledger_incompatible",
                format!(
                    "this plane cannot serve `{}` at its current commit: {}",
                    mirror.label(),
                    blocked.reason
                ),
            ));
        }
        block::clear_if_present(&mirror.path);

        let partitions = self.partitions(&mirror, &head, zone, ledger, profile)?;

        Ok(Loaded {
            mirror,
            head,
            partitions,
        })
    }

    /// The head of the mirror: the ref read now, the rest looked up by the commit it names.
    ///
    /// # Why the split
    ///
    /// Reading the ref is one small file, and it is read on every request on purpose — it is what
    /// makes a synchronization that advanced a ledger a second ago visible *now*, rather than when
    /// a cache happens to notice. Everything after it — the commit object, the manifest, decoding
    /// it and running the load gate over it — depends only on *which* commit that ref names, and
    /// so is cached by it and computed once per commit rather than once per request.
    fn head(&self, mirror: &store::Mirror, labels: &[(&str, &str)]) -> Result<Arc<Head>, ApiError> {
        let checkpoint = match snapshot::checkpoint_of(&mirror.path) {
            Ok(checkpoint) => checkpoint,
            Err(refusal) => return Err(self.refuse(mirror, &refusal, labels)),
        };
        let key = Cache::head_key(
            &mirror.identity.zone_id,
            &mirror.identity.ledger_id,
            &checkpoint.head,
        );
        if let Some(head) = self.cache.head(&key) {
            return Ok(head);
        }

        // Cold. One caller decodes; the rest wait here and then find it above.
        let gate = self.single_flight(&key);
        let _held = match gate.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(head) = self.cache.head(&key) {
            return Ok(head);
        }

        let head = match snapshot::head_at(&mirror.path, &checkpoint, &self.enabled) {
            Ok(head) => Arc::new(head),
            Err(refusal) => return Err(self.refuse(mirror, &refusal, labels)),
        };
        self.cache.keep_head(key, Arc::clone(&head));

        Ok(head)
    }

    /// The compiled partitions of the profile: from memory, or compiled now
    /// and kept.
    fn partitions(
        &self,
        mirror: &store::Mirror,
        head: &Arc<Head>,
        zone: &str,
        ledger: &str,
        profile: &str,
    ) -> Result<Vec<Arc<Partition>>, ApiError> {
        let labels = [("zone", zone), ("ledger", ledger)];
        let names = head
            .partitions_of(profile)
            .map_err(|refusal| self.refuse(mirror, &refusal, &labels))?;

        let mut compiled = Vec::new();
        for name in names {
            let key = Cache::partition_key(
                &mirror.identity.zone_id,
                &mirror.identity.ledger_id,
                &head.commit,
                &name,
            );
            if let Some(held) = self.cache.partition(&key) {
                self.metrics
                    .count(&super::measure::CACHE_LOOKUPS, &[("result", "hit")]);
                compiled.push(held);
                continue;
            }
            self.metrics
                .count(&super::measure::CACHE_LOOKUPS, &[("result", "miss")]);

            // One compiler per partition per commit. Compiling is idempotent and expensive, so
            // without this every request that arrives while the first is compiling does the same
            // work and throws it away — which is exactly what happens at a restart, at a commit
            // change and the moment an entry is evicted, when they all arrive at once.
            let gate = self.single_flight(&key);
            let _held = match gate.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Whoever held the gate has finished; the answer may already be here.
            if let Some(held) = self.cache.partition(&key) {
                compiled.push(held);
                continue;
            }

            let started = Instant::now();
            let partition = snapshot::compile(&mirror.path, head, &name)
                .map_err(|refusal| self.refuse(mirror, &refusal, &labels))?;
            self.metrics.observe(
                &super::measure::COMPILE_SECONDS,
                &labels,
                started.elapsed().as_secs_f64(),
            );
            self.metrics.count(
                &super::measure::COMPILATIONS,
                &[
                    ("zone", zone),
                    ("ledger", ledger),
                    ("partition", name.as_str()),
                ],
            );
            info!(
                event.name = "authz.partition_compiled",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                partition = name.as_str(),
                language = partition.language.as_str(),
                policies = partition.policies,
                bytes = partition.footprint,
                "a partition was compiled and kept in memory"
            );
            self.cache.keep_partition(key, Arc::clone(&partition));
            compiled.push(partition);
        }

        Ok(compiled)
    }

    /// Turns a load refusal into the answer a PEP can act on, and remembers
    /// the ones that will not fix themselves.
    fn refuse(
        &self,
        mirror: &store::Mirror,
        refusal: &Refusal,
        labels: &[(&str, &str)],
    ) -> ApiError {
        let (code, class, reason) = match refusal {
            Refusal::Empty => ("ledger_empty", ErrorClass::Unavailable, "ledger_empty"),
            Refusal::Incompatible(_) => (
                "ledger_incompatible",
                ErrorClass::Unavailable,
                "ledger_incompatible",
            ),
            Refusal::Damaged(_) => ("ledger_damaged", ErrorClass::Unavailable, "ledger_damaged"),
            Refusal::Unknown(_) => ("profile_unknown", ErrorClass::Validation, "profile_unknown"),
        };
        self.metrics
            .count(&super::measure::REFUSALS, &[("reason", reason)]);

        if let Refusal::Incompatible(detail) = refusal {
            // Written down, so the next round does not rediscover it — and so
            // an operator can see it on the volume.
            block::write(&mirror.path, &current_commit(&mirror.path), detail);
            self.metrics.set(&super::measure::BLOCKED, labels, 1.0);
            warn!(
                event.name = "authz.ledger_blocked",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                reason = detail.as_str(),
                "this engine cannot serve this ledger: refusing until it changes"
            );
        } else {
            debug!(
                event.name = "authz.ledger_unavailable",
                component = COMPONENT,
                ledger = mirror.label().as_str(),
                code = code,
                reason = %refusal,
                "a request could not be evaluated"
            );
        }

        ApiError::new(class, code, format!("`{}`: {refusal}", mirror.label()))
    }
}

/// One temporal decision, as the log records it.
///
/// A struct rather than a dozen arguments, because half of them are strings and a caller that
/// swapped two would produce a log entry that is wrong in a way nothing would catch.
pub struct TemporalDecision<'a> {
    pub decision_id: &'a str,
    pub mirror: &'a store::Mirror,
    pub head: &'a Head,
    pub profile: &'a str,
    /// The occurrence's principal, as `(type, id)`.
    pub subject: (&'a str, &'a str),
    /// The occurrence's resource, as `(type, id)`.
    pub resource: (&'a str, &'a str),
    /// The qualified action, as the occurrence named it.
    pub action: &'a str,
    /// The occurrence's request context, for the commitment.
    pub context: Option<serde_json::Value>,
    pub permit: bool,
    pub policies: &'a [String],
    pub reason: &'a str,
    pub request_id: Option<&'a str>,
    pub latency_us: u64,
    /// Where the occurrence this decision was made about sits.
    pub event: permguard_decisions::record::EventRef,
}

/// The half of a decider that loading needs.
///
/// Moved onto a blocking thread for the whole of a load, which is why it holds handles rather than
/// borrowing: a `&Decider` cannot cross `spawn_blocking`, and cloning the whole decider would
/// clone the journal and the audit worker with it.
struct Loading {
    cache: Arc<Cache>,
    metrics: Metrics,
    expire_after: Option<std::time::Duration>,
    enabled: permguard_languages::registry::Enabled,
    single_flight: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>>,
}

/// How many single-flight gates are kept before the finished ones are swept.
///
/// Not a bound on concurrency — a gate is created per key being loaded, and a plane serving many
/// ledgers legitimately has many. It is the point at which gates nobody is holding are dropped, so
/// the map cannot grow for ever across commits.
const SINGLE_FLIGHT_CEILING: usize = 1_024;

/// One ledger, loaded and ready to answer against.
pub struct Loaded {
    pub mirror: store::Mirror,
    pub head: Arc<Head>,
    /// The compiled partitions of the named profile, in the profile's order.
    pub partitions: Vec<Arc<Partition>>,
}

pub struct Decider {
    /// `<volume>/data/mirrors` — where the synchronization loop puts ledgers.
    root: PathBuf,
    cache: Arc<Cache>,
    metrics: Metrics,
    audit: Option<AuditTarget>,
    max_evaluations: usize,
    /// Where decisions are recorded, when this plane keeps a log.
    journal: Option<Arc<crate::decisions::Journal>>,
    /// Which caller-supplied attributes this plane may record in clear.
    include: permguard_core::decisions::IncludeSection,
    /// Turns an identifier into a token before it ever leaves this plane.
    pseudonymizer: Option<Arc<dyn permguard_core::pseudonym::Pseudonymizer>>,
    /// How old a mirror's last verified synchronization may grow before this
    /// plane refuses to answer from it. `None`: no bound.
    expire_after: Option<std::time::Duration>,
    /// How long one decision may spend deciding. `None`: no bound, which is what a decider built
    /// for a test that is about something else wants.
    budget: Option<std::time::Duration>,
    /// What this deployment has opted into, among the contracts whose shapes are not yet stable.
    enabled: permguard_languages::registry::Enabled,
    /// One gate per `(zone, ledger, commit[, partition])` being read or compiled.
    ///
    /// # Why a plane needs this
    ///
    /// Reading a manifest and compiling a policy set are expensive and *idempotent*: two requests
    /// that arrive on a cold ledger produce identical work and one of the two results is thrown
    /// away. That is merely wasteful with two requests. With a fleet's worth arriving at a restart,
    /// on a commit change, or the moment an entry is evicted, it is a stampede — every one of them
    /// parsing the same policies at once, on the same machine, while the cache they would all have
    /// hit sits empty until the first finishes.
    ///
    /// So the first caller for a key does the work and the rest wait for it, then find it cached.
    /// Keys are independent, so one slow ledger never queues another's.
    single_flight: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>>,
    /// The bound on concurrent blocking work — see [`Decider::with_blocking`].
    blocking: crate::blocking::Blocking,
    /// Profiles whose evaluation keeps overrunning its deadline — see
    /// [`crate::authz::quarantine`].
    quarantine: Arc<super::quarantine::Quarantine>,
}

enum AuditTarget {
    Direct(AuditRecorder),
    Queued(Arc<super::audit::DecisionAudit>),
}

impl Decider {
    /// Builds the decider from the plane's configuration.
    pub fn new(
        root: PathBuf,
        cache: Arc<Cache>,
        metrics: Metrics,
        recorder: Option<AuditRecorder>,
        max_evaluations: usize,
    ) -> Self {
        let metrics_for_pool = metrics.clone();

        Self {
            root,
            cache,
            metrics,
            audit: recorder.map(AuditTarget::Direct),
            max_evaluations: max_evaluations.max(1),
            journal: None,
            include: permguard_core::decisions::IncludeSection::default(),
            pseudonymizer: None,
            expire_after: None,
            budget: None,
            // Everything this build carries, unless a deployment says otherwise. A decider built
            // by a test is about something else, and should see what was compiled in.
            enabled: permguard_languages::registry::Enabled::everything(),
            single_flight: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // A bound on how much blocking work exists at once, defaulted rather than optional:
            // an unbounded `spawn_blocking` is what lets a plane accumulate instead of refusing,
            // and a deployment that has not thought about the number still gets one. The
            // composition root replaces it with the configured size.
            blocking: crate::blocking::Blocking::new(
                permguard_core::config::default_max_blocking(),
                metrics_for_pool,
            ),
            quarantine: Arc::new(super::quarantine::Quarantine::new()),
        }
    }

    /// The bound on concurrent blocking work this decider uses.
    ///
    /// Evaluation is the work that matters here. A provider is synchronous and upstream offers no
    /// way to interrupt one — the operation limit it enforces is a count, not a clock — so a
    /// provider that blocks holds its thread until it returns. What can be bounded is *how many* of
    /// them there are: one hung evaluation costs a permit, and when the permits are gone the plane
    /// refuses immediately instead of letting the runtime's queue grow behind it.
    pub fn with_blocking(mut self, blocking: crate::blocking::Blocking) -> Self {
        self.blocking = blocking;

        self
    }

    /// The half of this decider that loading needs, cheap to move onto a blocking thread.
    fn clone_for_loading(&self) -> Loading {
        Loading {
            cache: Arc::clone(&self.cache),
            metrics: self.metrics.clone(),
            expire_after: self.expire_after,
            enabled: self.enabled.clone(),
            single_flight: Arc::clone(&self.single_flight),
        }
    }

    /// Restricts this decider to the contracts a deployment has opted into.
    ///
    /// A ledger naming one it has not is refused at load, by name — not served and then found to
    /// behave differently after an upgrade.
    pub fn with_enabled(mut self, enabled: permguard_languages::registry::Enabled) -> Self {
        self.enabled = enabled;

        self
    }

    /// Bounds how long one decision may spend evaluating.
    ///
    /// # Why the work needs its own bound
    ///
    /// The transport's request timeout ends the *response*, not the work: an evaluation runs on a
    /// blocking thread, and when the HTTP layer gives up it drops the future holding that thread
    /// while the thread carries on — having already released the concurrency permit that was
    /// limiting how many of these could be in flight. Under load that is how a plane accumulates
    /// work nobody is waiting for.
    ///
    /// So the decision is told when to stop. Set a little under the transport's own timeout, so
    /// the work ends before the answer is abandoned rather than after it.
    pub fn with_budget(mut self, budget: Option<std::time::Duration>) -> Self {
        self.budget = budget;

        self
    }

    /// Records authorization decisions through the data plane's bounded audit worker.
    pub fn with_audit(mut self, audit: Option<Arc<super::audit::DecisionAudit>>) -> Self {
        if let Some(audit) = audit {
            self.audit = Some(AuditTarget::Queued(audit));
        }

        self
    }

    /// Bounds how old a mirror may grow and still be answered from.
    ///
    /// The freshness half of the consistency model: authenticity and
    /// no-rollback are enforced before a checkpoint moves, and this is the
    /// deployment's answer to "for how long". An expired mirror answers `503`
    /// — the same sentence as any other state this plane cannot serve —
    /// because deciding from a state that may have revoked somebody since is
    /// the one thing a deployment that set this bound said it would not do.
    pub fn with_expiry(mut self, expire_after: Option<std::time::Duration>) -> Self {
        self.expire_after = expire_after;

        self
    }

    /// Records every decision this decider answers.
    ///
    /// Separate from [`Self::new`] because a plane that keeps no log is the
    /// ordinary case, and because the journal is a singleton the plane opens
    /// once — a decider that built its own would open a second spool.
    pub fn with_journal(
        mut self,
        journal: Option<Arc<crate::decisions::Journal>>,
        pseudonymizer: Option<Arc<dyn permguard_core::pseudonym::Pseudonymizer>>,
        include: permguard_core::decisions::IncludeSection,
    ) -> Self {
        self.journal = journal;
        self.pseudonymizer = pseudonymizer;
        self.include = include;

        self
    }

    /// The mirrors root, for the surfaces that report on what is held.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// The cache, for the gauges.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Reads a freshly mirrored ledger, decides whether this engine may serve
    /// it, and compiles it into memory if it may.
    ///
    /// Called by the synchronization loop after a mirror advances, which is the
    /// right moment for three reasons: it is when the answer can change, it is
    /// off the decision path, and it means the **first** request after a sync
    /// is as fast as the thousandth.
    ///
    /// The whole check is skipped when the block file already names this
    /// commit: an incompatible ledger costs one small file read per round
    /// instead of a full read-and-compile that reaches the same refusal.
    pub fn warm(&self, mirror: &store::Mirror) -> Warmed {
        let commit = current_commit(&mirror.path);
        if commit.is_empty() {
            return Warmed::Empty;
        }
        if let Some(blocked) = block::blocks(&mirror.path, &commit) {
            self.metrics.set(
                &super::measure::BLOCKED,
                &[
                    ("zone", mirror.identity.zone_name.as_str()),
                    ("ledger", mirror.identity.ledger_name.as_str()),
                ],
                1.0,
            );

            return Warmed::Blocked(blocked.reason);
        }

        let head = match snapshot::head_with(&mirror.path, &self.enabled) {
            Ok(head) => Arc::new(head),
            Err(Refusal::Empty) => return Warmed::Empty,
            Err(Refusal::Incompatible(detail)) => {
                block::write(&mirror.path, &commit, &detail);
                self.metrics.set(
                    &super::measure::BLOCKED,
                    &[
                        ("zone", mirror.identity.zone_name.as_str()),
                        ("ledger", mirror.identity.ledger_name.as_str()),
                    ],
                    1.0,
                );
                warn!(
                    event.name = "authz.ledger_blocked",
                    component = COMPONENT,
                    ledger = mirror.label().as_str(),
                    commit = commit.as_str(),
                    reason = detail.as_str(),
                    "this engine cannot serve this ledger: refusing until it changes"
                );

                return Warmed::Blocked(detail);
            }
            Err(other) => return Warmed::Damaged(other.to_string()),
        };

        // Every partition the ledger declares, not only the default profile's:
        // whatever a caller asks for should already be in memory.
        let mut compiled = 0;
        for name in head.manifest.partitions.keys() {
            let key = Cache::partition_key(
                &mirror.identity.zone_id,
                &mirror.identity.ledger_id,
                &head.commit,
                name,
            );
            if self.cache.partition(&key).is_some() {
                continue;
            }
            match snapshot::compile(&mirror.path, &head, name) {
                Ok(partition) => {
                    self.cache.keep_partition(key, partition);
                    compiled += 1;
                }
                Err(Refusal::Incompatible(detail)) => {
                    block::write(&mirror.path, &head.commit, &detail);
                    self.metrics.set(
                        &super::measure::BLOCKED,
                        &[
                            ("zone", mirror.identity.zone_name.as_str()),
                            ("ledger", mirror.identity.ledger_name.as_str()),
                        ],
                        1.0,
                    );
                    warn!(
                        event.name = "authz.ledger_blocked",
                        component = COMPONENT,
                        ledger = mirror.label().as_str(),
                        partition = name.as_str(),
                        reason = detail.as_str(),
                        "a partition of this ledger cannot be compiled: refusing until it changes"
                    );

                    return Warmed::Blocked(detail);
                }
                Err(other) => return Warmed::Damaged(other.to_string()),
            }
        }

        block::clear_if_present(&mirror.path);
        self.metrics.set(
            &super::measure::BLOCKED,
            &[
                ("zone", mirror.identity.zone_name.as_str()),
                ("ledger", mirror.identity.ledger_name.as_str()),
            ],
            0.0,
        );
        self.publish_cache_gauges();
        debug!(
            event.name = "authz.ledger_warm",
            component = COMPONENT,
            ledger = mirror.label().as_str(),
            commit = head.commit.as_str(),
            compiled,
            "this ledger is compiled and ready to answer"
        );

        Warmed::Ready { compiled }
    }

    /// Answers one request.
    ///
    /// `trace` is the caller's W3C trace context, when it sent one: it is
    /// recorded with the decision so an investigation can join the two. Passed
    /// in rather than read here, because the header belongs to the transport
    /// and this path answers both of them.
    pub async fn decide(
        &self,
        request: &CheckRequest,
        trace: Option<TraceContext>,
    ) -> Result<CheckResponse, ApiError> {
        let started = Instant::now();
        let outcome = self.answer(request, trace).await;
        self.metrics.observe(
            &super::measure::REQUEST_SECONDS,
            &[],
            started.elapsed().as_secs_f64(),
        );
        self.publish_cache_gauges();

        outcome
    }

    async fn answer(
        &self,
        request: &CheckRequest,
        trace: Option<TraceContext>,
    ) -> Result<CheckResponse, ApiError> {
        // The decision's own clock, which the log records: how long the plane
        // took, separate from how long the transport took.
        let started = Instant::now();
        // Shared, never copied. The plan below runs on a blocking thread and needs the request to
        // outlive this frame; cloning it copied every evaluation's subject, resource and context
        // a second time, on top of the entity stores the contract already shares.
        let resolved = Arc::new(request.resolve(self.max_evaluations).map_err(|malformed| {
            self.metrics
                .count(&super::measure::REFUSALS, &[("reason", "malformed")]);
            // The profile's own status: a payload that is not a request is a
            // bad request, not a decision.
            ApiError::new(ErrorClass::Validation, malformed.code, malformed.message)
        })?);

        let Loaded {
            mirror,
            head,
            partitions,
        } = self
            .loaded(&resolved.zone, &resolved.ledger, &resolved.profile)
            .await?;

        // Off the async worker, and once for the whole batch. Deciding is CPU work — parsing
        // nothing, but running an engine over a policy set — and a Tokio worker inside an engine
        // is a worker not accepting connections. One hop, not one per evaluation: the batch is
        // sequential by contract (a semantic that stops at the first deny has to stop), so there
        // is nothing to interleave and every extra hop would be latency for its own sake.
        // Refused before evaluating, when evaluating this has been overrunning.
        //
        // A provider is synchronous and cannot be interrupted, so an evaluation that has stopped
        // returning costs a permit from the bounded pool until it does. Letting every request for
        // the same profile take another permit is how a plane spends its whole capacity on work
        // nobody is waiting for; the breaker spends one request per cooldown instead.
        let guarded = format!("{}/{}/{}", resolved.zone, resolved.ledger, resolved.profile);
        if let super::quarantine::Admits::No { overruns, retry_in } =
            self.quarantine.admits(&guarded)
        {
            self.metrics
                .count(&super::measure::REFUSALS, &[("reason", "quarantined")]);

            return Err(ApiError::new(
                ErrorClass::Unavailable,
                "evaluation_quarantined",
                format!(
                    "evaluating `{guarded}` overran its deadline {overruns} times in a row and is \
                     out of service for another {}s. A provider inside an evaluation cannot be \
                     interrupted, so this plane stops spending capacity on it and lets one request \
                     through when the cooldown ends",
                    retry_in.as_secs()
                ),
            ));
        }

        let plan = Plan {
            head: Arc::clone(&head),
            partitions,
            resolved: Arc::clone(&resolved),
            metrics: self.metrics.clone(),
            // Measured from when this decision began, not from here.
            //
            // The budget exists so the *work* ends before the answer is abandoned — a request
            // whose transport timeout has fired has already released the permit that was limiting
            // how many of these could be in flight, and anything still running is work nobody is
            // waiting for. Loading and compiling hold a blocking thread exactly as evaluating
            // does, so a budget that started after them could be spent in full on top of a slow
            // load and outlive the response it was supposed to fit inside.
            //
            // A decision whose load already used the whole budget therefore arrives here with none
            // left, and every partition refuses immediately: fail-closed, and honest about why.
            deadline: self.budget.map(|budget| started + budget),
        };
        // The breaker learns from inside the work, not from the future waiting on it.
        //
        // A request cancelled while its evaluation runs — an HTTP timeout, a client that hung up —
        // drops everything after the `.await`, so an overrun recorded there is recorded only when
        // the caller survived to record it. That is exactly backwards: the evaluations worth
        // learning from are the slow ones, and the slow ones are the ones whose callers gave up.
        let watching = (Arc::clone(&self.quarantine), guarded.clone(), self.budget);
        let decisions = self
            .blocking
            .run(&[], move || {
                let (quarantine, guarded, budget) = watching;
                let evaluating = Instant::now();
                let outcome = plan.run();
                if let Some(budget) = budget {
                    match evaluating.elapsed() > budget {
                        true => {
                            quarantine.overran(&guarded);
                        }
                        false => quarantine.in_time(&guarded),
                    }
                }

                outcome
            })
            .await
            .map_err(|refused| match refused {
                crate::blocking::Refused::AtCapacity(held) => {
                    self.metrics
                        .count(&super::measure::REFUSALS, &[("reason", "at_capacity")]);

                    ApiError::new(
                        ErrorClass::Unavailable,
                        "evaluation_at_capacity",
                        format!(
                            "{held}. An evaluation is synchronous and a provider inside one cannot \
                             be interrupted, so this plane bounds how many may run at once and \
                             refuses beyond it rather than queueing behind work that may not \
                             return"
                        ),
                    )
                }
                crate::blocking::Refused::Failed(why) => ApiError::new(
                    ErrorClass::Internal,
                    "decision_failed",
                    format!("the evaluation did not complete: {why}"),
                ),
            })??;

        // The whole request's verdict: for a plain request it is the one decision; for a
        // batch it is the operator its semantic names — `&&` for `execute_all` and
        // `deny_on_first_deny`, `||` for `permit_on_first_permit`. Computed by
        // `Semantic::combine`, which is also what the CLI uses to decide a batch offline and
        // to check that an answer of ours is coherent.
        let overall = resolved
            .semantic
            .combine(decisions.iter().map(|decision| decision.decision));
        for decision in &decisions {
            self.metrics.count(
                &super::measure::EVALUATIONS,
                &[
                    ("zone", resolved.zone.as_str()),
                    ("ledger", resolved.ledger.as_str()),
                    ("outcome", if decision.decision { "permit" } else { "deny" }),
                ],
            );
        }
        self.metrics.count(
            &super::measure::DECISIONS,
            &[
                ("zone", resolved.zone.as_str()),
                ("ledger", resolved.ledger.as_str()),
                ("outcome", if overall { "permit" } else { "deny" }),
            ],
        );

        let context = decisions
            .first()
            .and_then(|first| first.context.clone())
            .unwrap_or_default();
        // Before the answer leaves: a plane told to refuse rather than decide
        // unrecorded must refuse *here*, where the answer has not gone out yet.
        self.journal(
            &resolved,
            &mirror,
            &head,
            &decisions,
            trace.as_ref(),
            started,
        )
        .await?;
        self.record(&resolved, &mirror, &head, &decisions).await;

        Ok(CheckResponse {
            decision: overall,
            request_id: resolved.request_id.clone(),
            context: Some(context),
            evaluations: if resolved.boxcarred {
                Some(decisions)
            } else {
                None
            },
        })
    }

    /// The ledger a request names, loaded: its mirror, its verified head, and the compiled
    /// partitions of its profile.
    ///
    /// # Why both interfaces come through here
    ///
    /// Everything before a decision is the same question whichever interface asked it: is this
    /// ledger served here, is its mirror fresh enough to answer from, does its head verify, has
    /// this commit already been refused, and what does this profile compile to. Written twice —
    /// once for the stateless path and once for the temporal one — the second copy would be the
    /// one that forgets the expiry bound, or the block list, and a plane would answer from a state
    /// the other half of itself refuses.
    pub async fn loaded(
        &self,
        zone: &str,
        ledger: &str,
        profile: &str,
    ) -> Result<Loaded, ApiError> {
        // Off the runtime's threads, all of it.
        //
        // Everything below reads files and, on a miss, parses and compiles a policy set. Doing
        // that on a Tokio worker blocks a thread that is supposed to be accepting connections —
        // and a *cold* plane does it for every ledger at once, so a restart under load could stall
        // every worker on disk. Only the evaluation used to be moved off; the loading, which is
        // the expensive half, ran here.
        let (root, zone, ledger, profile) = (
            self.root.clone(),
            zone.to_owned(),
            ledger.to_owned(),
            profile.to_owned(),
        );
        let held = self.clone_for_loading();

        tokio::task::spawn_blocking(move || held.load(&root, &zone, &ledger, &profile))
            .await
            .unwrap_or_else(|error| {
                Err(ApiError::new(
                    ErrorClass::Internal,
                    "load_failed",
                    format!("the ledger could not be loaded: {error}"),
                ))
            })
    }

    fn publish_cache_gauges(&self) {
        let (entries, bytes) = self.cache.holdings();
        self.metrics
            .set(&super::measure::CACHE_ENTRIES, &[], entries as f64);
        self.metrics
            .set(&super::measure::CACHE_BYTES, &[], bytes as f64);
    }

    /// Puts the decision on the trail.
    ///
    /// Every decision, permit and deny alike: a trail that carried only denies
    /// could not answer "who read this, and when", which is the question an
    /// auditor actually asks.
    ///
    /// **One event per evaluation**, exactly as the decision log writes one
    /// record per evaluation. A boxcarred request asks about several subjects,
    /// resources and actions; a single event carrying the conjunction and the
    /// first question would attribute the whole batch to one of its members and
    /// lose the rest.
    ///
    /// The decision's subject is the *audited* subject when the caller named no
    /// principal, and it is carried as one — [`Subject::Principal`] is what a
    /// sink masks or pseudonymises. It is deliberately **not** interpolated into
    /// the target: a target is never a person (see
    /// [`AuditEvent::on`](permguard_core::AuditEvent::on)), so it names the
    /// ledger, the action, the resource and the outcome, and the subject stays
    /// in the field that knows how to protect it.
    async fn record(
        &self,
        resolved: &Resolved,
        mirror: &store::Mirror,
        head: &Head,
        decisions: &[Decision],
    ) {
        // When this plane keeps a decision log, the journal IS the decision
        // trail — every decision, hash-chained, signed and shipped. An audit
        // event beside it would say the same thing with weaker guarantees,
        // and cost a flush of the same disk the journal is flushing: the
        // operational trail keeps what only it records — lifecycle and
        // administration — and decisions live where they can be proven.
        if self.journal.is_some() {
            return;
        }
        let Some(audit) = &self.audit else {
            return;
        };
        for (index, decision) in decisions.iter().enumerate() {
            let query = resolved
                .queries
                .get(index)
                .map(|(query, _)| query.clone())
                .unwrap_or_default();
            let target = format!(
                "{} {} on {}:{} for a {} at {} ({}) decision={}",
                mirror.label(),
                query.action.name,
                query.resource.kind,
                query.resource.id,
                query.subject.kind,
                head.counter,
                decision
                    .context
                    .as_ref()
                    .and_then(|context| context.id.clone())
                    .unwrap_or_default(),
                if decision.decision { "permit" } else { "deny" },
            );
            let subject = resolved
                .principal
                .clone()
                .unwrap_or_else(|| format!("{}:{}", query.subject.kind, query.subject.id));

            match audit {
                AuditTarget::Queued(audit) => audit.record(subject, target),
                AuditTarget::Direct(recorder) => {
                    if let Err(error) = recorder
                        .record_on(
                            "authz.decision",
                            Subject::Principal(subject.as_str()),
                            &target,
                        )
                        .await
                    {
                        warn!(
                            event.name = "authz.audit_failed",
                            component = COMPONENT,
                            error = %error,
                            "a decision was answered and its audit record was not written"
                        );
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct OwnedDecided {
    id: String,
    at: String,
    zone: String,
    ledger: String,
    commit: String,
    counter: u64,
    profile: String,
    subject: (String, String),
    subject_properties: Option<serde_json::Map<String, serde_json::Value>>,
    resource: (String, String),
    resource_properties: Option<serde_json::Map<String, serde_json::Value>>,
    included_context: Option<serde_json::Map<String, serde_json::Value>>,
    action: String,
    principal: Option<(String, String)>,
    context: Option<serde_json::Value>,
    partition_inputs: Option<serde_json::Value>,
    permit: bool,
    policies: Vec<String>,
    reason: String,
    trace: Option<(String, String)>,
    request_id: Option<String>,
    latency_us: u64,
    /// The occurrence this decision was made about, for a temporal one.
    event: Option<permguard_decisions::record::EventRef>,
}

impl OwnedDecided {
    fn borrowed(&self) -> crate::decisions::journal::Decided<'_> {
        crate::decisions::journal::Decided {
            id: self.id.as_str(),
            at: self.at.clone(),
            zone: self.zone.as_str(),
            ledger: self.ledger.as_str(),
            commit: self.commit.as_str(),
            counter: self.counter,
            profile: self.profile.as_str(),
            subject: self.subject.clone(),
            subject_properties: self.subject_properties.clone(),
            resource: self.resource.clone(),
            resource_properties: self.resource_properties.clone(),
            included_context: self.included_context.clone(),
            action: self.action.clone(),
            principal: self.principal.clone(),
            context: self.context.clone(),
            partition_inputs: self.partition_inputs.clone(),
            permit: self.permit,
            policies: self.policies.clone(),
            reason: self.reason.clone(),
            trace: self.trace.clone(),
            request_id: self.request_id.clone(),
            latency_us: self.latency_us,
            event: self.event.clone(),
        }
    }
}

impl Decider {
    /// Writes one decision to the log, when this plane keeps one.
    ///
    /// On the decision path deliberately, and local-only by construction: a
    /// durable append and a flush, never a socket. The alternative — recording
    /// after the answer has gone — is a decision the deployment believes was
    /// logged and was not.
    ///
    /// **`on_full: closed` refuses the decision**, and that is the whole
    /// difference between the two modes: a deployment that said it would rather
    /// not decide than decide unrecorded gets exactly that. Answering anyway
    /// and writing a warning would make the setting a comment.
    ///
    /// Other write failures follow the same availability contract: `closed`
    /// refuses the request before the answer leaves, while `open` reports the
    /// incident and keeps answering.
    async fn journal(
        &self,
        resolved: &Resolved,
        mirror: &store::Mirror,
        head: &Head,
        decisions: &[Decision],
        trace: Option<&TraceContext>,
        started: Instant,
    ) -> Result<(), ApiError> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        // Pseudonymised here, at the source: the control plane never holds a
        // raw identifier, and neither does any consumer of the log.
        let token = |value: &str| match &self.pseudonymizer {
            Some(pseudonymizer) => pseudonymizer.pseudonymize(value),
            None => value.to_owned(),
        };
        let at = now_rfc3339();
        let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);

        // **One record per evaluation**, not one per request. A boxcarred
        // request carries several questions about several subjects, resources
        // and actions; folding them into one record would attribute all of them
        // to the first, and lose the rest of the audit trail entirely. The
        // request's own verdict — the conjunction — is not recorded as a
        // decision, because it is not one: it is an answer *about* decisions,
        // and a reader computes it from them.
        for (index, decision) in decisions.iter().enumerate() {
            let query = resolved
                .queries
                .get(index)
                .map(|(query, _)| query.clone())
                .unwrap_or_default();
            let context = decision.context.as_ref();

            let decided = OwnedDecided {
                id: context
                    .and_then(|context| context.id.as_deref())
                    .unwrap_or_default()
                    .to_owned(),
                at: at.clone(),
                zone: mirror.identity.zone_name.clone(),
                ledger: mirror.identity.ledger_name.clone(),
                commit: head.commit.clone(),
                counter: head.counter,
                profile: resolved.profile.clone(),
                subject: (query.subject.kind.clone(), token(&query.subject.id)),
                subject_properties: named(
                    &query.subject.properties,
                    &self.include.subject_properties,
                ),
                resource: (query.resource.kind.clone(), query.resource.id.clone()),
                resource_properties: named(
                    &query.resource.properties,
                    &self.include.resource_properties,
                ),
                included_context: named(&query.context, &self.include.context),
                action: query.action.name.clone(),
                principal: resolved
                    .principal
                    .as_ref()
                    .map(|principal| ("Principal".to_owned(), token(principal))),
                context: serde_json::to_value(&query.context).ok(),
                partition_inputs: serde_json::to_value(&query.partition_inputs).ok(),
                permit: decision.decision,
                policies: context
                    .map(|context| context.policies.clone())
                    .unwrap_or_default(),
                reason: context
                    .and_then(|context| context.reason_user.as_ref())
                    .map(|reason| reason.code.clone())
                    .unwrap_or_else(|| if decision.decision { "200" } else { "403" }.to_owned()),
                trace: trace.map(|trace| (trace.trace_id.clone(), trace.span_id.clone())),
                // The caller's own handle for *this* evaluation, when it
                // boxcarred: `request_id` per evaluation is how a PEP joins one
                // answer of a batch back to the question it asked.
                request_id: decision
                    .request_id
                    .clone()
                    .or_else(|| resolved.request_id.clone()),
                latency_us,
                // A stateless decision was made about a request, not about an occurrence. Left
                // absent rather than filled with something that stands in for one.
                event: None,
            };

            self.write(Arc::clone(journal), decided).await?;
        }

        Ok(())
    }

    /// Records one **temporal** decision, linked to the occurrence it was made about.
    ///
    /// The same journal, the same chain, the same signing and the same shipping as a stateless
    /// decision — because it is the same kind of fact, and a second trail for temporal decisions
    /// would be a second thing to verify, ship, retain and reconcile. What distinguishes it is one
    /// field: the pointer back to the event, which is how an investigator moves between the two
    /// logs without matching timestamps and hoping.
    ///
    /// Returns the refusal a plane configured not to answer unrecorded decisions produces, so the
    /// temporal path can fail the submission *after* the event is durable and *before* the verdict
    /// leaves — which is the only order in which both promises hold.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_temporal(&self, at: &TemporalDecision<'_>) -> Result<(), ApiError> {
        if self.journal.is_none() {
            return Ok(());
        }
        let token = |value: &str| match &self.pseudonymizer {
            Some(pseudonymizer) => pseudonymizer.pseudonymize(value),
            None => value.to_owned(),
        };
        let decided = OwnedDecided {
            id: at.decision_id.to_owned(),
            at: now_rfc3339(),
            zone: at.mirror.identity.zone_name.clone(),
            ledger: at.mirror.identity.ledger_name.clone(),
            commit: at.head.commit.clone(),
            counter: at.head.counter,
            profile: at.profile.to_owned(),
            subject: (at.subject.0.to_owned(), token(at.subject.1)),
            subject_properties: None,
            resource: (at.resource.0.to_owned(), at.resource.1.to_owned()),
            resource_properties: None,
            included_context: None,
            action: at.action.to_owned(),
            // The occurrence's principal *is* its subject: a temporal submission names one entity
            // that both acts and is decided about, and recording it twice would suggest a
            // delegation the payload cannot express.
            principal: None,
            context: at.context.clone(),
            partition_inputs: None,
            permit: at.permit,
            policies: at.policies.to_vec(),
            reason: at.reason.to_owned(),
            trace: None,
            request_id: at.request_id.map(ToOwned::to_owned),
            latency_us: at.latency_us,
            event: Some(at.event.clone()),
        };
        let Some(journal) = &self.journal else {
            return Ok(());
        };

        self.write(Arc::clone(journal), decided).await
    }

    /// Writes one record, and decides what a failure to write means.
    async fn write(
        &self,
        journal: Arc<crate::decisions::Journal>,
        decided: OwnedDecided,
    ) -> Result<(), ApiError> {
        let refuses_unrecorded = journal.refuses_unrecorded();
        // Through the same bound as everything else that waits on a disk. A decision record is a
        // durable write with a flush behind it, and an unbounded `spawn_blocking` here would be the
        // queue the pool exists to refuse — reached from the ordinary decision path, which is the
        // busiest one there is.
        let written = self
            .blocking
            .run(&[], move || journal.record(&decided.borrowed()))
            .await;
        let written = match written {
            Ok(written) => Ok(written),
            Err(crate::blocking::Refused::AtCapacity(held)) => {
                self.metrics
                    .count(&super::measure::REFUSALS, &[("reason", "at_capacity")]);

                return self.journal_error(refuses_unrecorded, held.to_string());
            }
            Err(crate::blocking::Refused::Failed(why)) => Err(why),
        };

        match written {
            Ok(Ok(crate::decisions::Written::Refused(reason))) => {
                warn!(
                    event.name = "authz.unrecordable",
                    component = COMPONENT,
                    reason = reason.as_str(),
                    "this plane cannot record decisions and is configured not to answer unrecorded \
                     ones: refusing"
                );

                Err(self.unrecordable(reason.as_str()))
            }
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => self.journal_error(refuses_unrecorded, error.to_string()),
            Err(why) => self.journal_error(
                refuses_unrecorded,
                format!("the journal writer failed: {why}"),
            ),
        }
    }

    fn journal_error(&self, refuses_unrecorded: bool, reason: String) -> Result<(), ApiError> {
        if refuses_unrecorded {
            warn!(
                event.name = "authz.unrecordable",
                component = COMPONENT,
                reason = reason.as_str(),
                "this plane cannot record decisions and is configured not to answer unrecorded \
                 ones: refusing"
            );

            return Err(self.unrecordable(reason.as_str()));
        }

        warn!(
            event.name = "authz.journal_failed",
            component = COMPONENT,
            error = reason.as_str(),
            "a decision was answered and its log record was not written"
        );

        Ok(())
    }

    fn unrecordable(&self, reason: &str) -> ApiError {
        self.metrics
            .count(&super::measure::REFUSALS, &[("reason", "unrecordable")]);
        ApiError::new(
            ErrorClass::Unavailable,
            "decision_unrecordable",
            format!(
                "this plane cannot record decisions right now ({reason}) and is configured to \
                 refuse rather than decide unrecorded"
            ),
        )
    }
}

/// The members of `available` the deployment named in `wanted`.
///
/// An allow-list, applied here rather than at the edge: what a decision *saw*
/// is committed to in every record, and what is kept in clear is only ever what
/// somebody asked for by name. A field added to a request tomorrow therefore
/// starts being committed to and does not start being recorded.
fn named(
    available: &serde_json::Map<String, serde_json::Value>,
    wanted: &[String],
) -> Option<serde_json::Map<String, serde_json::Value>> {
    if wanted.is_empty() {
        return None;
    }
    let kept: serde_json::Map<String, serde_json::Value> = wanted
        .iter()
        .filter_map(|name| {
            available
                .get(name)
                .map(|value| (name.clone(), value.clone()))
        })
        .collect();

    (!kept.is_empty()).then_some(kept)
}

fn now_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();

    permguard_core::time::to_rfc3339(seconds)
}

/// One request's evaluation, owned, so it can be handed to a blocking thread whole.
///
/// Everything it needs is a handle: the head and each compiled partition are already shared, and
/// what is copied is the request itself. Built so the decision path can leave the async runtime
/// without the borrow checker having an opinion about where a mirror lives.
struct Plan {
    head: Arc<Head>,
    partitions: Vec<Arc<Partition>>,
    resolved: Arc<Resolved>,
    metrics: permguard_core::Metrics,
    /// When this decision stops being worth making. Carried into every query, so each engine can
    /// decide whether to start and — where its interpreter allows it — whether to continue.
    deadline: Option<Instant>,
}

impl Plan {
    /// Every evaluation of the batch, in order, stopping where the semantic says to stop.
    fn run(self) -> Result<Vec<Decision>, ApiError> {
        // What each partition of this profile is given. Routed by `Asking::route` — the same
        // function `permguard test` calls — because an input belongs to the partition it names
        // and a Cedar policy reads an action's properties somewhere a Rego module does not. A
        // request whose addressing does not add up is refused here, before any policy is
        // consulted: an input naming a partition nobody has, of a type the ledger does not
        // declare, or one this partition's schema refuses, is a bad request and not a deny.
        let targets: Vec<PartitionTarget<'_>> = self
            .partitions
            .iter()
            .map(|partition| {
                PartitionTarget::new(&partition.name, &partition.language)
                    .accepting(
                        self.head
                            .manifest
                            .partitions
                            .get(&partition.name)
                            .and_then(|declared| declared.input.as_ref()),
                    )
                    .evaluated_by(partition.evaluator())
            })
            .collect();

        let mut decisions = Vec::with_capacity(self.resolved.queries.len());
        for (asking, request_id) in &self.resolved.queries {
            // The batch shares one deadline: 256 boxcarred evaluations that each got the full
            // budget would be 256 times the bound the deployment asked for.
            let asking = Asking {
                deadline: self.deadline,
                ..asking.clone()
            };
            let queries = asking.route(&targets).map_err(|malformed| {
                self.metrics
                    .count(&super::measure::REFUSALS, &[("reason", "malformed")]);

                ApiError::new(ErrorClass::Validation, malformed.code, malformed.message)
            })?;
            let decision = self.evaluate(queries, request_id.clone());
            let stop = self.resolved.semantic.stops(decision.decision);
            decisions.push(decision);
            if stop {
                break;
            }
        }

        Ok(decisions)
    }

    /// Evaluates one question against every partition of the profile — together — and combines
    /// the answers.
    ///
    /// `queries` is `partitions` materialised, in the same order: one input per partition, and
    /// the runtime's own reading of the action. They are paired by position, which
    /// `Asking::route` guarantees, and `evaluate_all` answers in that same order however the
    /// engines finished.
    fn evaluate(&self, queries: Vec<Query>, request_id: Option<String>) -> Decision {
        let work: Vec<(Arc<dyn permguard_languages::Evaluator>, Query)> = self
            .partitions
            .iter()
            .map(Arc::as_ref)
            .map(Partition::evaluator_shared)
            .zip(queries)
            .collect();
        let answered = permguard_languages::evaluate::evaluate_all(work);

        // Recorded here, on one thread and in the profile's order, from what each partition
        // reported: a metric written from inside a worker would be a metric whose order depended
        // on a race.
        for (partition, answer) in self.partitions.iter().zip(&answered) {
            self.metrics.observe(
                &super::measure::EVALUATION_SECONDS,
                &[
                    ("zone", self.resolved.zone.as_str()),
                    ("ledger", self.resolved.ledger.as_str()),
                    ("partition", partition.name.as_str()),
                ],
                answer.elapsed.as_secs_f64(),
            );
        }

        // The resolution is `permguard_languages::evaluate::resolve`, not a rule of this crate's
        // own: `permguard test` decides a workspace before it is ever pushed here, and the two
        // must not be able to disagree about what a set of verdicts means.
        let outcome = resolve(answered.into_iter().map(|answer| answer.verdict));
        let permit = outcome.permitted;

        Decision {
            decision: permit,
            request_id,
            context: Some(DecisionContext {
                id: Some(permguard_decisions::instance::mint()),
                reason_admin: Some(reason_admin(
                    permit,
                    &outcome.permits,
                    &outcome.denials,
                    &outcome.errors,
                )),
                reason_user: Some(reason_user(permit)),
                policies: outcome.determining().to_vec(),
            }),
        }
    }
}

/// The operator's half of a reason: what decided, or what went wrong.
///
/// A free function rather than a method, because two callers need it and neither owns the other:
/// the decider that answers a request, and the plan that evaluates one on a blocking thread.
fn reason_admin(
    permit: bool,
    permitted: &[String],
    denied: &[String],
    errors: &[String],
) -> Reason {
    if !errors.is_empty() {
        return Reason {
            code: "500".to_owned(),
            message: format!(
                "the request could not be evaluated, so it is denied: {}",
                errors.join("; ")
            ),
        };
    }
    if permit {
        return Reason {
            code: "200".to_owned(),
            message: format!("permitted by {}", permitted.join(", ")),
        };
    }
    if denied.is_empty() {
        return Reason {
            code: "403".to_owned(),
            message: "no policy permits this request".to_owned(),
        };
    }

    Reason {
        code: "403".to_owned(),
        message: format!("denied by {}", denied.join(", ")),
    }
}

fn reason_user(permit: bool) -> Reason {
    if permit {
        Reason {
            code: "200".to_owned(),
            message: "permitted".to_owned(),
        }
    } else {
        Reason {
            code: "403".to_owned(),
            message: "insufficient privileges. Contact your administrator".to_owned(),
        }
    }
}

/// The commit a mirror stands at, read cheaply and without a gate: the block
/// file has to name a commit even when the gate is what refused it.
fn current_commit(mirror: &std::path::Path) -> String {
    let store = permguard_control_client::store::FsStore::new(mirror);

    permguard_control_client::checkpoint::read(&store, "refs/main")
        .ok()
        .flatten()
        .map(|checkpoint| checkpoint.head)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    use permguard_languages::Verdict;

    /// The resolution itself is asserted where it lives — `permguard_languages::
    /// evaluate::resolve`. What is this crate's to keep true is that the decision
    /// path uses it, and reports what it returned.
    #[test]
    fn a_decision_reports_what_resolve_concluded() {
        let outcome = resolve([
            Verdict::permit(vec!["p1".to_owned()]),
            Verdict::deny(vec!["f1".to_owned()]),
        ]);

        assert!(!outcome.permitted, "an explicit deny still decides");
        assert_eq!(
            outcome.determining(),
            ["f1".to_owned()],
            "and a decision cites what refused it, not what permitted it"
        );
    }
}
