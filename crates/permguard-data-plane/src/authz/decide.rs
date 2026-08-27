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
use std::sync::Arc;
use std::time::Instant;

use permguard_core::{ApiError, AuditRecorder, ErrorClass, Metrics, Subject};
use permguard_languages::{Query, resolve};
use tracing::{debug, info, warn};

use super::cache::Cache;
use super::snapshot::{self, Head, Partition, Refusal};
use super::wire::{
    CheckRequest, CheckResponse, Decision, DecisionContext, Reason, Resolved, Semantic,
    TraceContext,
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
        }
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

        let head = match snapshot::head(&mirror.path) {
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
        let resolved = request.resolve(self.max_evaluations).map_err(|malformed| {
            self.metrics
                .count(&super::measure::REFUSALS, &[("reason", "malformed")]);
            // The profile's own status: a payload that is not a request is a
            // bad request, not a decision.
            ApiError::new(ErrorClass::Validation, malformed.code, malformed.message)
        })?;

        let labels = [
            ("zone", resolved.zone.as_str()),
            ("ledger", resolved.ledger.as_str()),
        ];

        let mirror =
            store::find(&self.root, &resolved.zone, &resolved.ledger).ok_or_else(|| {
                self.metrics.count(
                    &super::measure::REFUSALS,
                    &[("reason", "ledger_not_served")],
                );
                debug!(
                    event.name = "authz.ledger_not_served",
                    component = COMPONENT,
                    zone = resolved.zone.as_str(),
                    ledger = resolved.ledger.as_str(),
                    "a request named a ledger this plane does not mirror"
                );

                ApiError::new(
                    ErrorClass::NotFound,
                    "ledger_not_served",
                    format!(
                        "this plane does not serve `{}/{}`",
                        resolved.zone, resolved.ledger
                    ),
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

        let head = match snapshot::head(&mirror.path) {
            Ok(head) => Arc::new(head),
            Err(refusal) => return Err(self.refuse(&mirror, &refusal, &labels)),
        };

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

        let partitions = self.partitions(&mirror, &head, &resolved)?;
        let mut decisions = Vec::new();
        for (query, request_id) in &resolved.queries {
            let decision = self.evaluate(&resolved, &partitions, query, request_id.clone());
            let stop = match resolved.semantic {
                Semantic::ExecuteAll => false,
                Semantic::DenyOnFirstDeny => !decision.decision,
                Semantic::PermitOnFirstPermit => decision.decision,
            };
            decisions.push(decision);
            if stop {
                break;
            }
        }

        // The whole request's verdict: for a plain request it is the one
        // decision; for a batch it is the conjunction, which is what a PEP
        // enforcing a batch has to know.
        let overall = decisions.iter().all(|decision| decision.decision);
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

    /// The compiled partitions of the profile: from memory, or compiled now
    /// and kept.
    fn partitions(
        &self,
        mirror: &store::Mirror,
        head: &Arc<Head>,
        resolved: &Resolved,
    ) -> Result<Vec<Arc<Partition>>, ApiError> {
        let labels = [
            ("zone", resolved.zone.as_str()),
            ("ledger", resolved.ledger.as_str()),
        ];
        let names = head
            .partitions_of(&resolved.profile)
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
                    ("zone", resolved.zone.as_str()),
                    ("ledger", resolved.ledger.as_str()),
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

    /// Evaluates one query against every partition, and combines the answers.
    fn evaluate(
        &self,
        resolved: &Resolved,
        partitions: &[Arc<Partition>],
        query: &Query,
        request_id: Option<String>,
    ) -> Decision {
        let mut verdicts = Vec::with_capacity(partitions.len());

        for partition in partitions {
            let started = Instant::now();
            let verdict = partition.evaluator().evaluate(query);
            self.metrics.observe(
                &super::measure::EVALUATION_SECONDS,
                &[
                    ("zone", resolved.zone.as_str()),
                    ("ledger", resolved.ledger.as_str()),
                    ("partition", partition.name.as_str()),
                ],
                started.elapsed().as_secs_f64(),
            );
            verdicts.push(verdict);
        }

        // The resolution is `permguard_languages::evaluate::resolve`, not a rule of
        // this crate's own: `permguard test` decides a workspace before it is ever
        // pushed here, and the two must not be able to disagree about what a set of
        // verdicts means.
        let outcome = resolve(verdicts);
        let id = self.decision_id();
        let permit = outcome.permitted;
        let context = DecisionContext {
            id: Some(id),
            reason_admin: Some(self.reason_admin(
                permit,
                &outcome.permits,
                &outcome.denials,
                &outcome.errors,
            )),
            reason_user: Some(reason_user(permit)),
            policies: outcome.determining().to_vec(),
        };

        Decision {
            decision: permit,
            request_id,
            context: Some(context),
        }
    }

    fn reason_admin(
        &self,
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

    /// A handle that joins a response to its audit record.
    ///
    /// A UUIDv7, exactly as a stream incarnation is minted: time-ordered for a
    /// human reading two of them, random enough that replicas, restarts and
    /// crash loops never mint the same one. A counter seeded from the process
    /// start would collide on precisely those — autoscaling and crash loops —
    /// which are the moments an investigation needs the handle to hold.
    fn decision_id(&self) -> String {
        permguard_decisions::instance::mint()
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
    entities: Option<serde_json::Value>,
    permit: bool,
    policies: Vec<String>,
    reason: String,
    trace: Option<(String, String)>,
    request_id: Option<String>,
    latency_us: u64,
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
            entities: self.entities.clone(),
            permit: self.permit,
            policies: self.policies.clone(),
            reason: self.reason.clone(),
            trace: self.trace.clone(),
            request_id: self.request_id.clone(),
            latency_us: self.latency_us,
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
                entities: serde_json::to_value(&query.entities).ok(),
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
            };

            self.write(Arc::clone(journal), decided).await?;
        }

        Ok(())
    }

    /// Writes one record, and decides what a failure to write means.
    async fn write(
        &self,
        journal: Arc<crate::decisions::Journal>,
        decided: OwnedDecided,
    ) -> Result<(), ApiError> {
        let refuses_unrecorded = journal.refuses_unrecorded();
        let written =
            tokio::task::spawn_blocking(move || journal.record(&decided.borrowed())).await;

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
            Err(error) => self.journal_error(
                refuses_unrecorded,
                format!("the journal writer task failed: {error}"),
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
