// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the process counts about itself, and who is allowed to count it.
//!
//! Two hand-written gauges answer "is it up". They do not answer "is it slow", "is it refusing
//! anybody", or "was it already refusing people before the page fired" — and those are the questions
//! asked at three in the morning, when nobody can add an instrument to a running process.
//!
//! # Declared, not invented
//!
//! A metric is a `const` [`Metric`] written next to the code that records it, carrying its name, its
//! kind and its help text. Recording takes a reference to that declaration rather than a string, so a
//! typo is a compile error instead of a second series nobody notices, and the exposition can emit
//! `# HELP` and `# TYPE` because they were stated once rather than guessed at render time.
//!
//! # A contract, so the numbers can go somewhere else
//!
//! [`Recorder`] is the whole interface: record a value, and hand back what has been recorded. A build
//! that wants OpenTelemetry, or a hosted collector, implements it and changes nothing else — the code
//! that counts a request does not know what happens to the count. The in-process registry this
//! product ships is one implementation of it.
//!
//! # Labels are the dangerous part
//!
//! Every distinct combination of label values is a series held in memory for the life of the process.
//! Labels whose values come from a client — a path, a user agent, an identifier — turn a request into
//! an allocation an attacker controls the number of. Label by things with small, fixed ranges: a
//! method, a status class, an outcome. The registry defends itself with a ceiling, but a ceiling that
//! is being hit means the numbers stopped being useful some time ago.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What a number means, which decides how a recorded value is combined with what came before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Only ever goes up. Recording adds to it.
    ///
    /// A restart takes it back to zero, which is expected: a scraper reads the *rate*, and a counter
    /// that went backwards is how it knows the process restarted.
    Counter,
    /// A level that goes up and down. Recording replaces it.
    Gauge,
    /// A distribution. Recording adds one observation.
    ///
    /// This is what answers "how slow", which an average cannot: the mean of a hundred fast requests
    /// and one that took a minute is a fast request, and the minute is the one worth knowing about.
    Histogram,
}

/// A metric that exists, declared once next to whatever records it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Metric {
    name: &'static str,
    kind: Kind,
    help: &'static str,
    buckets: &'static [f64],
}

/// Bucket boundaries for something measured in seconds, from a millisecond to a minute.
///
/// Wide on purpose. Buckets that stop at a second cannot tell a request that took two seconds from
/// one that took two minutes, and the difference between those two is the entire incident.
pub const SECONDS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

impl Metric {
    /// Declares something that only goes up.
    pub const fn counter(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            kind: Kind::Counter,
            help,
            buckets: &[],
        }
    }

    /// Declares a level.
    pub const fn gauge(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            kind: Kind::Gauge,
            help,
            buckets: &[],
        }
    }

    /// Declares a distribution, observed into `buckets`.
    pub const fn histogram(
        name: &'static str,
        help: &'static str,
        buckets: &'static [f64],
    ) -> Self {
        Self {
            name,
            kind: Kind::Histogram,
            help,
            buckets,
        }
    }

    /// Returns the name a scraper sees.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns what the number means.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Returns the one-line description published beside it.
    pub fn help(&self) -> &'static str {
        self.help
    }

    /// Returns the bucket boundaries, which are empty for anything that is not a histogram.
    pub fn buckets(&self) -> &'static [f64] {
        self.buckets
    }
}

/// One label of one series: a registered name and a value from that name's vocabulary.
pub type Label<'a> = (LabelName, &'a str);

/// What a value outside its label's vocabulary is recorded as.
pub const OTHER: &str = "other";

/// A label a metric may carry, with every value it may take.
#[derive(Debug, PartialEq, Eq)]
pub struct LabelSpec {
    name: &'static str,
    values: &'static [&'static str],
}

/// A registered label name. The only way to obtain one is a constant of [`labels`], so a metric
/// cannot carry a label the registry does not list: that is a compile error, not a review comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelName(&'static LabelSpec);

impl LabelName {
    /// The name as the exposition writes it.
    pub fn as_str(self) -> &'static str {
        self.0.name
    }

    /// Every value the label may take; anything else is recorded as [`OTHER`].
    pub fn values(self) -> &'static [&'static str] {
        self.0.values
    }

    /// Whether `value` belongs to the vocabulary.
    pub fn admits(self, value: &str) -> bool {
        value == OTHER
            || self.0.values.contains(&value)
            || (self.0.name == "reason" && crate::codes::is_registered(value))
    }
}

/// The label registry: every label name a metric may carry, and each one's closed vocabulary.
///
/// P10 forbids tenant, resource, principal, request, stream and policy identifiers as labels; they
/// are absent from this list, and a value from outside a vocabulary — an identifier that reached a
/// label by mistake, or one an attacker chose — is recorded as [`OTHER`] and counted by
/// [`LABEL_VALUES_REFUSED`], so the number of series stays bounded whatever a client sends. The
/// vocabularies are part of the telemetry schema whose version [`TELEMETRY_SCHEMA`] publishes: a
/// change here is a schema change.
pub mod labels {
    use super::{LabelName, LabelSpec};

    macro_rules! label {
        ($(#[$doc:meta])* $constant:ident, $name:literal, [$($value:literal),* $(,)?]) => {
            $(#[$doc])*
            pub const $constant: LabelName =
                LabelName(&LabelSpec { name: $name, values: &[$($value),*] });
        };
    }

    label!(
        /// How an operation ended. Words, never a message or anything a client wrote.
        OUTCOME, "outcome", [
            "accepted", "blocked", "conflict", "damaged", "decided", "deferred", "deny",
            "dropped", "empty", "expired", "failed", "internal", "not_found", "ok",
            "out_of_order", "partial", "permit", "quarantined", "queued", "ready", "refused",
            "rejected", "replay", "replayed", "served", "skipped", "timeout", "unavailable",
            "unchanged", "validation", "written",
        ]
    );
    label!(
        /// Why something was refused: these words, or any stable code of
        /// [`crate::codes`], which is itself a closed registry.
        REASON, "reason", [
            "age_expiry", "at_capacity", "closed", "conflict", "event_ahead_of_clock",
            "event_application_incomplete", "event_id_conflict", "event_out_of_order",
            "event_routing_conflict", "event_too_late", "history_incomplete", "history_stale",
            "history_unorderable", "journal_full", "journal_unavailable", "ledger_damaged",
            "ledger_empty", "ledger_expired", "ledger_incompatible", "ledger_not_served",
            "malformed", "not_followed", "profile_unknown", "quarantined", "spool_full",
            "unattributable", "unavailable", "unrecordable", "unverifiable",
        ]
    );
    label!(
        /// The NOTP operation.
        OP, "op", ["fetch", "pull_negotiate", "push_commit", "push_negotiate", "ref", "upload"]
    );
    label!(
        /// How a NOTP batch was carried. The client names it, so the vocabulary is what bounds it.
        ENCODING, "encoding", ["deflate", "raw"]
    );
    label!(
        /// The catalog operation, as its audit action names it.
        ACTION, "action", [
            "ledger.create", "ledger.create.refused", "ledger.created", "ledger.delete",
            "ledger.delete.refused", "ledger.deleted", "ledger.rename", "ledger.rename.refused",
            "ledger.renamed", "zone.create", "zone.create.refused", "zone.created",
            "zone.delete", "zone.delete.refused", "zone.deleted", "zone.rename",
            "zone.rename.refused", "zone.renamed",
        ]
    );
    label!(
        /// What a read or a refusal applied to: a connection pool or peer, or an event stream or
        /// tenant read.
        SCOPE, "scope", ["peer", "pool", "stream", "tenant"]
    );
    label!(
        /// The process surface a request or a certificate belongs to.
        SURFACE, "surface", ["control-plane", "data-plane", "server", "telemetry"]
    );
    label!(
        /// What a key ring signs.
        ROLE, "role", ["operations", "tokens"]
    );
    label!(
        /// The HTTP method. The client chooses it, so the vocabulary is what bounds it.
        METHOD, "method", ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"]
    );
    label!(
        /// The kind of a decision record shipped.
        KIND, "kind", ["decision", "decision_retry", "marker"]
    );
    label!(
        /// A cache lookup.
        RESULT, "result", ["hit", "miss"]
    );
    label!(
        /// The HTTP status code answered.
        STATUS, "status", [
            "100", "101", "200", "201", "202", "203", "204", "205", "206", "207", "300", "301",
            "302", "303", "304", "307", "308", "400", "401", "402", "403", "404", "405", "406",
            "407", "408", "409", "410", "411", "412", "413", "414", "415", "416", "417", "421",
            "422", "423", "424", "425", "426", "428", "429", "431", "451", "500", "501", "502",
            "503", "504", "505", "506", "507", "508", "510", "511",
        ]
    );
    label!(
        /// Which issuer a key ring belongs to: the server itself, or a realm.
        ISSUER, "issuer", ["realm", "server"]
    );
    label!(
        /// The schema version itself.
        VERSION, "version", ["2"]
    );
    label!(
        /// The label whose value a recording refused, for [`super::LABEL_VALUES_REFUSED`].
        LABEL, "label", ["outcome", "reason", "op", "encoding", "action", "scope", "surface", "role", "method", "kind", "result", "status", "issuer", "version"]
    );

    /// Every registered label.
    pub const ALL: &[LabelName] = &[
        OUTCOME, REASON, OP, ENCODING, ACTION, SCOPE, SURFACE, ROLE, METHOD, KIND, RESULT, STATUS,
        ISSUER, VERSION, LABEL,
    ];
}

/// Recordings whose label value fell outside its vocabulary and was recorded as `other`.
pub const LABEL_VALUES_REFUSED: Metric = Metric::counter(
    "permguard_metric_label_values_refused_total",
    "Recordings whose label value was outside the label's registered vocabulary, by label.",
);

/// The telemetry schema this build exposes, as a gauge that always reads 1.
///
/// Version 2 removed every tenant, resource and stream identifier from the labels.
pub const TELEMETRY_SCHEMA: Metric = Metric::gauge(
    "permguard_telemetry_schema_info",
    "The telemetry schema this build exposes; reads 1, the version is the label.",
);

/// The schema version [`TELEMETRY_SCHEMA`] carries.
pub const TELEMETRY_SCHEMA_VERSION: &str = "2";

/// What a series currently reads.
#[derive(Debug, Clone, PartialEq)]
pub enum Reading {
    /// A counter or a gauge: one number.
    Value(f64),
    /// A histogram: how many observations fell at or below each boundary, and their total.
    Distribution {
        /// Each boundary and the number of observations at or below it.
        buckets: Vec<(f64, u64)>,
        /// How many observations there have been, including those above the last boundary.
        count: u64,
        /// What they add up to, which is what makes an average possible.
        sum: f64,
    },
}

/// One series, as it stood when the snapshot was taken.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// The declaration this came from.
    pub metric: Metric,
    /// What narrows it, in the order the exposition should write them.
    pub labels: Vec<(String, String)>,
    /// What it reads.
    pub reading: Reading,
}

/// Somewhere for numbers to go.
///
/// Implemented by whatever a build keeps its measurements in. The recording side takes a declaration
/// and a value; how the two are combined is decided by [`Metric::kind`], so an implementation never
/// has to be told twice and callers cannot disagree about it.
pub trait Recorder: Send + Sync + std::fmt::Debug {
    /// Records `value` against `metric`, narrowed by `labels`.
    ///
    /// Adds for a counter, replaces for a gauge, observes for a histogram. Never fails: a measurement
    /// that could return an error is a measurement whose error handling is more code than the thing
    /// being measured, and a process does not stop serving because it could not count.
    fn record(&self, metric: &Metric, labels: &[Label<'_>], value: f64);

    /// Returns every series held, for something that publishes them.
    fn snapshot(&self) -> Vec<Sample>;
}

/// The handle everything else holds.
///
/// Cheap to clone and safe to hold when nothing is installed, which is the point: a build that
/// records no metrics should not force every call site into an `if let`. With no recorder behind it
/// every method here is a branch and a return.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    recorder: Option<Arc<dyn Recorder>>,
    /// The per-resource values behind each aggregated gauge, by metric and then by resource. The
    /// resource never leaves this map: only the aggregate is recorded.
    resources: Arc<Mutex<HashMap<&'static str, Aggregated>>>,
}

/// One aggregated gauge: each resource's value, and the aggregate kept up to date as they change,
/// so setting one resource costs a constant amount of work rather than a pass over all of them.
#[derive(Debug, Default)]
struct Aggregated {
    values: HashMap<String, f64>,
    aggregate: f64,
}

impl Aggregated {
    /// Sets one resource's value and moves the aggregate with it.
    fn set(&mut self, resource: &str, value: f64, how: Aggregate) {
        let old = self.values.insert(resource.to_owned(), value);
        match how {
            Aggregate::Sum => self.aggregate += value - old.unwrap_or(0.0),
            Aggregate::Max => {
                if value >= self.aggregate {
                    self.aggregate = value;
                } else if old == Some(self.aggregate) {
                    // The resource that held the maximum fell: only then is a pass needed.
                    self.recompute(how);
                }
            }
            Aggregate::Min => {
                if self.values.len() == 1 || value <= self.aggregate {
                    self.aggregate = value;
                } else if old == Some(self.aggregate) {
                    self.recompute(how);
                }
            }
        }
    }

    /// The aggregate over every resource, computed afresh.
    fn recompute(&mut self, how: Aggregate) {
        let values = self.values.values().copied();
        self.aggregate = match how {
            Aggregate::Sum => values.sum(),
            Aggregate::Max => values.fold(0.0, f64::max),
            Aggregate::Min => values
                .fold(None, |least: Option<f64>, value| {
                    Some(least.map_or(value, |least| least.min(value)))
                })
                .unwrap_or(0.0),
        };
    }
}

/// How [`Metrics::set_aggregated`] combines the per-resource values of one gauge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregate {
    /// The total: bytes held, records behind, ledgers blocked.
    Sum,
    /// The largest: the stalest mirror, the longest staleness. Never below zero, which suits the
    /// ages and durations it is used for.
    Max,
    /// The smallest: the earliest of several "last happened at" timestamps. Zero with no resource.
    Min,
}

/// The most resources one process keeps a value for, across every aggregated gauge together: with
/// eight gauges keyed by ledger it is reached near eight thousand ledgers. A resource beyond it is
/// not added: its value is left out of the aggregate and counted, so the map stays bounded
/// whatever names reach it.
pub const AGGREGATED_RESOURCES_CEILING: usize = 65_536;

/// Per-resource values an aggregated gauge could not keep, because the ceiling was reached.
pub const AGGREGATED_RESOURCES_REFUSED: Metric = Metric::counter(
    "permguard_metric_aggregated_resources_refused_total",
    "Per-resource values not kept for an aggregated gauge because the resource ceiling was reached.",
);

impl Metrics {
    /// Returns a handle that discards everything.
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns a handle that records into `recorder`.
    pub fn new(recorder: Arc<dyn Recorder>) -> Self {
        Self {
            recorder: Some(recorder),
            resources: Arc::default(),
        }
    }

    /// Whether anything is actually being kept.
    pub fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// Adds one to a counter.
    pub fn count(&self, metric: &Metric, labels: &[Label<'_>]) {
        self.add(metric, labels, 1.0);
    }

    /// Adds `by` to a counter.
    pub fn add(&self, metric: &Metric, labels: &[Label<'_>], by: f64) {
        self.record(metric, labels, by);
    }

    /// Sets a gauge to `value`.
    pub fn set(&self, metric: &Metric, labels: &[Label<'_>], value: f64) {
        self.record(metric, labels, value);
    }

    /// Adds one observation to a histogram.
    pub fn observe(&self, metric: &Metric, labels: &[Label<'_>], value: f64) {
        self.record(metric, labels, value);
    }

    /// Sets one resource's value of a gauge whose series is the aggregate over every resource.
    ///
    /// P10 keeps resource identifiers out of labels, but a gauge such as "bytes a ledger holds" is
    /// set once per resource: recorded without a label, each resource would overwrite the last and
    /// the series would read whichever ledger happened to be measured last. Here each resource's
    /// value is kept beside the handle, keyed by `resource` — which is never recorded — and the
    /// gauge is set to the sum or the maximum over all of them.
    pub fn set_aggregated(&self, metric: &Metric, how: Aggregate, resource: &str, value: f64) {
        if self.recorder.is_none() || !value.is_finite() {
            return;
        }
        let mut held = self
            .resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let known = held
            .get(metric.name())
            .is_some_and(|gauge| gauge.values.contains_key(resource));
        let total: usize = held.values().map(|gauge| gauge.values.len()).sum();
        if !known && total >= AGGREGATED_RESOURCES_CEILING {
            drop(held);
            self.count(&AGGREGATED_RESOURCES_REFUSED, &[]);
            return;
        }
        let gauge = held.entry(metric.name()).or_default();
        gauge.set(resource, value, how);
        // Published while the map is still held, so two resources set at once cannot publish their
        // aggregates in the opposite order and leave the gauge on the older one.
        self.set(metric, &[], gauge.aggregate);
    }

    /// Forgets one resource of an aggregated gauge, when the resource is gone, and republishes.
    pub fn forget_aggregated(&self, metric: &Metric, how: Aggregate, resource: &str) {
        if self.recorder.is_none() {
            return;
        }
        let mut held = self
            .resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let gauge = held.entry(metric.name()).or_default();
        gauge.values.remove(resource);
        gauge.recompute(how);
        self.set(metric, &[], gauge.aggregate);
    }

    /// Forgets every resource of an aggregated gauge that `present` no longer admits, and
    /// republishes: a measuring round calls it with what it found, so a resource that went away
    /// stops counting toward the sum, the maximum or the minimum.
    pub fn retain_aggregated(
        &self,
        metric: &Metric,
        how: Aggregate,
        present: impl Fn(&str) -> bool,
    ) {
        if self.recorder.is_none() {
            return;
        }
        let mut held = self
            .resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let gauge = held.entry(metric.name()).or_default();
        gauge.values.retain(|resource, _| present(resource));
        gauge.recompute(how);
        self.set(metric, &[], gauge.aggregate);
    }

    /// Publishes the telemetry schema version, once at startup.
    pub fn publish_schema(&self) {
        self.set(
            &TELEMETRY_SCHEMA,
            &[(labels::VERSION, TELEMETRY_SCHEMA_VERSION)],
            1.0,
        );
    }

    /// Records with every label value inside its vocabulary: a value outside it becomes [`OTHER`]
    /// and is counted. The common case — every value admitted — allocates nothing.
    fn record(&self, metric: &Metric, labels: &[Label<'_>], value: f64) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        if labels.iter().all(|(name, held)| name.admits(held)) {
            recorder.record(metric, labels, value);
            return;
        }
        let admitted: Vec<Label<'_>> = labels
            .iter()
            .map(|(name, held)| {
                if name.admits(held) {
                    (*name, *held)
                } else {
                    recorder.record(
                        &LABEL_VALUES_REFUSED,
                        &[(self::labels::LABEL, name.as_str())],
                        1.0,
                    );
                    (*name, OTHER)
                }
            })
            .collect();
        recorder.record(metric, &admitted, value);
    }

    /// Returns every series held, or nothing when nothing is being kept.
    pub fn snapshot(&self) -> Vec<Sample> {
        match &self.recorder {
            Some(recorder) => recorder.snapshot(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const REQUESTS: Metric = Metric::counter("permguard_requests_total", "Requests served.");

    #[derive(Debug, Default)]
    struct Counting(std::sync::Mutex<Vec<(String, f64)>>);

    impl Recorder for Counting {
        fn record(&self, metric: &Metric, _labels: &[Label<'_>], value: f64) {
            if let Ok(mut recorded) = self.0.lock() {
                recorded.push((metric.name().to_owned(), value));
            }
        }

        fn snapshot(&self) -> Vec<Sample> {
            Vec::new()
        }
    }

    #[test]
    fn test_a_handle_with_nothing_behind_it_is_still_safe_to_call() {
        // The property that matters: a build that installs no recorder does not have to guard every
        // call site, so nobody is tempted to skip the measurement to avoid the `if let`.
        let metrics = Metrics::none();

        metrics.count(&REQUESTS, &[(labels::OUTCOME, "served")]);
        metrics.set(&REQUESTS, &[], 3.0);
        metrics.observe(&REQUESTS, &[], 0.25);

        assert!(!metrics.is_recording());
        assert!(metrics.snapshot().is_empty());
    }

    #[test]
    fn test_what_is_recorded_reaches_the_recorder() {
        let recorder = Arc::new(Counting::default());
        let metrics = Metrics::new(Arc::clone(&recorder) as Arc<dyn Recorder>);

        metrics.count(&REQUESTS, &[]);
        metrics.add(&REQUESTS, &[], 4.0);

        let recorded = recorder.0.lock().expect("the recorder is not poisoned");
        assert_eq!(
            *recorded,
            vec![
                ("permguard_requests_total".to_owned(), 1.0),
                ("permguard_requests_total".to_owned(), 4.0)
            ]
        );
    }

    #[test]
    fn test_a_declaration_carries_what_the_exposition_needs() {
        // `# HELP` and `# TYPE` come from here rather than from a guess at render time, which is only
        // possible because declaring a metric and recording to it are the same act.
        let latency = Metric::histogram(
            "permguard_request_seconds",
            "How long requests took.",
            SECONDS,
        );

        assert_eq!(latency.kind(), Kind::Histogram);
        assert!(!latency.help().is_empty());
        assert!(!latency.buckets().is_empty());
        assert!(REQUESTS.buckets().is_empty());
    }

    #[test]
    fn test_the_bucket_boundaries_climb() {
        // A bucket set that is not sorted silently produces cumulative counts that go backwards, which
        // renders as a histogram no query language can read.
        assert!(SECONDS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// One recording: metric, labels, value.
    type Recorded = (String, Vec<(String, String)>, f64);

    /// What a recorder was handed.
    #[derive(Debug, Default)]
    struct Labelled(std::sync::Mutex<Vec<Recorded>>);

    impl Recorder for Labelled {
        fn record(&self, metric: &Metric, labels: &[Label<'_>], value: f64) {
            if let Ok(mut recorded) = self.0.lock() {
                recorded.push((
                    metric.name().to_owned(),
                    labels
                        .iter()
                        .map(|(name, value)| (name.as_str().to_owned(), (*value).to_owned()))
                        .collect(),
                    value,
                ));
            }
        }

        fn snapshot(&self) -> Vec<Sample> {
            Vec::new()
        }
    }

    fn labelled() -> (Arc<Labelled>, Metrics) {
        let recorder = Arc::new(Labelled::default());
        let metrics = Metrics::new(Arc::clone(&recorder) as Arc<dyn Recorder>);
        (recorder, metrics)
    }

    #[test]
    fn test_the_registry_holds_no_identifier_and_no_duplicate() {
        let forbidden = [
            "zone",
            "ledger",
            "tenant",
            "resource",
            "principal",
            "subject",
            "request",
            "request_id",
            "stream",
            "policy",
            "partition",
            "pdp",
            "instance",
            "realm",
            "user",
            "id",
            "path",
            "event_id",
            "producer",
        ];
        let mut names = std::collections::BTreeSet::new();
        for label in labels::ALL {
            assert!(
                !forbidden.contains(&label.as_str()),
                "`{}` is an identifier P10 forbids as a label",
                label.as_str()
            );
            assert!(
                names.insert(label.as_str()),
                "`{}` is registered twice",
                label.as_str()
            );
            let values: std::collections::BTreeSet<_> = label.values().iter().collect();
            assert_eq!(
                values.len(),
                label.values().len(),
                "`{}` repeats a value",
                label.as_str()
            );
            assert!(
                !label.values().contains(&OTHER),
                "`other` is implied, never listed"
            );
        }
        let named: std::collections::BTreeSet<&str> = labels::ALL
            .iter()
            .filter(|label| **label != labels::LABEL)
            .map(|label| label.as_str())
            .collect();
        let listed: std::collections::BTreeSet<&str> =
            labels::LABEL.values().iter().copied().collect();
        assert_eq!(
            listed, named,
            "`label` names exactly the other registered labels"
        );
    }

    #[test]
    fn test_a_value_outside_its_vocabulary_is_recorded_as_other_and_counted() {
        let (recorder, metrics) = labelled();
        metrics.count(&REQUESTS, &[(labels::OUTCOME, "ok")]);
        metrics.count(&REQUESTS, &[(labels::OUTCOME, "acme-tenant-42")]);
        metrics.count(
            &REQUESTS,
            &[(labels::REASON, crate::codes::catalog::NAME_TAKEN)],
        );

        let recorded = recorder.0.lock().expect("the recorder is not poisoned");
        let value_of = |index: usize| recorded[index].1[0].1.clone();
        assert_eq!(value_of(0), "ok");
        assert_eq!(
            recorded[1],
            (
                LABEL_VALUES_REFUSED.name().to_owned(),
                vec![("label".to_owned(), "outcome".to_owned())],
                1.0
            )
        );
        assert_eq!(value_of(2), OTHER, "the identifier never became a series");
        assert_eq!(
            value_of(3),
            "name_taken",
            "a registered stable code is a reason"
        );
    }

    #[test]
    fn test_an_aggregated_gauge_publishes_only_the_aggregate_and_never_the_resource() {
        let gauge = Metric::gauge("permguard_test_bytes", "Bytes.");
        let (recorder, metrics) = labelled();
        metrics.set_aggregated(&gauge, Aggregate::Sum, "zone-a/ledger-a", 10.0);
        metrics.set_aggregated(&gauge, Aggregate::Sum, "zone-b/ledger-b", 5.0);
        metrics.set_aggregated(&gauge, Aggregate::Sum, "zone-a/ledger-a", 7.0);
        metrics.forget_aggregated(&gauge, Aggregate::Sum, "zone-b/ledger-b");

        let recorded = recorder.0.lock().expect("the recorder is not poisoned");
        let values: Vec<f64> = recorded.iter().map(|(_, _, value)| *value).collect();
        assert_eq!(values, [10.0, 15.0, 12.0, 7.0]);
        assert!(
            recorded.iter().all(|(_, labels, _)| labels.is_empty()),
            "no resource reaches a label"
        );
    }

    #[test]
    fn test_the_maximum_and_the_minimum_track_the_worst_resource() {
        let age = Metric::gauge("permguard_test_age", "Age.");
        let last = Metric::gauge("permguard_test_last", "Last.");
        let (recorder, metrics) = labelled();
        metrics.set_aggregated(&age, Aggregate::Max, "a", 3.0);
        metrics.set_aggregated(&age, Aggregate::Max, "b", 9.0);
        metrics.set_aggregated(&age, Aggregate::Max, "b", 1.0);
        metrics.set_aggregated(&last, Aggregate::Min, "a", 200.0);
        metrics.set_aggregated(&last, Aggregate::Min, "b", 100.0);

        let recorded = recorder.0.lock().expect("the recorder is not poisoned");
        let values: Vec<f64> = recorded.iter().map(|(_, _, value)| *value).collect();
        assert_eq!(values, [3.0, 9.0, 3.0, 200.0, 100.0]);
    }

    #[test]
    fn test_a_resource_that_is_no_longer_present_stops_counting() {
        let age = Metric::gauge("permguard_test_age", "Age.");
        let bytes = Metric::gauge("permguard_test_bytes", "Bytes.");
        let (recorder, metrics) = labelled();
        metrics.set_aggregated(&age, Aggregate::Max, "gone", 90.0);
        metrics.set_aggregated(&age, Aggregate::Max, "kept", 4.0);
        metrics.set_aggregated(&bytes, Aggregate::Sum, "gone", 6.0);
        metrics.retain_aggregated(&age, Aggregate::Max, |resource| resource == "kept");

        let recorded = recorder.0.lock().expect("the recorder is not poisoned");
        let values: Vec<f64> = recorded.iter().map(|(_, _, value)| *value).collect();
        // The stalest resource went away, so the gauge falls to the one that is left; another
        // gauge's resource of the same name is untouched.
        assert_eq!(values, [90.0, 90.0, 6.0, 4.0]);
        drop(recorded);
        metrics.set_aggregated(&bytes, Aggregate::Sum, "other", 1.0);
        let recorded = recorder.0.lock().expect("the recorder is not poisoned");
        assert_eq!(recorded.last().map(|(_, _, value)| *value), Some(7.0));
    }

    #[test]
    fn test_the_kept_aggregate_equals_one_computed_afresh_after_every_change() {
        // A fixed pseudo-random walk: resources rise, fall, and are forgotten in every order.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move |bound: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % bound
        };
        for how in [Aggregate::Sum, Aggregate::Max, Aggregate::Min] {
            let mut kept = Aggregated::default();
            for _ in 0..5_000 {
                let resource = format!("ledger-{}", next(40));
                if next(10) == 0 {
                    kept.values.remove(&resource);
                    kept.recompute(how);
                } else {
                    kept.set(&resource, next(1_000) as f64, how);
                }
                let mut fresh = Aggregated {
                    values: kept.values.clone(),
                    aggregate: 0.0,
                };
                fresh.recompute(how);
                assert_eq!(kept.aggregate, fresh.aggregate, "{how:?} drifted");
            }
        }
    }

    #[test]
    fn test_the_schema_version_is_published_as_a_label() {
        let (recorder, metrics) = labelled();
        metrics.publish_schema();
        let recorded = recorder.0.lock().expect("the recorder is not poisoned");
        assert_eq!(
            recorded[0],
            (
                "permguard_telemetry_schema_info".to_owned(),
                vec![("version".to_owned(), TELEMETRY_SCHEMA_VERSION.to_owned())],
                1.0
            )
        );
    }
}
