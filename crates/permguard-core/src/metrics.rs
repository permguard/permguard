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

use std::sync::Arc;

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

/// One name-and-value pair narrowing a metric.
pub type Label<'a> = (&'a str, &'a str);

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
pub struct Metrics(Option<Arc<dyn Recorder>>);

impl Metrics {
    /// Returns a handle that discards everything.
    pub fn none() -> Self {
        Self(None)
    }

    /// Returns a handle that records into `recorder`.
    pub fn new(recorder: Arc<dyn Recorder>) -> Self {
        Self(Some(recorder))
    }

    /// Whether anything is actually being kept.
    pub fn is_recording(&self) -> bool {
        self.0.is_some()
    }

    /// Adds one to a counter.
    pub fn count(&self, metric: &Metric, labels: &[Label<'_>]) {
        self.add(metric, labels, 1.0);
    }

    /// Adds `by` to a counter.
    pub fn add(&self, metric: &Metric, labels: &[Label<'_>], by: f64) {
        if let Some(recorder) = &self.0 {
            recorder.record(metric, labels, by);
        }
    }

    /// Sets a gauge to `value`.
    pub fn set(&self, metric: &Metric, labels: &[Label<'_>], value: f64) {
        if let Some(recorder) = &self.0 {
            recorder.record(metric, labels, value);
        }
    }

    /// Adds one observation to a histogram.
    pub fn observe(&self, metric: &Metric, labels: &[Label<'_>], value: f64) {
        if let Some(recorder) = &self.0 {
            recorder.record(metric, labels, value);
        }
    }

    /// Returns every series held, or nothing when nothing is being kept.
    pub fn snapshot(&self) -> Vec<Sample> {
        match &self.0 {
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

        metrics.count(&REQUESTS, &[("outcome", "served")]);
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
}
