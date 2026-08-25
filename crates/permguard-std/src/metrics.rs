// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An in-process registry: the numbers, held here, until something scrapes them.
//!
//! No dependency, no background task, no exporter. A `HashMap` behind a lock, read whole when
//! `/metrics` is asked for. That is the right shape for a process that is scraped every fifteen
//! seconds and records a handful of things per request — anything more elaborate would be machinery
//! in front of a hundred numbers.
//!
//! # A lock, and why it is not the bottleneck
//!
//! Recording takes a write lock for the length of a hash lookup and an addition. At the rate this is
//! recorded — single figures per request — the lock is uncontended in any load these surfaces will
//! see, and the alternative (an atomic per series, resolved through a read lock) buys nothing until
//! the recording rate is orders of magnitude higher. It is measurable, so it can be revisited on
//! evidence rather than on taste.
//!
//! # The ceiling
//!
//! Every distinct set of label values is a series that lives until the process exits. A label whose
//! values come from a client is therefore an allocation an attacker controls the count of, and one
//! misplaced label is enough to turn a scrape into a memory exhaustion. This registry refuses to hold
//! more than [`SERIES_CEILING`] of them and says so once — the numbers are already wrong by then, but
//! the process is still up to report that they are.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use permguard_core::metrics::{Kind, Label, Metric, Reading, Recorder, Sample};

/// The `component` every record from here carries.
const COMPONENT: &str = "metrics";

/// How many distinct series this will hold before it stops taking new ones.
///
/// Far above what a correct set of declarations produces — a few dozen metrics with a few label
/// values each — and far below what would trouble a process. Reaching it means a label is carrying
/// something it should not.
pub const SERIES_CEILING: usize = 10_000;

/// One series: a metric, narrowed by a particular set of label values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Series {
    name: &'static str,
    labels: Vec<(String, String)>,
}

/// What a series holds.
#[derive(Debug)]
enum Held {
    /// A counter or a gauge.
    Value(f64),
    /// A histogram: one count per boundary, plus the totals.
    Distribution {
        counts: Vec<u64>,
        count: u64,
        sum: f64,
    },
}

/// The numbers this process has recorded about itself.
#[derive(Debug, Default)]
pub struct Registry {
    series: RwLock<HashMap<Series, (Metric, Held)>>,
    /// Whether the ceiling has already been reported, so a runaway label is one log record rather
    /// than one per request — which under the conditions that cause it is the same as no record.
    overflowed: AtomicBool,
}

impl Registry {
    /// Builds an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns how many distinct series are held, which is the number worth watching.
    pub fn len(&self) -> usize {
        match self.series.read() {
            Ok(held) => held.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Whether nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Sorts labels, so the same pair given in either order is the same series rather than two.
fn keyed(labels: &[Label<'_>]) -> Vec<(String, String)> {
    let mut owned: Vec<(String, String)> = labels
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    owned.sort();

    owned
}

impl Recorder for Registry {
    fn record(&self, metric: &Metric, labels: &[Label<'_>], value: f64) {
        // A measurement that is not a number would render as `NaN` in the exposition and poison every
        // query that touches the series, so it is dropped at the door.
        if !value.is_finite() {
            return;
        }

        let key = Series {
            name: metric.name(),
            labels: keyed(labels),
        };

        // Poisoning is stepped over rather than respected. It means a panic happened somewhere while
        // this lock was held; what it protects is a map of counters, which cannot be left half-written
        // by a panic in a way that matters. Treating it as fatal would mean one panic anywhere in the
        // process silently ends measurement for the rest of its life — and the process would still be
        // serving, with a `/metrics` that answers and says nothing.
        let mut held = match self.series.write() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };

        match held.get_mut(&key) {
            Some((_, existing)) => apply(metric, existing, value),
            None => {
                if held.len() >= SERIES_CEILING {
                    if !self.overflowed.swap(true, Ordering::SeqCst) {
                        tracing::error!(
                            event.name = "metrics.series_ceiling_reached",
                            component = COMPONENT,
                            ceiling = SERIES_CEILING,
                            metric = metric.name(),
                            "refusing new series: a label is carrying something with too many values"
                        );
                    }

                    return;
                }

                let mut fresh = empty(metric);
                apply(metric, &mut fresh, value);
                held.insert(key, (*metric, fresh));
            }
        }
    }

    fn snapshot(&self) -> Vec<Sample> {
        let held = match self.series.read() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut samples: Vec<Sample> = held
            .iter()
            .map(|(series, (metric, held))| Sample {
                metric: *metric,
                labels: series.labels.clone(),
                reading: read(metric, held),
            })
            .collect();

        // A `HashMap` hands them back in whatever order it likes, and an exposition whose lines move
        // between scrapes is one nobody can diff. Sorting also groups a metric's series together,
        // which is what the format expects.
        samples.sort_by(|left, right| {
            left.metric
                .name()
                .cmp(right.metric.name())
                .then_with(|| left.labels.cmp(&right.labels))
        });

        samples
    }
}

/// Builds the zero a series starts from.
fn empty(metric: &Metric) -> Held {
    match metric.kind() {
        Kind::Counter | Kind::Gauge => Held::Value(0.0),
        Kind::Histogram => Held::Distribution {
            counts: vec![0; metric.buckets().len()],
            count: 0,
            sum: 0.0,
        },
    }
}

/// Combines `value` with what is already there, as the metric's kind says to.
fn apply(metric: &Metric, held: &mut Held, value: f64) {
    match (metric.kind(), held) {
        (Kind::Counter, Held::Value(current)) => {
            // A counter only goes up. A negative addition would make the rate a scraper computes read
            // as a restart, which is a lie about the process rather than about the number.
            if value >= 0.0 {
                *current += value;
            }
        }
        (Kind::Gauge, Held::Value(current)) => *current = value,
        (Kind::Histogram, Held::Distribution { counts, count, sum }) => {
            for (index, boundary) in metric.buckets().iter().enumerate() {
                if value <= *boundary
                    && let Some(slot) = counts.get_mut(index)
                {
                    *slot += 1;
                }
            }

            *count += 1;
            *sum += value;
        }
        // A declaration whose kind changed between recording and reading cannot happen: the kind is a
        // `const` field of the declaration the caller passed, and the series was created from it.
        _ => {}
    }
}

/// Turns what is held into what a publisher reads.
fn read(metric: &Metric, held: &Held) -> Reading {
    match held {
        Held::Value(value) => Reading::Value(*value),
        Held::Distribution { counts, count, sum } => Reading::Distribution {
            buckets: metric
                .buckets()
                .iter()
                .copied()
                .zip(counts.iter().copied())
                .collect(),
            count: *count,
            sum: *sum,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use permguard_core::metrics::SECONDS;

    const REQUESTS: Metric = Metric::counter("permguard_requests_total", "Requests served.");
    const CONNECTIONS: Metric = Metric::gauge("permguard_connections", "Connections held.");
    const LATENCY: Metric = Metric::histogram(
        "permguard_request_seconds",
        "How long requests took.",
        SECONDS,
    );

    /// The reading of the one series matching `name`.
    fn only(registry: &Registry, name: &str) -> Reading {
        let samples = registry.snapshot();
        let matching: Vec<&Sample> = samples
            .iter()
            .filter(|sample| sample.metric.name() == name)
            .collect();

        assert_eq!(matching.len(), 1, "expected one `{name}` series");

        matching[0].reading.clone()
    }

    #[test]
    fn test_a_counter_accumulates_and_a_gauge_replaces() {
        let registry = Registry::new();

        registry.record(&REQUESTS, &[], 1.0);
        registry.record(&REQUESTS, &[], 1.0);
        registry.record(&REQUESTS, &[], 3.0);

        registry.record(&CONNECTIONS, &[], 40.0);
        registry.record(&CONNECTIONS, &[], 12.0);

        assert_eq!(
            only(&registry, "permguard_requests_total"),
            Reading::Value(5.0)
        );
        assert_eq!(
            only(&registry, "permguard_connections"),
            Reading::Value(12.0)
        );
    }

    #[test]
    fn test_a_counter_cannot_be_made_to_go_backwards() {
        // A counter that decreases reads to a scraper as a process restart, so a caller passing a
        // negative — by arithmetic error or otherwise — would fabricate an event that never happened.
        let registry = Registry::new();

        registry.record(&REQUESTS, &[], 5.0);
        registry.record(&REQUESTS, &[], -3.0);

        assert_eq!(
            only(&registry, "permguard_requests_total"),
            Reading::Value(5.0)
        );
    }

    #[test]
    fn test_a_measurement_that_is_not_a_number_never_enters() {
        // One NaN in a series makes every query over it return NaN for as long as the process lives.
        let registry = Registry::new();

        registry.record(&CONNECTIONS, &[], f64::NAN);
        registry.record(&CONNECTIONS, &[], f64::INFINITY);

        assert!(registry.is_empty(), "a non-number was recorded");
    }

    #[test]
    fn test_a_histogram_counts_every_bucket_an_observation_falls_within() {
        let registry = Registry::new();

        registry.record(&LATENCY, &[], 0.003);
        registry.record(&LATENCY, &[], 0.4);
        // Above the last boundary: counted in the total, in no bucket.
        registry.record(&LATENCY, &[], 120.0);

        let Reading::Distribution {
            buckets,
            count,
            sum,
        } = only(&registry, "permguard_request_seconds")
        else {
            panic!("a histogram read as a single value");
        };

        assert_eq!(count, 3);
        assert!((sum - 120.403).abs() < 1e-9, "the total was {sum}");

        // Cumulative: each boundary holds everything at or below it, so the counts never decrease.
        assert!(
            buckets.windows(2).all(|pair| pair[0].1 <= pair[1].1),
            "the counts are not cumulative: {buckets:?}"
        );

        let at = |boundary: f64| {
            buckets
                .iter()
                .find(|(edge, _)| (*edge - boundary).abs() < f64::EPSILON)
                .map(|(_, count)| *count)
                .unwrap_or_default()
        };
        assert_eq!(at(0.001), 0, "3ms is not at or below 1ms");
        assert_eq!(at(0.005), 1);
        assert_eq!(at(0.5), 2);
        assert_eq!(at(60.0), 2, "two minutes is not at or below a minute");
    }

    #[test]
    fn test_labels_given_in_any_order_are_one_series() {
        // Otherwise the same measurement recorded from two call sites that wrote their labels in
        // different orders becomes two half-counted series, and neither is the truth.
        let registry = Registry::new();

        registry.record(&REQUESTS, &[("method", "GET"), ("status", "200")], 1.0);
        registry.record(&REQUESTS, &[("status", "200"), ("method", "GET")], 1.0);

        assert_eq!(registry.len(), 1);
        assert_eq!(
            only(&registry, "permguard_requests_total"),
            Reading::Value(2.0)
        );
    }

    #[test]
    fn test_different_label_values_are_different_series() {
        let registry = Registry::new();

        registry.record(&REQUESTS, &[("status", "200")], 1.0);
        registry.record(&REQUESTS, &[("status", "503")], 1.0);

        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_a_label_with_unbounded_values_cannot_exhaust_the_process() {
        // The attack: a label carrying something a client chooses — a path, an identifier — so that
        // every request allocates a series that lives until the process exits.
        let registry = Registry::new();

        for attempt in 0..(SERIES_CEILING + 500) {
            registry.record(&REQUESTS, &[("path", &format!("/{attempt}"))], 1.0);
        }

        assert_eq!(registry.len(), SERIES_CEILING);

        // And what was already there still records, so the ceiling costs the new series rather than
        // the measurements that were working.
        registry.record(&REQUESTS, &[("path", "/0")], 1.0);
        let samples = registry.snapshot();
        let first = samples
            .iter()
            .find(|sample| sample.labels == vec![("path".to_owned(), "/0".to_owned())])
            .expect("the first series is still held");
        assert_eq!(first.reading, Reading::Value(2.0));
    }

    #[test]
    fn test_a_panic_elsewhere_does_not_end_measurement_for_the_life_of_the_process() {
        // A panic while any number was being written poisons the lock. Respecting that would mean the
        // process keeps serving with a `/metrics` that answers and reports nothing — the worst of the
        // three outcomes, because it looks like a healthy process with nothing happening.
        let registry = std::sync::Arc::new(Registry::new());
        registry.record(&REQUESTS, &[], 1.0);

        let poisoning = std::sync::Arc::clone(&registry);
        let panicked = std::thread::spawn(move || {
            let _held = poisoning.series.write();

            panic!("something, somewhere");
        })
        .join();
        assert!(panicked.is_err(), "the thread did not panic");
        assert!(registry.series.is_poisoned());

        registry.record(&REQUESTS, &[], 1.0);
        assert_eq!(
            only(&registry, "permguard_requests_total"),
            Reading::Value(2.0)
        );
    }

    #[test]
    fn test_a_snapshot_reads_the_same_way_twice() {
        // The exposition is diffed by people and parsed by machines; lines that move between scrapes
        // for no reason waste both.
        let registry = Registry::new();

        for status in ["500", "200", "404", "503"] {
            registry.record(&REQUESTS, &[("status", status)], 1.0);
        }
        registry.record(&CONNECTIONS, &[], 7.0);

        let first = registry.snapshot();
        let second = registry.snapshot();

        assert_eq!(first, second);
        assert!(
            first
                .windows(2)
                .all(|pair| (pair[0].metric.name(), &pair[0].labels)
                    <= (pair[1].metric.name(), &pair[1].labels)),
            "the snapshot is not ordered"
        );
    }
}
