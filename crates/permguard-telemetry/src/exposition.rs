// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Turning a snapshot into the text a scraper reads.
//!
//! Written out by hand rather than taken from a client library, and the reason is the same one the
//! image is built from `scratch` for: the format is a dozen lines of rules, and a dependency that
//! renders it brings a registry, a global recorder, an exporter and a runtime with it — all of which
//! this already has, in a shape chosen for this product rather than inherited.
//!
//! # The rules that matter
//!
//! * `# HELP` and `# TYPE` appear once per metric name, before its series;
//! * a histogram is three families — `_bucket` with an `le` label, `_sum`, `_count` — and the buckets
//!   are cumulative, ending at `+Inf`;
//! * a backslash, a quote or a newline inside a label value has to be escaped, or a value carrying one
//!   ends the line early and everything after it parses as something else.
//!
//! That last one is the whole reason this is not a `format!` at the call site. Label values reach here
//! from code that will one day label something with a string it did not choose, and an exposition a
//! value can break out of is a way to write arbitrary series into a monitoring system.

use std::fmt::Write;

use permguard_core::metrics::{Kind, Reading, Sample};

/// Renders `samples` as a Prometheus exposition.
///
/// Expects them grouped by metric name, which is what a snapshot returns.
pub fn render(samples: &[Sample]) -> String {
    let mut out = String::new();
    let mut described: Option<&str> = None;

    for sample in samples {
        let name = sample.metric.name();

        if described != Some(name) {
            let _ = writeln!(out, "# HELP {name} {}", escaped(sample.metric.help()));
            let _ = writeln!(out, "# TYPE {name} {}", kind(sample.metric.kind()));
            described = Some(name);
        }

        match &sample.reading {
            Reading::Value(value) => {
                let _ = writeln!(
                    out,
                    "{name}{} {}",
                    labels(&sample.labels, None),
                    number(*value)
                );
            }
            Reading::Distribution {
                buckets,
                count,
                sum,
            } => {
                for (boundary, at) in buckets {
                    let _ = writeln!(
                        out,
                        "{name}_bucket{} {at}",
                        labels(&sample.labels, Some(&number(*boundary)))
                    );
                }

                // Everything, including whatever fell above the last boundary. A histogram whose
                // `+Inf` is missing is one no query can normalise against.
                let _ = writeln!(
                    out,
                    "{name}_bucket{} {count}",
                    labels(&sample.labels, Some("+Inf"))
                );
                let _ = writeln!(
                    out,
                    "{name}_sum{} {}",
                    labels(&sample.labels, None),
                    number(*sum)
                );
                let _ = writeln!(out, "{name}_count{} {count}", labels(&sample.labels, None));
            }
        }
    }

    out
}

/// The word the format uses for a kind.
fn kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Counter => "counter",
        Kind::Gauge => "gauge",
        Kind::Histogram => "histogram",
    }
}

/// Writes the label set, with `le` appended when this is a bucket line.
fn labels(labels: &[(String, String)], le: Option<&str>) -> String {
    if labels.is_empty() && le.is_none() {
        return String::new();
    }

    let mut out = String::from("{");
    for (index, (name, value)) in labels.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }

        let _ = write!(out, "{name}=\"{}\"", escaped(value));
    }

    if let Some(boundary) = le {
        if !labels.is_empty() {
            out.push(',');
        }

        let _ = write!(out, "le=\"{boundary}\"");
    }

    out.push('}');

    out
}

/// Escapes what would otherwise end a line, or a quoted value, early.
fn escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }

    out
}

/// Writes a number the way the format wants it.
///
/// Whole values without a decimal point, because most of these are counts and `5` reads better than
/// `5.0` to whoever is looking at a scrape by eye.
fn number(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use permguard_core::metrics::{Metric, SECONDS};

    fn sample(metric: Metric, labels: &[(&str, &str)], reading: Reading) -> Sample {
        Sample {
            metric,
            labels: labels
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            reading,
        }
    }

    #[test]
    fn test_a_counter_is_described_once_and_then_listed() {
        let requests = Metric::counter("permguard_requests_total", "Requests served.");
        let text = render(&[
            sample(requests, &[("status", "2xx")], Reading::Value(7.0)),
            sample(requests, &[("status", "5xx")], Reading::Value(1.0)),
        ]);

        assert_eq!(
            text,
            "# HELP permguard_requests_total Requests served.\n\
             # TYPE permguard_requests_total counter\n\
             permguard_requests_total{status=\"2xx\"} 7\n\
             permguard_requests_total{status=\"5xx\"} 1\n"
        );
    }

    #[test]
    fn test_a_metric_with_no_labels_carries_no_braces() {
        let up = Metric::gauge("permguard_up", "Whether the process reports itself live.");
        let text = render(&[sample(up, &[], Reading::Value(1.0))]);

        assert!(text.ends_with("permguard_up 1\n"), "{text}");
    }

    #[test]
    fn test_a_histogram_ends_at_infinity_and_carries_its_totals() {
        let latency = Metric::histogram(
            "permguard_request_seconds",
            "How long requests took.",
            SECONDS,
        );
        let text = render(&[sample(
            latency,
            &[],
            Reading::Distribution {
                buckets: vec![(0.001, 0), (0.005, 1), (0.5, 2)],
                count: 3,
                sum: 120.403,
            },
        )]);

        assert!(text.contains("# TYPE permguard_request_seconds histogram\n"));
        assert!(text.contains("permguard_request_seconds_bucket{le=\"0.001\"} 0\n"));
        assert!(text.contains("permguard_request_seconds_bucket{le=\"0.005\"} 1\n"));
        assert!(
            text.contains("permguard_request_seconds_bucket{le=\"+Inf\"} 3\n"),
            "the observation above the last boundary was lost: {text}"
        );
        assert!(text.contains("permguard_request_seconds_sum 120.403\n"));
        assert!(text.contains("permguard_request_seconds_count 3\n"));
    }

    #[test]
    fn test_a_label_value_cannot_break_out_of_the_line_it_is_on() {
        // The attack: a label whose value closes the quote and opens a series of its own, so a string
        // that reached a label from outside writes whatever it likes into a monitoring system.
        let requests = Metric::counter("permguard_requests_total", "Requests served.");
        let text = render(&[sample(
            requests,
            &[(
                "outcome",
                "x\" } 999\npermguard_requests_total{outcome=\"forged",
            )],
            Reading::Value(1.0),
        )]);

        assert_eq!(
            text.lines().count(),
            3,
            "a label value added lines of its own: {text}"
        );
        assert!(text.contains("\\\""), "the quote was not escaped: {text}");
        assert!(text.contains("\\n"), "the newline was not escaped: {text}");
    }

    #[test]
    fn test_help_text_cannot_break_out_either() {
        let odd = Metric::counter("permguard_odd_total", "First line.\nsecond line.");
        let text = render(&[sample(odd, &[], Reading::Value(0.0))]);

        assert_eq!(text.lines().count(), 3, "{text}");
    }

    #[test]
    fn test_nothing_recorded_renders_as_nothing() {
        assert!(render(&[]).is_empty());
    }
}
