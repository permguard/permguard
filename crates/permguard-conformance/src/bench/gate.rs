// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The end-to-end serving gate (TS-4): the release candidate meets its published objective with
//! its headroom, or refuses within bounds, and never reaches the network from a decision.
//!
//! The gate drives the candidate's own binaries as [`super::run`] does, under a configuration with
//! a small request bound so overload is cheap to reach, and judges three steps per interface,
//! evidence mode and workload:
//!
//! | Step           | Offered concurrency                              | Must                                                              |
//! | -------------- | ------------------------------------------------ | ----------------------------------------------------------------- |
//! | representative | `representative_concurrency` of `bench/slo.json` | answer everything correctly within the p99 objective              |
//! | headroom       | that, divided by one less the headroom           | the same: the candidate has the headroom it publishes             |
//! | overload       | four times the request bound                     | the bound refuses typed, within its p99; no error, answers correct |
//!
//! A representative or headroom step that misses on latency alone (everything answered, nothing
//! refused, nothing failed) is measured once more and fails only if it misses again: a shared
//! runner's disk can stall one window, a slow candidate is slow in both.
//!
//! After every run on a server, the gate reads `permguard_decision_path_egress_total` off the
//! candidate's own metrics: any network call a decision made was refused and counted there, and
//! anything but zero fails the gate.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

use super::load::{self, Target};
use super::report::{Slo, Step, step_meets};
use super::server::{self, Binaries};

/// The request bound the gate runs the candidate under: small, so overload is four times it.
pub const REQUEST_BOUND: usize = 32;

/// What the gate is asked to do.
#[derive(Debug, Clone)]
pub struct Options {
    pub binaries: Binaries,
    pub example: std::path::PathBuf,
    pub languages: String,
    pub directory: std::path::PathBuf,
    pub slo: Slo,
    pub interfaces: Vec<String>,
    pub evidence: Vec<String>,
    pub step: Duration,
    pub warmup: Duration,
}

/// One judgement.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Check {
    pub interface: String,
    pub evidence: String,
    pub workload: String,
    pub step: String,
    pub passed: bool,
    pub detail: String,
}

/// The gate's verdict, every judgement in it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub passed: bool,
    pub checks: Vec<Check>,
    /// Network calls the candidate refused on its decision path, per evidence mode's server.
    pub egress_refused: BTreeMap<String, u64>,
}

/// The concurrency the headroom requires: the representative one, divided by one less the
/// headroom, rounded up.
pub fn headroom_concurrency(slo: &Slo) -> usize {
    ((slo.representative_concurrency as f64) / (1.0 - slo.headroom)).ceil() as usize
}

/// Whether a step that met the objective is judged a pass, and why not.
pub fn judge_within(step: &Step, objective_ms: f64) -> Result<(), String> {
    if step_meets(step, objective_ms) {
        return Ok(());
    }
    Err(format!(
        "c={}: {} answered, {} refused, {} errors {:?}, p99 {:.2} ms against {objective_ms} ms",
        step.concurrency, step.ok, step.refused, step.errors, step.error_kinds, step.latency_ms.p99
    ))
}

/// Whether a step that missed its objective missed on latency alone: every request answered,
/// none refused, none failed. Only such a step is measured a second time.
pub fn latency_only(step: &Step) -> bool {
    step.ok > 0 && step.refused == 0 && step.errors == 0
}

/// Whether an overload step refused within bounds, and why not.
pub fn judge_overload(step: &Step, refusal_p99_ms: f64) -> Result<(), String> {
    let mut wrong = Vec::new();
    if step.refused == 0 {
        wrong.push("nothing was refused past the request bound".to_owned());
    } else if !step.refusal_codes.contains_key(super::load::SHED) {
        // Refusals from the pools alone mean the request bound never refused anything: the
        // setting did not take, or the shed answer is no longer the typed one.
        wrong.push(format!(
            "the request bound refused nothing; the refusals were {:?}",
            step.refusal_codes
        ));
    }
    if step.errors > 0 {
        wrong.push(format!("{} errors {:?}", step.errors, step.error_kinds));
    }
    match &step.refusal_latency_ms {
        Some(latency) if latency.p99 > refusal_p99_ms => wrong.push(format!(
            "refusals took {:.2} ms at p99 against {refusal_p99_ms} ms",
            latency.p99
        )),
        _ => {}
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("c={}: {}", step.concurrency, wrong.join("; ")))
    }
}

/// A counter's value in a Prometheus text exposition, when the series is there.
pub fn counter(exposition: &str, name: &str) -> Option<u64> {
    exposition.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?;
        let value = rest.strip_prefix(' ').or_else(|| {
            rest.strip_prefix('{')
                .and_then(|labelled| labelled.split_once("} ").map(|(_, value)| value))
        })?;
        value.trim().parse::<f64>().ok().map(|value| value as u64)
    })
}

/// Runs the gate. `progress` hears a line per judgement.
pub fn gate(options: &Options, progress: &mut dyn FnMut(&str)) -> Result<Verdict, String> {
    std::fs::create_dir_all(&options.directory).map_err(|error| error.to_string())?;
    let dataset = server::dataset(&options.example, "gate")?;
    let representative = options.slo.representative_concurrency;
    let headroom = headroom_concurrency(&options.slo);
    let overload = 4 * REQUEST_BOUND;
    if headroom >= REQUEST_BOUND {
        return Err(format!(
            "the headroom step ({headroom}) would meet the gate's request bound ({REQUEST_BOUND})"
        ));
    }
    let mut settings = BTreeMap::new();
    settings.insert(
        "PERMGUARD_LIMITS_CONCURRENT_REQUESTS".to_owned(),
        REQUEST_BOUND.to_string(),
    );
    let mut checks = Vec::new();
    let mut egress_refused = BTreeMap::new();
    for evidence in &options.evidence {
        let objective = options
            .slo
            .p99_for(evidence)
            .ok_or_else(|| format!("no objective is published for `{evidence}`"))?;
        let directory = options.directory.join(format!("gate-{evidence}"));
        let server = server::start(&options.binaries, &directory, evidence, &settings)?;
        server::apply(
            &options.binaries,
            &server,
            &options.example,
            &options.languages,
        )
        .map_err(|error| format!("{error}\n{}", server.log_tail()))?;
        for interface in &options.interfaces {
            let target = Target {
                interface: interface.clone(),
                http: server.data_http.clone(),
                grpc: server.data_grpc.clone(),
            };
            for workload in &dataset.workloads {
                let requests = load::requests(&options.example, workload)?;
                load::wait_serving(&target, &requests, Duration::from_secs(120))
                    .map_err(|error| format!("{error}\n{}", server.log_tail()))?;
                load::step(&target, &requests, 2, options.warmup, None)?;
                for (name, concurrency) in [
                    ("representative", representative),
                    ("headroom", headroom),
                    ("overload", overload),
                ] {
                    let step = load::step(&target, &requests, concurrency, options.step, None)?;
                    let judged = if name == "overload" {
                        judge_overload(&step, options.slo.refusal_p99_ms)
                    } else {
                        match judge_within(&step, objective) {
                            // Only latency missed: measured once more, and a miss again fails.
                            // A shared runner's disk can stall one window; a slow candidate is
                            // slow in both. Errors, refusals and wrong answers are never retried.
                            Err(first) if latency_only(&step) => {
                                let again = load::step(
                                    &target,
                                    &requests,
                                    concurrency,
                                    options.step,
                                    None,
                                )?;
                                judge_within(&again, objective)
                                    .map_err(|second| format!("{first}; measured again: {second}"))
                                    .map(|()| {
                                        progress(&format!(
                                            "note {interface} {evidence} {} {name}: {first}; \
                                             measured again within the objective",
                                            workload.name
                                        ));
                                    })
                            }
                            judged => judged,
                        }
                    };
                    let check = Check {
                        interface: interface.clone(),
                        evidence: evidence.clone(),
                        workload: workload.name.clone(),
                        step: name.to_owned(),
                        passed: judged.is_ok(),
                        detail: judged.err().unwrap_or_else(|| {
                            format!(
                                "c={concurrency}: {} answered, {} refused {:?}, p99 {:.2} ms",
                                step.ok, step.refused, step.refusal_codes, step.latency_ms.p99
                            )
                        }),
                    };
                    progress(&format!(
                        "{} {interface} {evidence} {} {name}: {}",
                        if check.passed { "pass" } else { "FAIL" },
                        workload.name,
                        check.detail
                    ));
                    checks.push(check);
                }
            }
        }
        let exposition = server::metrics(&server)?;
        let name = permguard_core::egress::REFUSED.name();
        let refused = counter(&exposition, name).ok_or_else(|| {
            format!("the candidate does not publish `{name}`: the failpoint is not installed")
        })?;
        progress(&format!(
            "{} {evidence}: {refused} network calls refused on the decision path",
            if refused == 0 { "pass" } else { "FAIL" }
        ));
        egress_refused.insert(evidence.clone(), refused);
        drop(server);
    }
    let passed = checks.iter().all(|check| check.passed)
        && egress_refused.values().all(|refused| *refused == 0);
    Ok(Verdict {
        passed,
        checks,
        egress_refused,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::report::Percentiles;

    fn slo(representative: usize, headroom: f64) -> Slo {
        Slo {
            p99_ms: BTreeMap::from([("disabled".to_owned(), 10.0)]),
            headroom,
            refusal_p99_ms: 20.0,
            representative_concurrency: representative,
        }
    }

    fn step(ok: u64, refused: u64, errors: u64, p99: f64, refusal_p99: Option<f64>) -> Step {
        let refusal_codes = if refused > 0 {
            BTreeMap::from([(crate::bench::load::SHED.to_owned(), refused)])
        } else {
            BTreeMap::new()
        };
        let latency = |p99: f64| Percentiles {
            p50: p99,
            p95: p99,
            p99,
            max: p99,
        };
        Step {
            concurrency: 8,
            seconds: 1.0,
            ok,
            refused,
            errors,
            refusal_codes,
            error_kinds: BTreeMap::new(),
            latency_ms: latency(p99),
            refusal_latency_ms: refusal_p99.map(latency),
            throughput_rps: ok as f64,
            cpu_seconds: None,
            peak_rss_bytes: None,
        }
    }

    #[test]
    fn test_the_headroom_step_is_the_representative_one_divided_by_one_less_the_headroom() {
        assert_eq!(headroom_concurrency(&slo(8, 0.3)), 12);
        assert_eq!(headroom_concurrency(&slo(10, 0.5)), 20);
        assert_eq!(headroom_concurrency(&slo(1, 0.0)), 1);
    }

    #[test]
    fn test_within_the_objective_means_everything_answered_in_time() {
        assert!(judge_within(&step(100, 0, 0, 9.0, None), 10.0).is_ok());
        assert!(
            judge_within(&step(100, 0, 0, 11.0, None), 10.0).is_err(),
            "too slow"
        );
        assert!(
            judge_within(&step(100, 1, 0, 1.0, None), 10.0).is_err(),
            "a refusal"
        );
        assert!(
            judge_within(&step(100, 0, 1, 1.0, None), 10.0).is_err(),
            "an error"
        );
        assert!(
            judge_within(&step(0, 0, 0, 0.0, None), 10.0).is_err(),
            "nothing answered"
        );
    }

    #[test]
    fn test_only_a_miss_on_latency_alone_is_measured_again() {
        assert!(
            latency_only(&step(100, 0, 0, 30.0, None)),
            "slow, nothing else"
        );
        assert!(!latency_only(&step(100, 1, 0, 30.0, None)), "a refusal");
        assert!(!latency_only(&step(100, 0, 1, 30.0, None)), "an error");
        assert!(!latency_only(&step(0, 0, 0, 0.0, None)), "nothing answered");
    }

    #[test]
    fn test_overload_must_refuse_fast_and_fail_nothing() {
        assert!(judge_overload(&step(10, 50, 0, 30.0, Some(5.0)), 20.0).is_ok());
        let none = judge_overload(&step(10, 0, 0, 30.0, None), 20.0).expect_err("nothing refused");
        assert!(none.contains("nothing was refused"), "{none}");
        let slow = judge_overload(&step(10, 50, 0, 30.0, Some(25.0)), 20.0).expect_err("slow");
        assert!(slow.contains("refusals took"), "{slow}");
        let broken = judge_overload(&step(10, 50, 2, 30.0, Some(5.0)), 20.0).expect_err("errors");
        assert!(broken.contains("2 errors"), "{broken}");
        // Refused by the pools alone: the request bound was never exercised.
        let mut pools = step(10, 50, 0, 30.0, Some(5.0));
        pools.refusal_codes = BTreeMap::from([("evaluation_at_capacity".to_owned(), 50)]);
        let unbounded = judge_overload(&pools, 20.0).expect_err("no shed");
        assert!(
            unbounded.contains("request bound refused nothing"),
            "{unbounded}"
        );
    }

    #[test]
    fn test_a_counter_is_read_off_the_exposition_with_or_without_labels() {
        let text = "# HELP x help\n# TYPE x counter\nx 3\ny{a=\"b\"} 7\nxx 9\n";
        assert_eq!(counter(text, "x"), Some(3));
        assert_eq!(counter(text, "y"), Some(7));
        assert_eq!(counter(text, "z"), None, "an absent series is not zero");
    }
}
