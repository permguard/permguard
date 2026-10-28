// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The benchmark report, `permguard.bench.report.v1`, and the two things read off it: the published
//! objective it is judged against, and the capacity a deployment may configure from it.
//!
//! The report states what was measured and where, never what a deployment will get. A number in it
//! is true of the platform, storage class, dataset and configuration it names beside it; carried to
//! another platform it is a guess, which is why the capacity section is computed from the report
//! and never copied into a default (H-09).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The report's format identifier.
pub const SCHEMA: &str = permguard_core::domains::format::BENCH_REPORT_V1;

/// The whole report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub build: Build,
    pub platform: Platform,
    pub storage: Storage,
    pub dataset: Dataset,
    pub configuration: Configuration,
    pub measurement: Measurement,
    pub runs: Vec<Run>,
    pub slo: Slo,
    pub capacity: Vec<Capacity>,
}

/// The binaries measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Build {
    /// What `permguard-all-in-one --version` printed.
    pub version: String,
    /// The source revision, when the run knew it.
    pub revision: Option<String>,
}

/// Where the binaries ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub kernel: Option<String>,
    pub cpu_model: Option<String>,
    pub logical_cores: usize,
    pub memory_bytes: Option<u64>,
}

/// The storage the volume lived on: the class the operator of the run declared, and what a
/// flush cost on it, measured before the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Storage {
    pub class: String,
    pub fsync_probe: FsyncProbe,
}

/// A 4 KiB write followed by a data flush, repeated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsyncProbe {
    pub samples: usize,
    pub p50_us: u64,
    pub p99_us: u64,
}

/// What was asked, and of which policies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dataset {
    /// The example workspace applied, relative to the repository.
    pub name: String,
    /// `sha256:` over every file of it, in path order: the same digest is the same dataset.
    pub digest: String,
    pub workloads: Vec<Workload>,
}

/// One profile's requests, and the runtimes its partitions run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    /// The workload's name: the profile, and `boxcarred` for its batches.
    pub name: String,
    pub profile: String,
    /// Batches of evaluations in one request (`evaluations`, `EvaluateMany`).
    pub boxcarred: bool,
    pub runtimes: Vec<String>,
    /// The request files, each with the decision the example's own tests expect of it.
    pub requests: Vec<Expected>,
}

/// A request file and its expected decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Expected {
    pub file: String,
    pub decision: bool,
}

/// The configuration the plane ran under, as far as capacity is concerned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Configuration {
    pub assurance_profile: String,
    /// How a request reached the plane.
    pub transport: String,
    /// What authenticated a request: the run grants evaluation to every caller, so the P5 step
    /// "authn/authz (local)" is not in these latencies.
    pub authentication: String,
    /// What the measured process is: CPU and peak RSS are of all of it.
    pub process: String,
    /// The capacity settings the run set, by their environment name; a setting absent here ran at
    /// its default.
    pub settings: BTreeMap<String, String>,
    /// The memory budgets in force, by their environment name.
    pub memory_budgets: BTreeMap<String, String>,
}

/// How the numbers were taken.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Measurement {
    /// Closed loop: each client sends its next request when the last one is answered.
    pub model: String,
    /// Where the clients ran: on the server's host they share its cores.
    pub clients: String,
    /// How long a client waited for one answer before counting it an error.
    pub client_timeout_seconds: f64,
    pub step_seconds: f64,
    pub warmup_seconds: f64,
    /// How CPU and peak RSS were read: `procfs` (exact) or `ps-sampled` (the highest sample).
    pub process_method: String,
}

/// One interface, evidence mode and workload, measured at each offered concurrency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub interface: String,
    pub evidence: String,
    pub workload: String,
    pub steps: Vec<Step>,
    /// The lowest concurrency at which the plane refused a request with a typed overload answer;
    /// `None` when no step reached it.
    pub refusal_point: Option<RefusalPoint>,
}

/// One rung of the ladder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub concurrency: usize,
    pub seconds: f64,
    /// Answered with the expected decision.
    pub ok: u64,
    /// Refused with a typed overload answer.
    pub refused: u64,
    /// Anything else: a wrong decision, an untyped failure, a broken connection.
    pub errors: u64,
    pub refusal_codes: BTreeMap<String, u64>,
    pub error_kinds: BTreeMap<String, u64>,
    /// Latency of the answered requests.
    pub latency_ms: Percentiles,
    /// Latency of the refusals: how fast the plane says no.
    pub refusal_latency_ms: Option<Percentiles>,
    pub throughput_rps: f64,
    pub cpu_seconds: Option<f64>,
    pub peak_rss_bytes: Option<u64>,
}

/// Latency percentiles, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Percentiles {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

/// Where refusals began.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RefusalPoint {
    pub concurrency: usize,
    /// The answered throughput at that step.
    pub throughput_rps: f64,
}

/// The published objective (`bench/slo.json`), carried into the report it judged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slo {
    /// The p99 latency objective per evidence mode, in milliseconds.
    pub p99_ms: BTreeMap<String, f64>,
    /// The fraction of a measured capacity a configuration leaves unused.
    pub headroom: f64,
    /// How slow a refusal may be at p99, in milliseconds: refusing is only useful when it is fast.
    pub refusal_p99_ms: f64,
    /// The concurrency the serving gate holds a release candidate to the objective at (TS-4), and,
    /// divided by one less the headroom, the concurrency it must also meet it at.
    pub representative_concurrency: usize,
}

impl Slo {
    /// Reads and checks a published objective.
    pub fn parse(text: &str) -> Result<Self, String> {
        let slo: Slo = serde_json::from_str(text).map_err(|error| error.to_string())?;
        if !(0.0..1.0).contains(&slo.headroom) {
            return Err(format!(
                "the headroom is a fraction in [0, 1), not {}",
                slo.headroom
            ));
        }
        if slo.p99_ms.is_empty() || slo.p99_ms.values().any(|ms| !ms.is_finite() || *ms <= 0.0) {
            return Err("every evidence mode needs a positive p99 objective".to_owned());
        }
        if !slo.refusal_p99_ms.is_finite() || slo.refusal_p99_ms <= 0.0 {
            return Err("the refusal objective must be positive".to_owned());
        }
        if slo.representative_concurrency == 0 {
            return Err("the representative concurrency must be at least one".to_owned());
        }
        Ok(slo)
    }

    /// The objective for `evidence`, when one is published.
    pub fn p99_for(&self, evidence: &str) -> Option<f64> {
        self.p99_ms.get(evidence).copied()
    }
}

/// What one interface and evidence mode may be configured for, read off the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capacity {
    pub interface: String,
    pub evidence: String,
    /// The highest concurrency every workload answered within the objective, with no refusal and
    /// no error; `None` when not even the first step did.
    pub sustained_concurrency: Option<usize>,
    /// That concurrency less the headroom: the request bound a deployment on this platform sets.
    pub recommended_concurrent_requests: Option<usize>,
    /// The ladder ended before the plane stopped meeting the objective: the sustained concurrency
    /// is a floor of the capacity, not the capacity.
    pub ladder_exhausted: bool,
}

/// Whether a step met the objective: answered everything, refused nothing, failed nothing, and
/// stayed within the p99.
pub fn step_meets(step: &Step, p99_objective_ms: f64) -> bool {
    step.ok > 0 && step.refused == 0 && step.errors == 0 && step.latency_ms.p99 <= p99_objective_ms
}

/// The capacity of every interface and evidence mode the runs measured.
///
/// A concurrency counts as sustained only when *every* workload of that interface and mode met
/// the objective at it, and every lower step did too: a ladder that recovers after failing is a
/// measurement of noise, not of capacity.
pub fn capacity(runs: &[Run], slo: &Slo) -> Vec<Capacity> {
    let mut groups: BTreeMap<(String, String), Vec<&Run>> = BTreeMap::new();
    for run in runs {
        groups
            .entry((run.interface.clone(), run.evidence.clone()))
            .or_default()
            .push(run);
    }
    groups
        .into_iter()
        .map(|((interface, evidence), runs)| {
            let exhausted = slo.p99_for(&evidence).is_some_and(|objective| {
                runs.iter()
                    .all(|run| run.steps.iter().all(|step| step_meets(step, objective)))
            });
            let sustained = slo.p99_for(&evidence).and_then(|objective| {
                runs.iter()
                    .map(|run| {
                        run.steps
                            .iter()
                            .take_while(|step| step_meets(step, objective))
                            .map(|step| step.concurrency)
                            .last()
                    })
                    .try_fold(usize::MAX, |least, sustained| {
                        sustained.map(|sustained| least.min(sustained))
                    })
                    .filter(|least| *least != usize::MAX)
            });
            Capacity {
                interface,
                evidence,
                sustained_concurrency: sustained,
                recommended_concurrent_requests: sustained.map(|sustained| {
                    ((sustained as f64) * (1.0 - slo.headroom)).floor().max(1.0) as usize
                }),
                ladder_exhausted: exhausted,
            }
        })
        .collect()
}

/// The lowest step at which the plane refused anything.
pub fn refusal_point(steps: &[Step]) -> Option<RefusalPoint> {
    steps
        .iter()
        .find(|step| step.refused > 0)
        .map(|step| RefusalPoint {
            concurrency: step.concurrency,
            throughput_rps: step.throughput_rps,
        })
}

/// Percentiles of `samples`, in milliseconds, by the nearest-rank method; `None` for no samples.
pub fn percentiles(samples: &mut [f64]) -> Option<Percentiles> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_by(f64::total_cmp);
    let rank = |q: f64| {
        let index = ((q * samples.len() as f64).ceil() as usize).clamp(1, samples.len()) - 1;
        samples[index]
    };
    Some(Percentiles {
        p50: rank(0.50),
        p95: rank(0.95),
        p99: rank(0.99),
        max: samples[samples.len() - 1],
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn slo() -> Slo {
        Slo::parse(r#"{"p99_ms": {"disabled": 10.0, "required": 50.0}, "headroom": 0.25, "refusal_p99_ms": 20.0, "representative_concurrency": 4}"#)
            .expect("an objective")
    }

    fn step(concurrency: usize, p99: f64, refused: u64, errors: u64) -> Step {
        Step {
            concurrency,
            seconds: 1.0,
            ok: 100,
            refused,
            errors,
            refusal_codes: BTreeMap::new(),
            error_kinds: BTreeMap::new(),
            latency_ms: Percentiles {
                p50: p99 / 2.0,
                p95: p99,
                p99,
                max: p99,
            },
            refusal_latency_ms: None,
            throughput_rps: 100.0 * concurrency as f64,
            cpu_seconds: None,
            peak_rss_bytes: None,
        }
    }

    fn run(interface: &str, evidence: &str, workload: &str, steps: Vec<Step>) -> Run {
        Run {
            interface: interface.to_owned(),
            evidence: evidence.to_owned(),
            workload: workload.to_owned(),
            refusal_point: refusal_point(&steps),
            steps,
        }
    }

    #[test]
    fn test_nearest_rank_percentiles_are_samples_and_never_interpolations() {
        let mut samples: Vec<f64> = (1..=100).map(f64::from).collect();
        let p = percentiles(&mut samples).expect("samples");
        assert_eq!((p.p50, p.p95, p.p99, p.max), (50.0, 95.0, 99.0, 100.0));
        let mut one = vec![7.0];
        let p = percentiles(&mut one).expect("one sample");
        assert_eq!((p.p50, p.p99), (7.0, 7.0));
        assert!(percentiles(&mut []).is_none());
    }

    #[test]
    fn test_capacity_is_the_last_step_every_workload_met_less_the_headroom() {
        let runs = vec![
            run(
                "http",
                "disabled",
                "default",
                vec![
                    step(1, 1.0, 0, 0),
                    step(8, 4.0, 0, 0),
                    step(64, 9.0, 0, 0),
                    step(256, 30.0, 0, 0),
                ],
            ),
            // The other workload stops meeting the objective earlier: the group's capacity is its.
            run(
                "http",
                "disabled",
                "gateway",
                vec![step(1, 1.0, 0, 0), step(8, 4.0, 0, 0), step(64, 12.0, 0, 0)],
            ),
        ];
        let capacity = capacity(&runs, &slo());
        assert_eq!(capacity.len(), 1);
        assert_eq!(capacity[0].sustained_concurrency, Some(8));
        assert_eq!(capacity[0].recommended_concurrent_requests, Some(6));
        assert!(!capacity[0].ladder_exhausted);
        // A ladder every step of which met the objective measured a floor, and says so.
        let short = vec![run(
            "http",
            "disabled",
            "default",
            vec![step(1, 1.0, 0, 0), step(4, 2.0, 0, 0)],
        )];
        let floor = &super::capacity(&short, &slo())[0];
        assert_eq!(floor.sustained_concurrency, Some(4));
        assert!(floor.ladder_exhausted);
    }

    #[test]
    fn test_a_refusal_or_an_error_ends_the_sustained_ladder_even_when_a_later_step_recovers() {
        let runs = vec![run(
            "grpc",
            "required",
            "default",
            vec![step(1, 1.0, 0, 0), step(4, 2.0, 0, 1), step(16, 3.0, 0, 0)],
        )];
        assert_eq!(capacity(&runs, &slo())[0].sustained_concurrency, Some(1));
        let refused = vec![run(
            "grpc",
            "required",
            "default",
            vec![step(1, 1.0, 0, 0), step(4, 2.0, 3, 0), step(16, 3.0, 0, 0)],
        )];
        assert_eq!(capacity(&refused, &slo())[0].sustained_concurrency, Some(1));
        assert_eq!(
            refused[0].refusal_point,
            Some(RefusalPoint {
                concurrency: 4,
                throughput_rps: 400.0
            })
        );
    }

    #[test]
    fn test_no_step_met_and_no_objective_published_are_both_no_capacity_not_zero() {
        let runs = vec![run(
            "http",
            "required",
            "default",
            vec![step(1, 99.0, 0, 0)],
        )];
        assert_eq!(capacity(&runs, &slo())[0].sustained_concurrency, None);
        assert_eq!(
            capacity(&runs, &slo())[0].recommended_concurrent_requests,
            None
        );
        let unpublished = vec![run("http", "sampled", "default", vec![step(1, 1.0, 0, 0)])];
        assert_eq!(
            capacity(&unpublished, &slo())[0].sustained_concurrency,
            None
        );
    }

    #[test]
    fn test_an_objective_that_cannot_judge_anything_is_refused() {
        assert!(Slo::parse(r#"{"p99_ms": {}, "headroom": 0.2, "refusal_p99_ms": 5.0, "representative_concurrency": 4}"#).is_err());
        assert!(
            Slo::parse(r#"{"p99_ms": {"required": 0.0}, "headroom": 0.2, "refusal_p99_ms": 5.0, "representative_concurrency": 4}"#)
                .is_err()
        );
        assert!(
            Slo::parse(r#"{"p99_ms": {"required": 5.0}, "headroom": 1.0, "refusal_p99_ms": 5.0, "representative_concurrency": 4}"#)
                .is_err()
        );
        assert!(
            Slo::parse(r#"{"p99_ms": {"required": 5.0}, "headroom": 0.2, "refusal_p99_ms": 0.0, "representative_concurrency": 4}"#)
                .is_err()
        );
        assert!(
            Slo::parse(r#"{"p99_ms": {"required": 5.0}, "headroom": 0.2, "refusal_p99_ms": 5.0, "representative_concurrency": 4, "extra": 1}"#)
                .is_err()
        );
    }
}
