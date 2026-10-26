// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! TS-3, H-09: every release carries its benchmark report, and the harness measures everything a
//! Data Plane serves.
//!
//! The release workflow is read as data: a job measures the Linux binaries the release published
//! with `permguard-bench` and holds no token that may write, and a job that compiles nothing attaches
//! the report. CI runs the same harness on every change. The harness's interfaces and evidence
//! modes are checked against the product's own: a mode added to the configuration and not to the
//! benchmark fails here, not in a release that silently stopped measuring it.

#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use permguard_conformance::bench::load::INTERFACES;
use permguard_conformance::bench::server::EVIDENCE_MODES;
use permguard_core::config::DecisionLogMode;
use serde_norway::Value;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workflow(name: &str) -> Value {
    let path = repository().join(".github/workflows").join(name);
    serde_norway::from_str(&std::fs::read_to_string(&path).expect("the workflow is readable"))
        .expect("the workflow is YAML")
}

fn job<'a>(workflow: &'a Value, name: &str) -> &'a Value {
    workflow["jobs"]
        .get(name)
        .unwrap_or_else(|| panic!("no job `{name}`"))
}

/// Every `run` script of a job, joined.
fn scripts(job: &Value) -> String {
    job["steps"]
        .as_sequence()
        .expect("steps")
        .iter()
        .filter_map(|step| step.get("run").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether a permission map grants any write.
fn grants_write(permissions: Option<&Value>) -> bool {
    permissions
        .and_then(Value::as_mapping)
        .is_some_and(|permissions| {
            permissions
                .values()
                .any(|level| level.as_str() == Some("write"))
        })
}

/// Whether `job` may write: its own permissions, or the workflow's when it declares none.
fn writes(workflow: &Value, job: &Value) -> bool {
    match job.get("permissions") {
        Some(own) => grants_write(Some(own)),
        None => grants_write(workflow.get("permissions")),
    }
}

#[test]
fn test_a_release_measures_what_it_published_and_attaches_the_report() {
    let release = workflow("release-pipeline.yml");
    let benchmark = job(&release, "benchmark");
    assert_eq!(
        benchmark["needs"],
        serde_norway::from_str::<Value>("[build]").expect("YAML"),
        "the benchmark measures the published release, so it runs after it is built"
    );
    let run = scripts(benchmark);
    assert!(
        run.contains("gh release download") && run.contains("permguard_all_in_one_Linux_x86_64"),
        "the binaries measured are the ones the release published:\n{run}"
    );
    assert!(
        run.contains("permguard-bench run") && run.contains("--server ./permguard-all-in-one"),
        "{run}"
    );
    assert!(
        !writes(&release, benchmark),
        "the benchmark compiles the harness: it must not hold a token that may write"
    );
    assert_eq!(
        benchmark["continue-on-error"].as_bool(),
        Some(true),
        "the benchmark reports on a published release and never blocks it"
    );

    let publish = job(&release, "publish-benchmark");
    assert_eq!(
        publish["needs"],
        serde_norway::from_str::<Value>("[build, benchmark]").expect("YAML")
    );
    assert!(
        publish["if"]
            .as_str()
            .is_some_and(|condition| condition.contains("always()")),
        "the report, or the note saying why there is none, is attached whatever the benchmark did"
    );
    assert!(
        writes(&release, publish),
        "attaching the report needs `contents: write`"
    );
    let attach = scripts(publish);
    assert!(
        attach.contains("gh release upload")
            && attach.contains("permguard-benchmark.json")
            && attach.contains("permguard-benchmark.txt"),
        "{attach}"
    );
    assert!(
        !attach.contains("cargo"),
        "the job that may write compiles nothing"
    );
}

#[test]
fn test_ci_runs_the_harness_on_every_change() {
    let ci = workflow("ci.yml");
    let run = scripts(job(&ci, "benchmark"));
    assert!(
        run.contains("permguard-bench run") && run.contains("permguard-bench capacity"),
        "{run}"
    );
}

/// Every evidence mode the configuration accepts is one the benchmark measures. The match is
/// exhaustive, so a new mode is a compile error here until it is measured.
#[test]
fn test_the_harness_measures_every_evidence_mode_and_interface() {
    let spelled = |mode: DecisionLogMode| match mode {
        DecisionLogMode::Required => "required",
        DecisionLogMode::Disabled => "disabled",
    };
    for mode in [DecisionLogMode::Required, DecisionLogMode::Disabled] {
        assert_eq!(spelled(mode), mode.as_str());
        assert!(
            EVIDENCE_MODES.contains(&mode.as_str()),
            "`{}` is not measured",
            mode.as_str()
        );
    }
    // The native PDP is served over HTTP and gRPC, on the same listener.
    assert_eq!(INTERFACES, ["http", "grpc"]);
}

/// The published objective is what the release is judged by: it parses, and names every mode.
#[test]
fn test_the_published_objective_judges_every_mode() {
    let slo = permguard_conformance::bench::report::Slo::parse(
        &std::fs::read_to_string(repository().join("bench/slo.json")).expect("bench/slo.json"),
    )
    .expect("the published objective is valid");
    for mode in EVIDENCE_MODES {
        assert!(slo.p99_for(mode).is_some(), "no objective for `{mode}`");
    }
}
