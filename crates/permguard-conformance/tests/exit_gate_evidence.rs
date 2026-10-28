// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-7.13: every release carries the iteration exit gate's evidence, pinned and attested.
//!
//! The release pipeline is read as data. The tagged source is fuzzed for the release budget by a
//! job that compiles and may not write; the serving gate's verdict is kept from the verification
//! and the traceability report from the tests; and a last job, which compiles nothing, attaches
//! them, writes the evidence manifest over the release as published, attests it and verifies it
//! the way an auditor would. A step dropped from the chain fails here, not in a release that
//! silently stopped carrying its evidence.

#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use serde_norway::Value;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn release() -> Value {
    let path = repository().join(".github/workflows/release-pipeline.yml");
    serde_norway::from_str(&std::fs::read_to_string(&path).expect("the workflow is readable"))
        .expect("the workflow is YAML")
}

fn job<'a>(workflow: &'a Value, name: &str) -> &'a Value {
    workflow["jobs"]
        .get(name)
        .unwrap_or_else(|| panic!("no job `{name}`"))
}

fn steps(job: &Value) -> &[Value] {
    job["steps"].as_sequence().expect("steps")
}

/// Every `run` script of a job, joined.
fn scripts(job: &Value) -> String {
    steps(job)
        .iter()
        .filter_map(|step| step.get("run").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The steps of a job that use `action` (its name before the `@`).
fn using<'a>(job: &'a Value, action: &str) -> Vec<&'a Value> {
    steps(job)
        .iter()
        .filter(|step| {
            step.get("uses")
                .and_then(Value::as_str)
                .is_some_and(|uses| uses.split('@').next() == Some(action))
        })
        .collect()
}

/// The level a job's permissions grant `scope`, or the workflow's when the job declares none.
fn permission(workflow: &Value, job: &Value, scope: &str) -> Option<String> {
    let permissions = job.get("permissions").or(workflow.get("permissions"))?;
    match permissions {
        Value::String(all) => Some(all.trim_end_matches("-all").to_owned()),
        Value::Mapping(held) => held.get(scope).and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

/// The paths a job's `actions/upload-artifact` steps keep, joined.
fn kept(job: &Value) -> String {
    using(job, "actions/upload-artifact")
        .iter()
        .filter_map(|step| step["with"].get("path").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The artifacts a job's `actions/download-artifact` steps fetch by name.
fn fetched(job: &Value) -> Vec<String> {
    using(job, "actions/download-artifact")
        .iter()
        .filter_map(|step| step["with"].get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn needs(job: &Value) -> Vec<String> {
    match &job["needs"] {
        Value::String(one) => vec![one.clone()],
        Value::Sequence(many) => many
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

#[test]
fn the_verification_keeps_the_serving_gate_and_the_traceability_report() {
    let release = release();
    let verify = job(&release, "verify");
    assert!(
        scripts(verify).contains("permguard-bench gate")
            && scripts(verify).contains("permguard-gate.json"),
        "the serving gate runs before anything is published"
    );
    assert!(
        kept(verify).contains("permguard-gate.json"),
        "{}",
        kept(verify)
    );
    // The tests run beside the gate rather than before it — neither needs the other, and the
    // release waits for the slower, not for both — and the traceability report is theirs to keep.
    let tests = job(&release, "tests");
    assert!(
        scripts(tests).contains("cargo nextest run --workspace")
            && scripts(tests).contains("cargo test --workspace --all-features --locked --doc"),
        "{}",
        scripts(tests)
    );
    assert!(
        kept(tests).contains("target/traceability.json"),
        "{}",
        kept(tests)
    );
    // Both reach the job that attaches them.
    let evidence = job(&release, "evidence");
    let fetched = fetched(evidence);
    for artifact in ["verified", "traceability"] {
        assert!(
            fetched.iter().any(|name| name == artifact),
            "the evidence job fetches {artifact}: {fetched:?}"
        );
    }
}

#[test]
fn the_tagged_source_is_fuzzed_for_the_release_budget() {
    let release = release();
    let fuzz = job(&release, "fuzz");
    // It waits for nothing: it compiles the tagged source with its own toolchain and reads nothing
    // another job produces, and the budget is the long pole of the run, so it starts at once.
    assert_eq!(needs(fuzz), Vec::<String>::new());
    // Every target ten minutes does not fit one job: the targets are dealt to six shards.
    let shards: Vec<u64> = fuzz["strategy"]["matrix"]["shard"]
        .as_sequence()
        .expect("a shard matrix")
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    assert_eq!(shards, [0, 1, 2, 3, 4, 5]);
    assert_eq!(fuzz["env"]["SHARDS"].as_u64(), Some(6));
    assert_eq!(fuzz["strategy"]["fail-fast"].as_bool(), Some(false));
    let run = scripts(fuzz);
    assert!(run.contains("(NR - 1) % shards == shard"), "{run}");
    assert!(
        run.contains("./scripts/fuzz.sh 600 \"${targets[@]}\""),
        "{run}"
    );
    assert!(run.contains("fuzz-shard-${SHARD}.json"), "{run}");
    assert_eq!(
        permission(&release, fuzz, "contents").as_deref(),
        Some("read"),
        "fuzzing compiles: it must not hold a token that may write"
    );
    let publish = job(&release, "publish-fuzz");
    assert_eq!(
        permission(&release, publish, "contents").as_deref(),
        Some("write")
    );
    let attach = scripts(publish);
    for part in [
        "shards/fuzz-shard-*.json",
        "length == 6",
        "== $expected",
        "fuzz-release.json",
        "fuzz-release.txt",
    ] {
        assert!(attach.contains(part), "{part} in:\n{attach}");
    }
    assert!(
        !attach.contains("cargo"),
        "the job that may write compiles nothing"
    );
}

#[test]
fn the_last_job_pins_attests_and_verifies_the_evidence_of_the_release() {
    let release = release();
    let evidence = job(&release, "evidence");
    let waited = needs(evidence);
    for before in [
        "verify",
        "tests",
        "build",
        "publish-benchmark",
        "publish-drills",
        "publish-fuzz",
        "publish-reproducibility",
    ] {
        assert!(
            waited.iter().any(|held| held == before),
            "the manifest is written after {before}: {waited:?}"
        );
    }
    assert!(
        evidence["if"]
            .as_str()
            .is_some_and(|condition| condition.contains("always()")),
        "the manifest is written whatever the reports did, and names what is missing"
    );
    for (scope, level) in [
        ("contents", "write"),
        ("id-token", "write"),
        ("attestations", "write"),
    ] {
        assert_eq!(
            permission(&release, evidence, scope).as_deref(),
            Some(level),
            "{scope}"
        );
    }
    let run = scripts(evidence);
    for part in [
        "gh release download",
        "./scripts/evidence-manifest.sh evidence",
        "gh release upload \"${GITHUB_REF_NAME}\" evidence-manifest.json",
        "./scripts/verify-evidence.sh evidence \"${GITHUB_REPOSITORY}\"",
        "permguard-gate",
        "traceability",
    ] {
        assert!(run.contains(part), "{part} in:\n{run}");
    }
    let attested: Vec<&str> = using(evidence, "actions/attest")
        .iter()
        .filter_map(|step| step["with"].get("subject-path").and_then(Value::as_str))
        .collect();
    assert_eq!(attested, ["evidence-manifest.json"]);
    // The manifest is attested before it is published and verified.
    let order: Vec<usize> = ["actions/attest@", "verify-evidence.sh"]
        .iter()
        .map(|marker| {
            steps(evidence)
                .iter()
                .position(|step| {
                    step.get("uses")
                        .and_then(Value::as_str)
                        .is_some_and(|uses| uses.starts_with(marker))
                        || step
                            .get("run")
                            .and_then(Value::as_str)
                            .is_some_and(|run| run.contains(marker))
                })
                .unwrap_or_else(|| panic!("no step with {marker}"))
        })
        .collect();
    assert!(order[0] < order[1], "{order:?}");
}

/// The pipeline's own rule: a job that may sign compiles nothing, so no dependency's build script
/// runs where the token that signs in this repository's name can be minted. A tripwire on the
/// jobs' own `run` scripts: what a called script or action does is held by review.
#[test]
fn no_job_that_may_sign_compiles() {
    let release = release();
    for (name, held) in release["jobs"].as_mapping().expect("jobs") {
        if held.get("uses").is_some() {
            continue;
        }
        if permission(&release, held, "id-token").as_deref() == Some("write") {
            let run = scripts(held);
            assert!(
                !run.contains("cargo") && !run.contains("docker build"),
                "{name:?} may sign and compiles:\n{run}"
            );
        }
    }
}

/// The scripts the jobs run exist and are executable.
#[test]
fn the_evidence_scripts_are_executable() {
    for script in [
        "scripts/evidence-manifest.sh",
        "scripts/verify-evidence.sh",
        "scripts/fuzz.sh",
    ] {
        let path = repository().join(script);
        let metadata = std::fs::metadata(&path).unwrap_or_else(|_| panic!("no {script}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert!(
                metadata.permissions().mode() & 0o111 != 0,
                "{script} is executable"
            );
        }
        let _ = metadata;
    }
}
