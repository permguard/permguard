// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance gate per language claims no more than the repository proves (TL-6).
//!
//! `permguard_languages::conformance` records each runtime's items as passing with evidence, or
//! open. This reads every evidence it names and fails when one is not there:
//!
//! | Evidence                       | Checked                                                      |
//! | ------------------------------ | ------------------------------------------------------------ |
//! | `<crate>/<path>::<function>`   | the file exists and defines that function                    |
//! | `ci:<job>`                     | the CI workflow runs that job                                |
//! | `file:<path>#<text>`           | the file exists and says that text                           |
//!
//! CI runs every test it names, so CI passing is the evidence passing. The replay item must name
//! CI jobs on two operating systems.

#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use permguard_languages::conformance::{ITEMS, Item, State, gate};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workflow() -> String {
    std::fs::read_to_string(root().join(".github/workflows/ci.yml")).expect("the CI workflow")
}

/// The `runs-on` of the CI job `job`, or `None` when the workflow has no such job.
fn runner_of(workflow: &str, job: &str) -> Option<String> {
    let header = format!("  {job}:");
    let mut lines = workflow.lines().skip_while(|line| *line != header);
    lines.next()?;
    lines
        // The job ends where the next job, two spaces in, begins.
        .take_while(|line| {
            !(line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':'))
        })
        .find_map(|line| line.trim().strip_prefix("runs-on:"))
        .map(|runner| runner.trim().to_owned())
}

fn check(evidence: &str, workflow: &str) -> Result<(), String> {
    if let Some(job) = evidence.strip_prefix("ci:") {
        return runner_of(workflow, job)
            .map(|_| ())
            .ok_or_else(|| format!("the CI workflow runs no job `{job}`"));
    }
    if let Some(rest) = evidence.strip_prefix("file:") {
        let (path, text) = rest.split_once('#').ok_or("no `#text`")?;
        let content = std::fs::read_to_string(root().join(path))
            .map_err(|error| format!("{path}: {error}"))?;
        return if content.contains(text) {
            Ok(())
        } else {
            Err(format!("{path} does not say `{text}`"))
        };
    }
    let (file, function) = evidence.split_once("::").ok_or("no `::function`")?;
    let (krate, path) = file.split_once('/').ok_or("no crate")?;
    let source = std::fs::read_to_string(root().join("crates").join(krate).join(path))
        .map_err(|error| format!("{file}: {error}"))?;
    is_a_test(&source, function).map_err(|why| format!("{file}: `{function}` {why}"))
}

/// Whether `source` defines `function` as a test that runs: a `#[test]` or `#[tokio::test]` that
/// is not `#[ignore]`d, or, in a test binary without the harness, a case its runner registers.
fn is_a_test(source: &str, function: &str) -> Result<(), String> {
    let lines: Vec<&str> = source.lines().collect();
    let defined = lines
        .iter()
        .position(|line| {
            let line = line.trim_start();
            !line.starts_with("//")
                && (line.starts_with(&format!("fn {function}("))
                    || line.starts_with(&format!("async fn {function}(")))
        })
        .ok_or("is not defined")?;
    // The attributes and doc comments right above the definition.
    let above: Vec<&str> = lines[..defined]
        .iter()
        .rev()
        .map(|line| line.trim())
        .take_while(|line| {
            line.starts_with("#[") || line.starts_with("///") || line.starts_with("//")
        })
        .collect();
    if above.iter().any(|line| line.starts_with("#[ignore")) {
        return Err("is ignored".to_owned());
    }
    if above
        .iter()
        .any(|line| *line == "#[test]" || line.starts_with("#[tokio::test"))
    {
        return Ok(());
    }
    // A harness-less binary registers its cases by name in what it runs.
    let registered =
        source.contains("harness::run") && source.matches(&format!("\"{function}\"")).count() >= 1;
    if registered {
        Ok(())
    } else {
        Err("is not a test: no `#[test]`, and no runner registers it".to_owned())
    }
}

/// An evidence without its fault label (`panic=`, …), and the label.
fn unlabelled(evidence: &str) -> (Option<&str>, &str) {
    match evidence.split_once('=') {
        Some((label, rest)) if !label.contains('/') && !label.contains(':') => (Some(label), rest),
        _ => (None, evidence),
    }
}

#[test]
fn every_evidence_the_gate_names_exists() {
    let workflow = workflow();
    let mut missing = Vec::new();
    for language in permguard_languages::languages() {
        for record in gate(language.name()) {
            if let State::Passing(evidence) = record.state {
                for item in evidence {
                    let (_, item) = unlabelled(item);
                    if let Err(why) = check(item, &workflow) {
                        missing.push(format!(
                            "{} {:?} `{item}`: {why}",
                            language.name(),
                            record.item
                        ));
                    }
                }
            }
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

/// Fault injection passes only with every fault proven: panic, timeout, memory and cache.
#[test]
fn fault_injection_names_every_fault() {
    use permguard_languages::conformance::FAULTS;

    for language in permguard_languages::languages() {
        for record in gate(language.name()) {
            let (Item::FaultInjection, State::Passing(evidence)) = (record.item, record.state)
            else {
                continue;
            };
            let labels: std::collections::BTreeSet<&str> = evidence
                .iter()
                .filter_map(|item| unlabelled(item).0)
                .collect();
            for fault in FAULTS {
                assert!(
                    labels.contains(fault),
                    "{}: no `{fault}=` evidence",
                    language.name()
                );
            }
        }
    }
}

#[test]
fn replay_names_ci_jobs_on_two_operating_systems() {
    let workflow = workflow();
    for language in permguard_languages::languages() {
        let Some(record) = gate(language.name())
            .iter()
            .find(|record| record.item == Item::Replay)
        else {
            panic!("{}: no replay record", language.name());
        };
        let State::Passing(evidence) = record.state else {
            continue;
        };
        let systems: std::collections::BTreeSet<&str> = evidence
            .iter()
            .filter_map(|item| item.strip_prefix("ci:"))
            .filter_map(|job| runner_of(&workflow, job))
            .map(|runner| {
                if runner.starts_with("macos") {
                    "macos"
                } else if runner.starts_with("ubuntu") {
                    "linux"
                } else {
                    "other"
                }
            })
            .collect();
        assert!(
            systems.contains("linux") && systems.contains("macos"),
            "{}: replay runs on {systems:?}",
            language.name()
        );
    }
}

#[test]
fn the_checks_here_refuse_what_does_not_exist() {
    let workflow = workflow();
    assert!(check("ci:check", &workflow).is_ok());
    assert!(check("ci:no-such-job", &workflow).is_err());
    // A function that is not a test is not evidence.
    assert!(check("permguard-languages/src/conformance.rs::gate", &workflow).is_err());
    assert!(
        check(
            "permguard-languages/src/conformance.rs::cedar_and_rego_are_production_ready_and_dogwood_says_what_is_open",
            &workflow
        )
        .is_ok()
    );
    assert!(
        check(
            "permguard-languages/tests/rego_supervised.rs::rego_requires_isolation_from_production",
            &workflow
        )
        .is_ok(),
        "a harness-less case its runner registers"
    );
    assert!(
        is_a_test("#[test]\n#[ignore]\nfn skipped() {}\n", "skipped").is_err(),
        "an ignored test is not evidence"
    );
    assert!(
        is_a_test("// fn ghost() {}\n", "ghost").is_err(),
        "a comment is not a test"
    );
    assert!(
        check(
            "permguard-languages/src/conformance.rs::no_such_function",
            &workflow
        )
        .is_err()
    );
    assert!(check("permguard-languages/src/nothing.rs::gate", &workflow).is_err());
    assert!(check("file:.goreleaser-pro.yaml#sboms", &workflow).is_ok());
    assert!(check("file:.goreleaser-pro.yaml#no such text anywhere", &workflow).is_err());
    assert_eq!(ITEMS.len(), 8);
}
