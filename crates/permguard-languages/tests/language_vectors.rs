// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Each runtime's golden vectors (TL-6): manifests the load gate accepts or refuses, partitions
//! that compile or are refused, and requests with the verdict or the error they must answer.
//!
//! `tests/vectors/<runtime>.json` is the expected output, recorded against one locked engine:
//!
//! | Section      | What a vector states                                                         |
//! | ------------ | ---------------------------------------------------------------------------- |
//! | `engine`     | the engine crate and the version `Cargo.lock` locked when it was recorded     |
//! | `manifests`  | a manifest's YAML and whether the load gate accepts it, or the refusal's text |
//! | `partitions` | policies and artifacts, and whether they compile, or the refusal's text       |
//! | `requests`   | a request and its verdict — `P`, `D`, `A` or `E` with its code — or the input  |
//! |              | the partition's schema refused before any policy was consulted               |
//!
//! The same expected bytes on every platform CI runs them on is the deterministic replay; the
//! `engine` member is the differential: when `Cargo.lock` locks another engine version, the
//! vectors fail until they are recorded again — `PERMGUARD_BLESS=1 cargo test -p
//! permguard-languages --test language_vectors` — and the diff of their expected outputs is what an
//! engine upgrade changes, reviewed before it lands.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use permguard_languages::artifact::{ArtifactBlob, Artifacts, artifact_type};
use permguard_languages::{
    Action, Entity, Evaluator, PartitionData, Query, StoredPolicy, Verdict, evaluating, language,
};
use serde_json::{Value, json};

const RUNTIMES: [&str; 2] = ["cedar", "rego"];

fn path(runtime: &str) -> String {
    format!(
        "{}/tests/vectors/{runtime}.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn blessing() -> bool {
    std::env::var("PERMGUARD_BLESS").is_ok_and(|value| value == "1")
}

/// What the load gate answers for a manifest's YAML.
fn manifest_outcome(yaml: &str) -> Value {
    let manifest = match permguard_languages::manifest_file::from_yaml(yaml.as_bytes()) {
        Ok(manifest) => manifest,
        Err(error) => return json!({ "refused": error }),
    };
    match permguard_languages::registry::check_manifest(&manifest) {
        Ok(()) => json!("accepted"),
        Err(error) => json!({ "refused": error.detail }),
    }
}

/// A partition's artifacts, by registered type name.
fn artifacts(declared: &Value) -> Artifacts {
    let mut artifacts = Artifacts::default();
    for (type_name, data) in declared.as_object().into_iter().flatten() {
        let artifact = artifact_type(type_name)
            .unwrap_or_else(|| panic!("`{type_name}` is no registered artifact type"));
        let data = match data {
            Value::String(text) => text.as_bytes().to_vec(),
            other => serde_json::to_vec(other).expect("JSON"),
        };
        artifacts.insert(
            artifact,
            ArtifactBlob {
                name: artifact
                    .canonical_filename()
                    .unwrap_or(artifact.semantic_role())
                    .to_owned(),
                media_type: artifact.media_type().to_owned(),
                data,
            },
        );
    }
    artifacts
}

fn compile(runtime: &str, partition: &Value) -> Result<Box<dyn Evaluator>, String> {
    let policies: Vec<StoredPolicy> = partition["policies"]
        .as_array()
        .expect("policies")
        .iter()
        .map(|policy| StoredPolicy {
            id: policy["id"].as_str().expect("an id").to_owned(),
            alias: None,
            source: policy["source"]
                .as_str()
                .expect("a source")
                .as_bytes()
                .to_vec(),
        })
        .collect();
    evaluating(runtime)
        .expect("the runtime evaluates")
        .compile(&policies, &artifacts(&partition["artifacts"]))
}

fn entity(declared: &Value) -> Entity {
    Entity {
        kind: declared["type"].as_str().expect("a type").to_owned(),
        id: declared["id"].as_str().expect("an id").to_owned(),
        properties: declared["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default(),
    }
}

fn query(request: &Value) -> Query {
    let input = match (&request["input"]["cedar"], &request["input"]["rego"]) {
        (Value::Array(items), _) => {
            PartitionData::CedarEntities(std::sync::Arc::new(items.clone()))
        }
        (_, Value::Object(document)) => {
            PartitionData::RegoData(std::sync::Arc::new(document.clone()))
        }
        _ => PartitionData::Absent,
    };
    Query {
        subject: entity(&request["subject"]),
        resource: entity(&request["resource"]),
        action: Action {
            name: request["action"]["name"]
                .as_str()
                .expect("an action")
                .to_owned(),
            properties: request["action"]["properties"]
                .as_object()
                .cloned()
                .unwrap_or_default(),
        },
        context: request["context"].as_object().cloned().unwrap_or_default(),
        deadline: None,
        input,
    }
}

/// A verdict as the vectors write it: the algebra's letter, the deciding policies, the codes.
fn written(verdict: &Verdict) -> Value {
    match verdict {
        Verdict::Permit { determining } => json!({ "verdict": "P", "determining": determining }),
        Verdict::Deny {
            determining,
            beside,
        } => {
            let mut written = json!({ "verdict": "D", "determining": determining });
            if let Some(beside) = beside {
                written["beside"] = json!(beside.code);
            }
            written
        }
        Verdict::Abstain => json!({ "verdict": "A" }),
        Verdict::Error { code, .. } => json!({ "verdict": "E", "code": code }),
    }
}

/// The vectors of `runtime` as this build answers them.
fn observed(runtime: &str, vectors: &Value) -> Value {
    let mut out = vectors.clone();
    let engine = language(runtime).expect("the runtime").engine().locked;
    out["engine"] = json!({ "name": engine.name, "version": engine.version });
    for manifest in out["manifests"].as_array_mut().expect("manifests") {
        manifest["expect"] = manifest_outcome(manifest["yaml"].as_str().expect("yaml"));
    }
    let mut compiled = BTreeMap::new();
    for partition in out["partitions"].as_array_mut().expect("partitions") {
        let name = partition["name"].as_str().expect("a name").to_owned();
        match compile(runtime, partition) {
            Ok(evaluator) => {
                partition["expect"] = json!("compiles");
                compiled.insert(name, evaluator);
            }
            Err(error) => partition["expect"] = json!({ "refused": error }),
        }
    }
    for request in out["requests"].as_array_mut().expect("requests") {
        let partition = request["partition"].as_str().expect("a partition");
        let evaluator = compiled
            .get(partition)
            .unwrap_or_else(|| panic!("{runtime}: `{partition}` did not compile"));
        // The request path's order: the input is checked against the partition's schema before
        // any policy is consulted, and a refused input is the caller's mistake, never a verdict.
        let query = query(request);
        request["expect"] = match evaluator.check_input(&query.input) {
            Ok(()) => written(&evaluator.evaluate(&query)),
            Err(why) => json!({ "input_refused": why }),
        };
    }
    out
}

fn check(runtime: &str) {
    let file = path(runtime);
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(&file).unwrap_or_else(|error| panic!("{file}: {error}")),
    )
    .expect("the vectors are JSON");
    let observed = observed(runtime, &vectors);
    if blessing() {
        let mut text = serde_json::to_string_pretty(&observed).expect("JSON");
        text.push('\n');
        std::fs::write(&file, text).expect("the vectors are recorded");
        return;
    }
    let engine = language(runtime).expect("the runtime").engine().locked;
    assert_eq!(
        vectors["engine"],
        json!({ "name": engine.name, "version": engine.version }),
        "{runtime}: the vectors were recorded against another engine; record them again with \
         PERMGUARD_BLESS=1 and review the diff before the upgrade lands"
    );
    let sections = ["manifests", "partitions", "requests"];
    for section in sections {
        let expected = vectors[section].as_array().expect("a section");
        let answered = observed[section].as_array().expect("a section");
        assert!(!expected.is_empty(), "{runtime}: no {section}");
        for (expected, answered) in expected.iter().zip(answered) {
            assert_eq!(
                expected["expect"], answered["expect"],
                "{runtime} {section} `{}`",
                expected["name"]
            );
        }
    }
}

#[test]
fn test_cedar_answers_its_golden_vectors() {
    check("cedar");
}

#[test]
fn test_rego_answers_its_golden_vectors() {
    check("rego");
}

/// Every verdict of the algebra, and an error, is somewhere in each runtime's vectors: a file that
/// only ever permits proves nothing about the rest.
#[test]
fn test_every_runtimes_vectors_cover_the_whole_algebra() {
    for runtime in RUNTIMES {
        let vectors: Value =
            serde_json::from_str(&std::fs::read_to_string(path(runtime)).expect("readable"))
                .expect("JSON");
        let verdicts: std::collections::BTreeSet<String> = vectors["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .map(|request| {
                request["expect"]["verdict"]
                    .as_str()
                    .unwrap_or("?")
                    .to_owned()
            })
            .collect();
        for letter in ["P", "D", "A", "E"] {
            assert!(verdicts.contains(letter), "{runtime}: no `{letter}` vector");
        }
        let manifests = vectors["manifests"].as_array().expect("manifests");
        assert!(
            manifests.iter().any(|m| m["expect"] == "accepted"),
            "{runtime}"
        );
        assert!(
            manifests
                .iter()
                .any(|m| m["expect"].get("refused").is_some()),
            "{runtime}"
        );
        let partitions = vectors["partitions"].as_array().expect("partitions");
        assert!(
            partitions
                .iter()
                .any(|p| p["expect"].get("refused").is_some()),
            "{runtime}"
        );
    }
}
