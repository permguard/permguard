// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Upstream corpus parity for Cedar (TL-6): the hand-written integration cases of
//! `cedar-policy/cedar-integration-tests`, at the revision of the 4.11 run, decided through this
//! build's Cedar runtime exactly as upstream's own harness decides them.
//!
//! `tests/corpus/cedar/SOURCE.json` names the repository, the revision, the engine version the
//! corpus was recorded for and every vendored file's digest. Each request's upstream answer —
//! `decision`, `reason`, `errors` — maps to the languages model's algebra:
//!
//! | Upstream                                      | Here                                        |
//! | --------------------------------------------- | ------------------------------------------- |
//! | `allow`, no error                             | `P`, citing exactly the `reason` policies   |
//! | `allow` beside an error                       | `E`: no permit is released beside a failure |
//! | `deny`, a `reason`                            | `D`, citing exactly the forbids             |
//! | `deny`, no `reason`, no error                 | `A`                                         |
//! | `deny`, no `reason`, an error                 | `E`                                         |
//!
//! A case whose policies do not validate against their schema is out of scope: the runtime refuses
//! such a load by design (strict validation), where upstream's harness decides it anyway. The test
//! counts them, so the corpus cannot quietly shrink to nothing.

#![allow(clippy::expect_used, clippy::panic)]

use std::str::FromStr as _;

use permguard_languages::artifact::Artifacts;
use permguard_languages::{
    Action, Entity, PartitionData, Query, StoredPolicy, Verdict, evaluating, language,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/cedar")
}

fn source() -> Value {
    serde_json::from_str(&std::fs::read_to_string(root().join("SOURCE.json")).expect("SOURCE"))
        .expect("JSON")
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(root().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn test_the_vendored_corpus_is_the_one_its_source_names() {
    let source = source();
    assert_eq!(
        source["revision"],
        "1ce53a69c686413ab6aabc8af80b0925898a7f54"
    );
    for (path, digest) in source["files"].as_object().expect("files") {
        let actual = format!(
            "sha256:{}",
            Sha256::digest(read(path))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            digest,
            &Value::from(actual),
            "{path} changed since it was vendored"
        );
    }
    // Recorded for the engine this build locks: an upgrade takes a corpus at its own revision.
    let engine = language("cedar").expect("cedar").engine().locked;
    assert_eq!(
        source["engine"],
        serde_json::json!({ "name": engine.name, "version": engine.version }),
        "the corpus was vendored for another Cedar: vendor the revision of the locked engine's run"
    );
}

/// The upstream answer as the algebra's verdict.
fn expected(request: &Value) -> String {
    let mut reason: Vec<String> = request["reason"]
        .as_array()
        .expect("reason")
        .iter()
        .map(|policy| policy.as_str().expect("an id").to_owned())
        .collect();
    reason.sort();
    let errors = !request["errors"].as_array().expect("errors").is_empty();
    match (
        request["decision"].as_str().expect("decision"),
        reason.is_empty(),
        errors,
    ) {
        ("allow", _, false) => format!("P {reason:?}"),
        ("allow", _, true) => "E".to_owned(),
        ("deny", false, _) => format!("D {reason:?}"),
        ("deny", true, false) => "A".to_owned(),
        ("deny", true, true) => "E".to_owned(),
        (other, ..) => panic!("an upstream decision `{other}`"),
    }
}

fn answered(verdict: &Verdict) -> String {
    let mut determining = verdict.determining().to_vec();
    determining.sort();
    match verdict {
        Verdict::Permit { .. } => format!("P {determining:?}"),
        Verdict::Deny { .. } => format!("D {determining:?}"),
        Verdict::Abstain => "A".to_owned(),
        Verdict::Error { .. } => "E".to_owned(),
    }
}

fn uid(declared: &Value) -> (String, String) {
    (
        declared["type"].as_str().expect("a type").to_owned(),
        declared["id"].as_str().expect("an id").to_owned(),
    )
}

#[test]
fn test_cedar_reproduces_the_upstream_integration_corpus() {
    let source = source();
    let runtime = evaluating("cedar").expect("cedar evaluates");
    let mut decided = 0;
    let mut out_of_scope = Vec::new();
    for test in source["tests"].as_array().expect("tests") {
        let test = test.as_str().expect("a path");
        let case: Value = serde_json::from_slice(&read(test)).expect("a case");
        if case["shouldValidate"] == Value::Bool(false) {
            out_of_scope.push(test.to_owned());
            continue;
        }
        let text =
            String::from_utf8(read(case["policies"].as_str().expect("policies"))).expect("UTF-8");
        // Upstream names the policies of a file `policy0`, `policy1`, … in order: the same ids
        // here, one stored policy each, so a cited policy is the one upstream cites.
        let set = cedar_policy::PolicySet::from_str(&text).expect("the upstream policies parse");
        let mut policies: Vec<StoredPolicy> = set
            .policies()
            .map(|policy| StoredPolicy {
                id: policy.id().to_string(),
                alias: None,
                source: policy.to_string().into_bytes(),
            })
            .collect();
        policies.sort_by(|a, b| a.id.cmp(&b.id));
        let artifacts = match case["schema"].as_str() {
            Some(schema) => Artifacts::just(
                permguard_core::domains::artifact::CEDAR_SCHEMA_V1,
                &read(schema),
            )
            .expect("the Cedar schema artifact"),
            None => Artifacts::default(),
        };
        let compiled = runtime
            .compile(&policies, &artifacts)
            .unwrap_or_else(|error| panic!("{test}: {error}"));
        let entities: Vec<Value> = match case["entities"].as_str() {
            Some(path) => serde_json::from_slice(&read(path)).expect("entities"),
            None => Vec::new(),
        };
        let input = PartitionData::CedarEntities(std::sync::Arc::new(entities));
        for request in case["requests"].as_array().expect("requests") {
            let (principal_type, principal) = uid(&request["principal"]);
            let (resource_type, resource) = uid(&request["resource"]);
            let (action_type, action) = uid(&request["action"]);
            let query = Query {
                subject: Entity {
                    kind: principal_type,
                    id: principal,
                    properties: Default::default(),
                },
                resource: Entity {
                    kind: resource_type,
                    id: resource,
                    properties: Default::default(),
                },
                action: Action {
                    name: format!("{action_type}::{action}"),
                    properties: Default::default(),
                },
                context: request["context"].as_object().cloned().unwrap_or_default(),
                deadline: None,
                input: input.clone(),
            };
            let verdict = match compiled.check_input(&query.input) {
                Ok(()) => compiled.evaluate(&query),
                Err(why) => panic!(
                    "{test} `{}`: the input was refused: {why}",
                    request["description"]
                ),
            };
            assert_eq!(
                answered(&verdict),
                expected(request),
                "{test}: {} ({verdict:?})",
                request["description"]
            );
            decided += 1;
        }
    }
    // The corpus at this revision: what is decided and what is out of scope, counted.
    assert_eq!(
        out_of_scope,
        Vec::<String>::new(),
        "out of scope at this revision"
    );
    // Every request of the 22 cases at this revision: the count moves only with the corpus.
    assert_eq!(decided, 74, "upstream requests decided");
}
