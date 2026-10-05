// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! REGO-03: a Rego partition compiled and decided in its supervised worker, against the real
//! runtime catalogue, as the Data Plane runs it from `production` upward.
//!
//! Run without the test harness, because the binary has two lives: started with the worker
//! argument it serves frames for the real runtimes, started plainly it supervises itself.

#![allow(clippy::print_stdout)]

use permguard_languages::evaluate::{Action, Entity, Query, StoredPolicy};
use permguard_languages::worker::{Isolated, Supervisors};

mod harness;

fn main() -> std::process::ExitCode {
    permguard_languages::worker::serve_if_worker();

    let cases: [(&str, harness::Case); 3] = [
        (
            "a_rego_partition_decides_in_its_supervised_worker",
            a_rego_partition_decides_in_its_supervised_worker,
        ),
        (
            "a_partition_the_runtime_refuses_is_refused_by_the_worker",
            a_partition_the_runtime_refuses_is_refused_by_the_worker,
        ),
        (
            "rego_requires_isolation_from_production",
            rego_requires_isolation_from_production,
        ),
    ];
    harness::run(&cases)
}

fn query(subject: &str) -> Query {
    let entity = |kind: &str, id: &str| Entity {
        kind: kind.to_owned(),
        id: id.to_owned(),
        properties: serde_json::Map::new(),
    };
    Query {
        subject: entity("user", subject),
        resource: entity("document", "budget"),
        action: Action {
            name: "read".to_owned(),
            properties: serde_json::Map::new(),
        },
        context: serde_json::Map::new(),
        deadline: None,
        input: permguard_languages::PartitionData::default(),
    }
}

fn stored(id: &str, source: &str) -> StoredPolicy {
    StoredPolicy {
        id: id.to_owned(),
        source: source.as_bytes().to_vec(),
        alias: None,
    }
}

fn a_rego_partition_decides_in_its_supervised_worker() -> bool {
    // The supervised worker exists only on Unix.
    if !cfg!(unix) {
        return false;
    }
    let supervisors = Supervisors::default();
    let evaluator = supervisors
        .compile(
            "rego",
            &[stored(
                "01a0-alice",
                "package isolated\nimport rego.v1\nallow if { input.subject.id == \"alice\" }\n",
            )],
            &permguard_languages::artifact::Artifacts::default(),
        )
        .unwrap_or_else(|why| panic!("compiles in the worker: {why:?}"));
    assert!(evaluator.evaluate(&query("alice")).permitted());
    assert!(!evaluator.evaluate(&query("bob")).permitted());
    assert_eq!(evaluator.policies(), vec!["01a0-alice".to_owned()]);
    true
}

fn a_partition_the_runtime_refuses_is_refused_by_the_worker() -> bool {
    if !cfg!(unix) {
        return false;
    }
    let supervisors = Supervisors::default();
    let refused = supervisors
        .compile(
            "rego",
            &[stored(
                "01a0-clock",
                "package clock\nimport rego.v1\nallow if { time.now_ns() > 0 }\n",
            )],
            &permguard_languages::artifact::Artifacts::default(),
        )
        .err();
    assert!(
        matches!(&refused, Some(Isolated::Refused(why)) if why.contains("time.now_ns")),
        "the allow-list holds in the worker too: {refused:?}"
    );
    true
}

fn rego_requires_isolation_from_production() -> bool {
    use permguard_core::assurance::AssuranceProfile::{Development, Production, Regulated};
    use permguard_languages::registry::isolation_required;

    assert!(!isolation_required("rego", Development));
    assert!(isolation_required("rego", Production));
    assert!(isolation_required("rego", Regulated));
    assert!(
        !isolation_required("cedar", Regulated),
        "Cedar is bounded in-process"
    );
    true
}
