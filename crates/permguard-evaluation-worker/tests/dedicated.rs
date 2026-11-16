// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dedicated evaluation worker, started by a supervisor that is another executable: what an
//! application embedding the Data Plane gets when it names this binary in place of its own.
//!
//! | What happens                              | What it proves                                    |
//! | ----------------------------------------- | ------------------------------------------------- |
//! | a Rego partition compiled and decided     | the protocol, across two executables              |
//! | a partition the runtime refuses           | refused by the worker, as an in-process compile   |
//! | the binary started by hand                | it refuses, on standard error, and answers nobody |
//! | an executable that is no worker           | the partition is unavailable, never evaluated here |
//!
//! The supervisor here is this test's own process, with the real runtime catalogue; the worker is
//! the binary Cargo built for this package.

#![allow(clippy::expect_used, clippy::panic)]
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

use permguard_languages::artifact::Artifacts;
use permguard_languages::evaluate::{Action, Entity, Query, StoredPolicy};
use permguard_languages::worker::{Isolated, Supervisors};

/// The dedicated worker, as Cargo built it for this package.
fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_permguard-evaluation-worker"))
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

const ALICE: &str =
    "package isolated\nimport rego.v1\nallow if { input.subject.id == \"alice\" }\n";

#[test]
fn test_a_rego_partition_is_compiled_and_decided_in_the_dedicated_worker() {
    let supervisors = Supervisors::default().started_from(worker());

    let evaluator = supervisors
        .compile(
            "rego",
            &[stored("01a0-alice", ALICE)],
            &Artifacts::default(),
        )
        .unwrap_or_else(|why| panic!("compiles in the dedicated worker: {why:?}"));

    assert!(evaluator.evaluate(&query("alice")).permitted());
    let denied = evaluator.evaluate(&query("bob"));
    assert!(!denied.permitted());
    assert!(denied.error().is_none(), "a deny, not an error: {denied:?}");
}

#[test]
fn test_a_partition_the_runtime_refuses_is_refused_by_the_dedicated_worker() {
    let supervisors = Supervisors::default().started_from(worker());

    let refused = supervisors
        .compile(
            "rego",
            &[stored("01a0-broken", "package ???")],
            &Artifacts::default(),
        )
        .err()
        .expect("not a Rego module");

    assert!(
        matches!(refused, Isolated::Refused(_)),
        "refused by the runtime, in the worker: {refused:?}"
    );
}

#[test]
fn test_the_worker_started_by_hand_refuses_and_answers_nobody() {
    for arguments in [&[][..], &["--help"][..], &["rego"][..]] {
        let output = Command::new(worker())
            .args(arguments)
            .output()
            .expect("the worker runs");

        assert_eq!(output.status.code(), Some(64), "{arguments:?}");
        assert!(
            output.stdout.is_empty(),
            "{arguments:?}: it wrote to standard output"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("It is not started by hand"),
            "{arguments:?}"
        );
    }
}

#[test]
fn test_an_executable_that_is_no_worker_leaves_the_partition_unavailable() {
    // An executable that exits at once, whatever it is handed: it speaks no protocol.
    let supervisors = Supervisors::default().started_from(PathBuf::from("/usr/bin/true"));

    let unavailable = supervisors
        .compile(
            "rego",
            &[stored("01a0-alice", ALICE)],
            &Artifacts::default(),
        )
        .err()
        .expect("nothing answered a frame");

    assert!(
        matches!(unavailable, Isolated::Unavailable(_)),
        "unavailable, and never compiled in this process instead: {unavailable:?}"
    );
}
