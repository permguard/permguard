// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The mutation engine on PostgreSQL against a real server (iteration 03, E23 to E25, E30):
//! what the file engine's callers are promised, kept by one transaction.
//!
//! The tests need a server, as `foundations.rs` says, and are skipped without one.

#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};

use permguard_host::operations::journal::{Initiator, RequestKey};
use permguard_host::operations::mutation::{
    Applied, Applying, Begin, Engine as _, Failure, MutationError, Outcome, replayed_on,
    run_checked_on,
};
use permguard_postgres::mutations::PostgresMutations;
use permguard_postgres::{Database, Unit};
use support::{config, scratch, server};

/// A request of `principal` to create the grant `request_id` names.
fn begin(principal: &str, request_id: &str, digest: &str) -> Begin {
    Begin {
        domain: "grants",
        operation: "grants.create",
        action: "host.grant.created",
        initiator: Initiator::Principal(principal.to_owned()),
        request: Some(RequestKey {
            request_id: request_id.to_owned(),
            digest: digest.to_owned(),
        }),
        target: Some("grant/new".to_owned()),
    }
}

/// The domain of the tests: one table of grants, each written beside the operation that made it.
fn domain(database: &Database) {
    database
        .write(|unit| {
            unit.batch_execute(
                "CREATE TABLE grants (name text PRIMARY KEY, operation bytea NOT NULL)",
            )
        })
        .expect("the domain's table");
}

/// The domain write: the grant `name`, inside the unit the engine handed over.
fn grant(applying: &Applying<'_>, name: &str) -> Result<Applied<String>, Failure<String>> {
    let unit = applying
        .unit::<Unit>()
        .ok_or_else(|| Failure::Refused("no unit of work".to_owned()))?;
    unit.execute(
        "INSERT INTO grants (name, operation) VALUES ($1, $2)",
        &[&name, &applying.operation_id().as_bytes().as_slice()],
    )
    .map_err(|error| Failure::Indeterminate(error.to_string()))?;
    Ok(Applied {
        revision: 1,
        target: Some(format!("grant/{name}")),
        value: format!("created {name}"),
    })
}

fn count(database: &Database, query: &str) -> i64 {
    database
        .write(|unit| Ok(unit.query_one(query, &[])?.get(0)))
        .expect("read")
}

/// E24: the change, the operation's row and its audit rows are kept together, and a retry of
/// the same request learns the first answer without the domain write being run again; the same
/// id under another request is refused, and another principal's same id is its own request.
#[test]
fn an_operation_is_kept_whole_and_a_retry_learns_its_answer() {
    let Some(server) = server("an_operation_is_kept_whole_and_a_retry_learns_its_answer") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    domain(database);
    let engine = PostgresMutations::new(Database::clone(database));

    let first = run_checked_on(
        &engine,
        begin("alice", "request-1", "d1"),
        || Ok::<(), String>(()),
        |applying| grant(applying, "read"),
    )
    .expect("applied");
    assert_eq!(first, Outcome::Applied("created read".to_owned()));
    assert_eq!(count(database, "SELECT count(*) FROM grants"), 1);
    assert_eq!(
        count(
            database,
            "SELECT count(*) FROM permguard_mutations m JOIN grants g
             ON g.operation = m.operation_id
             WHERE m.state = 'applied' AND m.revision = 1 AND m.target = 'grant/read'"
        ),
        1,
        "the operation's row names the write it made"
    );
    assert_eq!(
        count(
            database,
            "SELECT count(*) FROM permguard_mutation_audit
             WHERE phase IN ('intent', 'applied') AND action = 'host.grant.created'
               AND subject_kind = 'principal' AND subject = 'alice'"
        ),
        2
    );

    let ran = AtomicUsize::new(0);
    let retry = run_checked_on(
        &engine,
        begin("alice", "request-1", "d1"),
        || Ok::<(), String>(()),
        |applying| {
            ran.fetch_add(1, Ordering::SeqCst);
            grant(applying, "read")
        },
    )
    .expect("answered");
    assert_eq!(retry, Outcome::Replayed("created read".to_owned()));
    assert_eq!(ran.load(Ordering::SeqCst), 0, "the write is not run again");
    assert_eq!(
        replayed_on::<String, String>(&engine, &begin("alice", "request-1", "d1"))
            .expect("answered"),
        Some(Outcome::Replayed("created read".to_owned()))
    );
    assert_eq!(
        replayed_on::<String, String>(&engine, &begin("alice", "request-2", "d1"))
            .expect("answered"),
        None
    );

    let reused = run_checked_on(
        &engine,
        begin("alice", "request-1", "another"),
        || Ok::<(), String>(()),
        |applying| grant(applying, "write"),
    );
    assert!(
        matches!(reused, Err(MutationError::RequestIdReused(_))),
        "{reused:?}"
    );
    let other = run_checked_on(
        &engine,
        begin("bob", "request-1", "d1"),
        || Ok::<(), String>(()),
        |applying| grant(applying, "write"),
    )
    .expect("another principal's request");
    assert_eq!(other, Outcome::Applied("created write".to_owned()));
    assert_eq!(count(database, "SELECT count(*) FROM grants"), 2);
}

/// A domain write that refuses is undone, and the operation is kept as failed with its record;
/// a validation that refuses keeps nothing at all; a write that cannot say keeps nothing. The
/// same request id then applies anew.
#[test]
fn a_refused_write_is_undone_and_recorded_failed() {
    let Some(server) = server("a_refused_write_is_undone_and_recorded_failed") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    domain(database);
    let engine = PostgresMutations::new(Database::clone(database));

    let refused = run_checked_on::<String, String>(
        &engine,
        begin("alice", "request-1", "d1"),
        || Ok(()),
        |applying| {
            grant(applying, "read")?;
            Err(Failure::Refused("not allowed".to_owned()))
        },
    );
    assert!(matches!(refused, Err(MutationError::Refused(reason)) if reason == "not allowed"));
    assert_eq!(
        count(database, "SELECT count(*) FROM grants"),
        0,
        "the write is undone"
    );
    assert_eq!(
        count(
            database,
            "SELECT count(*) FROM permguard_mutations WHERE state = 'failed'"
        ),
        1
    );
    assert_eq!(
        count(
            database,
            "SELECT count(*) FROM permguard_mutation_audit WHERE phase IN ('intent', 'failed')"
        ),
        2
    );

    let unchecked = run_checked_on::<String, String>(
        &engine,
        begin("alice", "request-2", "d1"),
        || Err("not valid".to_owned()),
        |_| unreachable!("a refused validation applies nothing"),
    );
    assert!(matches!(unchecked, Err(MutationError::Refused(reason)) if reason == "not valid"));
    let unknown = run_checked_on::<String, String>(
        &engine,
        begin("alice", "request-3", "d1"),
        || Ok(()),
        |applying| {
            grant(applying, "read")?;
            Err(Failure::Indeterminate(
                "the write may have landed".to_owned(),
            ))
        },
    );
    assert!(
        matches!(unknown, Err(MutationError::Indeterminate(_))),
        "{unknown:?}"
    );
    assert_eq!(count(database, "SELECT count(*) FROM grants"), 0);
    assert_eq!(
        count(database, "SELECT count(*) FROM permguard_mutations"),
        1
    );

    // The id of the refused request is free: the same request applies anew.
    let again = run_checked_on(
        &engine,
        begin("alice", "request-1", "d1"),
        || Ok::<(), String>(()),
        |applying| grant(applying, "read"),
    )
    .expect("applied anew");
    assert_eq!(again, Outcome::Applied("created read".to_owned()));
}

/// E30: of the instances that apply one request at the same moment, each on connections of its
/// own, one write is kept; every instance is answered that write's answer or told to retry,
/// and a retry learns it.
#[test]
fn instances_that_apply_one_request_together_keep_one_write() {
    let Some(server) = server("instances_that_apply_one_request_together_keep_one_write") else {
        return;
    };
    let scratch = scratch(&server);
    domain(&scratch.database);
    const INSTANCES: usize = 6;
    const ROUNDS: usize = 4;
    let instances: Vec<PostgresMutations> = (0..INSTANCES)
        .map(|_| {
            PostgresMutations::new(
                Database::connect(config(&server, Some(scratch.schema.clone()), 2))
                    .expect("an instance connects"),
            )
        })
        .collect();
    for round in 0..ROUNDS {
        let request = format!("request-{round}");
        let name = format!("grant-{round}");
        let barrier = Barrier::new(INSTANCES);
        let answers: Vec<_> = std::thread::scope(|scope| {
            let running: Vec<_> = instances
                .iter()
                .map(|engine| {
                    let (barrier, request, name) = (&barrier, &request, &name);
                    scope.spawn(move || {
                        barrier.wait();
                        run_checked_on(
                            engine,
                            begin("alice", request, "d1"),
                            || Ok::<(), String>(()),
                            |applying| grant(applying, name),
                        )
                    })
                })
                .collect();
            running
                .into_iter()
                .map(|instance| instance.join().expect("an instance finished"))
                .collect()
        });
        assert_eq!(
            count(
                &scratch.database,
                &format!("SELECT count(*) FROM grants WHERE name = '{name}'")
            ),
            1,
            "round {round}: one write: {answers:?}"
        );
        let expected = format!("created {name}");
        let mut applied = 0;
        for answer in &answers {
            match answer {
                Ok(Outcome::Applied(value)) => {
                    assert_eq!(value, &expected);
                    applied += 1;
                }
                Ok(Outcome::Replayed(value)) => assert_eq!(value, &expected),
                // Kept nothing, and says so: the caller's retry is answered below.
                Err(MutationError::Unavailable(_)) => {}
                other => panic!("round {round}: an instance answered {other:?}"),
            }
        }
        assert_eq!(
            applied, 1,
            "round {round}: one instance applied: {answers:?}"
        );
        for engine in &instances {
            assert_eq!(
                replayed_on::<String, String>(engine, &begin("alice", &request, "d1"))
                    .expect("answered"),
                Some(Outcome::Replayed(expected.clone()))
            );
        }
    }
    assert_eq!(
        count(
            &scratch.database,
            "SELECT count(*) FROM permguard_mutations WHERE state = 'applied'"
        ),
        ROUNDS as i64
    );
}

/// A mutation asked from a thread that drives asynchronous tasks, with a domain write that
/// could not be sent to another thread, is run where it was asked.
#[test]
fn a_mutation_runs_from_inside_a_runtime_on_the_callers_thread() {
    let Some(server) = server("a_mutation_runs_from_inside_a_runtime_on_the_callers_thread") else {
        return;
    };
    let scratch = scratch(&server);
    domain(&scratch.database);
    let engine = PostgresMutations::new(Database::clone(&scratch.database));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    // Not `Send`: the write stays on the thread that asked.
    let seen = std::rc::Rc::new(std::cell::Cell::new(0));
    let answer = runtime.block_on(async {
        run_checked_on(
            &engine,
            begin("alice", "request-1", "d1"),
            || Ok::<(), String>(()),
            |applying| {
                seen.set(seen.get() + 1);
                grant(applying, "read")
            },
        )
    });
    assert_eq!(
        answer.expect("applied"),
        Outcome::Applied("created read".to_owned())
    );
    assert_eq!(seen.get(), 1);
    assert!(
        engine
            .recover(&NoDomain)
            .expect("nothing to recover")
            .reconciled
            .is_empty()
    );
}

struct NoDomain;

impl permguard_host::operations::mutation::Domain for NoDomain {
    fn name(&self) -> &'static str {
        "grants"
    }

    fn observe(
        &self,
        _operation_id: &permguard_host::operations::journal::OperationId,
        _target: Option<&str>,
    ) -> Result<Option<permguard_host::operations::mutation::Observed>, String> {
        Ok(None)
    }
}

const CHILD_SCHEMA: &str = "PERMGUARD_TEST_POSTGRES_CHILD_SCHEMA";

/// The kill test's child: dies inside the domain write of a mutation.
#[test]
#[ignore = "the kill test's child, run by `a_process_killed_inside_a_mutation_leaves_nothing`"]
fn child_dies_inside_a_mutation() {
    let (Ok(schema), Some(server)) = (
        std::env::var(CHILD_SCHEMA),
        server("child_dies_inside_a_mutation"),
    ) else {
        return;
    };
    let engine = PostgresMutations::new(
        Database::connect(config(&server, Some(schema), 1)).expect("connected"),
    );
    let _ = run_checked_on::<String, String>(
        &engine,
        begin("alice", "request-1", "d1"),
        || Ok(()),
        |applying| {
            grant(applying, "read")?;
            std::process::abort();
        },
    );
}

/// E30: a process killed inside a mutation leaves no write, no operation, no audit row and no
/// hold: the same request applies at once on another instance.
#[test]
fn a_process_killed_inside_a_mutation_leaves_nothing() {
    let Some(server) = server("a_process_killed_inside_a_mutation_leaves_nothing") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    domain(database);
    let status = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--ignored",
            "--exact",
            "child_dies_inside_a_mutation",
            "--nocapture",
        ])
        .env(CHILD_SCHEMA, &scratch.schema)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("the child runs");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            status.signal(),
            Some(6),
            "the child aborted inside its domain write"
        );
    }
    assert!(!status.success());
    assert_eq!(
        count(
            database,
            "SELECT (SELECT count(*) FROM grants) + (SELECT count(*) FROM permguard_mutations)
                  + (SELECT count(*) FROM permguard_mutation_audit)"
        ),
        0,
        "nothing of the killed mutation is kept"
    );
    let engine = PostgresMutations::new(Database::clone(database));
    let applied = run_checked_on(
        &engine,
        begin("alice", "request-1", "d1"),
        || Ok::<(), String>(()),
        |applying| grant(applying, "read"),
    )
    .expect("the same request applies on another instance");
    assert_eq!(applied, Outcome::Applied("created read".to_owned()));
}
