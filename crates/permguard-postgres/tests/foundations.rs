// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The foundations against a real PostgreSQL: the schema, the unit of work, the leases, and the
//! first store contract's conformance suite on this backend.
//!
//! The tests need a server and say where it is with `PERMGUARD_TEST_POSTGRES`, a connection
//! string such as `host=127.0.0.1 port=5432 user=permguard password=… dbname=permguard`;
//! `scripts/test-postgres.sh` starts a disposable one and runs them. Without the variable each
//! test says it was skipped and passes: a build with no database at hand stays green, and the
//! pipeline that has one runs them. Every test works in a schema of its own and drops it.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use permguard_postgres::lease::{self, Lost};
use permguard_postgres::time::PostgresClockMark;
use permguard_postgres::{Config, Database, DbError, Failure, Tls, schema};

use permguard_postgres::testing::{config, scratch, scratch_with, server};

/// E29: a fresh database is brought to this build's schema; a second migration finds nothing to
/// do; instances that start together apply once; a schema newer than the build refuses, and
/// changes nothing.
#[test]
fn the_schema_is_applied_once_and_a_newer_one_is_refused() {
    let Some(server) = server("the_schema_is_applied_once_and_a_newer_one_is_refused") else {
        return;
    };
    let scratch = scratch_with(&server, 8, false);
    let database = &scratch.database;
    let barrier = Barrier::new(6);
    std::thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                barrier.wait();
                assert_eq!(
                    schema::migrate(database).expect("migrated"),
                    schema::known()
                );
            });
        }
    });
    let applied: i64 = database
        .write(|transaction| {
            Ok(transaction
                .query_one("SELECT count(*) FROM permguard_schema", &[])?
                .get(0))
        })
        .expect("read");
    assert_eq!(applied, i64::from(schema::known()), "each migration once");

    let newer = schema::known() + 1;
    database
        .write(|transaction| {
            transaction.execute(
                "INSERT INTO permguard_schema (version, name) VALUES ($1, 'from a later build')",
                &[&newer],
            )
        })
        .expect("a later build's migration");
    match schema::migrate(database) {
        Err(DbError::SchemaNewer { found, known }) => {
            assert_eq!((found, known), (newer, schema::known()));
        }
        other => panic!("a newer schema answered {other:?}"),
    }
}

/// E25: of the units of work that read one row and write what they read plus one, none is lost:
/// the ones the database could not serialize are run again, and the row counts them all.
#[test]
fn units_of_work_that_read_then_write_lose_no_update() {
    let Some(server) = server("units_of_work_that_read_then_write_lose_no_update") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    database
        .write(|transaction| {
            transaction.batch_execute(
                "CREATE TABLE counter (id integer PRIMARY KEY, value bigint NOT NULL);
                 INSERT INTO counter VALUES (1, 0)",
            )
        })
        .expect("a counter");
    const THREADS: usize = 8;
    const EACH: usize = 10;
    let barrier = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..EACH {
                    database
                        .write(|transaction| {
                            let value: i64 = transaction
                                .query_one("SELECT value FROM counter WHERE id = 1", &[])?
                                .get(0);
                            transaction.execute(
                                "UPDATE counter SET value = $1 WHERE id = 1",
                                &[&(value + 1)],
                            )
                        })
                        .expect("counted");
                }
            });
        }
    });
    let value: i64 = database
        .write(|transaction| {
            Ok(transaction
                .query_one("SELECT value FROM counter WHERE id = 1", &[])?
                .get(0))
        })
        .expect("read");
    assert_eq!(value, (THREADS * EACH) as i64);
}

/// A refusal of the work rolls its transaction back: nothing it wrote is kept.
#[test]
fn a_refused_unit_of_work_changes_nothing() {
    let Some(server) = server("a_refused_unit_of_work_changes_nothing") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    let refused = database
        .transaction::<(), &str>(|transaction| {
            transaction.execute(
                "INSERT INTO permguard_clock_marks (scope, mark) VALUES ('refused', 7)",
                &[],
            )?;
            Err(Failure::Refused("not this time"))
        })
        .expect("the database answered");
    assert_eq!(refused, Err("not this time"));
    let kept: i64 = database
        .write(|transaction| {
            Ok(transaction
                .query_one("SELECT count(*) FROM permguard_clock_marks", &[])?
                .get(0))
        })
        .expect("read");
    assert_eq!(kept, 0);
}

/// A unit of work one of whose statements failed is never said committed, even when the work
/// went on and answered as if nothing had happened: the database undoes such a transaction at
/// its `COMMIT` without a word, and the unit says what the statement was answered instead.
#[test]
fn a_unit_whose_statement_failed_is_not_committed() {
    let Some(server) = server("a_unit_whose_statement_failed_is_not_committed") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    database
        .write(|unit| {
            unit.execute(
                "INSERT INTO permguard_clock_marks (scope, mark) VALUES ('held', 1)",
                &[],
            )
        })
        .expect("a row");
    let answered = database.write(|unit| {
        unit.execute(
            "INSERT INTO permguard_clock_marks (scope, mark) VALUES ('beside', 2)",
            &[],
        )?;
        // The same key again: refused, and the work goes on as if it had not been.
        let _ = unit.execute(
            "INSERT INTO permguard_clock_marks (scope, mark) VALUES ('held', 3)",
            &[],
        );
        Ok(())
    });
    assert!(
        matches!(answered, Err(DbError::Unavailable(_))),
        "{answered:?}"
    );
    let kept: i64 = database
        .write(|unit| {
            Ok(unit
                .query_one("SELECT count(*) FROM permguard_clock_marks", &[])?
                .get(0))
        })
        .expect("read");
    assert_eq!(kept, 1, "nothing of the failed unit is kept");
}

/// A scope is held by one transaction at a time, to the transaction's end.
#[test]
fn a_scope_is_held_by_one_transaction_at_a_time() {
    let Some(server) = server("a_scope_is_held_by_one_transaction_at_a_time") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    let inside = AtomicUsize::new(0);
    let most = AtomicUsize::new(0);
    let barrier = Barrier::new(6);
    std::thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                barrier.wait();
                database
                    .under_scope::<(), ()>("one at a time", |_| {
                        let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        inside.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .expect("the database answered")
                    .expect("held and released");
            });
        }
    });
    assert_eq!(most.load(Ordering::SeqCst), 1);
}

/// A lease is one holder's until it expires or is released; each new holding is a new
/// generation; a write under a lease that was lost is refused in its own transaction (E27).
#[test]
fn a_lease_has_one_holder_and_a_lost_one_writes_nothing() {
    let Some(server) = server("a_lease_has_one_holder_and_a_lost_one_writes_nothing") else {
        return;
    };
    let scratch = scratch(&server);
    let database = &scratch.database;
    let long = Duration::from_secs(60);

    // Of the instances that ask together, one is given the lease.
    let barrier = Barrier::new(6);
    let given: Vec<_> = std::thread::scope(|scope| {
        let askers: Vec<_> = (0..6)
            .map(|asker| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    lease::acquire(
                        database,
                        "ring.maintenance",
                        &format!("instance-{asker}"),
                        long,
                    )
                    .expect("answered")
                })
            })
            .collect();
        askers
            .into_iter()
            .filter_map(|asker| asker.join().expect("an asker finished"))
            .collect()
    });
    assert_eq!(given.len(), 1, "{given:?}");
    let first = given[0].clone();
    assert_eq!(first.generation, 1);

    // The holder asking again keeps its holding; another is refused while it holds.
    assert_eq!(
        lease::acquire(database, "ring.maintenance", &first.holder, long).expect("answered"),
        Some(first.clone())
    );
    assert_eq!(
        lease::acquire(database, "ring.maintenance", "another", long).expect("answered"),
        None
    );
    assert_eq!(
        lease::renew(database, &first, long).expect("answered"),
        Ok(())
    );

    // A write under the lease commits while the lease is held.
    let write = |held: &lease::Lease, mark: i64| {
        database
            .transaction::<(), Lost>(|transaction| {
                lease::held(transaction, held, Lost)?;
                transaction.execute(
                    "INSERT INTO permguard_clock_marks (scope, mark) VALUES ('leased', $1)
                     ON CONFLICT (scope) DO UPDATE SET mark = EXCLUDED.mark",
                    &[&mark],
                )?;
                Ok(())
            })
            .expect("the database answered")
    };
    assert_eq!(write(&first, 1), Ok(()));

    // Released, it is another's at the next generation, and the first holder writes nothing.
    lease::release(database, &first).expect("released");
    let second = lease::acquire(database, "ring.maintenance", "another", long)
        .expect("answered")
        .expect("free once released");
    assert_eq!(second.generation, 2);
    assert_eq!(write(&first, 2), Err(Lost), "a lost lease writes nothing");
    assert_eq!(
        lease::renew(database, &first, long).expect("answered"),
        Err(Lost)
    );
    assert_eq!(write(&second, 3), Ok(()));

    // An expired lease is taken without a release.
    let short = lease::acquire(
        database,
        "audit.sweep",
        "instance-a",
        Duration::from_millis(50),
    )
    .expect("answered")
    .expect("free");
    std::thread::sleep(Duration::from_millis(120));
    let taken = lease::acquire(database, "audit.sweep", "instance-b", long)
        .expect("answered")
        .expect("expired");
    assert_eq!((short.generation, taken.generation), (1, 2));
    let mark: i64 = database
        .write(|transaction| {
            Ok(transaction
                .query_one(
                    "SELECT mark FROM permguard_clock_marks WHERE scope = 'leased'",
                    &[],
                )?
                .get(0))
        })
        .expect("read");
    assert_eq!(mark, 3);
}

/// The first store contract on this backend passes the suite the file backend passes, each case
/// on a mark of its own, and two instances over one database share the mark.
#[test]
fn the_clock_mark_keeps_its_contract_on_postgresql() {
    let Some(server) = server("the_clock_mark_keeps_its_contract_on_postgresql") else {
        return;
    };
    let scratch = scratch(&server);
    let made = AtomicUsize::new(0);
    permguard_host::time::suite::run(&|| {
        let case = made.fetch_add(1, Ordering::Relaxed);
        Arc::new(PostgresClockMark::new(
            Arc::clone(&scratch.database),
            format!("suite-{case}"),
        ))
    });

    use permguard_host::time::ClockMark as _;
    let other = Arc::new(
        Database::connect(config(&server, Some(scratch.schema.clone()), 2)).expect("connected"),
    );
    let (one, two) = (
        PostgresClockMark::new(Arc::clone(&scratch.database), "host"),
        PostgresClockMark::new(other, "host"),
    );
    one.raise(1_800_000_100).expect("raised");
    two.raise(1_800_000_050)
        .expect("a lower mark from another instance");
    assert_eq!(two.read().expect("read"), Some(1_800_000_100));
}

/// A unit of work asked from a thread that drives asynchronous tasks is run, as a store
/// contract called from a request handler is.
#[test]
fn a_unit_of_work_runs_from_inside_a_runtime() {
    let Some(server) = server("a_unit_of_work_runs_from_inside_a_runtime") else {
        return;
    };
    let scratch = scratch(&server);
    let database = Arc::clone(&scratch.database);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let one: i32 = runtime.block_on(async move {
        database
            .write(|transaction| Ok(transaction.query_one("SELECT 1", &[])?.get(0)))
            .expect("answered")
    });
    assert_eq!(one, 1);
}

const CHILD_SCHEMA: &str = "PERMGUARD_TEST_POSTGRES_CHILD_SCHEMA";

/// The kill test's child: writes inside a unit of work and dies before the work ends.
#[test]
#[ignore = "the kill test's child, run by `a_process_killed_inside_a_unit_of_work_leaves_nothing`"]
fn child_dies_inside_a_unit_of_work() {
    let (Ok(schema), Some(server)) = (
        std::env::var(CHILD_SCHEMA),
        server("child_dies_inside_a_unit_of_work"),
    ) else {
        return;
    };
    let database = Database::connect(config(&server, Some(schema), 1)).expect("connected");
    let _ = database.write(|transaction| {
        transaction.execute(
            "INSERT INTO permguard_clock_marks (scope, mark) VALUES ('killed', 7)",
            &[],
        )?;
        // The lease row is taken too, so the parent proves no hold outlives the process.
        transaction.execute(
            "INSERT INTO permguard_leases (name, holder, generation, expires_at)
             VALUES ('killed', 'child', 1, now() + interval '1 hour')",
            &[],
        )?;
        std::process::abort();
        #[allow(unreachable_code)]
        Ok(())
    });
}

/// E30: a process killed in the middle of a unit of work leaves nothing of it: no row, and no
/// hold on what it touched, so the next instance does the same work at once.
#[test]
fn a_process_killed_inside_a_unit_of_work_leaves_nothing() {
    let Some(server) = server("a_process_killed_inside_a_unit_of_work_leaves_nothing") else {
        return;
    };
    let scratch = scratch(&server);
    let status = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--ignored",
            "--exact",
            "child_dies_inside_a_unit_of_work",
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
            "the child aborted inside its unit of work"
        );
    }
    assert!(!status.success(), "the child died inside its unit of work");

    let database = &scratch.database;
    let kept: i64 = database
        .write(|transaction| {
            Ok(transaction
                .query_one(
                    "SELECT (SELECT count(*) FROM permguard_clock_marks)
                          + (SELECT count(*) FROM permguard_leases)",
                    &[],
                )?
                .get(0))
        })
        .expect("read");
    assert_eq!(kept, 0, "nothing of the killed work is kept");
    // Nothing is held: the same rows are written by the next instance without a wait.
    let taken = lease::acquire(database, "killed", "survivor", Duration::from_secs(60))
        .expect("answered")
        .expect("free");
    assert_eq!(taken.generation, 1);
}

/// The connection is TLS, the server's certificate verified against the roots the configuration
/// names: with them the session is encrypted, and with other roots there is no session at all.
/// `PERMGUARD_TEST_POSTGRES_CA` names the test server's certificate authority.
#[test]
fn a_verified_connection_is_encrypted_and_an_unknown_authority_is_refused() {
    let test = "a_verified_connection_is_encrypted_and_an_unknown_authority_is_refused";
    let Some(server) = server(test) else {
        return;
    };
    let Ok(authority) = std::env::var("PERMGUARD_TEST_POSTGRES_CA") else {
        eprintln!("{test}: skipped, PERMGUARD_TEST_POSTGRES_CA names no certificate authority");
        return;
    };
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;

    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&authority).expect("the authority reads") {
        roots
            .add(certificate.expect("a certificate"))
            .expect("a root");
    }
    let verified = Config {
        tls: Tls::Verified(Arc::new(roots)),
        ..config(&server, None, 1)
    };
    let database = Database::connect(verified.clone()).expect("connected over TLS");
    let encrypted: bool = database
        .write(|transaction| {
            Ok(transaction
                .query_one(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                    &[],
                )?
                .get(0))
        })
        .expect("read");
    assert!(encrypted, "the session is encrypted");

    // Roots that do not hold the server's authority: no session, never one in the clear.
    let stranger = Config {
        tls: Tls::Verified(Arc::new(rustls::RootCertStore::empty())),
        ..verified
    };
    assert!(matches!(
        Database::connect(stranger),
        Err(DbError::Unavailable(_))
    ));
}

/// A database that does not answer is said unavailable, in the time it is waited for.
#[test]
fn a_database_that_does_not_answer_is_unavailable() {
    let unreachable = Config {
        host: "127.0.0.1".to_owned(),
        // The discard port: nothing answers PostgreSQL there.
        port: 9,
        database: "permguard".to_owned(),
        user: "permguard".to_owned(),
        password: None,
        schema: None,
        tls: Tls::Disabled,
        pool: 1,
        wait: Duration::from_secs(2),
    };
    assert!(matches!(
        Database::connect(unreachable),
        Err(DbError::Unavailable(_))
    ));
}
