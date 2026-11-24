// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The single jobs on PostgreSQL (iteration 03, WP-28.2): a job is run by the instance that
//! holds its lease, `job/<name>`, and what it writes on its thread is fenced by that lease
//! (decision E27). The lease is kept to its expiry, one cadence, so of the instances that ask
//! within one cadence one runs the job; its holder asking again at the next extends it.

use std::time::Duration;

use permguard_host::jobs::SingleJobs;

use crate::database::Database;

/// The shortest hold of a job: a cadence shorter than this still holds the job this long.
const SHORTEST: Duration = Duration::from_secs(30);

/// The single jobs of one instance over `database`.
#[derive(Debug, Clone)]
pub struct PostgresJobs {
    database: Database,
    /// This instance, as the leases it holds name it.
    holder: String,
}

impl PostgresJobs {
    /// The jobs of the instance `holder` over `database`, whose schema is this build's.
    pub fn new(database: Database, holder: impl Into<String>) -> Self {
        Self {
            database,
            holder: holder.into(),
        }
    }
}

impl SingleJobs for PostgresJobs {
    fn run(
        &self,
        name: &str,
        every: Duration,
        work: &mut dyn FnMut() -> bool,
    ) -> Result<bool, String> {
        let Some(lease) = crate::lease::acquire(
            &self.database,
            &format!("job/{name}"),
            &self.holder,
            every.max(SHORTEST),
        )
        .map_err(|error| error.to_string())?
        else {
            return Ok(false);
        };
        let fenced = self.database.fenced(lease.clone());
        let done = work();
        drop(fenced);
        if !done {
            // A holder whose work failed gives the job up: another instance takes it at its next
            // turn, rather than wait for one that keeps failing.
            crate::lease::release(&self.database, &lease).map_err(|error| error.to_string())?;
        }
        Ok(true)
    }

    fn shared(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::database::DbError;
    use crate::testing::{Cases, server};

    /// Of the instances that ask for one job together, one runs it; while it holds the job the
    /// others do not, and its holder asking again does.
    #[test]
    fn one_instance_runs_a_job_a_cadence_on_postgresql() {
        let Some(server) = server("one_instance_runs_a_job_a_cadence_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        const INSTANCES: usize = 6;
        let instances: Vec<PostgresJobs> = (0..INSTANCES)
            .map(|n| PostgresJobs::new(database.clone(), format!("instance-{n}")))
            .collect();
        let (ran, together) = (AtomicUsize::new(0), Barrier::new(INSTANCES));
        let winners: Vec<usize> = std::thread::scope(|scope| {
            let asking: Vec<_> = instances
                .iter()
                .enumerate()
                .map(|(n, jobs)| {
                    let (ran, together) = (&ran, &together);
                    scope.spawn(move || {
                        together.wait();
                        let held = jobs
                            .run("ring", Duration::from_secs(60), &mut || {
                                ran.fetch_add(1, Ordering::SeqCst);
                                true
                            })
                            .expect("asked");
                        held.then_some(n)
                    })
                })
                .collect();
            asking
                .into_iter()
                .filter_map(|thread| thread.join().expect("asked"))
                .collect()
        });
        assert_eq!(ran.load(Ordering::SeqCst), 1, "one ran the job");
        assert_eq!(winners.len(), 1);
        let holder = &instances[winners[0]];
        let other = &instances[(winners[0] + 1) % INSTANCES];
        assert!(
            !other
                .run("ring", Duration::from_secs(60), &mut || true)
                .expect("asked"),
            "another instance does not run a job held"
        );
        assert!(
            holder
                .run("ring", Duration::from_secs(60), &mut || true)
                .expect("asked"),
            "its holder runs it again"
        );
        assert!(
            other
                .run("another", Duration::from_secs(60), &mut || true)
                .expect("asked"),
            "each job is held apart"
        );
    }

    /// A holder whose work failed gives the job up: another instance runs it at its next turn,
    /// instead of waiting for the hold of one that keeps failing to expire.
    #[test]
    fn a_holder_whose_work_failed_gives_the_job_up_on_postgresql() {
        let Some(server) = server("a_holder_whose_work_failed_gives_the_job_up_on_postgresql")
        else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        let (failing, other) = (
            PostgresJobs::new(database.clone(), "failing"),
            PostgresJobs::new(database.clone(), "other"),
        );
        let every = Duration::from_secs(3_600);
        assert!(failing.run("sweep", every, &mut || false).expect("asked"));
        let ran = AtomicUsize::new(0);
        assert!(
            other
                .run("sweep", every, &mut || {
                    ran.fetch_add(1, Ordering::SeqCst);
                    true
                })
                .expect("asked"),
            "the job given up is another instance's at once"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        // A holder whose work succeeded keeps it.
        assert!(!failing.run("sweep", every, &mut || true).expect("asked"));
    }

    /// What a job writes on its thread is written only while it holds the job's lease (E27): a
    /// holder whose lease expired and was taken writes nothing, through a unit of its own or one
    /// the mutation engine begins.
    #[test]
    fn a_job_writes_only_while_it_holds_its_lease_on_postgresql() {
        let Some(server) = server("a_job_writes_only_while_it_holds_its_lease_on_postgresql")
        else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        database
            .write(|unit| unit.batch_execute("CREATE TABLE written (n integer NOT NULL)"))
            .expect("a table");
        let write = |n: i32| {
            database.write(|unit| unit.execute("INSERT INTO written (n) VALUES ($1)", &[&n]))
        };
        let lease = crate::lease::acquire(&database, "job/x", "first", Duration::from_secs(1))
            .expect("asked")
            .expect("held");
        let fenced = database.fenced(lease);
        write(1).expect("written while held");
        std::thread::sleep(Duration::from_millis(1_200));
        // Another instance, which runs nothing under the first's lease, takes it over.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    crate::lease::acquire(&database, "job/x", "second", Duration::from_secs(60))
                        .expect("asked")
                        .expect("taken over")
                })
                .join()
                .expect("taken over");
        });
        assert!(matches!(write(2), Err(DbError::Fenced(name)) if name == "job/x"));
        assert!(matches!(database.begin(), Err(DbError::Fenced(_))));
        drop(fenced);
        write(3).expect("written outside the job");
        let held: Vec<i32> = database
            .write(|unit| {
                Ok(unit
                    .query("SELECT n FROM written ORDER BY n", &[])?
                    .into_iter()
                    .map(|row| row.get(0))
                    .collect())
            })
            .expect("read");
        assert_eq!(held, vec![1, 3]);
    }
}
