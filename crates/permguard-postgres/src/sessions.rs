// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The open task sessions of every instance (iteration 03, WP-28.4): a row a session, so a member
//! connected to one instance and another incarnation of it arriving at another meet in the clone
//! alarm, and a task's signed concurrency counts the sessions of every instance.
//!
//! The rows of one membership are changed under a scope of their own, at `READ COMMITTED`: an
//! open reads the sessions the ones before it committed, and of two incarnations that open
//! together one is opened and the other meets it. A row closes with its session; one a stopped
//! instance left goes past its lease, and is removed by the next open of its membership.

use permguard_host::membership::task::{Live, SessionStore, Unopened};

use crate::database::{Database, Failure, Unit};

fn number(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn boot(bytes: &[u8]) -> [u8; 16] {
    <[u8; 16]>::try_from(bytes).unwrap_or([0; 16])
}

/// The open sessions kept in one database.
#[derive(Debug, Clone)]
pub struct PostgresSessions {
    database: Database,
}

impl PostgresSessions {
    /// The sessions kept in `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn scope(membership_id: &[u8; 16]) -> String {
        let hex: String = membership_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("task-sessions/{hex}")
    }
}

fn held(unit: &Unit, membership_id: &[u8; 16], now: u64) -> Result<Vec<Live>, crate::SqlError> {
    Ok(unit
        .query(
            "SELECT task_id, epoch, member_boot_id, coordinator_boot_id, opened_at, expires_at
             FROM permguard_task_sessions WHERE membership = $1 AND expires_at > $2",
            &[&membership_id.as_slice(), &number(now)],
        )?
        .into_iter()
        .map(|row| Live {
            task_id: row.get(0),
            epoch: u64::try_from(row.get::<_, i64>(1)).unwrap_or(0),
            member_boot_id: boot(&row.get::<_, Vec<u8>>(2)),
            coordinator_boot_id: boot(&row.get::<_, Vec<u8>>(3)),
            opened_at: u64::try_from(row.get::<_, i64>(4)).unwrap_or(0),
            expires_at: u64::try_from(row.get::<_, i64>(5)).unwrap_or(0),
        })
        .collect())
}

impl SessionStore for PostgresSessions {
    fn open(
        &self,
        membership_id: &[u8; 16],
        live: &Live,
        now: u64,
        max_concurrency: u64,
    ) -> Result<String, Unopened> {
        self.database
            .under_scope(&Self::scope(membership_id), |unit| {
                unit.execute(
                    "DELETE FROM permguard_task_sessions WHERE membership = $1 AND expires_at <= $2",
                    &[&membership_id.as_slice(), &number(now)],
                )?;
                let open = held(unit, membership_id, now)?;
                if let Some(other) = open
                    .iter()
                    .find(|other| other.member_boot_id != live.member_boot_id)
                {
                    return Err(Failure::Refused(Unopened::Clone(other.clone())));
                }
                let running = open
                    .iter()
                    .filter(|other| other.task_id == live.task_id)
                    .count();
                if u64::try_from(running).unwrap_or(u64::MAX) >= max_concurrency {
                    return Err(Failure::Refused(Unopened::Busy));
                }
                let key: String = unit
                    .query_one(
                        "INSERT INTO permguard_task_sessions
                             (membership, session, task_id, epoch, member_boot_id,
                              coordinator_boot_id, opened_at, expires_at)
                         VALUES ($1, gen_random_uuid()::text, $2, $3, $4, $5, $6, $7)
                         RETURNING session",
                        &[
                            &membership_id.as_slice(),
                            &live.task_id,
                        &number(live.epoch),
                        &live.member_boot_id.as_slice(),
                        &live.coordinator_boot_id.as_slice(),
                            &number(live.opened_at),
                            &number(live.expires_at),
                        ],
                    )?
                    .get(0);
                Ok(key)
            })
            .map_err(|error| Unopened::Unavailable(error.to_string()))?
    }

    fn close(&self, membership_id: &[u8; 16], key: &str) {
        // A row that could not be removed goes past its lease, and the next open removes it.
        let _ = self.database.write(|unit| {
            unit.execute(
                "DELETE FROM permguard_task_sessions WHERE membership = $1 AND session = $2",
                &[&membership_id.as_slice(), &key],
            )
            .map(|_| ())
        });
    }

    fn set_epoch(&self, membership_id: &[u8; 16], key: &str, epoch: u64) {
        let _ = self.database.write(|unit| {
            unit.execute(
                "UPDATE permguard_task_sessions SET epoch = $3
                 WHERE membership = $1 AND session = $2",
                &[&membership_id.as_slice(), &key, &number(epoch)],
            )
            .map(|_| ())
        });
    }

    fn of(&self, membership_id: &[u8; 16], now: u64) -> Vec<Live> {
        self.database
            .write(|unit| held(unit, membership_id, now))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::testing::{Cases, server};

    fn live(task: &str, boot: u8) -> Live {
        Live {
            task_id: task.to_owned(),
            epoch: 1,
            member_boot_id: [boot; 16],
            coordinator_boot_id: [9; 16],
            opened_at: 100,
            expires_at: 200,
        }
    }

    /// Two instances over one database: a session one opens is seen by the other, another
    /// incarnation of its member meets it on either, a task's concurrency counts both, and a
    /// session closed, or past its lease, is gone for both.
    #[test]
    fn the_open_sessions_are_every_instances_on_postgresql() {
        let Some(server) = server("the_open_sessions_are_every_instances_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        let (one, other) = (
            PostgresSessions::new(database.clone()),
            PostgresSessions::new(database.clone()),
        );
        let membership = [1_u8; 16];
        let first = one
            .open(&membership, &live("decisions", 1), 100, 2)
            .expect("opened");
        assert_eq!(other.of(&membership, 100), vec![live("decisions", 1)]);
        // Another incarnation, at the other instance: the clone alarm's case.
        assert_eq!(
            other.open(&membership, &live("decisions", 2), 100, 2),
            Err(Unopened::Clone(live("decisions", 1)))
        );
        // The same incarnation: a second session, then the task's concurrency.
        let second = other
            .open(&membership, &live("decisions", 1), 100, 2)
            .expect("opened");
        assert_eq!(
            one.open(&membership, &live("decisions", 1), 100, 2),
            Err(Unopened::Busy)
        );
        other.set_epoch(&membership, &second, 2);
        assert!(
            one.of(&membership, 100)
                .iter()
                .any(|session| session.epoch == 2)
        );
        one.close(&membership, &first);
        other.close(&membership, &second);
        assert!(one.of(&membership, 100).is_empty());
        // A session a stopped instance left goes past its lease.
        one.open(&membership, &live("decisions", 1), 100, 2)
            .expect("opened");
        assert!(other.of(&membership, 200).is_empty());
        other
            .open(&membership, &live("decisions", 2), 200, 2)
            .expect("the incarnation before is gone past its lease");
    }
}
