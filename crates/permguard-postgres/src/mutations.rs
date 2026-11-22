// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The mutation engine on PostgreSQL (iteration 03, decisions E23 to E25): a security mutation
//! is one `SERIALIZABLE` transaction.
//!
//! ```text
//! BEGIN
//!   the answer a retry learns, when the request id was applied inside the window
//!   the caller's validation
//!   the operation's row, and its audit row `intent`
//!   the domain write, inside this transaction: the token carries it
//!   the revision and the answer in the operation's row, and its audit row `applied`
//! COMMIT
//! ```
//!
//! The change, its record, its audit rows and its idempotency key are kept together or not at
//! all, so nothing is left open and there is nothing to recover: the three answers of the file
//! engine's recovery are the file engine's alone. A domain write that refuses is undone and the
//! operation is kept as `failed`, with its audit row, as the file engine keeps it.
//!
//! A transaction the database could not serialize kept nothing and is answered unavailable:
//! the domain write is run once, so the caller's retry, with the same request id, runs it again.
//! Two instances that apply one request id at the same moment cannot both commit: the second
//! finds the first's row, and is answered what the first was.
//!
//! The audit rows are the operation's audit record on this backend; sealing them to the trail's
//! objects is the audit engine's, with its own implementation here.

use std::time::Duration;

use permguard_host::operations::journal::{Initiator, OperationId};
use permguard_host::operations::mutation::{
    AppliedBytes, Applying, Begin, Declined, Domain, Ended, Engine, Recovered, Stopped, Subsystem,
};
use postgres::error::SqlState;

use crate::database::{Database, SqlError, Unit, again};

/// How long an applied answer is kept for a retry: the file engine's window.
pub const WINDOW: Duration = permguard_host::operations::mutation::WINDOW;

/// The point the transaction goes back to when the domain write refuses.
const BEFORE_THE_WRITE: &str = "before_the_domain_write";

/// The mutation engine of one database.
#[derive(Debug, Clone)]
pub struct PostgresMutations {
    database: Database,
}

fn unavailable(error: impl std::fmt::Display) -> Stopped {
    Stopped::Unavailable(error.to_string())
}

fn kind(initiator: &Initiator) -> (&'static str, &str) {
    match initiator {
        Initiator::Principal(name) => ("principal", name),
        Initiator::System(name) => ("system", name),
    }
}

/// The key a retry is recognized by: only a principal's request is one a caller may retry.
fn key(begin: &Begin) -> Option<(&str, &str, &str)> {
    match (&begin.initiator, &begin.request) {
        (Initiator::Principal(principal), Some(request)) => {
            Some((principal, &request.request_id, &request.digest))
        }
        _ => None,
    }
}

/// The answer a retry of `begin` learns in `unit`, when its request id was applied inside the
/// window; the same id under another request is refused.
fn lookup(unit: &Unit, begin: &Begin) -> Result<Option<Ended>, Stopped> {
    let Some((principal, request_id, digest)) = key(begin) else {
        return Ok(None);
    };
    let held = unit
        .query_opt(
            "SELECT operation_id, operation, request_digest, revision, result, target
             FROM permguard_mutations
             WHERE initiator_kind = 'principal' AND initiator = $1 AND request_id = $2
               AND state = 'applied' AND at > now() - make_interval(secs => $3)",
            &[&principal, &request_id, &WINDOW.as_secs_f64()],
        )
        .map_err(unavailable)?;
    let Some(row) = held else {
        return Ok(None);
    };
    let (operation, held_digest): (String, String) = (row.get(1), row.get(2));
    if operation != begin.operation || held_digest != digest {
        return Err(Stopped::RequestIdReused(
            "this request id was already used for a different mutation inside the replay window",
        ));
    }
    let result: Option<Vec<u8>> = row.get(4);
    match result {
        Some(bytes) => Ok(Some(Ended::Replayed(bytes))),
        None => {
            let id: Vec<u8> = row.get(0);
            let id: [u8; 16] = id
                .try_into()
                .map_err(|_| unavailable("an operation id that is not 16 bytes"))?;
            let revision: Option<i64> = row.get(3);
            Ok(Some(Ended::Reconciled {
                operation_id: OperationId::from_bytes(id),
                revision: revision
                    .and_then(|revision| u64::try_from(revision).ok())
                    .unwrap_or(0),
                target: row.get(5),
            }))
        }
    }
}

fn audit(
    unit: &Unit,
    begin: &Begin,
    operation_id: &OperationId,
    phase: &str,
    target: Option<&str>,
) -> Result<(), SqlError> {
    let (subject_kind, subject) = kind(&begin.initiator);
    unit.execute(
        "INSERT INTO permguard_mutation_audit
             (operation_id, phase, action, subject_kind, subject, target)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &operation_id.as_bytes().as_slice(),
            &phase,
            &begin.action,
            &subject_kind,
            &subject,
            &target,
        ],
    )?;
    Ok(())
}

impl PostgresMutations {
    /// The engine of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    /// One attempt at the whole operation, in one transaction.
    fn attempt(
        &self,
        begin: &Begin,
        check: &mut dyn FnMut() -> bool,
        apply: &mut dyn FnMut(&Applying<'_>) -> Result<AppliedBytes, Declined>,
    ) -> Result<Ended, Attempted> {
        let unit = self.database.begin().map_err(unavailable)?;
        if let Some(answer) = lookup(&unit, begin)? {
            return Ok(answer);
        }
        // From here to the commit this thread is inside the operation's unit of work: what a
        // store of this database reads or changes on it, it reads and changes in the operation.
        let _inside = self.database.enter(&unit);
        if !check() {
            return Err(Stopped::Unchecked.into());
        }
        let operation_id = OperationId::mint()
            .ok_or_else(|| unavailable("the OS random source refused an operation id"))?;
        let (initiator_kind, initiator) = kind(&begin.initiator);
        let (request_id, digest) = match key(begin) {
            Some((_, request_id, digest)) => (Some(request_id), Some(digest)),
            None => (None, None),
        };
        // A request id applied before the window, by this principal, is free again: its row
        // keeps the operation and gives the id back.
        if let Some(request_id) = request_id {
            unit.execute(
                "UPDATE permguard_mutations SET request_id = NULL, request_digest = NULL
                 WHERE initiator_kind = 'principal' AND initiator = $1 AND request_id = $2
                   AND state = 'applied' AND at <= now() - make_interval(secs => $3)",
                &[&initiator, &request_id, &WINDOW.as_secs_f64()],
            )?;
        }
        unit.execute(
            "INSERT INTO permguard_mutations
                 (operation_id, domain, operation, action, initiator_kind, initiator,
                  request_id, request_digest, target, state)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'applied')",
            &[
                &operation_id.as_bytes().as_slice(),
                &begin.domain,
                &begin.operation,
                &begin.action,
                &initiator_kind,
                &initiator,
                &request_id,
                &digest,
                &begin.target,
            ],
        )?;
        audit(
            &unit,
            begin,
            &operation_id,
            "intent",
            begin.target.as_deref(),
        )?;
        unit.mark(BEFORE_THE_WRITE)?;

        let applied = match apply(&Applying::within(operation_id, unit.as_ref())) {
            Ok(applied) => applied,
            Err(Declined::Refused) => {
                // The write is undone and the operation kept as failed, with its record.
                unit.back_to(BEFORE_THE_WRITE)?;
                unit.execute(
                    "UPDATE permguard_mutations
                     SET state = 'failed', request_id = NULL, request_digest = NULL
                     WHERE operation_id = $1",
                    &[&operation_id.as_bytes().as_slice()],
                )?;
                audit(
                    &unit,
                    begin,
                    &operation_id,
                    "failed",
                    begin.target.as_deref(),
                )?;
                unit.commit()?;
                return Err(Stopped::Refused.into());
            }
            // The transaction is dropped: nothing of the write is kept, whatever it reached.
            Err(Declined::Indeterminate) => return Err(Stopped::Indeterminate.into()),
        };
        let revision = i64::try_from(applied.revision)
            .map_err(|_| unavailable("a revision past the range the database keeps"))?;
        unit.execute(
            "UPDATE permguard_mutations SET revision = $2, result = $3, target = $4
             WHERE operation_id = $1",
            &[
                &operation_id.as_bytes().as_slice(),
                &revision,
                &applied.result,
                &applied.target.as_deref().or(begin.target.as_deref()),
            ],
        )?;
        audit(
            &unit,
            begin,
            &operation_id,
            "applied",
            applied.target.as_deref().or(begin.target.as_deref()),
        )?;
        unit.commit()?;
        Ok(Ended::Applied)
    }
}

/// Why an attempt did not end: what the caller is told, or the database's failure to read.
enum Attempted {
    Stopped(Stopped),
    Sql(SqlError),
}

impl From<Stopped> for Attempted {
    fn from(stopped: Stopped) -> Self {
        Self::Stopped(stopped)
    }
}

impl From<SqlError> for Attempted {
    fn from(error: SqlError) -> Self {
        Self::Sql(error)
    }
}

impl Engine for PostgresMutations {
    fn run_bytes(
        &self,
        begin: Begin,
        check: &mut dyn FnMut() -> bool,
        apply: &mut dyn FnMut(&Applying<'_>) -> Result<AppliedBytes, Declined>,
    ) -> Result<Ended, Stopped> {
        let ended = match self.attempt(&begin, check, apply) {
            Ok(ended) => Ok(ended),
            Err(Attempted::Stopped(stopped)) => Err(stopped),
            // The same request id, applied by another instance while this one was applying:
            // nothing of this attempt is kept, and the first's answer is this one's.
            Err(Attempted::Sql(error)) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                let unit = self.database.begin().map_err(unavailable)?;
                match lookup(&unit, &begin)? {
                    Some(answer) => Ok(answer),
                    None => Err(unavailable(error)),
                }
            }
            Err(Attempted::Sql(error)) if again(&error) => {
                self.database.retried();
                Err(Stopped::Unavailable(format!(
                    "the mutation could not be serialized with another and kept nothing: {error}"
                )))
            }
            Err(Attempted::Sql(error)) => Err(unavailable(error)),
        };
        self.database.ended(match &ended {
            Ok(_) => "committed",
            Err(Stopped::Unchecked | Stopped::Refused) => "refused",
            Err(_) => "failed",
        });
        ended
    }

    fn replayed_bytes(&self, begin: &Begin) -> Result<Option<Ended>, Stopped> {
        let unit = self.database.begin().map_err(unavailable)?;
        lookup(&unit, begin)
    }

    /// Nothing is left open by a transaction: there is nothing to resolve.
    fn recover(&self, _domain: &dyn Domain) -> Result<Recovered, String> {
        Ok(Recovered::default())
    }

    fn subsystem(&self, name: &str) -> Subsystem {
        crate::gate::PostgresGate::subsystem(self.database.clone(), name)
    }
}
