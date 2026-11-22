// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`ReplayStore`]: a row a plan, `permguard_plans`.
//!
//! | Rule of the contract                                  | Kept by                                    |
//! | ----------------------------------------------------- | ------------------------------------------ |
//! | a plan is consumed once                               | the row's `consumed` column, set once      |
//! | an approval is decided on the plan as it stands       | the read and the write in one transaction  |
//!
//! The results of requests answered before the mutation engine kept them are the file backend's
//! history: this backend never held one, and answers that it holds none. A retry is answered by
//! the mutation engine, from the operation's own row.

use permguard_host::api::replay::{Plan, ReplayError, ReplayStore, Stored, Unapproved};
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::{Applying, Observed};

use crate::database::{Database, DbError, Failure, Unit};

impl From<DbError> for ReplayError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The plans of one database.
#[derive(Debug, Clone)]
pub struct PostgresReplay {
    database: Database,
}

fn decoded(record: &str) -> Result<Plan, ReplayError> {
    serde_json::from_str(record)
        .map_err(|error| ReplayError::Malformed(format!("a plan held does not read: {error}")))
}

fn encoded(plan: &Plan) -> Result<String, ReplayError> {
    serde_json::to_string(plan)
        .map_err(|error| ReplayError::Malformed(format!("a plan does not encode: {error}")))
}

/// The plans `condition` selects, each with whether it was run, in the order of their keys.
fn plans<E: From<ReplayError>>(
    unit: &Unit,
    condition: &str,
    parameters: &[&(dyn postgres::types::ToSql + Sync)],
) -> Result<Vec<(Plan, bool)>, Failure<E>> {
    unit.query(
        &format!(
            "SELECT record, consumed FROM permguard_plans WHERE {condition}
             ORDER BY principal, plan_id"
        ),
        parameters,
    )?
    .into_iter()
    .map(|row| {
        decoded(&row.get::<_, String>(0))
            .map(|plan| (plan, row.get(1)))
            .map_err(|error| Failure::Refused(E::from(error)))
    })
    .collect()
}

impl PostgresReplay {
    /// The plans of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn read<T>(
        &self,
        work: impl Fn(&Unit) -> Result<T, Failure<ReplayError>>,
    ) -> Result<T, ReplayError> {
        self.database.transaction(work)?
    }
}

impl ReplayStore for PostgresReplay {
    fn result(
        &self,
        _principal: &str,
        _request_id: &str,
        _now: u64,
    ) -> Result<Option<Stored>, ReplayError> {
        Ok(None)
    }

    fn held(&self) -> Result<usize, ReplayError> {
        Ok(0)
    }

    fn write_plan(&self, _applying: &Applying<'_>, plan: &Plan) -> Result<(), ReplayError> {
        let record = encoded(plan)?;
        let expires = i64::try_from(plan.expires).unwrap_or(i64::MAX);
        self.read(|unit| {
            unit.execute(
                "INSERT INTO permguard_plans (principal, plan_id, record, expires, consumed)
                 VALUES ($1, $2, $3, $4, false)
                 ON CONFLICT (principal, plan_id) DO UPDATE SET
                     record = EXCLUDED.record, expires = EXCLUDED.expires",
                &[&plan.principal, &plan.plan_id, &record, &expires],
            )?;
            Ok(())
        })
    }

    fn plan(&self, principal: &str, plan_id: &str) -> Result<Option<(Plan, bool)>, ReplayError> {
        self.read(|unit| {
            Ok(plans(
                unit,
                "principal = $1 AND plan_id = $2",
                &[&principal, &plan_id],
            )?
            .pop())
        })
    }

    fn find(&self, plan_id: &str) -> Result<Option<(Plan, bool)>, ReplayError> {
        self.read(|unit| Ok(plans(unit, "plan_id = $1", &[&plan_id])?.into_iter().next()))
    }

    fn plans(&self) -> Result<Vec<(Plan, bool)>, ReplayError> {
        self.read(|unit| plans(unit, "true", &[]))
    }

    fn approve(
        &self,
        _applying: &Applying<'_>,
        plan_id: &str,
        decide: permguard_host::api::replay::Decide<'_>,
    ) -> Result<Option<Plan>, Unapproved> {
        // The plan `decide` judges and the plan its approval joins are read and written in one
        // serializable transaction: no approval is recorded for a plan another change moved.
        self.database
            .transaction(|unit| {
                let Some((mut plan, consumed)) =
                    plans::<Unapproved>(unit, "plan_id = $1", &[&plan_id])?
                        .into_iter()
                        .next()
                else {
                    return Ok(None);
                };
                let approval = decide(&plan, consumed)
                    .map_err(|refusal| Failure::Refused(Unapproved::Refused(refusal)))?;
                plan.approvals.push(approval);
                let record =
                    encoded(&plan).map_err(|error| Failure::Refused(Unapproved::Store(error)))?;
                unit.execute(
                    "UPDATE permguard_plans SET record = $3
                     WHERE principal = $1 AND plan_id = $2",
                    &[&plan.principal, &plan.plan_id, &record],
                )?;
                Ok(Some(plan))
            })
            .map_err(|error| Unapproved::Store(error.into()))?
    }

    fn consume(
        &self,
        _applying: &Applying<'_>,
        principal: &str,
        plan_id: &str,
    ) -> Result<(), ReplayError> {
        self.read(|unit| {
            let Some(row) = unit.query_opt(
                "SELECT consumed FROM permguard_plans WHERE principal = $1 AND plan_id = $2",
                &[&principal, &plan_id],
            )?
            else {
                return Err(Failure::Refused(ReplayError::PlanUnknown));
            };
            if row.get::<_, bool>(0) {
                return Err(Failure::Refused(ReplayError::PlanConsumed));
            }
            let spent = unit.execute(
                "UPDATE permguard_plans SET consumed = true
                 WHERE principal = $1 AND plan_id = $2 AND NOT consumed",
                &[&principal, &plan_id],
            )?;
            if spent == 1 {
                Ok(())
            } else {
                Err(Failure::Refused(ReplayError::PlanConsumed))
            }
        })
    }

    fn operation(
        &self,
        operation_id: &OperationId,
        target: Option<&str>,
    ) -> Result<Option<Observed>, ReplayError> {
        let Some(target) = target else {
            return Ok(None);
        };
        self.read(|unit| {
            if let Some(plan_id) = target.strip_prefix("consume:") {
                // A plan is consumed once, by the one change it was made for: a consumed plan is
                // that change's consumption, as on the file backend.
                let consumed = unit.query_opt(
                    "SELECT record FROM permguard_plans WHERE plan_id = $1 AND consumed",
                    &[&plan_id],
                )?;
                return consumed
                    .map(|row| {
                        decoded(&row.get::<_, String>(0))
                            .map(|plan| Observed {
                                revision: plan.revision,
                                target: Some(target.to_owned()),
                            })
                            .map_err(Failure::Refused)
                    })
                    .transpose();
            }
            let recorded = operation_id.to_string();
            Ok(plans::<ReplayError>(unit, "plan_id = $1", &[&target])?
                .into_iter()
                .find(|(plan, _)| {
                    plan.approvals
                        .iter()
                        .any(|approval| approval.operation_id == recorded)
                })
                .map(|(plan, _)| Observed {
                    revision: plan.revision,
                    target: Some(target.to_owned()),
                }))
        })
    }
}
