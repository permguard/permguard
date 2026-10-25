// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Garbage collection on the Host API (WP-7.11b, `6-contracts/8-contract-host-api.md` lifecycle,
//! configuration and operations).
//!
//! | Route                            | Grant       | Request                   | Answer                                            |
//! | -------------------------------- | ----------- | ------------------------- | ------------------------------------------------- |
//! | `POST /host/v1/gc/{job}/plan`    | `gc.manage` | `{request_id, resource?}` | the receipt; the candidates, what is kept and why |
//! | `POST /host/v1/gc/{job}/run`     | `gc.manage` | `{request_id, receipt}`   | what was removed, what was kept and why, receipt  |
//!
//! The grant is checked on the scope: the job's Plane when `resource` is absent, or a zone or
//! ledger of it, and the run on the scope its plan names. A plan changes nothing. A run spends its
//! plan in an operation of its own (`host.plan.consumed`), sweeps the scope again outside any
//! operation, under every recheck the Plane's background pass makes and within its bound, and is
//! recorded in a last one (`host.gc.ran`): what the plan listed is what was removable then, not an
//! order to remove it. A retry of a recorded run answers it and never sweeps twice; a run cut
//! before its record leaves its plan spent, and the caller plans again. No plan requires an
//! approval: holds, pins, refs and the grace keep what must stay whoever runs it.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, Resource, operations};
use permguard_core::{ErrorClass, codes};

use super::grants::{rfc3339, unreachable_reconciliation};
use super::replay::{self, Plan};
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::gc::{self, GcError, GcJob, Report};
use crate::operations::mutation::{Applied, Failure};

/// The plan step, as the transaction names it.
pub const PLAN: &str = "gc.plan";
/// The run step.
pub const RUN: &str = "gc.run";
/// The action a plan is recorded under.
pub const AUDIT_PLANNED: &str = "host.gc.planned";
/// The action a run is recorded under, even one that removed nothing.
pub const AUDIT_RAN: &str = "host.gc.ran";

/// `POST /host/v1/gc/{job}/plan`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanGc {
    #[serde(default)]
    pub request_id: String,
    /// The Plane's zone or ledger to sweep, as a grant names it; the whole Plane when absent.
    #[serde(default)]
    pub resource: Option<String>,
}

/// What a plan answers: its receipt, and what a run would remove and keep now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPlanned {
    pub job: String,
    /// The scope the plan names.
    pub resource: String,
    pub plan_id: String,
    /// What the plan changes, `sha256:<hex>`.
    pub plan_digest: String,
    /// RFC 3339: when the plan can no longer be run.
    pub expires: String,
    /// The receipt the run presents, COSE_Sign1 `permguard.operation.plan.v1`, base64url.
    pub receipt: String,
    pub approvals_required: u64,
    pub report: Report,
}

/// `POST /host/v1/gc/{job}/run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGc {
    #[serde(default)]
    pub request_id: String,
    /// The receipt the plan step answered.
    pub receipt: String,
}

/// What a run answers: what it removed, what it kept and why, the plan it spent and its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcRan {
    pub receipt: Receipt,
    pub job: String,
    pub resource: String,
    pub plan_id: String,
    pub report: Report,
}

/// A job the Host knows, the Plane that provides it and its handler.
struct Provided {
    operation: &'static str,
    plane: String,
    handler: Arc<dyn GcJob>,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        message,
    )
}

/// The refusal of a job that did not plan or run.
fn refusal_of(job: &str, step: &str, error: GcError) -> Refusal {
    match error {
        GcError::NotFound(why) => Refusal::new(
            ErrorClass::NotFound,
            codes::common::NOT_FOUND,
            format!("the gc job `{job}` {step} nothing: {why}"),
        ),
        GcError::Failed(why) => Refusal::new(
            ErrorClass::Unavailable,
            codes::common::UNAVAILABLE,
            format!("the gc job `{job}` {step} nothing: {why}"),
        ),
    }
}

fn unknown_plan() -> Refusal {
    Refusal::new(
        ErrorClass::NotFound,
        codes::host::PLAN_UNKNOWN,
        "no plan of that id is held for this job",
    )
}

/// `resource` when it is the Plane `plane`, or a zone or a ledger of it.
fn within(plane: &str, resource: &Resource) -> bool {
    match resource {
        Resource::Plane { plane: of }
        | Resource::Zone { plane: of, .. }
        | Resource::Ledger { plane: of, .. } => of == plane,
        Resource::Host => false,
    }
}

impl HostApi {
    /// The jobs the Planes provide, which the composition fills (WP-7.11b).
    pub fn gc_jobs(&self) -> Arc<gc::Jobs> {
        Arc::clone(&self.gc)
    }

    /// `job` as the Host knows it and a Plane provides it.
    fn provided_job(&self, job: &str) -> Result<Provided, Refusal> {
        let operation = gc::plan_operation(job).ok_or_else(|| {
            Refusal::new(
                ErrorClass::NotFound,
                codes::common::NOT_FOUND,
                format!(
                    "no gc job is named `{job}`: the jobs are {}",
                    gc::JOBS.join(", ")
                ),
            )
        })?;
        let (plane, handler) = self.gc.get(job).ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                format!("the Plane that provides the gc job `{job}` is not composed"),
            )
        })?;
        Ok(Provided {
            operation,
            plane,
            handler,
        })
    }

    /// `POST /host/v1/gc/{job}/plan` (WP-7.11b).
    pub fn plan_gc(&self, actor: &Actor, job: &str, plan: PlanGc) -> Result<GcPlanned, Refusal> {
        let provided = self.provided_job(job);
        let parsed = plan.resource.as_deref().map(Resource::parse);
        // Admitted on the scope before anything is told: the Plane's when it is not named, the
        // Host's when neither the scope nor the job reads.
        let scope = match (&parsed, &provided) {
            (Some(Ok(resource)), _) => resource.clone(),
            (None, Ok(provided)) => Resource::plane(provided.plane.clone()),
            _ => Resource::host(),
        };
        let admitted = self.admit_on(actor, operations::GC_MANAGE, &scope)?;
        let provided = provided?;
        if let Some(Err(error)) = parsed {
            return Err(invalid(format!("`resource`: {error}")));
        }
        if !within(&provided.plane, &scope) {
            return Err(invalid(format!(
                "the gc job `{job}` sweeps `plane/{}`, a zone or a ledger of it, not `{scope}`",
                provided.plane
            )));
        }
        let mutation = Mutation {
            request_id: plan.request_id.clone(),
            expected_revision: None,
        };
        let now = self.time.now_secs();
        let target = format!("{job}:{scope}");
        let request = (job, &plan);
        // A retry is answered before the store is walked again (after the review).
        if let Some(answered) = self.replayed(
            replay::DOMAIN,
            &admitted.principal,
            PLAN,
            AUDIT_PLANNED,
            &mutation,
            &request,
            Some(target.clone()),
            |_, _, _| Err(unreachable_reconciliation(PLAN)),
        )? {
            return Ok(answered);
        }
        // Read before the transaction, which a plan never waits on: what it lists is what was
        // removable then.
        let report = provided
            .handler
            .plan(&scope)
            .map_err(|error| refusal_of(job, "planned", error))?;
        self.transact(
            replay::DOMAIN,
            &admitted.principal,
            PLAN,
            AUDIT_PLANNED,
            &mutation,
            &request,
            Some(target.clone()),
            || Ok(()),
            |applying| {
                let issued = self
                    .issue_plan(
                        applying,
                        super::plans::Issue {
                            kind: provided.operation,
                            internal: provided.operation,
                            stored_target: target.clone(),
                            target: scope.to_string(),
                            revision: 0,
                            parameters: &[("job", job)],
                            principal: &admitted.principal,
                        },
                        now,
                    )
                    .map_err(Failure::Refused)?;
                Ok(Applied {
                    revision: 0,
                    target: Some(target.clone()),
                    value: GcPlanned {
                        job: job.to_owned(),
                        resource: scope.to_string(),
                        plan_id: issued.plan.plan_id,
                        plan_digest: issued.plan_digest,
                        expires: rfc3339(issued.expires),
                        receipt: issued.receipt,
                        approvals_required: issued.approvals_required,
                        report,
                    },
                })
            },
            // A plan leaves no trace a run could rebuild its answer from: one recovery commits is
            // answered as applied, and its plan, which nobody was answered, expires unused.
            |_, _, _| Err(unreachable_reconciliation(PLAN)),
        )
    }

    /// `POST /host/v1/gc/{job}/run` (WP-7.11b).
    pub fn run_gc(&self, actor: &Actor, job: &str, run: RunGc) -> Result<GcRan, Refusal> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Admitted on the scope the receipt names, before the plan is looked up: a receipt that
        // does not read is admitted on the Host, and names no plan of a job. The plan held for
        // the caller decides the rest.
        let named = URL_SAFE_NO_PAD
            .decode(&run.receipt)
            .ok()
            .and_then(|bytes| crate::operations::plan::read_receipt(&bytes).ok())
            .and_then(|receipt| Resource::parse(&receipt.target).ok());
        let scope = named.clone().unwrap_or_else(Resource::host);
        let admitted = self.admit_on(actor, operations::GC_MANAGE, &scope)?;
        let provided = self.provided_job(job)?;
        let mutation = Mutation {
            request_id: run.request_id.clone(),
            expected_revision: None,
        };
        let now = self.time.now_secs();
        let target = format!("{job}:{scope}");
        let presented = || -> Result<Plan, Refusal> {
            let plan = self.presented_plan(&admitted.principal, &run.receipt, now)?;
            if plan.operation != provided.operation || plan.target != target {
                return Err(unknown_plan());
            }
            Ok(plan)
        };
        let request = (job, &run);
        // A retry is answered from the run it repeats, and sweeps nothing.
        if let Some(answered) = self.replayed(
            replay::DOMAIN,
            &admitted.principal,
            RUN,
            AUDIT_RAN,
            &mutation,
            &request,
            Some(target.clone()),
            |_, _, _| Err(unreachable_reconciliation(RUN)),
        )? {
            return Ok(answered);
        }
        // Spent first, in an operation of its own, checked and spent under one lock: two runs of
        // one receipt never both sweep, and whatever happens to the sweep, the receipt is spent.
        let plan = {
            let _spending = self
                .gc_spending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let plan = presented()?;
            super::plans::consume_plan(self.mutations()?, &self.replay, &admitted.principal, &plan)
                .map_err(|error| {
                    Refusal::new(
                        ErrorClass::Unavailable,
                        codes::common::UNAVAILABLE,
                        format!("the plan could not be spent, nothing was swept: {error}"),
                    )
                })?;
            plan
        };
        // The sweep runs outside any operation: the backup barrier and the journal wait for no
        // sweep (after the review).
        let swept = provided.handler.run(&scope, &plan.plan_id);
        // And is recorded in a short operation whose answer a retry is given: a sweep that failed
        // is recorded failed, its plan spent.
        self.transact(
            replay::DOMAIN,
            &admitted.principal,
            RUN,
            AUDIT_RAN,
            &mutation,
            &request,
            Some(target.clone()),
            || Ok(()),
            |applying| {
                let report = swept
                    .clone()
                    .map_err(|error| Failure::Refused(refusal_of(job, "swept", error)))?;
                Ok(Applied {
                    revision: 0,
                    target: Some(target.clone()),
                    value: GcRan {
                        receipt: self.receipt(applying.operation_id(), 0),
                        job: job.to_owned(),
                        resource: scope.to_string(),
                        plan_id: plan.plan_id.clone(),
                        report,
                    },
                })
            },
            // A run recovery committed without its answer swept already: the caller plans again,
            // and the next run removes what is still removable.
            |_, _, _| Err(unreachable_reconciliation(RUN)),
        )
    }
}

#[cfg(test)]
mod tests;
