// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Plan receipts and dual control on the Host API (WP-3.9, owner decisions of 2026-10-11).
//!
//! | Route                               | What                                                         |
//! | ----------------------------------- | ------------------------------------------------------------ |
//! | every `…/plan` of a two-step change | answers the receipt and how many approvals it requires       |
//! | every `…/run`                       | presents the receipt, the planner alone, once the approvals  |
//! |                                     | are given                                                    |
//! | `GET /host/v1/plans?status`         | the plans whose operation the caller may do                  |
//! | `POST /host/v1/plans/{id}/approve`  | one approval per principal holding the operation's grant,    |
//! |                                     | never the planner's                                          |
//!
//! A receipt needs the `host.operations` ring: without `operations.keys` a plan is refused
//! `unavailable`, as the verification bundle is (WP-3.4).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, Principal, Resource, operations};
use permguard_core::{ErrorClass, codes};

use crate::keys::ring::HOST_OPERATIONS;
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Applying, Begin, Failure, Mutations, Outcome};
use crate::operations::plan::{
    self, Approval, GRANT_REVOKE, IDENTITY_RESET, KEYS_REVOKE, MEMBERSHIP_REVOKE, PlanReceipt,
    PlanSigner,
};

use super::grants::{rfc3339, unreachable_reconciliation};
use super::replay::{self, Plan, PlanApproval, Replay, mint_id};
use super::{HostApi, Mutation, Receipt, Refusal};

/// The action an approval is recorded under, in the `security` trail.
pub const AUDIT_APPROVED: &str = "host.plan.approved";

/// The action a plan consumed ahead of its change is recorded under: the offline reset's.
pub const AUDIT_CONSUMED: &str = "host.plan.consumed";

/// One approval as the plans store shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub principal: String,
    /// RFC 3339.
    pub approved_at: String,
    /// COSE_Sign1 `permguard.operation.approval.v1`, base64url.
    pub approval: String,
}

/// One plan as the plans store shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanView {
    pub plan_id: String,
    /// `grant.revoke`, `keys.revoke`, `membership.revoke` or `identity.reset`.
    pub operation: String,
    pub target: String,
    pub revision: u64,
    /// The planner.
    pub principal: String,
    pub plan_digest: String,
    /// RFC 3339.
    pub expires: String,
    pub approvals_required: u64,
    pub approvals: Vec<ApprovalView>,
    /// `pending`, `ready`, `consumed` or `expired`.
    pub status: String,
    /// The receipt, COSE_Sign1 `permguard.operation.plan.v1`, base64url.
    pub receipt: String,
}

/// What `GET /host/v1/plans` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanList {
    pub plans: Vec<PlanView>,
}

/// `POST /host/v1/plans/{id}/approve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovePlan {
    #[serde(default)]
    pub request_id: String,
}

/// What an approval answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanApproved {
    pub receipt: Receipt,
    pub plan: PlanView,
}

/// What a plan step adds to its answer.
#[derive(Debug, Clone)]
pub struct Issued {
    pub plan: Plan,
    /// The receipt, base64url.
    pub receipt: String,
    /// The receipt's bytes: what the offline reset writes.
    pub envelope: Vec<u8>,
    pub plan_digest: String,
    pub approvals_required: u64,
    pub expires: u64,
}

/// What a plan step asks [`sign_plan`] for.
pub struct Issue<'a> {
    /// The operation as the receipt names it.
    pub kind: &'static str,
    /// The operation as the plan's run checks it.
    pub internal: &'static str,
    /// What the run reads back from the plan.
    pub stored_target: String,
    /// The exact resource the receipt names.
    pub target: String,
    pub revision: u64,
    pub parameters: &'a [(&'a str, &'a str)],
    pub principal: &'a Principal,
}

/// The grant an operation needs, which its approvers need too.
fn grant_of(kind: &str) -> Option<&'static str> {
    match kind {
        GRANT_REVOKE => Some(operations::AUTHZ_ADMIN),
        KEYS_REVOKE => Some(operations::KEYS_ADMIN),
        MEMBERSHIP_REVOKE => Some(operations::MEMBERSHIP_ADMIN),
        IDENTITY_RESET => Some(operations::IDENTITY_ADMIN),
        _ => None,
    }
}

/// The operation an approval of `kind` runs under, in the [`replay::DOMAIN`] domain.
fn approval_of(kind: &str) -> Option<&'static str> {
    match kind {
        GRANT_REVOKE => Some("grants.revoke.approve"),
        KEYS_REVOKE => Some("keys.revoke.approve"),
        MEMBERSHIP_REVOKE => Some("members.revoke.approve"),
        IDENTITY_RESET => Some("identity.reset.approve"),
        _ => None,
    }
}

fn status_of(plan: &Plan, consumed: bool, now: u64) -> &'static str {
    if consumed {
        "consumed"
    } else if plan.expires <= now {
        "expired"
    } else if (plan.approvals.len() as u64) < plan.approvals_required {
        "pending"
    } else {
        "ready"
    }
}

/// `plan` as `viewer` sees it: the receipt is the planner's capability, shown to the planner alone.
fn view(plan: &Plan, consumed: bool, now: u64, viewer: &str) -> PlanView {
    let receipt = URL_SAFE_NO_PAD
        .decode(&plan.receipt)
        .ok()
        .and_then(|bytes| plan::read_receipt(&bytes).ok());
    PlanView {
        plan_id: plan.plan_id.clone(),
        operation: plan.kind.clone(),
        target: receipt
            .as_ref()
            .map_or_else(|| plan.target.clone(), |receipt| receipt.target.clone()),
        revision: plan.revision,
        principal: plan.principal.clone(),
        plan_digest: plan.digest.clone(),
        expires: rfc3339(plan.expires),
        approvals_required: plan.approvals_required,
        approvals: plan
            .approvals
            .iter()
            .map(|approval| ApprovalView {
                principal: approval.principal.clone(),
                approved_at: rfc3339(approval.approved_at),
                approval: approval.envelope.clone(),
            })
            .collect(),
        status: status_of(plan, consumed, now).to_owned(),
        receipt: if viewer == plan.principal {
            plan.receipt.clone()
        } else {
            String::new()
        },
    }
}

fn unknown() -> Refusal {
    Refusal::new(
        ErrorClass::NotFound,
        codes::host::PLAN_UNKNOWN,
        "no plan of that id is held",
    )
}

/// Signs the receipt of `issue` with `signer`, the `host.operations` ring, and answers the plan
/// the plans store keeps: what every plan step of the Host API and the offline reset write. No
/// signer refuses `unavailable`.
pub fn sign_plan(
    signer: Option<&dyn PlanSigner>,
    issue: Issue<'_>,
    host_id: [u8; 16],
    dual_control: bool,
    now: u64,
) -> Result<Issued, Refusal> {
    let signer = signer.ok_or_else(|| {
        Refusal::new(
            ErrorClass::Unavailable,
            codes::common::UNAVAILABLE,
            "a plan receipt is signed by `host.operations`, and this Host runs without \
             `operations.keys`",
        )
    })?;
    let plan_id = mint_id()?;
    let nonce = mint_id()?;
    let bytes16 = |text: &str| -> Result<[u8; 16], Refusal> {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .filter_map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
            .collect();
        bytes
            .try_into()
            .map_err(|_| unreachable_reconciliation(issue.internal))
    };
    let approvals_required = plan::approvals_required(issue.kind, dual_control);
    let expires = now.saturating_add(plan::lifetime(approvals_required).as_secs());
    let plan_digest =
        plan::plan_digest(issue.kind, &issue.target, issue.revision, issue.parameters);
    let receipt = PlanReceipt {
        plan_id: bytes16(&plan_id)?,
        operation: issue.kind.to_owned(),
        target: issue.target.clone(),
        revision: issue.revision,
        principal: issue.principal.as_str().to_owned(),
        plan_digest: plan_digest.clone(),
        expires,
        nonce: bytes16(&nonce)?,
        approvals_required,
        host_id,
        created_at: now,
    };
    let envelope = signer.sign_receipt(&receipt).map_err(|error| {
        Refusal::new(
            ErrorClass::Unavailable,
            codes::common::UNAVAILABLE,
            format!("the plan receipt could not be signed: {error}"),
        )
    })?;
    let encoded = URL_SAFE_NO_PAD.encode(&envelope);
    let plan = Plan {
        plan_id,
        operation: issue.internal.to_owned(),
        target: issue.stored_target,
        revision: issue.revision,
        digest: plan_digest.to_string(),
        expires,
        principal: issue.principal.as_str().to_owned(),
        kind: issue.kind.to_owned(),
        receipt: encoded.clone(),
        approvals_required,
        approvals: Vec::new(),
        created_at: now,
    };
    Ok(Issued {
        plan,
        receipt: encoded,
        envelope,
        plan_digest: plan_digest.to_string(),
        approvals_required,
        expires,
    })
}

/// The plan the receipt `bytes` names, when `replay` holds it for `principal`, it was neither run
/// nor expired at `now`, the bytes are the receipt the plan step answered, and it holds the
/// approvals it requires: what every run step reads before it changes anything.
pub fn held_plan(
    replay: &Replay,
    principal: &Principal,
    bytes: &[u8],
    now: u64,
) -> Result<Plan, Refusal> {
    let receipt = plan::read_receipt(bytes).map_err(|error| {
        Refusal::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            format!("`receipt` is not a plan receipt: {error}"),
        )
    })?;
    let plan_id: String = receipt
        .plan_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let plan = replay.plan_of(principal, &plan_id, now)?;
    let held = URL_SAFE_NO_PAD.decode(&plan.receipt).unwrap_or_default();
    if held != bytes {
        return Err(Refusal::new(
            ErrorClass::Validation,
            codes::host::PLAN_DIGEST_MISMATCH,
            "the receipt presented is not the one the plan step answered",
        ));
    }
    if (plan.approvals.len() as u64) < plan.approvals_required {
        return Err(Refusal::new(
            ErrorClass::Conflict,
            codes::host::PLAN_APPROVALS_MISSING,
            format!(
                "the plan requires {} approval(s) and holds {}",
                plan.approvals_required,
                plan.approvals.len()
            ),
        ));
    }
    Ok(plan)
}

/// Consumes `plan` of `principal` in an operation of its own, before the change it plans runs:
/// what the offline reset does, whose change is several operations and completes without its
/// plan once interrupted. Whatever happens after, the receipt is spent: plan again.
pub fn consume_plan(
    mutations: &Mutations,
    replay: &Replay,
    principal: &Principal,
    plan: &Plan,
) -> Result<(), String> {
    let target = Some(format!("consume:{}", plan.plan_id));
    let outcome = mutations.run(
        Begin {
            domain: replay::DOMAIN,
            operation: "plan.consume",
            action: AUDIT_CONSUMED,
            initiator: Initiator::System(principal.as_str().to_owned()),
            request: None,
            target: target.clone(),
        },
        |applying| {
            replay
                .consume(applying, principal, &plan.plan_id)
                .map_err(|error| Failure::Refused(error.to_string()))?;
            Ok(Applied {
                revision: plan.revision,
                target,
                value: (),
            })
        },
    );
    match outcome {
        Ok(Outcome::Applied(())) => Ok(()),
        Ok(_) => Err("the plan's consumption was answered from another operation".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

impl HostApi {
    /// Whether `operations.dual_control` is in force: required by `regulated`, or switched on.
    pub(super) fn dual_control(&self) -> bool {
        use permguard_core::assurance::{AssuranceProfile, Control};
        let control = Control::OperationsDualControl;
        self.assurance
            .profile
            .parse::<AssuranceProfile>()
            .is_ok_and(|profile| profile.at_least(control.floor()))
            || self
                .assurance
                .added_controls
                .iter()
                .any(|added| added == control.name())
    }

    /// Mints a plan inside the plan step's operation: its id, nonce and digest, its receipt
    /// signed under `host.operations`, the plan kept for its run and its approvals.
    /// The Host a receipt or an approval names: one without an identity signs neither.
    fn receipt_host_id(&self) -> Result<[u8; 16], Refusal> {
        self.identity
            .as_ref()
            .map(|identity| identity.host_id())
            .ok_or_else(|| {
                Refusal::new(
                    ErrorClass::Unavailable,
                    codes::common::UNAVAILABLE,
                    "a plan receipt names the Host, and this Host has no identity",
                )
            })
    }

    pub(super) fn issue_plan(
        &self,
        applying: &Applying<'_>,
        issue: Issue<'_>,
        now: u64,
    ) -> Result<Issued, Refusal> {
        let signer = self.keys.ring(HOST_OPERATIONS);
        let host_id = self.receipt_host_id()?;
        let issued = sign_plan(
            signer.map(|ring| ring.as_ref() as &dyn PlanSigner),
            issue,
            host_id,
            self.dual_control(),
            now,
        )?;
        self.replay.plan(applying, issued.plan.clone())?;
        Ok(issued)
    }

    /// The plan the receipt `presented` stands for, held for `principal`: the very receipt the
    /// plan step answered, not run, not expired, with every approval it requires.
    pub(super) fn presented_plan(
        &self,
        principal: &Principal,
        presented: &str,
        now: u64,
    ) -> Result<Plan, Refusal> {
        let bytes = URL_SAFE_NO_PAD.decode(presented).map_err(|_| {
            Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                "`receipt` is the plan receipt the plan step answered, base64url",
            )
        })?;
        held_plan(&self.replay, principal, &bytes, now)
    }

    /// `GET /host/v1/plans?status`: the plans whose operation the caller may do on the Host.
    pub fn plans(&self, actor: &Actor, status: Option<&str>) -> Result<PlanList, Refusal> {
        if let Some(status) = status
            && !matches!(status, "pending" | "ready" | "consumed" | "expired")
        {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                "`status` is `pending`, `ready`, `consumed` or `expired`",
            ));
        }
        // Someone authenticated, holding at least one of the operations' grants: anyone else is
        // refused as every route refuses.
        let holds = |grant: &str| {
            self.authorization
                .authorize(actor, grant, &Resource::host())
                .is_ok()
        };
        if !plan::OPERATIONS
            .iter()
            .filter_map(|kind| grant_of(kind))
            .any(holds)
        {
            self.authorization
                .authorize(actor, operations::AUTHZ_ADMIN, &Resource::host())?;
        }
        let principal = actor.principal()?;
        let _permit = self.bounds.admit(&principal)?;
        let now = self.time.now_secs();
        let mut plans: Vec<PlanView> = self
            .replay
            .plans()
            .into_iter()
            .filter(|(plan, _)| {
                grant_of(&plan.kind).is_some_and(|grant| {
                    self.authorization
                        .authorize(actor, grant, &Resource::host())
                        .is_ok()
                })
            })
            .map(|(plan, consumed)| view(&plan, consumed, now, principal.as_str()))
            .filter(|view| status.is_none_or(|status| view.status == status))
            .collect();
        plans.sort_by(|a, b| a.plan_id.cmp(&b.plan_id));
        Ok(PlanList { plans })
    }

    /// `POST /host/v1/plans/{id}/approve`: one approval of a principal holding the plan's
    /// operation grant, not the planner, attested by the Host under `host.operations`.
    pub async fn approve_plan(
        &self,
        actor: &Actor,
        plan_id: &str,
        approve: ApprovePlan,
    ) -> Result<PlanApproved, Refusal> {
        let principal = actor.principal()?;
        let Some((held, _)) = self.replay.find(plan_id) else {
            // Nothing to approve: a caller holding none of the operations' grants learns nothing.
            let any = plan::OPERATIONS
                .iter()
                .filter_map(|kind| grant_of(kind))
                .any(|grant| {
                    self.authorization
                        .authorize(actor, grant, &Resource::host())
                        .is_ok()
                });
            if !any {
                self.authorization
                    .authorize(actor, operations::AUTHZ_ADMIN, &Resource::host())?;
            }
            return Err(unknown());
        };
        let grant = grant_of(&held.kind).ok_or_else(unknown)?;
        let operation = approval_of(&held.kind).ok_or_else(unknown)?;
        let admitted = self.admit(actor, grant)?;
        let signer = self.keys.ring(HOST_OPERATIONS).ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "an approval is attested by `host.operations`, and this Host runs without \
                 `operations.keys`",
            )
        })?;
        let mutation = Mutation {
            request_id: approve.request_id.clone(),
            expected_revision: None,
        };
        let now = self.time.now_secs();
        let target = (plan_id, &approve);
        let current = || -> Result<Plan, Refusal> {
            let (plan, consumed) = self.replay.find(plan_id).ok_or_else(unknown)?;
            if consumed {
                return Err(Refusal::new(
                    ErrorClass::Conflict,
                    codes::host::PLAN_EXPIRED,
                    "this plan was already run",
                ));
            }
            if plan.expires <= now {
                return Err(Refusal::new(
                    ErrorClass::Conflict,
                    codes::host::PLAN_EXPIRED,
                    "this plan has expired",
                ));
            }
            if plan.principal == principal.as_str() {
                return Err(Refusal::new(
                    ErrorClass::Conflict,
                    codes::host::PLAN_SELF_APPROVAL,
                    "the planner cannot approve its own plan",
                ));
            }
            if plan
                .approvals
                .iter()
                .any(|held| held.principal == principal.as_str())
            {
                return Err(Refusal::new(
                    ErrorClass::Conflict,
                    codes::host::PLAN_APPROVAL_REFUSED,
                    "this principal approved the plan already",
                ));
            }
            if (plan.approvals.len() as u64) >= plan.approvals_required {
                return Err(Refusal::new(
                    ErrorClass::Conflict,
                    codes::host::PLAN_APPROVAL_REFUSED,
                    "the plan holds every approval it requires",
                ));
            }
            Ok(plan)
        };
        self.transact(
            replay::DOMAIN,
            &admitted.principal,
            operation,
            AUDIT_APPROVED,
            &mutation,
            &target,
            Some(plan_id.to_owned()),
            || current().map(|_| ()),
            |applying| {
                let mut plan = current().map_err(Failure::Refused)?;
                let approval = Approval {
                    plan_digest: permguard_objects::digest::Digest::parse(&plan.digest)
                        .map_err(|_| Failure::Refused(unreachable_reconciliation(operation)))?,
                    principal: admitted.principal.as_str().to_owned(),
                    approved_at: now,
                    host_id: self.receipt_host_id().map_err(Failure::Refused)?,
                };
                let envelope = signer.sign_approval(&approval).map_err(|error| {
                    Failure::Refused(Refusal::new(
                        ErrorClass::Unavailable,
                        codes::common::UNAVAILABLE,
                        format!("the approval could not be attested: {error}"),
                    ))
                })?;
                let held = PlanApproval {
                    principal: approval.principal.clone(),
                    approved_at: now,
                    envelope: URL_SAFE_NO_PAD.encode(envelope),
                    operation_id: applying.operation_id().to_string(),
                };
                self.replay
                    .approve(applying, &plan.principal, &plan.plan_id, held.clone())
                    .map_err(|error| Failure::Refused(error.into()))?;
                plan.approvals.push(held);
                Ok(Applied {
                    revision: plan.revision,
                    target: Some(plan.plan_id.clone()),
                    value: PlanApproved {
                        receipt: self.receipt(applying.operation_id(), plan.revision),
                        plan: view(&plan, false, now, admitted.principal.as_str()),
                    },
                })
            },
            // Recovery commits an approval whose frame is durable: its retry answers the plan.
            |operation_id, revision, _| {
                let (plan, consumed) = self.replay.find(plan_id).ok_or_else(unknown)?;
                Ok(PlanApproved {
                    receipt: self.receipt(operation_id, revision),
                    plan: view(&plan, consumed, now, admitted.principal.as_str()),
                })
            },
        )
    }
}

#[cfg(test)]
mod tests;
