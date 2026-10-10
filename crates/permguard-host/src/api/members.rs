// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The memberships on the Host API (WP-4.1, owner decisions of 2026-10-09).
//!
//! | Route                                          | Grant              | Answer                                   |
//! | ---------------------------------------------- | ------------------ | ---------------------------------------- |
//! | `POST /host/v1/members/invites`                | `membership.admin` | the invitation and its token, once       |
//! | `GET /host/v1/members/invites`                 | `membership.read`  | the invitations, by hash, never a token  |
//! | `DELETE /host/v1/members/invites/{id}`         | `membership.admin` | a receipt                                |
//! | `GET /host/v1/members`, `…/{id}`               | `membership.read`  | status, selector, tasks, epoch, lease    |
//! | `POST …/{id}/approve`, `reject`                | `membership.admin` | a receipt and the manifest               |
//! | `POST …/{id}/suspend`, `resume`, `fence`       | `membership.admin` | a receipt and the manifest, a new epoch  |
//! | `POST …/{id}/appraise`                         | `membership.admin` | a receipt and the manifest, a new epoch  |
//! | `GET …/{id}/sessions`                          | `membership.read`  | the open task sessions, with boot ids    |
//! | `POST …/{id}/revoke/plan`, `…/revoke/run`      | `membership.admin` | a plan; a receipt and the manifest       |
//! | `POST /host/v1/memberships/join`, `…/{id}/sync`| `membership.admin` | the member's view of the membership      |
//!
//! `POST /host/v1/members/enroll` and `POST /host/v1/tasks/{task}/session` run only inside a
//! proven peer session (the `PeerChannel`); a listing never carries a token, a proof, a key or a
//! secret reference.
//!
//! A task requiring controls is approved only under an assurance binding the coordinator appraises
//! (WP-4.2): `approve` and `appraise` take the operator's approvals and the evidence; the member
//! view shows the binding and, while one is wanted, the appraisal state and its nonce.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use permguard_core::assurance::{AssuranceProfile, Control};
use permguard_core::authz::{Actor, Selector, operations};
use permguard_core::{ErrorClass, codes};

use super::grants::{Planned, plan_digest, rfc3339};
use super::replay::{PLAN_LIFETIME, Plan, mint_id};
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::identity::record::uuid_text;
use crate::membership::appraisal::{self, Appraisal, Approval, Evidence};
use crate::membership::member::{Connector, Join, Member, Target};
use crate::membership::record::{
    AssuranceBinding, HostRef, Invitation, LeasePolicy, Limits, Manifest, OperatorApproval, Role,
    Status, Task, TaskType,
};
use crate::membership::service::code_of;
use crate::membership::{
    APPRAISE, APPROVE, AUDIT_APPRAISED, AUDIT_APPROVED, AUDIT_ASSURANCE_APPROVED,
    AUDIT_ASSURANCE_REVOKED, AUDIT_FENCED, AUDIT_INVITE_REVOKED, AUDIT_INVITED, AUDIT_REJECTED,
    AUDIT_RESUMED, AUDIT_REVOKE_PLANNED, AUDIT_REVOKED, AUDIT_SUSPENDED, Capabilities, Coordinator,
    DOMAIN, FENCE, Held, INVITE, INVITE_REVOKE, MembershipError, Narrow, NewInvite, Offered,
    REJECT, RESUME, REVOKE_PLAN, REVOKE_RUN, SUSPEND, Store,
};
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Applying, Failure};
use permguard_core::{AuditEvent, AuditOutcome, AuditPhase, Fact, Subject};
use permguard_objects::cose::Sign1;

/// The revocation a plan names.
const REVOKE: &str = "members.revoke";

/// What the composition hands the facade for the memberships.
pub struct MembershipService {
    pub store: Arc<Store>,
    /// The task types this Host's Planes act in (WP-4.4 fills it).
    pub capabilities: Capabilities,
    /// How this Host reaches a coordinator; without one, a join and a sync are
    /// `peer_client_unconfigured`.
    pub connector: Option<Arc<dyn Connector>>,
    /// The coordinator's appraisal policy and the verifiers it trusts (WP-4.2).
    pub appraisal: Appraisal,
    /// The open task sessions this Host coordinates (WP-4.3).
    pub live: Arc<crate::membership::task::LiveSessions>,
}

/// One open task session of a membership, as an operator reads it (WP-4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    pub task_id: String,
    pub epoch: u64,
    /// The member's incarnation, hex: two at once is a clone alarm.
    pub member_boot_id: String,
    pub coordinator_boot_id: String,
    pub opened_at: String,
    pub expires_at: String,
}

/// `GET /host/v1/members/{id}/sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSessions {
    pub sessions: Vec<SessionView>,
}

/// A task's limits, as the Host API spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsView {
    pub max_body_bytes: u64,
    pub max_concurrency: u64,
    pub max_rate_per_minute: u64,
    pub max_batch_records: u64,
    pub retention_seconds: u64,
}

/// A task, as the Host API spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskView {
    pub task_id: String,
    #[serde(rename = "type")]
    pub task_type: String,
    /// The roles the type fixes; answered, and refused on a request that names others.
    #[serde(default)]
    pub provider_role: Option<String>,
    #[serde(default)]
    pub consumer_role: Option<String>,
    pub selector: String,
    pub resource_types: Vec<String>,
    pub required: bool,
    pub limits: LimitsView,
    #[serde(default)]
    pub assurance_requirements: Vec<String>,
}

impl From<&Task> for TaskView {
    fn from(task: &Task) -> Self {
        Self {
            task_id: task.task_id.clone(),
            task_type: task.task_type.as_str().to_owned(),
            provider_role: Some(task.task_type.provider().as_str().to_owned()),
            consumer_role: Some(task.task_type.consumer().as_str().to_owned()),
            selector: task.selector.to_string(),
            resource_types: task.resource_types.clone(),
            required: task.required,
            limits: LimitsView {
                max_body_bytes: task.limits.max_body_bytes,
                max_concurrency: task.limits.max_concurrency,
                max_rate_per_minute: task.limits.max_rate_per_minute,
                max_batch_records: task.limits.max_batch_records,
                retention_seconds: task.limits.retention_seconds,
            },
            assurance_requirements: task.assurance_requirements.clone(),
        }
    }
}

fn invalid(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        detail,
    )
}

impl TaskView {
    fn task(&self) -> Result<Task, Refusal> {
        let task_type: TaskType = self
            .task_type
            .parse()
            .map_err(|_| invalid(format!("`{}` is not a task type", self.task_type)))?;
        for (named, role) in [
            (&self.provider_role, task_type.provider()),
            (&self.consumer_role, task_type.consumer()),
        ] {
            if named.as_deref().is_some_and(|named| named != role.as_str()) {
                return Err(invalid(format!(
                    "`{}` is provided by the {} and consumed by the {}",
                    self.task_type,
                    task_type.provider().as_str(),
                    task_type.consumer().as_str()
                )));
            }
        }
        let task = Task {
            task_id: self.task_id.clone(),
            task_type,
            selector: selector(&self.selector)?,
            resource_types: self.resource_types.clone(),
            required: self.required,
            limits: Limits {
                max_body_bytes: self.limits.max_body_bytes,
                max_concurrency: self.limits.max_concurrency,
                max_rate_per_minute: self.limits.max_rate_per_minute,
                max_batch_records: self.limits.max_batch_records,
                retention_seconds: self.limits.retention_seconds,
            },
            assurance_requirements: self.assurance_requirements.clone(),
        };
        task.check().map_err(|error| invalid(error.0))?;
        Ok(task)
    }
}

fn selector(text: &str) -> Result<Selector, Refusal> {
    Selector::parse(text).map_err(|error| invalid(format!("`{text}`: {error}")))
}

fn tasks(views: &[TaskView]) -> Result<Vec<Task>, Refusal> {
    views.iter().map(TaskView::task).collect()
}

fn profile(text: &str) -> Result<AssuranceProfile, Refusal> {
    text.parse()
        .map_err(|_| invalid(format!("`{text}` is not an assurance profile")))
}

fn time(text: &str, what: &str) -> Result<u64, Refusal> {
    permguard_core::time::from_rfc3339(text)
        .and_then(|at| u64::try_from(at).ok())
        .ok_or_else(|| invalid(format!("`{what}` is an RFC 3339 time")))
}

/// Reads a membership or invitation id in its UUID text.
fn id_of(text: &str) -> Result<[u8; 16], Refusal> {
    if !text.is_ascii() {
        return Err(invalid("an id is the UUID's text"));
    }
    let digits: String = text.chars().filter(|c| *c != '-').collect();
    if digits.len() != 32 || text.len() != 36 {
        return Err(invalid(format!("`{text}` is not an id")));
    }
    let mut id = [0u8; 16];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[at * 2..at * 2 + 2], 16)
            .map_err(|_| invalid(format!("`{text}` is not an id")))?;
    }
    if uuid_text(&id) != text {
        return Err(invalid(format!("`{text}` is not an id")));
    }
    Ok(id)
}

/// `POST /host/v1/members/invites`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvite {
    pub request_id: String,
    pub selector: String,
    pub tasks: Vec<TaskView>,
    /// RFC 3339; 24 hours from now when absent, at most 7 days.
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub expected_fingerprint: Option<String>,
    #[serde(default)]
    pub min_assurance: Option<String>,
    /// Always 1: an invitation is used once.
    #[serde(default = "one")]
    pub max_uses: u64,
}

fn one() -> u64 {
    1
}

/// What creating an invitation answers: the token, once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCreated {
    pub receipt: Receipt,
    pub invite_id: String,
    /// 256 random bits, base64url without padding: shown now and never again.
    pub token: String,
    pub expires: String,
}

/// What the engine keeps of an invitation's issue: everything but the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InviteIssued {
    receipt: Receipt,
    invite_id: String,
    expires: String,
}

/// The refusal of a retried invitation: its token was shown once and is held nowhere.
fn shown_once() -> Refusal {
    Refusal::new(
        ErrorClass::Conflict,
        codes::host::INVITE_TOKEN_SHOWN,
        "the invitation was issued and its token cannot be shown again: delete it and invite again",
    )
}

/// One invitation, as listed: by its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteView {
    pub invite_id: String,
    pub selector: String,
    pub tasks: Vec<TaskView>,
    pub expires: String,
    pub expected_fingerprint: Option<String>,
    pub min_assurance: Option<String>,
    pub max_uses: u64,
    /// `issued`, `consumed`, `expired` or `revoked`.
    pub status: String,
    pub created_at: String,
    pub created_by: String,
}

impl InviteView {
    fn of(invitation: &Invitation, status: &str) -> Self {
        Self {
            invite_id: uuid_text(&invitation.invite_id),
            selector: invitation.selector.to_string(),
            tasks: invitation.tasks.iter().map(TaskView::from).collect(),
            expires: rfc3339(invitation.expires),
            expected_fingerprint: invitation.expected_fingerprint.clone(),
            min_assurance: invitation.min_assurance.map(|p| p.as_str().to_owned()),
            max_uses: invitation.max_uses,
            status: status.to_owned(),
            created_at: rfc3339(invitation.created_at),
            created_by: invitation.created_by.clone(),
        }
    }
}

/// `GET /host/v1/members/invites`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invites {
    pub invites: Vec<InviteView>,
}

/// What deleting an invitation answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteDeleted {
    pub receipt: Receipt,
}

/// A Host as a membership pins it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostView {
    pub host_id: String,
    pub epoch: u64,
    /// The first fingerprint: the identity's pin.
    pub fingerprint: String,
}

impl From<&HostRef> for HostView {
    fn from(host: &HostRef) -> Self {
        Self {
            host_id: uuid_text(&host.host_id),
            epoch: host.epoch,
            fingerprint: host.fingerprint.clone(),
        }
    }
}

/// A lease policy, as the Host API spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasePolicyView {
    pub max_session_seconds: u64,
    pub offline_grace_seconds: u64,
    pub clock_skew_seconds: u64,
    pub dormant_after_seconds: u64,
    pub revoke_after_seconds: u64,
}

impl From<&LeasePolicy> for LeasePolicyView {
    fn from(policy: &LeasePolicy) -> Self {
        Self {
            max_session_seconds: policy.max_session_seconds,
            offline_grace_seconds: policy.offline_grace_seconds,
            clock_skew_seconds: policy.clock_skew_seconds,
            dormant_after_seconds: policy.dormant_after_seconds,
            revoke_after_seconds: policy.revoke_after_seconds,
        }
    }
}

/// One membership, as an operator reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    pub membership_id: String,
    /// This Host's role in it.
    pub role: String,
    pub status: String,
    /// The fence: one more at every manifest; 0 while pending.
    pub epoch: u64,
    /// What `expected_revision` names.
    pub revision: u64,
    pub coordinator: HostView,
    pub member: HostView,
    pub selector: String,
    pub tasks: Vec<TaskView>,
    pub member_assurance: String,
    /// The lease policy the manifest signs; `null` while pending.
    pub lease_policy: Option<LeasePolicyView>,
    /// The manifest in force, COSE_Sign1 base64url; `null` while pending.
    pub manifest: Option<String>,
    pub updated_at: String,
    /// The last task session, from the session journal: comes with WP-4.4.
    pub last_session_at: Option<String>,
    /// The assurance binding the manifest signs; `null` when it signs none (WP-4.2).
    #[serde(default)]
    pub assurance: Option<AssuranceView>,
    /// While the coordinator appraises the tasks' controls: what the policy wants, what the
    /// declaration meets and the nonce evidence binds to; `null` otherwise (WP-4.2).
    #[serde(default)]
    pub appraisal: Option<AppraisalView>,
    /// Held for review since a peer named this epoch, which this coordinator never issued: no
    /// task until it is revoked (WP-4.3); `null` when not held.
    #[serde(default)]
    pub held_epoch: Option<u64>,
}

/// One claim of a binding, without the record it cites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimView {
    pub control: String,
    pub class: String,
    pub by: String,
}

/// An assurance binding, as an operator reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceView {
    /// `accepted` or `revoked`.
    pub verdict: String,
    /// Whether it admits tasks now: accepted, unexpired and, on the coordinator, under the policy
    /// in force.
    pub current: bool,
    pub policy_revision: String,
    pub task_ids: Vec<String>,
    pub claims: Vec<ClaimView>,
    pub appraised_by: String,
    pub issued_at: String,
    pub expires_at: String,
    /// What a task admission answers it by.
    pub binding_digest: String,
}

/// One control the tasks require, as the policy and the declaration stand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementView {
    pub control: String,
    /// The least class the policy wants; `null` when it does not appraise the control, which
    /// makes the task unapprovable.
    pub wants: Option<String>,
    /// Whether the member's declaration meets it.
    pub declared: bool,
}

/// The appraisal state of a membership whose tasks require controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppraisalView {
    pub policy_revision: String,
    /// The nonce evidence for this revision binds to, base64url: it changes with every revision.
    pub nonce: String,
    pub requirements: Vec<RequirementView>,
}

/// What the views read beside a membership.
struct Viewing<'a> {
    appraisal: &'a Appraisal,
    coordinator: Option<[u8; 16]>,
    now: u64,
}

impl AssuranceView {
    fn of(binding: &AssuranceBinding, current: bool) -> Self {
        Self {
            verdict: binding.verdict.as_str().to_owned(),
            current,
            policy_revision: binding.policy_revision.to_string(),
            task_ids: binding.task_ids.clone(),
            claims: binding
                .claims
                .iter()
                .map(|claim| ClaimView {
                    control: claim.control.name().to_owned(),
                    class: claim.class.as_str().to_owned(),
                    by: claim.by.clone(),
                })
                .collect(),
            appraised_by: binding.appraised_by.clone(),
            issued_at: rfc3339(binding.issued_at),
            expires_at: rfc3339(binding.expires_at),
            binding_digest: binding
                .digest()
                .map(|digest| digest.to_string())
                .unwrap_or_default(),
        }
    }
}

impl MemberView {
    fn of(held: &Held, viewing: &Viewing<'_>) -> Self {
        let (selector, tasks) = match &held.manifest {
            Some((manifest, ..)) => (&manifest.selector, &manifest.tasks),
            None => (&held.request.selector, &held.request.tasks),
        };
        let binding = held
            .manifest
            .as_ref()
            .and_then(|(manifest, ..)| manifest.assurance_binding.as_ref());
        let assurance = binding.map(|binding| {
            let current = match held.role {
                Role::Coordinator => viewing.appraisal.is_current(binding, viewing.now),
                // The member cannot read its coordinator's policy: the verdict and the expiry.
                Role::Member => {
                    binding.verdict == crate::membership::record::Verdict::Accepted
                        && viewing.now < binding.expires_at
                }
            };
            AssuranceView::of(binding, current)
        });
        // The coordinator's appraisal state, while it can still appraise: pending or active.
        let appraisal = viewing
            .coordinator
            .filter(|_| {
                held.role == Role::Coordinator
                    && matches!(held.status, Status::Pending | Status::Active)
            })
            .and_then(|coordinator| {
                let requirements = viewing
                    .appraisal
                    .requirements(tasks, held.request.member_assurance)
                    .ok()?;
                if requirements.is_empty() {
                    return None;
                }
                let state = match &held.manifest {
                    Some((_, _, digest)) => digest.clone(),
                    None => {
                        permguard_objects::digest::Digest::compute(&held.request.encode().ok()?)
                    }
                };
                Some(AppraisalView {
                    policy_revision: viewing.appraisal.policy.revision().to_string(),
                    nonce: URL_SAFE_NO_PAD.encode(appraisal::nonce(
                        &coordinator,
                        &held.request.membership_id,
                        &state,
                    )),
                    requirements: requirements
                        .into_iter()
                        .map(|requirement| RequirementView {
                            control: requirement.control.name().to_owned(),
                            wants: requirement.wants.map(|class| class.as_str().to_owned()),
                            declared: requirement.declared,
                        })
                        .collect(),
                })
            });
        Self {
            membership_id: uuid_text(&held.request.membership_id),
            role: held.role.as_str().to_owned(),
            status: held.status.as_str().to_owned(),
            epoch: held.epoch(),
            revision: held.revision,
            coordinator: (&held.request.coordinator).into(),
            member: (&held.request.member).into(),
            selector: selector.to_string(),
            tasks: tasks.iter().map(TaskView::from).collect(),
            member_assurance: held.request.member_assurance.as_str().to_owned(),
            lease_policy: held
                .manifest
                .as_ref()
                .map(|(manifest, ..)| (&manifest.lease_policy).into()),
            manifest: held
                .manifest
                .as_ref()
                .map(|(_, envelope, _)| URL_SAFE_NO_PAD.encode(envelope)),
            updated_at: rfc3339(held.updated_at),
            last_session_at: None,
            assurance,
            appraisal,
            held_epoch: held.held_epoch,
        }
    }
}

/// `GET /host/v1/members`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Members {
    pub members: Vec<MemberView>,
}

/// `POST …/{id}/approve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveMember {
    pub request_id: String,
    pub expected_revision: u64,
    /// A narrowing of the request: never wider.
    #[serde(default)]
    pub narrow: Option<NarrowView>,
    #[serde(default)]
    pub lease_policy: Option<LeasePolicyView>,
    /// What the tasks' controls are appraised with (WP-4.2).
    #[serde(default)]
    pub assurance: Option<AssuranceOffer>,
}

/// An operator's approval of one control: an accountable risk decision, with its reason and
/// expiry; the principal is the caller's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalView {
    pub control: String,
    pub reason: String,
    pub expires_at: String,
}

/// One piece of evidence for a registered verifier, base64url; kept by its digest alone.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceView {
    pub verifier: String,
    pub evidence: String,
}

impl std::fmt::Debug for EvidenceView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceView")
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

/// What an approval brings for the controls the tasks require.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceOffer {
    #[serde(default)]
    pub approvals: Vec<ApprovalView>,
    #[serde(default)]
    pub evidence: Vec<EvidenceView>,
}

/// `POST …/{id}/appraise`: the binding of an active membership renewed, or revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppraiseMember {
    pub request_id: String,
    pub expected_revision: u64,
    #[serde(default)]
    pub approvals: Vec<ApprovalView>,
    #[serde(default)]
    pub evidence: Vec<EvidenceView>,
    /// Revokes the binding instead: it admits no task from then on.
    #[serde(default)]
    pub revoke: Option<RevokeBinding>,
}

/// Why a binding is revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeBinding {
    pub reason: String,
}

/// The approvals and evidence of a request, read.
fn offer(
    approvals: &[ApprovalView],
    evidence: &[EvidenceView],
) -> Result<(Vec<Approval>, Vec<Evidence>), Refusal> {
    let approvals = approvals
        .iter()
        .map(|view| {
            let control = view.control.parse::<Control>().map_err(invalid)?;
            // Spelled exactly, as a task's requirement is.
            if control.name() != view.control {
                return Err(invalid(format!(
                    "`{}` is not a control's name",
                    view.control
                )));
            }
            Ok(Approval {
                control,
                reason: view.reason.clone(),
                expires_at: time(&view.expires_at, "expires_at")?,
            })
        })
        .collect::<Result<_, Refusal>>()?;
    if evidence.len() > appraisal::MAX_EVIDENCE_ITEMS {
        return Err(invalid(format!(
            "at most {} pieces of evidence",
            appraisal::MAX_EVIDENCE_ITEMS
        )));
    }
    let evidence = evidence
        .iter()
        .map(|view| {
            Ok(Evidence {
                verifier: view.verifier.clone(),
                evidence: URL_SAFE_NO_PAD
                    .decode(&view.evidence)
                    .map_err(|_| invalid("`evidence` is base64url"))?,
            })
        })
        .collect::<Result<_, Refusal>>()?;
    Ok((approvals, evidence))
}

/// An approval's narrowing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NarrowView {
    pub selector: String,
    pub tasks: Vec<TaskView>,
}

/// `POST …/{id}/reject`, `suspend`, `resume`, `fence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeMember {
    pub request_id: String,
    pub expected_revision: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

/// What a transition answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberChanged {
    /// The receipt; its revision is the membership's.
    pub receipt: Receipt,
    pub status: String,
    pub epoch: u64,
    /// The manifest issued, COSE_Sign1 base64url.
    pub manifest: String,
}

/// `POST …/{id}/revoke/plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanMemberRevoke {
    pub request_id: String,
    pub reason: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

/// `POST …/{id}/revoke/run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMemberRevoke {
    pub request_id: String,
    pub plan_id: String,
    pub plan_digest: String,
}

/// `POST /host/v1/memberships/join`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinMembership {
    pub request_id: String,
    pub coordinator: CoordinatorView,
    pub invite_id: String,
    /// The token the coordinator's operator handed over, base64url; never kept.
    pub token: String,
    pub requested: NarrowView,
}

/// Where and who the coordinator is: out of band, with the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorView {
    /// `https://<host>:<port>`.
    pub address: String,
    pub host_id: String,
    pub fingerprint: String,
}

/// `POST /host/v1/memberships/{id}/sync`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncMembership {
    pub request_id: String,
}

/// A membership refusal, as the Host API answers it.
pub fn refusal_of(error: MembershipError) -> Refusal {
    // What the coordinator refused keeps its code where the caller can act on it; a transport
    // failure is `unavailable`, its detail internal.
    if let MembershipError::Remote { code, reason } = &error {
        let (class, code) = match code.as_str() {
            codes::host::ENROLLMENT_REFUSED => {
                (ErrorClass::Validation, codes::host::ENROLLMENT_REFUSED)
            }
            codes::common::INVALID_ARGUMENT => {
                (ErrorClass::Validation, codes::common::INVALID_ARGUMENT)
            }
            codes::host::MEMBERSHIP_UNKNOWN => {
                (ErrorClass::NotFound, codes::host::MEMBERSHIP_UNKNOWN)
            }
            codes::host::IDENTITY_RESET_INCOMPLETE => {
                (ErrorClass::Conflict, codes::host::IDENTITY_RESET_INCOMPLETE)
            }
            _ => (ErrorClass::Unavailable, codes::common::UNAVAILABLE),
        };
        return Refusal::Api(
            permguard_core::ApiError::new(class, code, "the coordinator did not complete it")
                .with_internal(format!("`{code}`: {reason}")),
        );
    }
    let class = match &error {
        MembershipError::Unknown(_) => ErrorClass::NotFound,
        MembershipError::Conflict { expected, current } => {
            return Refusal::revision_mismatch(*expected, *current);
        }
        MembershipError::Transition { .. }
        | MembershipError::Equivocation(_)
        | MembershipError::NotSuccessor(_)
        | MembershipError::Held(_) => ErrorClass::Conflict,
        MembershipError::AssuranceUnavailable(_)
        | MembershipError::Ring(_)
        | MembershipError::Storage(_) => ErrorClass::Unavailable,
        _ => ErrorClass::Validation,
    };
    let code = match &error {
        MembershipError::Widened(_) => codes::host::MEMBERSHIP_WIDENED,
        MembershipError::TaskUnserved(_) => codes::host::TASK_UNSERVED,
        other => code_of(other),
    };
    if matches!(error, MembershipError::Storage(_)) {
        return Refusal::Api(
            permguard_core::ApiError::new(class, code, "the membership operation did not complete")
                .with_internal(error.to_string()),
        );
    }
    Refusal::new(class, code, error.to_string())
}

fn failure(error: MembershipError) -> Failure<Refusal> {
    if error.is_indeterminate() {
        Failure::Indeterminate(refusal_of(error))
    } else {
        Failure::Refused(refusal_of(error))
    }
}

impl HostApi {
    pub(super) fn memberships(&self) -> Result<&MembershipService, Refusal> {
        self.memberships.as_deref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "no membership store is open on this process",
            )
        })
    }

    /// The assurance profile this Host declares to a coordinator: the one its volume runs under.
    pub(super) fn declared_assurance(&self) -> Result<AssuranceProfile, Refusal> {
        self.assurance.profile.parse().map_err(|_| {
            Refusal::new(
                ErrorClass::Internal,
                codes::common::INTERNAL,
                "the assurance profile in force does not read back",
            )
        })
    }

    /// What the member views read beside a membership: the appraisal, this Host as coordinator
    /// (when its identity is open) and the time.
    fn viewing<'a>(&'a self, memberships: &'a MembershipService) -> Viewing<'a> {
        Viewing {
            appraisal: &memberships.appraisal,
            coordinator: self
                .host_identity()
                .ok()
                .map(crate::identity::Identity::host_id),
            now: self.time.now_secs(),
        }
    }

    /// Records each operator approval an operation took, inside it, before its change: the
    /// principal, the scope, the reason and the expiry (WP-4.2). A record that cannot be written
    /// refuses the operation.
    fn record_approvals(
        &self,
        applying: &Applying<'_>,
        approvals: &[OperatorApproval],
    ) -> Result<(), Failure<Refusal>> {
        if approvals.is_empty() {
            return Ok(());
        }
        let mutations = self.mutations().map_err(Failure::Refused)?;
        let operation_id = applying.operation_id();
        for approval in approvals {
            let target = uuid_text(&approval.membership_id);
            let tasks = approval.task_ids.join(",");
            let record = approval
                .digest()
                .map_err(|error| failure(MembershipError::from(error)))?
                .to_string();
            let facts = [
                ("control", Fact::Text(approval.control.name())),
                ("tasks", Fact::Text(&tasks)),
                ("reason", Fact::Text(&approval.reason)),
                ("expires_at", Fact::Uint(approval.expires_at)),
                ("record", Fact::Text(&record)),
            ];
            mutations
                .project(
                    &AuditEvent::new(
                        AUDIT_ASSURANCE_APPROVED,
                        Subject::Principal(&approval.principal),
                    )
                    .in_operation(operation_id.as_bytes(), AuditPhase::Intent)
                    .with_outcome(AuditOutcome::Ok)
                    .on(&target)
                    .with_facts(&facts),
                )
                .map_err(|error| {
                    // Nothing changed yet: the approval is refused, never applied unrecorded.
                    Failure::Refused(Refusal::Api(
                        permguard_core::ApiError::new(
                            ErrorClass::Unavailable,
                            codes::common::UNAVAILABLE,
                            "the audit trail did not take the operator's approval",
                        )
                        .with_internal(error),
                    ))
                })?;
        }
        Ok(())
    }

    /// Records a binding's revocation inside its operation, before its change: the principal,
    /// the reason and the controls it revoked (WP-4.2). A record that cannot be written refuses
    /// the operation.
    fn record_revocation(
        &self,
        applying: &Applying<'_>,
        principal: &str,
        manifest: &Manifest,
        reason: &str,
    ) -> Result<(), Failure<Refusal>> {
        let mutations = self.mutations().map_err(Failure::Refused)?;
        let operation_id = applying.operation_id();
        let target = uuid_text(&manifest.membership_id);
        let controls = manifest
            .assurance_binding
            .as_ref()
            .map(|binding| {
                binding
                    .claims
                    .iter()
                    .map(|claim| claim.control.name())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let facts = [
            ("controls", Fact::Text(&controls)),
            ("reason", Fact::Text(reason)),
        ];
        mutations
            .project(
                &AuditEvent::new(AUDIT_ASSURANCE_REVOKED, Subject::Principal(principal))
                    .in_operation(operation_id.as_bytes(), AuditPhase::Intent)
                    .with_outcome(AuditOutcome::Ok)
                    .on(&target)
                    .with_facts(&facts),
            )
            .map_err(|error| {
                Failure::Refused(Refusal::Api(
                    permguard_core::ApiError::new(
                        ErrorClass::Unavailable,
                        codes::common::UNAVAILABLE,
                        "the audit trail did not take the revocation",
                    )
                    .with_internal(error),
                ))
            })
    }

    pub(super) fn coordinator(&self) -> Result<Coordinator<'_>, Refusal> {
        Ok(Coordinator {
            identity: self.host_identity()?,
            rings: self.keys.rings(),
        })
    }

    /// `POST /host/v1/members/invites`.
    pub async fn create_invite(
        &self,
        actor: &Actor,
        invite: CreateInvite,
    ) -> Result<InviteCreated, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        // A retired identity offers nothing more.
        self.host_identity()?;
        let memberships = self.memberships()?;
        if invite.max_uses != 1 {
            return Err(invalid("`max_uses` is 1: an invitation is used once"));
        }
        let new = NewInvite {
            selector: selector(&invite.selector)?,
            tasks: tasks(&invite.tasks)?,
            expires: invite
                .expires
                .as_deref()
                .map(|text| time(text, "expires"))
                .transpose()?,
            expected_fingerprint: invite.expected_fingerprint.clone(),
            min_assurance: invite.min_assurance.as_deref().map(profile).transpose()?,
        };
        let mutation = Mutation {
            request_id: invite.request_id.clone(),
            expected_revision: None,
        };
        let now = self.time.now_secs();
        let by = admitted.principal.as_str().to_owned();
        // The engine keeps what a mutation answers, to replay it: the token stays out of it, in
        // this cell, so it reaches the caller once and no file.
        let minted = std::cell::Cell::new(None::<[u8; 32]>);
        let issued = self.transact(
            DOMAIN,
            &admitted.principal,
            INVITE,
            AUDIT_INVITED,
            &mutation,
            &invite,
            None,
            || Ok(()),
            |applying| {
                let (invitation, token) = memberships
                    .store
                    .invite(applying, new.clone(), &by, now)
                    .map_err(failure)?;
                minted.set(Some(token));
                Ok(Applied {
                    revision: 0,
                    target: Some(uuid_text(&invitation.invite_id)),
                    value: InviteIssued {
                        receipt: self.receipt(applying.operation_id(), 0),
                        invite_id: uuid_text(&invitation.invite_id),
                        expires: rfc3339(invitation.expires),
                    },
                })
            },
            |_, _, _| Err(shown_once()),
        )?;
        // A retry is answered from the replay window, which holds no token.
        let token = minted.take().ok_or_else(shown_once)?;
        Ok(InviteCreated {
            receipt: issued.receipt,
            invite_id: issued.invite_id,
            token: URL_SAFE_NO_PAD.encode(token),
            expires: issued.expires,
        })
    }

    /// `GET /host/v1/members/invites`.
    pub fn invites(&self, actor: &Actor) -> Result<Invites, Refusal> {
        let _admitted = self.admit(actor, operations::MEMBERSHIP_READ)?;
        let now = self.time.now_secs();
        Ok(Invites {
            invites: self
                .memberships()?
                .store
                .invitations(now)
                .iter()
                .map(|(invitation, status)| InviteView::of(invitation, status))
                .collect(),
        })
    }

    /// `DELETE /host/v1/members/invites/{id}`.
    pub async fn delete_invite(
        &self,
        actor: &Actor,
        id: &str,
        request_id: String,
    ) -> Result<InviteDeleted, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let memberships = self.memberships()?;
        let invite_id = id_of(id)?;
        let mutation = Mutation {
            request_id,
            expected_revision: None,
        };
        let now = self.time.now_secs();
        self.transact(
            DOMAIN,
            &admitted.principal,
            INVITE_REVOKE,
            AUDIT_INVITE_REVOKED,
            &mutation,
            &id,
            Some(id.to_owned()),
            || Ok(()),
            |applying| {
                memberships
                    .store
                    .revoke_invite(applying, &invite_id, now)
                    .map_err(|error| match error {
                        MembershipError::Unknown(detail) => Failure::Refused(Refusal::new(
                            ErrorClass::NotFound,
                            codes::host::INVITE_UNKNOWN,
                            detail,
                        )),
                        other => failure(other),
                    })?;
                Ok(Applied {
                    revision: 0,
                    target: Some(id.to_owned()),
                    value: InviteDeleted {
                        receipt: self.receipt(applying.operation_id(), 0),
                    },
                })
            },
            |operation_id, revision, _| {
                Ok(InviteDeleted {
                    receipt: self.receipt(operation_id, revision),
                })
            },
        )
    }

    /// `GET /host/v1/members?status=`.
    pub fn members(&self, actor: &Actor, status: Option<&str>) -> Result<Members, Refusal> {
        let _admitted = self.admit(actor, operations::MEMBERSHIP_READ)?;
        let status = status
            .map(|text| {
                text.parse::<Status>()
                    .map_err(|_| invalid(format!("`{text}` is not a membership status")))
            })
            .transpose()?;
        let memberships = self.memberships()?;
        let viewing = self.viewing(memberships);
        Ok(Members {
            members: memberships
                .store
                .memberships()
                .iter()
                .filter(|(_, held)| status.is_none_or(|status| held.status == status))
                .map(|(_, held)| MemberView::of(held, &viewing))
                .collect(),
        })
    }

    /// `GET /host/v1/members/{id}`.
    pub fn member(&self, actor: &Actor, id: &str) -> Result<MemberView, Refusal> {
        let _admitted = self.admit(actor, operations::MEMBERSHIP_READ)?;
        let memberships = self.memberships()?;
        let held = memberships
            .store
            .membership(&id_of(id)?)
            .ok_or_else(|| refusal_of(MembershipError::Unknown(format!("no membership `{id}`"))))?;
        Ok(MemberView::of(&held, &self.viewing(memberships)))
    }

    /// `GET /host/v1/members/{id}/sessions`: the open task sessions of a membership this Host
    /// coordinates, with the boot ids a clone alarm names (WP-4.3).
    pub fn member_sessions(&self, actor: &Actor, id: &str) -> Result<MemberSessions, Refusal> {
        let _admitted = self.admit(actor, operations::MEMBERSHIP_READ)?;
        let memberships = self.memberships()?;
        let membership_id = id_of(id)?;
        memberships
            .store
            .membership(&membership_id)
            .ok_or_else(|| refusal_of(MembershipError::Unknown(format!("no membership `{id}`"))))?;
        let hex = |bytes: &[u8; 16]| -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        };
        let now = self.time.now_secs();
        let mut sessions: Vec<SessionView> = memberships
            .live
            .of(&membership_id)
            .into_iter()
            // A connection whose lease ran out serves nothing more.
            .filter(|live| now < live.expires_at)
            .map(|live| SessionView {
                task_id: live.task_id,
                epoch: live.epoch,
                member_boot_id: hex(&live.member_boot_id),
                coordinator_boot_id: hex(&live.coordinator_boot_id),
                opened_at: rfc3339(live.opened_at),
                expires_at: rfc3339(live.expires_at),
            })
            .collect();
        sessions.sort_by(|a, b| (&a.opened_at, &a.task_id).cmp(&(&b.opened_at, &b.task_id)));
        Ok(MemberSessions { sessions })
    }

    /// `POST …/{id}/approve`: the genesis manifest, the request narrowed when asked.
    pub async fn approve_member(
        &self,
        actor: &Actor,
        id: &str,
        approve: ApproveMember,
    ) -> Result<MemberChanged, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let memberships = self.memberships()?;
        let coordinator = self.coordinator()?;
        let membership_id = id_of(id)?;
        let narrow = approve
            .narrow
            .as_ref()
            .map(|narrow| {
                Ok::<_, Refusal>(Narrow {
                    selector: selector(&narrow.selector)?,
                    tasks: tasks(&narrow.tasks)?,
                })
            })
            .transpose()?;
        let lease_policy = approve.lease_policy.map(|view| LeasePolicy {
            max_session_seconds: view.max_session_seconds,
            offline_grace_seconds: view.offline_grace_seconds,
            clock_skew_seconds: view.clock_skew_seconds,
            dormant_after_seconds: view.dormant_after_seconds,
            revoke_after_seconds: view.revoke_after_seconds,
        });
        let (approvals, evidence) = match &approve.assurance {
            Some(offered) => offer(&offered.approvals, &offered.evidence)?,
            None => (Vec::new(), Vec::new()),
        };
        let offered = Offered {
            appraisal: &memberships.appraisal,
            approvals: &approvals,
            evidence: &evidence,
            principal: admitted.principal.as_str(),
        };
        let now = self.time.now_secs();
        let check = || {
            memberships
                .store
                .check_approve(
                    &coordinator,
                    &memberships.capabilities,
                    &membership_id,
                    narrow.as_ref(),
                    lease_policy,
                    &offered,
                    Some(approve.expected_revision),
                    now,
                )
                .map(|(manifest, _, approvals)| (manifest, approvals))
        };
        let mutation = Mutation {
            request_id: approve.request_id.clone(),
            expected_revision: Some(approve.expected_revision),
        };
        self.transact(
            DOMAIN,
            &admitted.principal,
            APPROVE,
            AUDIT_APPROVED,
            &mutation,
            &(id, &approve),
            Some(id.to_owned()),
            // Checked inside the operation, so a refused approval (a task no Plane serves, a
            // control short of what the policy wants) leaves its intent and its refusal in the
            // audit trail.
            || Ok(()),
            |applying| {
                let (manifest, approvals) = check().map_err(failure)?;
                self.record_approvals(applying, &approvals)?;
                let (envelope, _) = memberships
                    .store
                    .approve(applying, &coordinator, &manifest, now)
                    .map_err(failure)?;
                self.changed(applying, &membership_id, &manifest, &envelope)
            },
            |operation_id, revision, _| {
                self.reconciled(&membership_id, operation_id, revision, APPROVE)
            },
        )
    }

    fn changed(
        &self,
        applying: &crate::operations::mutation::Applying<'_>,
        id: &[u8; 16],
        manifest: &Manifest,
        envelope: &[u8],
    ) -> Result<Applied<MemberChanged>, Failure<Refusal>> {
        let revision = self
            .memberships()
            .map_err(Failure::Refused)?
            .store
            .membership(id)
            .map_or(0, |held| held.revision);
        Ok(Applied {
            revision,
            target: Some(uuid_text(id)),
            value: MemberChanged {
                receipt: self.receipt(applying.operation_id(), revision),
                status: manifest.status.as_str().to_owned(),
                epoch: manifest.epoch,
                manifest: URL_SAFE_NO_PAD.encode(envelope),
            },
        })
    }

    /// The answer of an operation recovery committed: the manifest of the revision it produced,
    /// not whatever the membership holds now.
    fn reconciled(
        &self,
        id: &[u8; 16],
        operation_id: crate::operations::journal::OperationId,
        revision: u64,
        operation: &str,
    ) -> Result<MemberChanged, Refusal> {
        let unreachable = || super::grants::unreachable_reconciliation(operation);
        let store = &self.memberships()?.store;
        // The enrollment is a membership's revision 1, each manifest one more: the manifest of
        // revision `r` is the one of epoch `r - 1`.
        let envelope = store
            .history(id)
            .into_iter()
            .nth(usize::try_from(revision.saturating_sub(2)).unwrap_or(usize::MAX))
            .filter(|_| revision >= 2)
            .ok_or_else(unreachable)?;
        let manifest = Sign1::decode(&envelope)
            .ok()
            .and_then(|sign1| Manifest::decode(sign1.payload_unverified()).ok())
            .ok_or_else(unreachable)?;
        Ok(MemberChanged {
            receipt: self.receipt(operation_id, revision),
            status: manifest.status.as_str().to_owned(),
            epoch: manifest.epoch,
            manifest: URL_SAFE_NO_PAD.encode(envelope),
        })
    }

    /// A coordinator's transition to `to`, one manifest: reject, suspend, resume, fence.
    async fn change(
        &self,
        actor: &Actor,
        id: &str,
        change: ChangeMember,
        to: Status,
        operation: &'static str,
        action: &'static str,
    ) -> Result<MemberChanged, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let memberships = self.memberships()?;
        let coordinator = self.coordinator()?;
        let membership_id = id_of(id)?;
        if change
            .reason
            .as_deref()
            .is_some_and(|reason| reason.len() > 256 || reason.chars().any(char::is_control))
        {
            return Err(invalid("`reason` is printable text of at most 256 bytes"));
        }
        let now = self.time.now_secs();
        let check = || {
            memberships.store.check_successor(
                &coordinator,
                &membership_id,
                to,
                Some(change.expected_revision),
                now,
            )
        };
        let mutation = Mutation {
            request_id: change.request_id.clone(),
            expected_revision: Some(change.expected_revision),
        };
        self.transact(
            DOMAIN,
            &admitted.principal,
            operation,
            action,
            &mutation,
            &(id, operation, &change),
            Some(id.to_owned()),
            || check().map(|_| ()).map_err(refusal_of),
            |applying| {
                let manifest = check().map_err(failure)?;
                let (envelope, _) = if manifest.epoch == 1 {
                    memberships
                        .store
                        .approve(applying, &coordinator, &manifest, now)
                } else {
                    memberships
                        .store
                        .transition(applying, &coordinator, &manifest, now)
                }
                .map_err(failure)?;
                self.changed(applying, &membership_id, &manifest, &envelope)
            },
            |operation_id, revision, _| {
                self.reconciled(&membership_id, operation_id, revision, operation)
            },
        )
    }

    /// `POST …/{id}/reject`.
    pub async fn reject_member(
        &self,
        actor: &Actor,
        id: &str,
        change: ChangeMember,
    ) -> Result<MemberChanged, Refusal> {
        self.change(actor, id, change, Status::Rejected, REJECT, AUDIT_REJECTED)
            .await
    }

    /// `POST …/{id}/suspend`.
    pub async fn suspend_member(
        &self,
        actor: &Actor,
        id: &str,
        change: ChangeMember,
    ) -> Result<MemberChanged, Refusal> {
        self.change(
            actor,
            id,
            change,
            Status::Suspended,
            SUSPEND,
            AUDIT_SUSPENDED,
        )
        .await
    }

    /// `POST …/{id}/resume`: active again, a new epoch.
    pub async fn resume_member(
        &self,
        actor: &Actor,
        id: &str,
        change: ChangeMember,
    ) -> Result<MemberChanged, Refusal> {
        // Admitted before anything of the membership is read.
        let _admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let held = self
            .memberships()?
            .store
            .membership(&id_of(id)?)
            .ok_or_else(|| refusal_of(MembershipError::Unknown(format!("no membership `{id}`"))))?;
        if held.status != Status::Suspended {
            return Err(refusal_of(MembershipError::Transition {
                from: held.status,
                to: Status::Active,
            }));
        }
        self.change(actor, id, change, Status::Active, RESUME, AUDIT_RESUMED)
            .await
    }

    /// `POST …/{id}/fence`: still active, a new epoch.
    pub async fn fence_member(
        &self,
        actor: &Actor,
        id: &str,
        change: ChangeMember,
    ) -> Result<MemberChanged, Refusal> {
        // Admitted before anything of the membership is read.
        let _admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let held = self
            .memberships()?
            .store
            .membership(&id_of(id)?)
            .ok_or_else(|| refusal_of(MembershipError::Unknown(format!("no membership `{id}`"))))?;
        if held.status != Status::Active {
            return Err(refusal_of(MembershipError::Transition {
                from: held.status,
                to: Status::Active,
            }));
        }
        self.change(actor, id, change, Status::Active, FENCE, AUDIT_FENCED)
            .await
    }

    /// `POST …/{id}/appraise`: the binding renewed from the approvals and evidence given, or
    /// revoked; still active, a new epoch.
    pub async fn appraise_member(
        &self,
        actor: &Actor,
        id: &str,
        appraise: AppraiseMember,
    ) -> Result<MemberChanged, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let memberships = self.memberships()?;
        let coordinator = self.coordinator()?;
        let membership_id = id_of(id)?;
        if let Some(revoke) = &appraise.revoke {
            crate::membership::record::check_reason(&revoke.reason)
                .map_err(|error| invalid(error.0))?;
        }
        let (approvals, evidence) = offer(&appraise.approvals, &appraise.evidence)?;
        let offered = Offered {
            appraisal: &memberships.appraisal,
            approvals: &approvals,
            evidence: &evidence,
            principal: admitted.principal.as_str(),
        };
        let now = self.time.now_secs();
        let check = || {
            memberships.store.check_appraise(
                &coordinator,
                &membership_id,
                &offered,
                appraise.revoke.is_some(),
                Some(appraise.expected_revision),
                now,
            )
        };
        let mutation = Mutation {
            request_id: appraise.request_id.clone(),
            expected_revision: Some(appraise.expected_revision),
        };
        self.transact(
            DOMAIN,
            &admitted.principal,
            APPRAISE,
            AUDIT_APPRAISED,
            &mutation,
            &(id, &appraise),
            Some(id.to_owned()),
            // Inside the operation, so a refused appraisal is in the audit trail too.
            || Ok(()),
            |applying| {
                let (manifest, approvals) = check().map_err(failure)?;
                self.record_approvals(applying, &approvals)?;
                if let Some(revoke) = &appraise.revoke {
                    self.record_revocation(
                        applying,
                        admitted.principal.as_str(),
                        &manifest,
                        &revoke.reason,
                    )?;
                }
                let (envelope, _) = memberships
                    .store
                    .transition(applying, &coordinator, &manifest, now)
                    .map_err(failure)?;
                self.changed(applying, &membership_id, &manifest, &envelope)
            },
            |operation_id, revision, _| {
                self.reconciled(&membership_id, operation_id, revision, APPRAISE)
            },
        )
    }

    /// `POST …/{id}/revoke/plan`.
    pub async fn plan_member_revoke(
        &self,
        actor: &Actor,
        id: &str,
        plan: PlanMemberRevoke,
    ) -> Result<Planned, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let memberships = self.memberships()?;
        let coordinator = self.coordinator()?;
        let membership_id = id_of(id)?;
        if plan.reason.is_empty()
            || plan.reason.len() > 256
            || plan.reason.chars().any(char::is_control)
        {
            return Err(invalid("`reason` is printable text of 1 to 256 bytes"));
        }
        let now = self.time.now_secs();
        let current = || -> Result<u64, Refusal> {
            memberships
                .store
                .check_successor(
                    &coordinator,
                    &membership_id,
                    Status::Revoked,
                    plan.expected_revision,
                    now,
                )
                .map_err(refusal_of)?;
            Ok(memberships
                .store
                .membership(&membership_id)
                .map_or(0, |held| held.revision))
        };
        let mutation = Mutation {
            request_id: plan.request_id.clone(),
            expected_revision: plan.expected_revision,
        };
        let target = format!("{id}\n{}", plan.reason);
        self.transact(
            DOMAIN,
            &admitted.principal,
            REVOKE_PLAN,
            AUDIT_REVOKE_PLANNED,
            &mutation,
            &(id, &plan),
            Some(id.to_owned()),
            || current().map(|_| ()),
            |applying| {
                let revision = current().map_err(Failure::Refused)?;
                let expires = now.saturating_add(PLAN_LIFETIME.as_secs());
                let plan_id = mint_id().map_err(Failure::Refused)?;
                let digest = plan_digest(
                    &plan_id,
                    REVOKE,
                    &target,
                    revision,
                    admitted.principal.as_str(),
                    expires,
                );
                self.replay
                    .plan(
                        applying,
                        Plan {
                            plan_id: plan_id.clone(),
                            operation: REVOKE.to_owned(),
                            target: target.clone(),
                            revision,
                            digest: digest.clone(),
                            expires,
                            principal: admitted.principal.as_str().to_owned(),
                        },
                    )
                    .map_err(Failure::Refused)?;
                Ok(Applied {
                    revision,
                    target: Some(id.to_owned()),
                    value: Planned {
                        plan_id,
                        plan_digest: digest,
                        expires: rfc3339(expires),
                        revision,
                    },
                })
            },
            |_, _, _| Err(super::grants::unreachable_reconciliation(REVOKE_PLAN)),
        )
    }

    /// `POST …/{id}/revoke/run`: the revoked manifest.
    pub async fn run_member_revoke(
        &self,
        actor: &Actor,
        id: &str,
        run: RunMemberRevoke,
    ) -> Result<MemberChanged, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let memberships = self.memberships()?;
        let coordinator = self.coordinator()?;
        let membership_id = id_of(id)?;
        let now = self.time.now_secs();
        let presented = || -> Result<Plan, Refusal> {
            let plan = self
                .replay
                .plan_of(&admitted.principal, &run.plan_id, now)?;
            if plan.operation != REVOKE || plan.target.split('\n').next() != Some(id) {
                return Err(Refusal::new(
                    ErrorClass::NotFound,
                    codes::host::PLAN_UNKNOWN,
                    "no plan of that id is held for this membership",
                ));
            }
            if plan.digest != run.plan_digest {
                return Err(Refusal::new(
                    ErrorClass::Validation,
                    codes::host::PLAN_DIGEST_MISMATCH,
                    "the plan digest presented is not the one the plan step answered",
                ));
            }
            Ok(plan)
        };
        let mutation = Mutation {
            request_id: run.request_id.clone(),
            expected_revision: None,
        };
        self.transact(
            DOMAIN,
            &admitted.principal,
            REVOKE_RUN,
            AUDIT_REVOKED,
            &mutation,
            &(id, &run),
            Some(id.to_owned()),
            || presented().map(|_| ()),
            |applying| {
                let plan = presented().map_err(Failure::Refused)?;
                let manifest = memberships
                    .store
                    .check_successor(
                        &coordinator,
                        &membership_id,
                        Status::Revoked,
                        Some(plan.revision),
                        now,
                    )
                    .map_err(failure)?;
                let (envelope, _) = memberships
                    .store
                    .transition(applying, &coordinator, &manifest, now)
                    .map_err(failure)?;
                if let Err(error) = self
                    .replay
                    .consume(applying, &admitted.principal, &run.plan_id)
                {
                    tracing::warn!(
                        event.name = "host.plan_unconsumed",
                        component = super::COMPONENT,
                        error = %error,
                        "a run plan could not be marked consumed; the membership is revoked"
                    );
                }
                self.changed(applying, &membership_id, &manifest, &envelope)
            },
            |operation_id, revision, _| {
                self.reconciled(&membership_id, operation_id, revision, REVOKE_RUN)
            },
        )
    }

    fn member_side(&self) -> Result<(&MembershipService, &dyn Connector), Refusal> {
        let memberships = self.memberships()?;
        let connector = memberships.connector.as_deref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::host::PEER_CLIENT_UNCONFIGURED,
                "this Host cannot reach a coordinator: its Host listener has no TLS certificate \
                 or no client CA",
            )
        })?;
        Ok((memberships, connector))
    }

    pub(super) fn acting_member<'a>(
        &'a self,
        memberships: &'a MembershipService,
        connector: &'a dyn Connector,
    ) -> Result<Member<'a>, Refusal> {
        Ok(Member {
            store: &memberships.store,
            mutations: self.mutations()?,
            identity: self.host_identity()?,
            rings: self.keys.rings(),
            capabilities: &memberships.capabilities,
            connector,
            declared_assurance: self.declared_assurance()?,
            time: &self.time,
        })
    }

    /// `POST /host/v1/members/enroll` as a request of its own: an enrollment runs only inside a
    /// proven peer session, whoever asks.
    pub fn enroll_over_rest(&self) -> Refusal {
        Refusal::new(
            ErrorClass::Unavailable,
            codes::host::PEER_SESSIONS_UNSERVEABLE,
            "an enrollment runs inside a peer session, operation `enroll`, on the \
             `permguard.host.v1.IdentityService/PeerChannel` stream, never as a request of its own",
        )
    }

    /// `POST /host/v1/tasks/{task}/session`: a task session runs on the `PeerChannel`, opened by
    /// its lease request (owner decision of 2026-10-10), never as a request of its own.
    pub fn task_session_over_rest(&self) -> Refusal {
        Refusal::new(
            ErrorClass::Unavailable,
            codes::host::PEER_SESSIONS_UNSERVEABLE,
            "a task session runs inside a peer session, operation `task`, on the \
             `permguard.host.v1.IdentityService/PeerChannel` stream, opened by its lease request",
        )
    }

    /// `POST /host/v1/memberships/join`: enrolls with a coordinator and records the membership
    /// `pending` on this side.
    pub async fn join_membership(
        &self,
        actor: &Actor,
        join: JoinMembership,
    ) -> Result<MemberView, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let (memberships, connector) = self.member_side()?;
        Mutation {
            request_id: join.request_id.clone(),
            expected_revision: None,
        }
        .validated()?;
        let host_id = id_of(&join.coordinator.host_id)?;
        if !join.coordinator.address.starts_with("https://") {
            return Err(invalid(
                "the coordinator's address is `https://<host>:<port>`",
            ));
        }
        let token = URL_SAFE_NO_PAD
            .decode(&join.token)
            .map_err(|_| invalid("`token` is base64url"))?;
        let held = self
            .acting_member(memberships, connector)?
            .join(
                Initiator::Principal(admitted.principal.as_str().to_owned()),
                Join {
                    coordinator: Target {
                        address: join.coordinator.address.clone(),
                        host_id,
                        fingerprint: join.coordinator.fingerprint.clone(),
                    },
                    invite_id: id_of(&join.invite_id)?,
                    token,
                    selector: selector(&join.requested.selector)?,
                    tasks: tasks(&join.requested.tasks)?,
                },
            )
            .await
            .map_err(refusal_of)?;
        Ok(MemberView::of(&held, &self.viewing(memberships)))
    }

    /// `POST /host/v1/memberships/{id}/sync`: the coordinator's manifests since the one held.
    pub async fn sync_membership(
        &self,
        actor: &Actor,
        id: &str,
        sync: SyncMembership,
    ) -> Result<MemberView, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let (memberships, connector) = self.member_side()?;
        Mutation {
            request_id: sync.request_id.clone(),
            expected_revision: None,
        }
        .validated()?;
        let held = self
            .acting_member(memberships, connector)?
            .sync(
                Initiator::Principal(admitted.principal.as_str().to_owned()),
                &id_of(id)?,
            )
            .await
            .map_err(refusal_of)?;
        Ok(MemberView::of(&held, &self.viewing(memberships)))
    }
}

#[cfg(test)]
pub(crate) mod tests;
