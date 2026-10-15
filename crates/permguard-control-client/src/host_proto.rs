// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API's views from and to `permguard.host.v1`, field for field (WP-4.8): what the
//! server's gRPC binding maps one way, mapped back, so a command reads the same view over gRPC as
//! over REST. Bytes the views spell base64url travel raw on gRPC; an empty string is an absent
//! member, as everywhere on gRPC.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_host::api::grants::Created;
use permguard_host::api::members::{
    AppraisalView, AssuranceView, ClaimView, HostView, InviteView, LeasePolicyView, LimitsView,
    MemberChanged, MemberReportedView, MemberView, NarrowView, ProgressResourceView,
    RequirementView, SessionView, TaskObservedView, TaskView, ZoneReceiptView, ZoneTupleView,
};
use permguard_host::api::{AuditReference, GrantView, Planned, Receipt, Revoked};

use crate::host_v1 as proto;

/// Bytes as the views spell them.
pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The raw bytes a view spells base64url, for a request; a member that does not decode is the
/// caller's mistake, refused before anything is sent.
pub(crate) fn raw(text: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| "a member that should be base64url is not".to_owned())
}

fn blank(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

pub(crate) fn receipt(receipt: Option<proto::Receipt>) -> Receipt {
    let receipt = receipt.unwrap_or_default();
    let audit = receipt.audit.unwrap_or_default();
    Receipt {
        operation_id: receipt.operation_id,
        revision: receipt.revision,
        audit: AuditReference {
            trail: audit.trail,
            seq: audit.seq,
            digest: audit.digest,
        },
    }
}

pub(crate) fn task_out(task: &TaskView) -> proto::MembershipTask {
    proto::MembershipTask {
        task_id: task.task_id.clone(),
        r#type: task.task_type.clone(),
        provider_role: task.provider_role.clone().unwrap_or_default(),
        consumer_role: task.consumer_role.clone().unwrap_or_default(),
        selector: task.selector.clone(),
        resource_types: task.resource_types.clone(),
        required: task.required,
        limits: Some(proto::TaskLimits {
            max_body_bytes: task.limits.max_body_bytes,
            max_concurrency: task.limits.max_concurrency,
            max_rate_per_minute: task.limits.max_rate_per_minute,
            max_batch_records: task.limits.max_batch_records,
            retention_seconds: task.limits.retention_seconds,
        }),
        assurance_requirements: task.assurance_requirements.clone(),
        version: task.version.unwrap_or(1),
    }
}

pub(crate) fn task_in(task: proto::MembershipTask) -> TaskView {
    let limits = task.limits.unwrap_or_default();
    TaskView {
        task_id: task.task_id,
        task_type: task.r#type,
        provider_role: blank(task.provider_role),
        consumer_role: blank(task.consumer_role),
        selector: task.selector,
        resource_types: task.resource_types,
        required: task.required,
        limits: LimitsView {
            max_body_bytes: limits.max_body_bytes,
            max_concurrency: limits.max_concurrency,
            max_rate_per_minute: limits.max_rate_per_minute,
            max_batch_records: limits.max_batch_records,
            retention_seconds: limits.retention_seconds,
        },
        assurance_requirements: task.assurance_requirements,
        version: (task.version != 0).then_some(task.version),
    }
}

pub(crate) fn scope_out(scope: &NarrowView) -> proto::MembershipScope {
    proto::MembershipScope {
        selector: scope.selector.clone(),
        tasks: scope.tasks.iter().map(task_out).collect(),
    }
}

fn host_in(host: Option<proto::MembershipHost>) -> HostView {
    let host = host.unwrap_or_default();
    HostView {
        host_id: host.host_id,
        epoch: host.epoch,
        fingerprint: host.fingerprint,
    }
}

pub(crate) fn lease_out(policy: &LeasePolicyView) -> proto::LeasePolicy {
    proto::LeasePolicy {
        max_session_seconds: policy.max_session_seconds,
        offline_grace_seconds: policy.offline_grace_seconds,
        clock_skew_seconds: policy.clock_skew_seconds,
        dormant_after_seconds: policy.dormant_after_seconds,
        revoke_after_seconds: policy.revoke_after_seconds,
    }
}

fn lease_in(policy: proto::LeasePolicy) -> LeasePolicyView {
    LeasePolicyView {
        max_session_seconds: policy.max_session_seconds,
        offline_grace_seconds: policy.offline_grace_seconds,
        clock_skew_seconds: policy.clock_skew_seconds,
        dormant_after_seconds: policy.dormant_after_seconds,
        revoke_after_seconds: policy.revoke_after_seconds,
    }
}

fn assurance_in(binding: proto::AssuranceBinding) -> AssuranceView {
    AssuranceView {
        verdict: binding.verdict,
        current: binding.current,
        policy_revision: binding.policy_revision,
        task_ids: binding.task_ids,
        claims: binding
            .claims
            .into_iter()
            .map(|claim| ClaimView {
                control: claim.control,
                class: claim.class,
                by: claim.by,
            })
            .collect(),
        appraised_by: binding.appraised_by,
        issued_at: binding.issued_at,
        expires_at: binding.expires_at,
        binding_digest: binding.binding_digest,
    }
}

pub(crate) fn member_in(member: proto::Member) -> MemberView {
    MemberView {
        membership_id: member.membership_id,
        role: member.role,
        status: member.status,
        epoch: member.epoch,
        revision: member.revision,
        coordinator: host_in(member.coordinator),
        member: host_in(member.member),
        selector: member.selector,
        tasks: member.tasks.into_iter().map(task_in).collect(),
        member_assurance: member.member_assurance,
        lease_policy: member.lease_policy.map(lease_in),
        manifest: member.manifest.as_deref().map(b64),
        updated_at: member.updated_at,
        last_session_at: member.last_session_at,
        assurance: member.assurance.map(assurance_in),
        appraisal: member.appraisal.map(|appraisal| AppraisalView {
            policy_revision: appraisal.policy_revision,
            nonce: b64(&appraisal.nonce),
            requirements: appraisal
                .requirements
                .into_iter()
                .map(|requirement| RequirementView {
                    control: requirement.control,
                    wants: requirement.wants,
                    declared: requirement.declared,
                })
                .collect(),
        }),
        held_epoch: member.held_epoch,
        task_progress: member
            .task_progress
            .into_iter()
            .map(|task| TaskObservedView {
                task_id: task.task_id,
                last_session_at: task.last_session_at,
                member_reported: task.member_reported.map(|report| MemberReportedView {
                    report_seq: report.report_seq,
                    manifest_epoch: report.manifest_epoch,
                    member_boot_id: report.member_boot_id,
                    reported_at: report.reported_at,
                    received_at: report.received_at,
                    resources: report
                        .resources
                        .into_iter()
                        .map(|resource| ProgressResourceView {
                            resource: resource.resource,
                            state: resource.state,
                            frontier: resource.frontier,
                            checkpoint_digest: resource.checkpoint_digest,
                            verified_at: resource.verified_at,
                            reason: resource.reason,
                        })
                        .collect(),
                }),
                stale: task.stale,
                zone_receipts: task
                    .zone_receipts
                    .into_iter()
                    .map(|receipt| ZoneReceiptView {
                        resource: receipt.resource,
                        manifest_epoch: receipt.manifest_epoch,
                        confirmed_at: receipt.confirmed_at,
                        transcript_digest: receipt.transcript_digest,
                        keys: receipt
                            .keys
                            .into_iter()
                            .map(|key| ZoneTupleView {
                                purpose: key.purpose,
                                zone_id: key.zone_id,
                                scope: key.scope,
                                version: key.version,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

pub(crate) fn invite_in(invite: proto::Invite) -> InviteView {
    InviteView {
        invite_id: invite.invite_id,
        selector: invite.selector,
        tasks: invite.tasks.into_iter().map(task_in).collect(),
        expires: invite.expires,
        expected_fingerprint: invite.expected_fingerprint,
        min_assurance: invite.min_assurance,
        max_uses: invite.max_uses,
        status: invite.status,
        created_at: invite.created_at,
        created_by: invite.created_by,
    }
}

/// What every transition answers.
pub(crate) fn changed(
    receipt_of: Option<proto::Receipt>,
    status: String,
    epoch: u64,
    manifest: &[u8],
) -> MemberChanged {
    MemberChanged {
        receipt: receipt(receipt_of),
        status,
        epoch,
        manifest: b64(manifest),
    }
}

pub(crate) fn session_in(session: proto::MemberSession) -> SessionView {
    SessionView {
        task_id: session.task_id,
        epoch: session.epoch,
        member_boot_id: session.member_boot_id,
        coordinator_boot_id: session.coordinator_boot_id,
        opened_at: session.opened_at,
        expires_at: session.expires_at,
    }
}

pub(crate) fn grant_in(grant: Option<proto::Grant>) -> GrantView {
    let grant = grant.unwrap_or_default();
    GrantView {
        grant_id: grant.grant_id,
        principal: grant.principal,
        operations: grant.operations,
        selector: grant.selector,
        resource_types: grant.resource_types,
        constraints: grant.constraints.into_iter().collect(),
        revision: grant.revision,
        status: grant.status,
        issued_by: grant.issued_by,
        issued_at: grant.issued_at,
        expires_at: grant.expires_at,
    }
}

pub(crate) fn created(answer: proto::CreateGrantResponse) -> Created {
    Created {
        receipt: receipt(answer.receipt),
        grant: grant_in(answer.grant),
    }
}

pub(crate) fn revoked(answer: proto::RunGrantRevokeResponse) -> Revoked {
    Revoked {
        receipt: receipt(answer.receipt),
        grant: grant_in(answer.grant),
    }
}

/// A plan, from the members every plan answer carries.
pub(crate) fn planned(
    plan_id: String,
    plan_digest: String,
    expires: String,
    revision: u64,
    receipt: &[u8],
    approvals_required: u64,
) -> Planned {
    Planned {
        plan_id,
        plan_digest,
        expires,
        revision,
        receipt: b64(receipt),
        approvals_required,
    }
}
