// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard.host.v1.MembershipService` (WP-4.1): the memberships, each rpc one call into the
//! facade the REST routes call. Bytes the facade answers base64url travel raw; an empty string is
//! an absent member, as it is everywhere on gRPC.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tonic::{Request, Response, Status};

use permguard_host::api::members::{
    AppraiseMember, ApprovalView, ApproveMember, AssuranceOffer, AssuranceView, ChangeMember,
    CoordinatorView, CreateInvite, EvidenceView, JoinMembership, LeasePolicyView, LimitsView,
    MemberChanged, MemberView, NarrowView, PlanMemberRevoke, RevokeBinding, RunMemberRevoke,
    SyncMembership, TaskView,
};

use super::super::v1;
use super::super::v1::membership_service_server::MembershipService;
use super::{Answer, Served, blank, raw, receipt, unimplemented};

fn task_in(task: v1::MembershipTask) -> TaskView {
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
    }
}

fn task_out(task: TaskView) -> v1::MembershipTask {
    v1::MembershipTask {
        task_id: task.task_id,
        r#type: task.task_type,
        provider_role: task.provider_role.unwrap_or_default(),
        consumer_role: task.consumer_role.unwrap_or_default(),
        selector: task.selector,
        resource_types: task.resource_types,
        required: task.required,
        limits: Some(v1::TaskLimits {
            max_body_bytes: task.limits.max_body_bytes,
            max_concurrency: task.limits.max_concurrency,
            max_rate_per_minute: task.limits.max_rate_per_minute,
            max_batch_records: task.limits.max_batch_records,
            retention_seconds: task.limits.retention_seconds,
        }),
        assurance_requirements: task.assurance_requirements,
    }
}

fn scope_in(scope: v1::MembershipScope) -> NarrowView {
    NarrowView {
        selector: scope.selector,
        tasks: scope.tasks.into_iter().map(task_in).collect(),
    }
}

fn lease_in(policy: v1::LeasePolicy) -> LeasePolicyView {
    LeasePolicyView {
        max_session_seconds: policy.max_session_seconds,
        offline_grace_seconds: policy.offline_grace_seconds,
        clock_skew_seconds: policy.clock_skew_seconds,
        dormant_after_seconds: policy.dormant_after_seconds,
        revoke_after_seconds: policy.revoke_after_seconds,
    }
}

fn lease_out(policy: LeasePolicyView) -> v1::LeasePolicy {
    v1::LeasePolicy {
        max_session_seconds: policy.max_session_seconds,
        offline_grace_seconds: policy.offline_grace_seconds,
        clock_skew_seconds: policy.clock_skew_seconds,
        dormant_after_seconds: policy.dormant_after_seconds,
        revoke_after_seconds: policy.revoke_after_seconds,
    }
}

pub(super) fn host_out(host: permguard_host::api::members::HostView) -> v1::MembershipHost {
    v1::MembershipHost {
        host_id: host.host_id,
        epoch: host.epoch,
        fingerprint: host.fingerprint,
    }
}

fn approvals_in(approvals: Vec<v1::OperatorApproval>) -> Vec<ApprovalView> {
    approvals
        .into_iter()
        .map(|approval| ApprovalView {
            control: approval.control,
            reason: approval.reason,
            expires_at: approval.expires_at,
        })
        .collect()
}

/// The evidence travels raw on gRPC and base64url to the facade, as every byte member does.
fn evidence_in(evidence: Vec<v1::AttestationEvidence>) -> Vec<EvidenceView> {
    evidence
        .into_iter()
        .map(|item| EvidenceView {
            verifier: item.verifier,
            evidence: URL_SAFE_NO_PAD.encode(item.evidence),
        })
        .collect()
}

fn assurance_out(view: AssuranceView) -> v1::AssuranceBinding {
    v1::AssuranceBinding {
        verdict: view.verdict,
        current: view.current,
        policy_revision: view.policy_revision,
        task_ids: view.task_ids,
        claims: view
            .claims
            .into_iter()
            .map(|claim| v1::AssuranceClaim {
                control: claim.control,
                class: claim.class,
                by: claim.by,
            })
            .collect(),
        appraised_by: view.appraised_by,
        issued_at: view.issued_at,
        expires_at: view.expires_at,
        binding_digest: view.binding_digest,
    }
}

fn member_out(view: MemberView) -> Result<v1::Member, Status> {
    Ok(v1::Member {
        membership_id: view.membership_id,
        role: view.role,
        status: view.status,
        epoch: view.epoch,
        revision: view.revision,
        coordinator: Some(host_out(view.coordinator)),
        member: Some(host_out(view.member)),
        selector: view.selector,
        tasks: view.tasks.into_iter().map(task_out).collect(),
        member_assurance: view.member_assurance,
        lease_policy: view.lease_policy.map(lease_out),
        manifest: view.manifest.as_deref().map(raw).transpose()?,
        updated_at: view.updated_at,
        last_session_at: view.last_session_at,
        assurance: view.assurance.map(assurance_out),
        appraisal: view
            .appraisal
            .map(|appraisal| {
                Ok::<_, Status>(v1::AppraisalState {
                    policy_revision: appraisal.policy_revision,
                    nonce: raw(&appraisal.nonce)?,
                    requirements: appraisal
                        .requirements
                        .into_iter()
                        .map(|requirement| v1::AssuranceRequirement {
                            control: requirement.control,
                            wants: requirement.wants,
                            declared: requirement.declared,
                        })
                        .collect(),
                })
            })
            .transpose()?,
    })
}

fn change_in(
    membership_id: &str,
    request_id: String,
    expected_revision: u64,
    reason: Option<String>,
) -> (String, ChangeMember) {
    (
        membership_id.to_owned(),
        ChangeMember {
            request_id,
            expected_revision,
            reason,
        },
    )
}

/// The members every transition answers: receipt, status, epoch and the manifest's bytes.
struct Changed {
    receipt: Option<v1::Receipt>,
    status: String,
    epoch: u64,
    manifest: Vec<u8>,
}

fn changed(changed: MemberChanged) -> Result<Changed, Status> {
    Ok(Changed {
        receipt: Some(receipt(changed.receipt)),
        status: changed.status,
        epoch: changed.epoch,
        manifest: raw(&changed.manifest)?,
    })
}

#[tonic::async_trait]
impl MembershipService for Served {
    async fn create_invite(
        &self,
        request: Request<v1::CreateInviteRequest>,
    ) -> Answer<v1::CreateInviteResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let created = self
            .api
            .create_invite(
                &actor,
                CreateInvite {
                    request_id: asked.request_id,
                    selector: asked.selector,
                    tasks: asked.tasks.into_iter().map(task_in).collect(),
                    expires: asked.expires,
                    expected_fingerprint: asked.expected_fingerprint,
                    min_assurance: asked.min_assurance,
                    max_uses: asked.max_uses.unwrap_or(1),
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::CreateInviteResponse {
            receipt: Some(receipt(created.receipt)),
            invite_id: created.invite_id,
            token: raw(&created.token)?,
            expires: created.expires,
        }))
    }

    async fn list_invites(
        &self,
        request: Request<v1::ListInvitesRequest>,
    ) -> Answer<v1::ListInvitesResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self
            .api
            .invites(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListInvitesResponse {
            invites: listed
                .invites
                .into_iter()
                .map(|invite| v1::Invite {
                    invite_id: invite.invite_id,
                    selector: invite.selector,
                    tasks: invite.tasks.into_iter().map(task_out).collect(),
                    expires: invite.expires,
                    expected_fingerprint: invite.expected_fingerprint,
                    min_assurance: invite.min_assurance,
                    max_uses: invite.max_uses,
                    status: invite.status,
                    created_at: invite.created_at,
                    created_by: invite.created_by,
                })
                .collect(),
        }))
    }

    async fn delete_invite(
        &self,
        request: Request<v1::DeleteInviteRequest>,
    ) -> Answer<v1::DeleteInviteResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let deleted = self
            .api
            .delete_invite(&actor, &asked.invite_id, asked.request_id)
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::DeleteInviteResponse {
            receipt: Some(receipt(deleted.receipt)),
        }))
    }

    async fn list_members(
        &self,
        request: Request<v1::ListMembersRequest>,
    ) -> Answer<v1::ListMembersResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let listed = self
            .api
            .members(&actor, blank(asked.status).as_deref())
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListMembersResponse {
            members: listed
                .members
                .into_iter()
                .map(member_out)
                .collect::<Result<_, _>>()?,
        }))
    }

    async fn get_member(
        &self,
        request: Request<v1::GetMemberRequest>,
    ) -> Answer<v1::GetMemberResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let view = self
            .api
            .member(&actor, &asked.membership_id)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetMemberResponse {
            member: Some(member_out(view)?),
        }))
    }

    async fn approve_member(
        &self,
        request: Request<v1::ApproveMemberRequest>,
    ) -> Answer<v1::ApproveMemberResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let answer = self
            .api
            .approve_member(
                &actor,
                &asked.membership_id,
                ApproveMember {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    narrow: asked.narrow.map(scope_in),
                    lease_policy: asked.lease_policy.map(lease_in),
                    assurance: asked.assurance.map(|offer| AssuranceOffer {
                        approvals: approvals_in(offer.approvals),
                        evidence: evidence_in(offer.evidence),
                    }),
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        let Changed {
            receipt,
            status,
            epoch,
            manifest,
        } = changed(answer)?;
        Ok(Response::new(v1::ApproveMemberResponse {
            receipt,
            status,
            epoch,
            manifest,
        }))
    }

    async fn reject_member(
        &self,
        request: Request<v1::RejectMemberRequest>,
    ) -> Answer<v1::RejectMemberResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let (id, change) = change_in(
            &asked.membership_id,
            asked.request_id,
            asked.expected_revision,
            asked.reason,
        );
        let answer = self
            .api
            .reject_member(&actor, &id, change)
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        let Changed {
            receipt,
            status,
            epoch,
            manifest,
        } = changed(answer)?;
        Ok(Response::new(v1::RejectMemberResponse {
            receipt,
            status,
            epoch,
            manifest,
        }))
    }

    async fn suspend_member(
        &self,
        request: Request<v1::SuspendMemberRequest>,
    ) -> Answer<v1::SuspendMemberResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let (id, change) = change_in(
            &asked.membership_id,
            asked.request_id,
            asked.expected_revision,
            asked.reason,
        );
        let answer = self
            .api
            .suspend_member(&actor, &id, change)
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        let Changed {
            receipt,
            status,
            epoch,
            manifest,
        } = changed(answer)?;
        Ok(Response::new(v1::SuspendMemberResponse {
            receipt,
            status,
            epoch,
            manifest,
        }))
    }

    async fn resume_member(
        &self,
        request: Request<v1::ResumeMemberRequest>,
    ) -> Answer<v1::ResumeMemberResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let (id, change) = change_in(
            &asked.membership_id,
            asked.request_id,
            asked.expected_revision,
            asked.reason,
        );
        let answer = self
            .api
            .resume_member(&actor, &id, change)
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        let Changed {
            receipt,
            status,
            epoch,
            manifest,
        } = changed(answer)?;
        Ok(Response::new(v1::ResumeMemberResponse {
            receipt,
            status,
            epoch,
            manifest,
        }))
    }

    async fn fence_member(
        &self,
        request: Request<v1::FenceMemberRequest>,
    ) -> Answer<v1::FenceMemberResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let (id, change) = change_in(
            &asked.membership_id,
            asked.request_id,
            asked.expected_revision,
            asked.reason,
        );
        let answer = self
            .api
            .fence_member(&actor, &id, change)
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        let Changed {
            receipt,
            status,
            epoch,
            manifest,
        } = changed(answer)?;
        Ok(Response::new(v1::FenceMemberResponse {
            receipt,
            status,
            epoch,
            manifest,
        }))
    }

    async fn appraise_member(
        &self,
        request: Request<v1::AppraiseMemberRequest>,
    ) -> Answer<v1::AppraiseMemberResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let answer = self
            .api
            .appraise_member(
                &actor,
                &asked.membership_id,
                AppraiseMember {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    approvals: approvals_in(asked.approvals),
                    evidence: evidence_in(asked.evidence),
                    revoke: asked.revoke.map(|revoke| RevokeBinding {
                        reason: revoke.reason,
                    }),
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        let Changed {
            receipt,
            status,
            epoch,
            manifest,
        } = changed(answer)?;
        Ok(Response::new(v1::AppraiseMemberResponse {
            receipt,
            status,
            epoch,
            manifest,
        }))
    }

    async fn plan_member_revoke(
        &self,
        request: Request<v1::PlanMemberRevokeRequest>,
    ) -> Answer<v1::PlanMemberRevokeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let planned = self
            .api
            .plan_member_revoke(
                &actor,
                &asked.membership_id,
                PlanMemberRevoke {
                    request_id: asked.request_id,
                    reason: asked.reason,
                    expected_revision: asked.expected_revision,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::PlanMemberRevokeResponse {
            plan_id: planned.plan_id,
            plan_digest: planned.plan_digest,
            expires: planned.expires,
            revision: planned.revision,
        }))
    }

    async fn run_member_revoke(
        &self,
        request: Request<v1::RunMemberRevokeRequest>,
    ) -> Answer<v1::RunMemberRevokeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let answer = self
            .api
            .run_member_revoke(
                &actor,
                &asked.membership_id,
                RunMemberRevoke {
                    request_id: asked.request_id,
                    plan_id: asked.plan_id,
                    plan_digest: asked.plan_digest,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        let Changed {
            receipt,
            status,
            epoch,
            manifest,
        } = changed(answer)?;
        Ok(Response::new(v1::RunMemberRevokeResponse {
            receipt,
            status,
            epoch,
            manifest,
        }))
    }

    async fn list_member_sessions(
        &self,
        _request: Request<v1::ListMemberSessionsRequest>,
    ) -> Answer<v1::ListMemberSessionsResponse> {
        Err(unimplemented("ListMemberSessions"))
    }

    async fn join_membership(
        &self,
        request: Request<v1::JoinMembershipRequest>,
    ) -> Answer<v1::JoinMembershipResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let coordinator = asked.coordinator.unwrap_or_default();
        let view = self
            .api
            .join_membership(
                &actor,
                JoinMembership {
                    request_id: asked.request_id,
                    coordinator: CoordinatorView {
                        address: coordinator.address,
                        host_id: coordinator.host_id,
                        fingerprint: coordinator.fingerprint,
                    },
                    invite_id: asked.invite_id,
                    token: URL_SAFE_NO_PAD.encode(&asked.token),
                    requested: scope_in(asked.requested.unwrap_or_default()),
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::JoinMembershipResponse {
            member: Some(member_out(view)?),
        }))
    }

    async fn sync_membership(
        &self,
        request: Request<v1::SyncMembershipRequest>,
    ) -> Answer<v1::SyncMembershipResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let view = self
            .api
            .sync_membership(
                &actor,
                &asked.membership_id,
                SyncMembership {
                    request_id: asked.request_id,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::SyncMembershipResponse {
            member: Some(member_out(view)?),
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_host::api::members::{AppraisalView, ClaimView, HostView, RequirementView};

    use super::*;

    /// WP-4.2: evidence travels raw on gRPC and reaches the facade as base64url; the binding and
    /// the appraisal state come back field for field, the nonce as raw bytes.
    #[test]
    fn the_assurance_members_map_field_for_field_and_bytes_raw() {
        let evidence = evidence_in(vec![v1::AttestationEvidence {
            verifier: "tpm-quote".to_owned(),
            evidence: vec![0xEE, 0x00, 0xFF],
        }]);
        assert_eq!(evidence[0].verifier, "tpm-quote");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&evidence[0].evidence)
                .expect("base64url"),
            [0xEE, 0x00, 0xFF]
        );
        let approvals = approvals_in(vec![v1::OperatorApproval {
            control: permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL.to_owned(),
            reason: "witnessed".to_owned(),
            expires_at: "2099-01-01T00:00:00Z".to_owned(),
        }]);
        assert_eq!(
            approvals,
            [ApprovalView {
                control: permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL.to_owned(),
                reason: "witnessed".to_owned(),
                expires_at: "2099-01-01T00:00:00Z".to_owned(),
            }]
        );
        let host = HostView {
            host_id: "0190a5c3-0000-7000-8000-000000000011".to_owned(),
            epoch: 1,
            fingerprint: format!("sha256:{}", "ab".repeat(32)),
        };
        let nonce = [0xA7_u8; 32];
        let view = MemberView {
            membership_id: "0190a5c3-0000-7000-8000-000000000044".to_owned(),
            role: "coordinator".to_owned(),
            status: "active".to_owned(),
            epoch: 2,
            revision: 3,
            coordinator: host.clone(),
            member: host,
            selector: "plane/data/*".to_owned(),
            tasks: Vec::new(),
            member_assurance: "production".to_owned(),
            lease_policy: None,
            manifest: None,
            updated_at: "2027-01-01T00:00:00Z".to_owned(),
            last_session_at: None,
            assurance: Some(AssuranceView {
                verdict: "accepted".to_owned(),
                current: true,
                policy_revision: format!("sha256:{}", "01".repeat(32)),
                task_ids: vec!["decisions".to_owned()],
                claims: vec![ClaimView {
                    control: permguard_core::domains::assurance::CUSTODY_HSM.to_owned(),
                    class: "attested".to_owned(),
                    by: "tpm-quote".to_owned(),
                }],
                appraised_by: "spiffe://acme/operators/root".to_owned(),
                issued_at: "2027-01-01T00:00:00Z".to_owned(),
                expires_at: "2027-01-31T00:00:00Z".to_owned(),
                binding_digest: format!("sha256:{}", "02".repeat(32)),
            }),
            appraisal: Some(AppraisalView {
                policy_revision: format!("sha256:{}", "01".repeat(32)),
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                requirements: vec![RequirementView {
                    control: permguard_core::domains::assurance::CUSTODY_HSM.to_owned(),
                    wants: Some("attested".to_owned()),
                    declared: false,
                }],
            }),
        };
        let member = member_out(view).expect("maps");
        let assurance = member.assurance.expect("a binding");
        assert_eq!(assurance.verdict, "accepted");
        assert!(assurance.current);
        assert_eq!(assurance.task_ids, ["decisions"]);
        assert_eq!(assurance.claims[0].class, "attested");
        assert_eq!(assurance.claims[0].by, "tpm-quote");
        assert_eq!(assurance.expires_at, "2027-01-31T00:00:00Z");
        assert_eq!(
            assurance.binding_digest,
            format!("sha256:{}", "02".repeat(32))
        );
        let appraisal = member.appraisal.expect("an appraisal state");
        assert_eq!(appraisal.nonce, nonce);
        assert_eq!(appraisal.requirements[0].wants.as_deref(), Some("attested"));
        assert!(!appraisal.requirements[0].declared);
    }
}
