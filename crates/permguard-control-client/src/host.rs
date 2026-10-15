// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host listener, as a client sees it (TC-1): one facade over REST and gRPC, the scheme of
//! one URL deciding which (`https` or `grpcs`).
//!
//! The answers are the Host API's own views (`permguard_host::api`), read from JSON over REST and
//! mapped field for field from the generated messages over gRPC, so a command built on this
//! facade prints the same report whichever transport carried it. A refusal is the same
//! `{class, code, message}` on both: the REST body, or the gRPC status and its metadata.
//!
//! It reads the status and the identity, rotates the identity, and carries the memberships and
//! the grants (WP-4.8): every operation the `host identity`, `host members` and `host grants`
//! commands reach.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_host::api::grants::Created;
use permguard_host::api::identity::{
    IdentityRotated, IdentityVerified, IdentityView, RotateIdentity, VerifyIdentity,
};
use permguard_host::api::members::{
    ApproveMember, ChangeMember, CreateInvite, InviteCreated, InviteDeleted, Invites,
    JoinMembership, MemberChanged, MemberSessions, MemberVerification, MemberView, Members,
    PlanMemberRevoke, RunMemberRevoke, SyncMembership, VerifyMember,
};
use permguard_host::api::sessions::PeerSessionsView;
use permguard_host::api::status::{
    Assurance, ComponentView, DegradedView, ListenerView, StatusView,
};
use permguard_host::api::{CreateGrant, Grants, PlanRevoke, Planned, Revoked, RunRevoke};

use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::grpc::GrpcChannel;
use crate::host_proto as map;
use crate::host_v1 as proto;
use crate::http::Client;
use crate::tls::TlsOptions;

/// A membership transition that names the membership and its expected revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Reject,
    Suspend,
    Resume,
    Fence,
}

impl Change {
    fn verb(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Fence => "fence",
        }
    }
}

/// What the Host listener answers, whichever transport asked.
pub trait Host {
    /// `GET /host/v1/status`, `OperationsService.GetStatus`.
    fn status(&self) -> Result<StatusView, Failure>;
    /// `GET /host/v1/identity`, `IdentityService.GetIdentity`.
    fn identity(&self) -> Result<IdentityView, Failure>;
    /// `POST /host/v1/identity/verify`, `IdentityService.VerifyIdentity`.
    fn verify_identity(&self, request: &VerifyIdentity) -> Result<IdentityVerified, Failure>;
    /// `POST /host/v1/identity/rotate`, `IdentityService.RotateIdentity`.
    fn rotate_identity(&self, request: &RotateIdentity) -> Result<IdentityRotated, Failure>;

    /// `POST /host/v1/members/invites`, `MembershipService.CreateInvite`.
    fn create_invite(&self, request: &CreateInvite) -> Result<InviteCreated, Failure>;
    /// `GET /host/v1/members/invites`, `MembershipService.ListInvites`.
    fn invites(&self) -> Result<Invites, Failure>;
    /// `DELETE /host/v1/members/invites/{id}`, `MembershipService.DeleteInvite`.
    fn delete_invite(&self, invite_id: &str, request_id: &str) -> Result<InviteDeleted, Failure>;
    /// `GET /host/v1/members?status=`, `MembershipService.ListMembers`.
    fn members(&self, status: Option<&str>) -> Result<Members, Failure>;
    /// `GET /host/v1/members/{id}`, `MembershipService.GetMember`.
    fn member(&self, membership_id: &str) -> Result<MemberView, Failure>;
    /// `POST /host/v1/members/{id}/approve`, `MembershipService.ApproveMember`.
    fn approve_member(
        &self,
        membership_id: &str,
        request: &ApproveMember,
    ) -> Result<MemberChanged, Failure>;
    /// `POST /host/v1/members/{id}/{reject|suspend|resume|fence}`.
    fn change_member(
        &self,
        change: Change,
        membership_id: &str,
        request: &ChangeMember,
    ) -> Result<MemberChanged, Failure>;
    /// `POST /host/v1/members/{id}/revoke/plan`, `MembershipService.PlanMemberRevoke`.
    fn plan_member_revoke(
        &self,
        membership_id: &str,
        request: &PlanMemberRevoke,
    ) -> Result<Planned, Failure>;
    /// `POST /host/v1/members/{id}/revoke/run`, `MembershipService.RunMemberRevoke`.
    fn run_member_revoke(
        &self,
        membership_id: &str,
        request: &RunMemberRevoke,
    ) -> Result<MemberChanged, Failure>;
    /// `GET /host/v1/members/{id}/sessions`, `MembershipService.ListMemberSessions`.
    fn member_sessions(&self, membership_id: &str) -> Result<MemberSessions, Failure>;
    /// `POST /host/v1/memberships/join`, `MembershipService.JoinMembership`.
    fn join(&self, request: &JoinMembership) -> Result<MemberView, Failure>;
    /// `POST /host/v1/memberships/{id}/sync`, `MembershipService.SyncMembership`.
    fn sync_membership(
        &self,
        membership_id: &str,
        request: &SyncMembership,
    ) -> Result<MemberView, Failure>;
    /// `POST /host/v1/members/{id}/verify`, `MembershipService.VerifyMember`.
    fn verify_member(
        &self,
        membership_id: &str,
        request: &VerifyMember,
    ) -> Result<MemberVerification, Failure>;

    /// `GET /host/v1/grants?principal&selector`, `GrantService.ListGrants`.
    fn grants(&self, principal: Option<&str>, selector: Option<&str>) -> Result<Grants, Failure>;
    /// `POST /host/v1/grants`, `GrantService.CreateGrant`.
    fn create_grant(&self, request: &CreateGrant) -> Result<Created, Failure>;
    /// `POST /host/v1/grants/{id}/revoke/plan`, `GrantService.PlanGrantRevoke`.
    fn plan_grant_revoke(&self, grant_id: &str, request: &PlanRevoke) -> Result<Planned, Failure>;
    /// `POST /host/v1/grants/{id}/revoke/run`, `GrantService.RunGrantRevoke`.
    fn run_grant_revoke(&self, grant_id: &str, request: &RunRevoke) -> Result<Revoked, Failure>;
}

/// A request the caller got wrong before anything was sent.
fn usage(detail: impl Into<String>) -> Failure {
    let detail = detail.into();
    Failure {
        class: "validation".to_owned(),
        reason: permguard_core::codes::client::USAGE.to_owned(),
        detail,
        usage: true,
    }
}

/// A query value, percent-encoded: everything but the unreserved characters.
fn query_value(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// A path segment the Host API names: an id, refused when it would leave its segment.
fn segment(id: &str) -> Result<&str, Failure> {
    if id.is_empty() || id.contains(['/', '?', '#', '%']) || id == "." || id == ".." {
        return Err(usage(format!("`{id}` is not an id")));
    }
    Ok(id)
}

fn json(body: &impl serde::Serialize) -> Result<String, Failure> {
    serde_json::to_string(body).map_err(|error| usage(error.to_string()))
}

/// Connects to a Host listener: `https`/`http` ride REST, `grpcs`/`grpc` gRPC.
pub fn client(
    url: &str,
    tls: &TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn Host>, String> {
    let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;
    if endpoint.is_grpc() {
        return Ok(Box::new(GrpcHost(GrpcChannel::connect(
            url, tls, narrator,
        )?)));
    }
    let client = Client::new(
        std::time::Duration::from_secs(30),
        tls.clone(),
        endpoint.is_tls(),
    )
    .map_err(|error| error.to_string())?
    .with_narrator(narrator);
    Ok(Box::new(RestHost { client, endpoint }))
}

struct RestHost {
    client: Client,
    endpoint: Endpoint,
}

impl Host for RestHost {
    fn status(&self) -> Result<StatusView, Failure> {
        crate::catalog::call(&self.client, &self.endpoint, "GET", "/host/v1/status", None)
    }

    fn identity(&self) -> Result<IdentityView, Failure> {
        crate::catalog::call(
            &self.client,
            &self.endpoint,
            "GET",
            "/host/v1/identity",
            None,
        )
    }

    fn verify_identity(&self, request: &VerifyIdentity) -> Result<IdentityVerified, Failure> {
        self.post("/host/v1/identity/verify", &json(request)?)
    }

    fn rotate_identity(&self, request: &RotateIdentity) -> Result<IdentityRotated, Failure> {
        self.post("/host/v1/identity/rotate", &json(request)?)
    }

    fn create_invite(&self, request: &CreateInvite) -> Result<InviteCreated, Failure> {
        self.post("/host/v1/members/invites", &json(request)?)
    }

    fn invites(&self) -> Result<Invites, Failure> {
        self.get("/host/v1/members/invites")
    }

    fn delete_invite(&self, invite_id: &str, request_id: &str) -> Result<InviteDeleted, Failure> {
        crate::catalog::call(
            &self.client,
            &self.endpoint,
            "DELETE",
            &format!(
                "/host/v1/members/invites/{}?request_id={}",
                segment(invite_id)?,
                query_value(request_id)
            ),
            None,
        )
    }

    fn members(&self, status: Option<&str>) -> Result<Members, Failure> {
        match status {
            Some(status) => self.get(&format!("/host/v1/members?status={}", query_value(status))),
            None => self.get("/host/v1/members"),
        }
    }

    fn member(&self, membership_id: &str) -> Result<MemberView, Failure> {
        self.get(&format!("/host/v1/members/{}", segment(membership_id)?))
    }

    fn approve_member(
        &self,
        membership_id: &str,
        request: &ApproveMember,
    ) -> Result<MemberChanged, Failure> {
        self.post(
            &format!("/host/v1/members/{}/approve", segment(membership_id)?),
            &json(request)?,
        )
    }

    fn change_member(
        &self,
        change: Change,
        membership_id: &str,
        request: &ChangeMember,
    ) -> Result<MemberChanged, Failure> {
        self.post(
            &format!(
                "/host/v1/members/{}/{}",
                segment(membership_id)?,
                change.verb()
            ),
            &json(request)?,
        )
    }

    fn plan_member_revoke(
        &self,
        membership_id: &str,
        request: &PlanMemberRevoke,
    ) -> Result<Planned, Failure> {
        self.post(
            &format!("/host/v1/members/{}/revoke/plan", segment(membership_id)?),
            &json(request)?,
        )
    }

    fn run_member_revoke(
        &self,
        membership_id: &str,
        request: &RunMemberRevoke,
    ) -> Result<MemberChanged, Failure> {
        self.post(
            &format!("/host/v1/members/{}/revoke/run", segment(membership_id)?),
            &json(request)?,
        )
    }

    fn member_sessions(&self, membership_id: &str) -> Result<MemberSessions, Failure> {
        self.get(&format!(
            "/host/v1/members/{}/sessions",
            segment(membership_id)?
        ))
    }

    fn join(&self, request: &JoinMembership) -> Result<MemberView, Failure> {
        self.post("/host/v1/memberships/join", &json(request)?)
    }

    fn sync_membership(
        &self,
        membership_id: &str,
        request: &SyncMembership,
    ) -> Result<MemberView, Failure> {
        self.post(
            &format!("/host/v1/memberships/{}/sync", segment(membership_id)?),
            &json(request)?,
        )
    }

    fn verify_member(
        &self,
        membership_id: &str,
        request: &VerifyMember,
    ) -> Result<MemberVerification, Failure> {
        self.post(
            &format!("/host/v1/members/{}/verify", segment(membership_id)?),
            &json(request)?,
        )
    }

    fn grants(&self, principal: Option<&str>, selector: Option<&str>) -> Result<Grants, Failure> {
        let filters: Vec<String> = [("principal", principal), ("selector", selector)]
            .into_iter()
            .filter_map(|(name, value)| value.map(|value| format!("{name}={}", query_value(value))))
            .collect();
        if filters.is_empty() {
            self.get("/host/v1/grants")
        } else {
            self.get(&format!("/host/v1/grants?{}", filters.join("&")))
        }
    }

    fn create_grant(&self, request: &CreateGrant) -> Result<Created, Failure> {
        self.post("/host/v1/grants", &json(request)?)
    }

    fn plan_grant_revoke(&self, grant_id: &str, request: &PlanRevoke) -> Result<Planned, Failure> {
        self.post(
            &format!("/host/v1/grants/{}/revoke/plan", segment(grant_id)?),
            &json(request)?,
        )
    }

    fn run_grant_revoke(&self, grant_id: &str, request: &RunRevoke) -> Result<Revoked, Failure> {
        self.post(
            &format!("/host/v1/grants/{}/revoke/run", segment(grant_id)?),
            &json(request)?,
        )
    }
}

impl RestHost {
    fn get<T: for<'de> serde::Deserialize<'de>>(&self, path: &str) -> Result<T, Failure> {
        crate::catalog::call(&self.client, &self.endpoint, "GET", path, None)
    }

    fn post<T: for<'de> serde::Deserialize<'de>>(
        &self,
        path: &str,
        body: &str,
    ) -> Result<T, Failure> {
        crate::catalog::call(&self.client, &self.endpoint, "POST", path, Some(body))
    }
}

struct GrpcHost(GrpcChannel);

impl Host for GrpcHost {
    fn status(&self) -> Result<StatusView, Failure> {
        let mut client =
            proto::operations_service_client::OperationsServiceClient::new(self.0.channel());
        let answer = self
            .0
            .run("GetStatus", client.get_status(proto::GetStatusRequest {}))
            .map_err(crate::grpc::failure_of)?;
        Ok(status_of(answer))
    }

    fn identity(&self) -> Result<IdentityView, Failure> {
        let mut client =
            proto::identity_service_client::IdentityServiceClient::new(self.0.channel());
        let answer = self
            .0
            .run(
                "GetIdentity",
                client.get_identity(proto::GetIdentityRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        // REST carries bytes as base64url without padding; the view is that spelling on both.
        Ok(IdentityView {
            host_id: answer.host_id,
            epoch: answer.epoch,
            fingerprint: answer.fingerprint,
            document: URL_SAFE_NO_PAD.encode(answer.document),
            successions: answer
                .successions
                .iter()
                .map(|record| URL_SAFE_NO_PAD.encode(record))
                .collect(),
            first_public_key: URL_SAFE_NO_PAD.encode(answer.first_public_key),
            protocol_versions: answer.protocol_versions,
        })
    }

    fn verify_identity(&self, request: &VerifyIdentity) -> Result<IdentityVerified, Failure> {
        let mut client =
            proto::identity_service_client::IdentityServiceClient::new(self.0.channel());
        let answer = self
            .0
            .run(
                "VerifyIdentity",
                client.verify_identity(proto::VerifyIdentityRequest {
                    address: request.address.clone(),
                    host_id: request.host_id.clone(),
                    fingerprint: request.fingerprint.clone(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(IdentityVerified {
            host_id: answer.host_id,
            epoch: answer.epoch,
            fingerprint: answer.fingerprint,
            verified: answer.verified,
        })
    }

    fn rotate_identity(&self, request: &RotateIdentity) -> Result<IdentityRotated, Failure> {
        let mut client =
            proto::identity_service_client::IdentityServiceClient::new(self.0.channel());
        let answer = self
            .0
            .run(
                "RotateIdentity",
                client.rotate_identity(proto::RotateIdentityRequest {
                    request_id: request.request_id.clone(),
                    expected_epoch: request.expected_epoch,
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(IdentityRotated {
            receipt: map::receipt(answer.receipt),
            succession: map::b64(&answer.succession),
        })
    }

    fn create_invite(&self, request: &CreateInvite) -> Result<InviteCreated, Failure> {
        let answer = self
            .0
            .run(
                "CreateInvite",
                self.members_client()
                    .create_invite(proto::CreateInviteRequest {
                        request_id: request.request_id.clone(),
                        selector: request.selector.clone(),
                        tasks: request.tasks.iter().map(map::task_out).collect(),
                        expires: request.expires.clone(),
                        expected_fingerprint: request.expected_fingerprint.clone(),
                        min_assurance: request.min_assurance.clone(),
                        max_uses: Some(request.max_uses),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(InviteCreated {
            receipt: map::receipt(answer.receipt),
            invite_id: answer.invite_id,
            token: map::b64(&answer.token),
            expires: answer.expires,
        })
    }

    fn invites(&self) -> Result<Invites, Failure> {
        let answer = self
            .0
            .run(
                "ListInvites",
                self.members_client()
                    .list_invites(proto::ListInvitesRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Invites {
            invites: answer.invites.into_iter().map(map::invite_in).collect(),
        })
    }

    fn delete_invite(&self, invite_id: &str, request_id: &str) -> Result<InviteDeleted, Failure> {
        let answer = self
            .0
            .run(
                "DeleteInvite",
                self.members_client()
                    .delete_invite(proto::DeleteInviteRequest {
                        invite_id: invite_id.to_owned(),
                        request_id: request_id.to_owned(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(InviteDeleted {
            receipt: map::receipt(answer.receipt),
        })
    }

    fn members(&self, status: Option<&str>) -> Result<Members, Failure> {
        let answer = self
            .0
            .run(
                "ListMembers",
                self.members_client()
                    .list_members(proto::ListMembersRequest {
                        status: status.unwrap_or_default().to_owned(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Members {
            members: answer.members.into_iter().map(map::member_in).collect(),
        })
    }

    fn member(&self, membership_id: &str) -> Result<MemberView, Failure> {
        let answer = self
            .0
            .run(
                "GetMember",
                self.members_client().get_member(proto::GetMemberRequest {
                    membership_id: membership_id.to_owned(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::member_in(answer.member.unwrap_or_default()))
    }

    fn approve_member(
        &self,
        membership_id: &str,
        request: &ApproveMember,
    ) -> Result<MemberChanged, Failure> {
        let assurance = request
            .assurance
            .as_ref()
            .map(|offer| {
                Ok::<_, Failure>(proto::AssuranceOffer {
                    approvals: offer
                        .approvals
                        .iter()
                        .map(|approval| proto::OperatorApproval {
                            control: approval.control.clone(),
                            reason: approval.reason.clone(),
                            expires_at: approval.expires_at.clone(),
                        })
                        .collect(),
                    evidence: offer
                        .evidence
                        .iter()
                        .map(|item| {
                            Ok(proto::AttestationEvidence {
                                verifier: item.verifier.clone(),
                                evidence: map::raw(&item.evidence).map_err(usage)?,
                            })
                        })
                        .collect::<Result<_, Failure>>()?,
                })
            })
            .transpose()?;
        let answer = self
            .0
            .run(
                "ApproveMember",
                self.members_client()
                    .approve_member(proto::ApproveMemberRequest {
                        membership_id: membership_id.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                        narrow: request.narrow.as_ref().map(map::scope_out),
                        lease_policy: request.lease_policy.as_ref().map(map::lease_out),
                        assurance,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::changed(
            answer.receipt,
            answer.status,
            answer.epoch,
            &answer.manifest,
        ))
    }

    fn change_member(
        &self,
        change: Change,
        membership_id: &str,
        request: &ChangeMember,
    ) -> Result<MemberChanged, Failure> {
        let mut client = self.members_client();
        let (id, request_id, revision, reason) = (
            membership_id.to_owned(),
            request.request_id.clone(),
            request.expected_revision,
            request.reason.clone(),
        );
        let answer = match change {
            Change::Reject => self
                .0
                .run(
                    "RejectMember",
                    client.reject_member(proto::RejectMemberRequest {
                        membership_id: id,
                        request_id,
                        expected_revision: revision,
                        reason,
                    }),
                )
                .map(|a| (a.receipt, a.status, a.epoch, a.manifest)),
            Change::Suspend => self
                .0
                .run(
                    "SuspendMember",
                    client.suspend_member(proto::SuspendMemberRequest {
                        membership_id: id,
                        request_id,
                        expected_revision: revision,
                        reason,
                    }),
                )
                .map(|a| (a.receipt, a.status, a.epoch, a.manifest)),
            Change::Resume => self
                .0
                .run(
                    "ResumeMember",
                    client.resume_member(proto::ResumeMemberRequest {
                        membership_id: id,
                        request_id,
                        expected_revision: revision,
                        reason,
                    }),
                )
                .map(|a| (a.receipt, a.status, a.epoch, a.manifest)),
            Change::Fence => self
                .0
                .run(
                    "FenceMember",
                    client.fence_member(proto::FenceMemberRequest {
                        membership_id: id,
                        request_id,
                        expected_revision: revision,
                        reason,
                    }),
                )
                .map(|a| (a.receipt, a.status, a.epoch, a.manifest)),
        }
        .map_err(crate::grpc::failure_of)?;
        Ok(map::changed(answer.0, answer.1, answer.2, &answer.3))
    }

    fn plan_member_revoke(
        &self,
        membership_id: &str,
        request: &PlanMemberRevoke,
    ) -> Result<Planned, Failure> {
        let answer = self
            .0
            .run(
                "PlanMemberRevoke",
                self.members_client()
                    .plan_member_revoke(proto::PlanMemberRevokeRequest {
                        membership_id: membership_id.to_owned(),
                        request_id: request.request_id.clone(),
                        reason: request.reason.clone(),
                        expected_revision: request.expected_revision,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::planned(
            answer.plan_id,
            answer.plan_digest,
            answer.expires,
            answer.revision,
            &answer.receipt,
            answer.approvals_required,
        ))
    }

    fn run_member_revoke(
        &self,
        membership_id: &str,
        request: &RunMemberRevoke,
    ) -> Result<MemberChanged, Failure> {
        let receipt = map::raw(&request.receipt).map_err(usage)?;
        let answer = self
            .0
            .run(
                "RunMemberRevoke",
                self.members_client()
                    .run_member_revoke(proto::RunMemberRevokeRequest {
                        membership_id: membership_id.to_owned(),
                        request_id: request.request_id.clone(),
                        receipt,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::changed(
            answer.receipt,
            answer.status,
            answer.epoch,
            &answer.manifest,
        ))
    }

    fn member_sessions(&self, membership_id: &str) -> Result<MemberSessions, Failure> {
        let answer = self
            .0
            .run(
                "ListMemberSessions",
                self.members_client()
                    .list_member_sessions(proto::ListMemberSessionsRequest {
                        membership_id: membership_id.to_owned(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(MemberSessions {
            sessions: answer.sessions.into_iter().map(map::session_in).collect(),
        })
    }

    fn join(&self, request: &JoinMembership) -> Result<MemberView, Failure> {
        let token = map::raw(&request.token).map_err(usage)?;
        let answer = self
            .0
            .run(
                "JoinMembership",
                self.members_client()
                    .join_membership(proto::JoinMembershipRequest {
                        request_id: request.request_id.clone(),
                        coordinator: Some(proto::MembershipCoordinator {
                            address: request.coordinator.address.clone(),
                            host_id: request.coordinator.host_id.clone(),
                            fingerprint: request.coordinator.fingerprint.clone(),
                        }),
                        invite_id: request.invite_id.clone(),
                        token,
                        requested: Some(map::scope_out(&request.requested)),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::member_in(answer.member.unwrap_or_default()))
    }

    fn sync_membership(
        &self,
        membership_id: &str,
        request: &SyncMembership,
    ) -> Result<MemberView, Failure> {
        let answer = self
            .0
            .run(
                "SyncMembership",
                self.members_client()
                    .sync_membership(proto::SyncMembershipRequest {
                        membership_id: membership_id.to_owned(),
                        request_id: request.request_id.clone(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::member_in(answer.member.unwrap_or_default()))
    }

    fn verify_member(
        &self,
        membership_id: &str,
        request: &VerifyMember,
    ) -> Result<MemberVerification, Failure> {
        let answer = self
            .0
            .run(
                "VerifyMember",
                self.members_client()
                    .verify_member(proto::VerifyMemberRequest {
                        membership_id: membership_id.to_owned(),
                        request_id: request.request_id.clone(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(MemberVerification {
            receipt: map::receipt(answer.receipt),
            membership_id: answer.membership_id,
            status: answer.status,
            scheduled_at: answer.scheduled_at,
            member: map::member_in(answer.member.unwrap_or_default()),
        })
    }

    fn grants(&self, principal: Option<&str>, selector: Option<&str>) -> Result<Grants, Failure> {
        let answer = self
            .0
            .run(
                "ListGrants",
                self.grants_client().list_grants(proto::ListGrantsRequest {
                    principal: principal.unwrap_or_default().to_owned(),
                    selector: selector.unwrap_or_default().to_owned(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Grants {
            revision: answer.revision,
            grants: answer
                .grants
                .into_iter()
                .map(|grant| map::grant_in(Some(grant)))
                .collect(),
        })
    }

    fn create_grant(&self, request: &CreateGrant) -> Result<Created, Failure> {
        let answer = self
            .0
            .run(
                "CreateGrant",
                self.grants_client()
                    .create_grant(proto::CreateGrantRequest {
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                        principal: request.principal.clone(),
                        operations: request.operations.clone(),
                        selector: request.selector.clone(),
                        resource_types: request.resource_types.clone(),
                        constraints: request
                            .constraints
                            .iter()
                            .map(|(name, value)| (name.clone(), value.clone()))
                            .collect(),
                        expires_at: request.expires_at.clone(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::created(answer))
    }

    fn plan_grant_revoke(&self, grant_id: &str, request: &PlanRevoke) -> Result<Planned, Failure> {
        let answer = self
            .0
            .run(
                "PlanGrantRevoke",
                self.grants_client()
                    .plan_grant_revoke(proto::PlanGrantRevokeRequest {
                        grant_id: grant_id.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::planned(
            answer.plan_id,
            answer.plan_digest,
            answer.expires,
            answer.revision,
            &answer.receipt,
            answer.approvals_required,
        ))
    }

    fn run_grant_revoke(&self, grant_id: &str, request: &RunRevoke) -> Result<Revoked, Failure> {
        let receipt = map::raw(&request.receipt).map_err(usage)?;
        let answer = self
            .0
            .run(
                "RunGrantRevoke",
                self.grants_client()
                    .run_grant_revoke(proto::RunGrantRevokeRequest {
                        grant_id: grant_id.to_owned(),
                        request_id: request.request_id.clone(),
                        receipt,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(map::revoked(answer))
    }
}

impl GrpcHost {
    fn members_client(
        &self,
    ) -> proto::membership_service_client::MembershipServiceClient<crate::grpc::AuthChannel> {
        proto::membership_service_client::MembershipServiceClient::new(self.0.channel())
    }

    fn grants_client(
        &self,
    ) -> proto::grant_service_client::GrantServiceClient<crate::grpc::AuthChannel> {
        proto::grant_service_client::GrantServiceClient::new(self.0.channel())
    }
}

/// The status view a `GetStatusResponse` means, field for field.
fn status_of(answer: proto::GetStatusResponse) -> StatusView {
    let assurance = answer.assurance.unwrap_or_default();
    let peer_sessions = answer.peer_sessions.unwrap_or_default();
    StatusView {
        live: answer.live,
        ready: answer.ready,
        state: answer.state,
        degraded: answer
            .degraded
            .into_iter()
            .map(|degraded| DegradedView {
                capability: degraded.capability,
                reason: degraded.reason,
            })
            .collect(),
        components: answer
            .components
            .into_iter()
            .map(|component| ComponentView {
                component: component.component,
                kind: component.kind,
                state: component.state,
                required: component.required,
                stalled_since: component.stalled_since,
                last_success: component.last_success,
                next_attempt: component.next_attempt,
                reason: component.reason,
            })
            .collect(),
        assurance: Assurance {
            profile: assurance.profile,
            enforcement: assurance.enforcement,
            added_controls: assurance.added_controls,
            relaxations: assurance.relaxations,
        },
        peer_sessions: PeerSessionsView {
            served: peer_sessions.served,
            reason: peer_sessions.reason,
        },
        listeners: answer
            .listeners
            .into_iter()
            .map(|listener| ListenerView {
                name: listener.name,
                class: listener.class,
                authentication: listener.authentication,
                client_allow: listener.client_allow,
                tls_min_version: listener.tls_min_version,
            })
            .collect(),
    }
}
