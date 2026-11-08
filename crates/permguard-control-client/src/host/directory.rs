// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host listener's roles, local users and identity providers, as a client sees them (WP-8.1):
//! what `host roles`, `host users` and `host providers` reach, over REST and gRPC alike. The
//! answers are the Host API's own views. A password travels in a request body and is never in
//! an answer.

use permguard_host::api::directory::{
    Changed, CreateRole, CreateUser, Link, Member, Plain, ProviderKey, ProviderView, Providers,
    RoleDetail, RoleSummary, Roles, SetPassword, UpdateRole, UpdateUser, UserDetail, UserSummary,
    Users,
};

use permguard_host::api::recovery::{RecoveryAcknowledged, RecoveryView};

use super::{GrpcHost, RestHost, json, segment};
use crate::catalog::Failure;
use crate::host_proto as map;
use crate::host_v1 as proto;

/// The Host's roles, local users and identity providers (WP-8.1).
pub trait Directory {
    fn roles(&self) -> Result<Roles, Failure>;
    fn role(&self, name: &str) -> Result<RoleDetail, Failure>;
    fn create_role(&self, request: &CreateRole) -> Result<Changed, Failure>;
    fn update_role(&self, name: &str, request: &UpdateRole) -> Result<Changed, Failure>;
    fn delete_role(&self, name: &str, request: &Plain) -> Result<Changed, Failure>;
    fn add_member(&self, role: &str, request: &Member) -> Result<Changed, Failure>;
    fn remove_member(&self, role: &str, request: &Member) -> Result<Changed, Failure>;
    fn roles_of(&self, principal: &str) -> Result<Vec<String>, Failure>;
    fn users(&self) -> Result<Users, Failure>;
    fn user(&self, name: &str) -> Result<UserDetail, Failure>;
    fn create_user(&self, request: &CreateUser) -> Result<Changed, Failure>;
    fn update_user(&self, name: &str, request: &UpdateUser) -> Result<Changed, Failure>;
    fn set_password(&self, name: &str, request: &SetPassword) -> Result<Changed, Failure>;
    fn set_user_status(
        &self,
        name: &str,
        active: bool,
        request: &Plain,
    ) -> Result<Changed, Failure>;
    fn reset_factor(&self, name: &str, request: &Plain) -> Result<Changed, Failure>;
    fn unlock_user(&self, name: &str) -> Result<bool, Failure>;
    fn link_user(&self, name: &str, link: bool, request: &Link) -> Result<Changed, Failure>;
    fn delete_user(&self, name: &str, request: &Plain) -> Result<Changed, Failure>;
    fn providers(&self) -> Result<Providers, Failure>;
    fn refresh_provider(&self, name: &str) -> Result<ProviderView, Failure>;
    /// The recovery started offline, waiting to be acknowledged (WP-8.2).
    fn recovery(&self) -> Result<RecoveryView, Failure>;
    /// Acknowledges it: the Host leaves `degraded: recovery`.
    fn acknowledge_recovery(&self) -> Result<RecoveryAcknowledged, Failure>;
}

impl Directory for RestHost {
    fn roles(&self) -> Result<Roles, Failure> {
        self.get("/iam/v1/roles")
    }

    fn role(&self, name: &str) -> Result<RoleDetail, Failure> {
        self.get(&format!("/iam/v1/roles/{}", segment(name)?))
    }

    fn create_role(&self, request: &CreateRole) -> Result<Changed, Failure> {
        self.post("/iam/v1/roles", &json(request)?)
    }

    fn update_role(&self, name: &str, request: &UpdateRole) -> Result<Changed, Failure> {
        self.patch(
            &format!("/iam/v1/roles/{}", segment(name)?),
            &json(request)?,
        )
    }

    fn delete_role(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.post(
            &format!("/iam/v1/roles/{}/delete", segment(name)?),
            &json(request)?,
        )
    }

    fn add_member(&self, role: &str, request: &Member) -> Result<Changed, Failure> {
        self.post(
            &format!("/iam/v1/roles/{}/members", segment(role)?),
            &json(request)?,
        )
    }

    fn remove_member(&self, role: &str, request: &Member) -> Result<Changed, Failure> {
        self.post(
            &format!("/iam/v1/roles/{}/members/remove", segment(role)?),
            &json(request)?,
        )
    }

    fn roles_of(&self, principal: &str) -> Result<Vec<String>, Failure> {
        self.get(&format!("/iam/v1/principals/{}/roles", segment(principal)?))
    }

    fn users(&self) -> Result<Users, Failure> {
        self.get("/iam/v1/users")
    }

    fn user(&self, name: &str) -> Result<UserDetail, Failure> {
        self.get(&format!("/iam/v1/users/{}", segment(name)?))
    }

    fn create_user(&self, request: &CreateUser) -> Result<Changed, Failure> {
        self.post("/iam/v1/users", &json(request)?)
    }

    fn update_user(&self, name: &str, request: &UpdateUser) -> Result<Changed, Failure> {
        self.patch(
            &format!("/iam/v1/users/{}", segment(name)?),
            &json(request)?,
        )
    }

    fn set_password(&self, name: &str, request: &SetPassword) -> Result<Changed, Failure> {
        self.post(
            &format!("/iam/v1/users/{}/password", segment(name)?),
            &json(request)?,
        )
    }

    fn set_user_status(
        &self,
        name: &str,
        active: bool,
        request: &Plain,
    ) -> Result<Changed, Failure> {
        let verb = if active { "enable" } else { "disable" };
        self.post(
            &format!("/iam/v1/users/{}/{verb}", segment(name)?),
            &json(request)?,
        )
    }

    fn reset_factor(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.post(
            &format!("/iam/v1/users/{}/factor/reset", segment(name)?),
            &json(request)?,
        )
    }

    fn unlock_user(&self, name: &str) -> Result<bool, Failure> {
        let answer: serde_json::Value =
            self.post(&format!("/iam/v1/users/{}/unlock", segment(name)?), "{}")?;
        Ok(answer
            .get("unlocked")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    }

    fn link_user(&self, name: &str, link: bool, request: &Link) -> Result<Changed, Failure> {
        let path = if link { "links" } else { "links/remove" };
        self.post(
            &format!("/iam/v1/users/{}/{path}", segment(name)?),
            &json(request)?,
        )
    }

    fn delete_user(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.post(
            &format!("/iam/v1/users/{}/delete", segment(name)?),
            &json(request)?,
        )
    }

    fn providers(&self) -> Result<Providers, Failure> {
        self.get("/iam/v1/providers")
    }

    fn refresh_provider(&self, name: &str) -> Result<ProviderView, Failure> {
        self.post(
            &format!("/iam/v1/providers/{}/refresh", segment(name)?),
            "{}",
        )
    }

    fn recovery(&self) -> Result<RecoveryView, Failure> {
        self.get("/iam/v1/recovery")
    }

    fn acknowledge_recovery(&self) -> Result<RecoveryAcknowledged, Failure> {
        self.post("/iam/v1/recovery/acknowledge", "{}")
    }
}

pub(super) fn changed(answer: proto::DirectoryChangeResponse) -> Changed {
    Changed {
        receipt: map::receipt(answer.receipt),
        revision: answer.revision,
        changed: answer.changed,
    }
}

fn user_in(user: proto::UserSummary) -> UserSummary {
    UserSummary {
        name: user.name,
        email: user.email,
        display: user.display,
        status: user.status,
        password: user.password,
        factor: user.factor,
        links: user.links,
        roles: user.roles,
        locked_for: user.locked_for,
        revision: user.revision,
    }
}

fn provider_in(provider: proto::Provider) -> ProviderView {
    ProviderView {
        name: provider.name,
        issuer: provider.issuer,
        claim: provider.claim,
        source: provider.source,
        location: provider.location,
        keys: provider
            .keys
            .into_iter()
            .map(|key| ProviderKey {
                kid: key.kid,
                algorithm: key.algorithm,
            })
            .collect(),
        fetched_at: provider.fetched_at,
        age_seconds: provider.age_seconds,
        failure: provider.failure,
        failed_at: provider.failed_at,
        state: provider.state,
    }
}

fn count(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

impl GrpcHost {
    fn roles_client(
        &self,
    ) -> crate::iam_v1::role_service_client::RoleServiceClient<crate::grpc::AuthChannel> {
        crate::iam_v1::role_service_client::RoleServiceClient::new(self.0.channel())
    }

    fn users_client(
        &self,
    ) -> crate::iam_v1::user_service_client::UserServiceClient<crate::grpc::AuthChannel> {
        crate::iam_v1::user_service_client::UserServiceClient::new(self.0.channel())
    }

    fn providers_client(
        &self,
    ) -> crate::iam_v1::provider_service_client::ProviderServiceClient<crate::grpc::AuthChannel>
    {
        crate::iam_v1::provider_service_client::ProviderServiceClient::new(self.0.channel())
    }
}

impl Directory for GrpcHost {
    fn roles(&self) -> Result<Roles, Failure> {
        let answer = self
            .0
            .run(
                "ListRoles",
                self.roles_client().list_roles(proto::ListRolesRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Roles {
            revision: answer.revision,
            roles: answer
                .roles
                .into_iter()
                .map(|role| RoleSummary {
                    name: role.name,
                    description: role.description,
                    members: count(role.members),
                    grants: count(role.grants),
                    revision: role.revision,
                })
                .collect(),
        })
    }

    fn role(&self, name: &str) -> Result<RoleDetail, Failure> {
        let answer = self
            .0
            .run(
                "GetRole",
                self.roles_client().get_role(proto::GetRoleRequest {
                    name: name.to_owned(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(RoleDetail {
            name: answer.name,
            description: answer.description,
            members: answer.members,
            grants: answer
                .grants
                .into_iter()
                .map(|grant| map::grant_in(Some(grant)))
                .collect(),
            revision: answer.revision,
            directory_revision: answer.directory_revision,
        })
    }

    fn create_role(&self, request: &CreateRole) -> Result<Changed, Failure> {
        self.0
            .run(
                "CreateRole",
                self.roles_client().create_role(proto::CreateRoleRequest {
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                    name: request.name.clone(),
                    description: request.description.clone(),
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn update_role(&self, name: &str, request: &UpdateRole) -> Result<Changed, Failure> {
        self.0
            .run(
                "UpdateRole",
                self.roles_client().update_role(proto::UpdateRoleRequest {
                    name: name.to_owned(),
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                    description: request.description.clone(),
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn delete_role(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.0
            .run(
                "DeleteRole",
                self.roles_client().delete_role(proto::DeleteRoleRequest {
                    name: name.to_owned(),
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn add_member(&self, role: &str, request: &Member) -> Result<Changed, Failure> {
        self.0
            .run(
                "AddMember",
                self.roles_client().add_member(proto::MemberRequest {
                    role: role.to_owned(),
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                    member: request.member.clone(),
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn remove_member(&self, role: &str, request: &Member) -> Result<Changed, Failure> {
        self.0
            .run(
                "RemoveMember",
                self.roles_client().remove_member(proto::MemberRequest {
                    role: role.to_owned(),
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                    member: request.member.clone(),
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn roles_of(&self, principal: &str) -> Result<Vec<String>, Failure> {
        self.0
            .run(
                "RolesOf",
                self.roles_client().roles_of(proto::RolesOfRequest {
                    principal: principal.to_owned(),
                }),
            )
            .map(|answer| answer.roles)
            .map_err(crate::grpc::failure_of)
    }

    fn users(&self) -> Result<Users, Failure> {
        let answer = self
            .0
            .run(
                "ListUsers",
                self.users_client().list_users(proto::ListUsersRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Users {
            revision: answer.revision,
            users: answer.users.into_iter().map(user_in).collect(),
        })
    }

    fn user(&self, name: &str) -> Result<UserDetail, Failure> {
        let answer = self
            .0
            .run(
                "GetUser",
                self.users_client().get_user(proto::GetUserRequest {
                    name: name.to_owned(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(UserDetail {
            user: user_in(answer.user.unwrap_or_default()),
            grants: answer
                .grants
                .into_iter()
                .map(|grant| map::grant_in(Some(grant)))
                .collect(),
            directory_revision: answer.directory_revision,
        })
    }

    fn create_user(&self, request: &CreateUser) -> Result<Changed, Failure> {
        self.0
            .run(
                "CreateUser",
                self.users_client().create_user(proto::CreateUserRequest {
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                    name: request.name.clone(),
                    email: request.email.clone(),
                    display: request.display.clone(),
                    password: request.password.clone(),
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn update_user(&self, name: &str, request: &UpdateUser) -> Result<Changed, Failure> {
        self.0
            .run(
                "UpdateUser",
                self.users_client().update_user(proto::UpdateUserRequest {
                    name: name.to_owned(),
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                    email: request.email.clone(),
                    display: request.display.clone(),
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn set_password(&self, name: &str, request: &SetPassword) -> Result<Changed, Failure> {
        self.0
            .run(
                "SetPassword",
                self.users_client().set_password(proto::SetPasswordRequest {
                    name: name.to_owned(),
                    request_id: request.request_id.clone(),
                    password: request.password.clone(),
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn set_user_status(
        &self,
        name: &str,
        active: bool,
        request: &Plain,
    ) -> Result<Changed, Failure> {
        self.0
            .run(
                "SetUserStatus",
                self.users_client()
                    .set_user_status(proto::SetUserStatusRequest {
                        name: name.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                        active,
                    }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn reset_factor(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.0
            .run(
                "ResetFactor",
                self.users_client().reset_factor(proto::UserPlainRequest {
                    name: name.to_owned(),
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn unlock_user(&self, name: &str) -> Result<bool, Failure> {
        self.0
            .run(
                "UnlockUser",
                self.users_client().unlock_user(proto::UnlockUserRequest {
                    name: name.to_owned(),
                }),
            )
            .map(|answer| answer.unlocked)
            .map_err(crate::grpc::failure_of)
    }

    fn link_user(&self, name: &str, link: bool, request: &Link) -> Result<Changed, Failure> {
        self.0
            .run(
                "LinkUser",
                self.users_client().link_user(proto::LinkUserRequest {
                    name: name.to_owned(),
                    request_id: request.request_id.clone(),
                    subject: request.subject.clone(),
                    link,
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn delete_user(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.0
            .run(
                "DeleteUser",
                self.users_client().delete_user(proto::UserPlainRequest {
                    name: name.to_owned(),
                    request_id: request.request_id.clone(),
                    expected_revision: request.expected_revision,
                }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn providers(&self) -> Result<Providers, Failure> {
        let answer = self
            .0
            .run(
                "ListProviders",
                self.providers_client()
                    .list_providers(proto::ListProvidersRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Providers {
            providers: answer.providers.into_iter().map(provider_in).collect(),
        })
    }

    fn refresh_provider(&self, name: &str) -> Result<ProviderView, Failure> {
        self.0
            .run(
                "RefreshProvider",
                self.providers_client()
                    .refresh_provider(proto::RefreshProviderRequest {
                        name: name.to_owned(),
                    }),
            )
            .map(provider_in)
            .map_err(crate::grpc::failure_of)
    }

    fn recovery(&self) -> Result<RecoveryView, Failure> {
        let answer = self
            .0
            .run(
                "GetRecovery",
                crate::iam_v1::recovery_service_client::RecoveryServiceClient::new(
                    self.0.channel(),
                )
                .get_recovery(proto::GetRecoveryRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(RecoveryView {
            waiting: answer.waiting,
            started_at: answer.started_at,
            reason: answer.reason,
        })
    }

    fn acknowledge_recovery(&self) -> Result<RecoveryAcknowledged, Failure> {
        let answer = self
            .0
            .run(
                "AcknowledgeRecovery",
                crate::iam_v1::recovery_service_client::RecoveryServiceClient::new(
                    self.0.channel(),
                )
                .acknowledge_recovery(proto::AcknowledgeRecoveryRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(RecoveryAcknowledged {
            acknowledged: answer.acknowledged,
            started_at: answer.started_at,
            reason: answer.reason,
        })
    }
}
