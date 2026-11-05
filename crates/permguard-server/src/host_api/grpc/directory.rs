// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `RoleService`, `UserService` and `ProviderService` (WP-8.1): each rpc one call into the facade
//! the REST routes call. A password arrives in a request and is never answered.

use tonic::{Request, Response};

use permguard_host::api::directory::{
    Changed, CreateRole, CreateUser, Link, Member, Plain, ProviderView, SetPassword, UpdateRole,
    UpdateUser, UserSummary,
};

use super::super::v1;
use super::super::v1::provider_service_server::ProviderService;
use super::super::v1::role_service_server::RoleService;
use super::super::v1::user_service_server::UserService;
use super::{Answer, Served, grant, receipt};

fn changed(changed: Changed) -> v1::DirectoryChangeResponse {
    v1::DirectoryChangeResponse {
        receipt: Some(receipt(changed.receipt)),
        revision: changed.revision,
        changed: changed.changed,
    }
}

fn user(user: UserSummary) -> v1::UserSummary {
    v1::UserSummary {
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

fn provider(view: ProviderView) -> v1::Provider {
    v1::Provider {
        name: view.name,
        issuer: view.issuer,
        claim: view.claim,
        source: view.source,
        location: view.location,
        keys: view
            .keys
            .into_iter()
            .map(|key| v1::ProviderKey {
                kid: key.kid,
                algorithm: key.algorithm,
            })
            .collect(),
        fetched_at: view.fetched_at,
        age_seconds: view.age_seconds,
        failure: view.failure,
        failed_at: view.failed_at,
        state: view.state,
    }
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[tonic::async_trait]
impl RoleService for Served {
    async fn list_roles(
        &self,
        request: Request<v1::ListRolesRequest>,
    ) -> Answer<v1::ListRolesResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self
            .api
            .roles(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListRolesResponse {
            revision: listed.revision,
            roles: listed
                .roles
                .into_iter()
                .map(|role| v1::RoleSummary {
                    name: role.name,
                    description: role.description,
                    members: count(role.members),
                    grants: count(role.grants),
                    revision: role.revision,
                })
                .collect(),
        }))
    }

    async fn get_role(&self, request: Request<v1::GetRoleRequest>) -> Answer<v1::GetRoleResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let role = self
            .api
            .role(&actor, &asked.name)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetRoleResponse {
            name: role.name,
            description: role.description,
            members: role.members,
            grants: role.grants.into_iter().map(grant).collect(),
            revision: role.revision,
            directory_revision: role.directory_revision,
        }))
    }

    async fn create_role(
        &self,
        request: Request<v1::CreateRoleRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .create_role(
                &actor,
                CreateRole {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    name: asked.name,
                    description: asked.description,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn update_role(
        &self,
        request: Request<v1::UpdateRoleRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .update_role(
                &actor,
                &asked.name,
                UpdateRole {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    description: asked.description,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn delete_role(
        &self,
        request: Request<v1::DeleteRoleRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .delete_role(
                &actor,
                &asked.name,
                Plain {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn add_member(
        &self,
        request: Request<v1::MemberRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .add_member(
                &actor,
                &asked.role,
                Member {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    member: asked.member,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn remove_member(
        &self,
        request: Request<v1::MemberRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .remove_member(
                &actor,
                &asked.role,
                Member {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    member: asked.member,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn roles_of(&self, request: Request<v1::RolesOfRequest>) -> Answer<v1::RolesOfResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let roles = self
            .api
            .roles_of(&actor, &asked.principal)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::RolesOfResponse { roles }))
    }
}

#[tonic::async_trait]
impl UserService for Served {
    async fn list_users(
        &self,
        request: Request<v1::ListUsersRequest>,
    ) -> Answer<v1::ListUsersResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self
            .api
            .users(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListUsersResponse {
            revision: listed.revision,
            users: listed.users.into_iter().map(user).collect(),
        }))
    }

    async fn get_user(&self, request: Request<v1::GetUserRequest>) -> Answer<v1::GetUserResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let detail = self
            .api
            .user(&actor, &asked.name)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetUserResponse {
            user: Some(user(detail.user)),
            grants: detail.grants.into_iter().map(grant).collect(),
            directory_revision: detail.directory_revision,
        }))
    }

    async fn create_user(
        &self,
        request: Request<v1::CreateUserRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let create = CreateUser {
            request_id: asked.request_id,
            expected_revision: asked.expected_revision,
            name: asked.name,
            email: asked.email,
            display: asked.display,
            password: asked.password,
        };
        // Argon2id runs off the runtime's threads.
        let handle = tokio::runtime::Handle::current();
        let done = self
            .blocking(move |api| handle.block_on(api.create_user(&actor, create)))
            .await?;
        Ok(Response::new(changed(done)))
    }

    async fn update_user(
        &self,
        request: Request<v1::UpdateUserRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .update_user(
                &actor,
                &asked.name,
                UpdateUser {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    email: asked.email,
                    display: asked.display,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn set_password(
        &self,
        request: Request<v1::SetPasswordRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let set = SetPassword {
            request_id: asked.request_id,
            password: asked.password,
        };
        let name = asked.name;
        let handle = tokio::runtime::Handle::current();
        let done = self
            .blocking(move |api| handle.block_on(api.set_password(&actor, &name, set)))
            .await?;
        Ok(Response::new(changed(done)))
    }

    async fn set_user_status(
        &self,
        request: Request<v1::SetUserStatusRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .set_status(
                &actor,
                &asked.name,
                asked.active,
                Plain {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn reset_factor(
        &self,
        request: Request<v1::UserPlainRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .reset_factor(
                &actor,
                &asked.name,
                Plain {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn unlock_user(
        &self,
        request: Request<v1::UnlockUserRequest>,
    ) -> Answer<v1::UnlockUserResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let unlocked = self
            .api
            .unlock_user(&actor, &asked.name)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::UnlockUserResponse { unlocked }))
    }

    async fn link_user(
        &self,
        request: Request<v1::LinkUserRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .link_user(
                &actor,
                &asked.name,
                Link {
                    request_id: asked.request_id,
                    subject: asked.subject,
                },
                asked.link,
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn delete_user(
        &self,
        request: Request<v1::UserPlainRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .delete_user(
                &actor,
                &asked.name,
                Plain {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }
}

#[tonic::async_trait]
impl ProviderService for Served {
    async fn list_providers(
        &self,
        request: Request<v1::ListProvidersRequest>,
    ) -> Answer<v1::ListProvidersResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self
            .api
            .providers(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListProvidersResponse {
            providers: listed.providers.into_iter().map(provider).collect(),
        }))
    }

    async fn refresh_provider(
        &self,
        request: Request<v1::RefreshProviderRequest>,
    ) -> Answer<v1::Provider> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let refreshed = self
            .blocking(move |api| api.refresh_provider(&actor, &asked.name))
            .await?;
        Ok(Response::new(provider(refreshed)))
    }
}
