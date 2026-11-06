// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API's roles, local users and identity providers (WP-8.1, `2-security/5` Roles,
//! Local users, Identity providers): one facade both transports call, every route `authz.admin`,
//! every change one security mutation with its request id and expected revision.
//!
//! A role or a user that still holds active grants is not deleted: the refusal names them, and
//! the command line revokes them first, each its own operation, so a crash between two steps
//! only ever leaves less access. A password arrives in a request body, is checked against the
//! policy and hashed here, and is never answered, logged or audited.

use std::sync::Arc;
use std::time::Duration;

use permguard_core::authz::{Actor, operations};
use permguard_core::{ErrorClass, codes};
use serde::{Deserialize, Serialize};

use super::grants::{GrantView, rfc3339};
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::authz::directory::{
    Change, Directory, DirectoryError, MUTATION_DOMAIN, Role, User, UserStatus, role_principal,
    user_principal,
};
use crate::authz::oidc::{KeyState, Verifier};
use crate::authz::signin::SignIn;
use crate::operations::directory::{failure, names};
use crate::operations::mutation::Applied;

/// What the facade consults for roles, users and providers, given once the server built them.
pub struct Identities {
    pub directory: Arc<Directory>,
    pub signin: Option<Arc<SignIn>>,
    pub providers: Vec<Arc<Verifier>>,
    /// The password policy's `min_length`, for a password an administrator sets.
    pub min_length: usize,
}

/// One role in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSummary {
    pub name: String,
    pub description: String,
    pub members: usize,
    pub grants: usize,
    pub revision: u64,
}

/// `GET /host/v1/roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roles {
    pub revision: u64,
    pub roles: Vec<RoleSummary>,
}

/// `GET /host/v1/roles/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDetail {
    pub name: String,
    pub description: String,
    pub members: Vec<String>,
    pub grants: Vec<GrantView>,
    pub revision: u64,
    pub directory_revision: u64,
}

/// One user, never its password or factor: whether it holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSummary {
    pub name: String,
    pub email: Option<String>,
    pub display: Option<String>,
    pub status: String,
    pub password: bool,
    pub factor: bool,
    pub links: Vec<String>,
    pub roles: Vec<String>,
    /// Seconds the user stays locked by failed sign-ins, when it is.
    pub locked_for: Option<u64>,
    pub revision: u64,
}

/// `GET /host/v1/users`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Users {
    pub revision: u64,
    pub users: Vec<UserSummary>,
}

/// `GET /host/v1/users/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDetail {
    pub user: UserSummary,
    pub grants: Vec<GrantView>,
    pub directory_revision: u64,
}

/// What a directory change answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changed {
    pub receipt: Receipt,
    /// The directory revision after it.
    pub revision: u64,
    /// Whether it wrote anything: adding a member already there writes nothing.
    pub changed: bool,
}

/// `POST /host/v1/roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRole {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// `PATCH /host/v1/roles/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRole {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    pub description: String,
}

/// A change that names nothing more than its target: a deletion, a status, a factor reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plain {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

/// `POST /host/v1/roles/{name}/members` and `…/members/remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    pub member: String,
}

/// `POST /host/v1/users`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// `PATCH /host/v1/users/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUser {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display: Option<String>,
}

/// `POST /host/v1/users/{name}/password`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetPassword {
    #[serde(default)]
    pub request_id: String,
    pub password: String,
}

/// `POST /host/v1/users/{name}/links` and `…/links/remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    #[serde(default)]
    pub request_id: String,
    pub subject: String,
}

/// One identity provider, never its keys: their ids and algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderView {
    pub name: String,
    pub issuer: String,
    pub claim: String,
    pub source: String,
    pub location: String,
    pub keys: Vec<ProviderKey>,
    pub fetched_at: Option<String>,
    pub age_seconds: Option<u64>,
    pub failure: Option<String>,
    pub failed_at: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderKey {
    pub kid: Option<String>,
    pub algorithm: String,
}

/// `GET /host/v1/providers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Providers {
    pub providers: Vec<ProviderView>,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        message,
    )
}

fn refusal_of(error: DirectoryError) -> Refusal {
    match error {
        DirectoryError::Invalid(detail) => invalid(detail),
        DirectoryError::NotFound(detail) => {
            Refusal::new(ErrorClass::NotFound, codes::common::NOT_FOUND, detail)
        }
        DirectoryError::Exists(detail) => {
            Refusal::new(ErrorClass::Conflict, codes::common::CONFLICT, detail)
        }
        DirectoryError::Conflict { expected, current } => {
            Refusal::revision_mismatch(expected, current)
        }
        other @ (DirectoryError::Storage(_) | DirectoryError::Record(_)) => Refusal::Api(
            permguard_core::ApiError::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "the directory could not apply the mutation",
            )
            .with_internal(other.to_string()),
        ),
    }
}

fn provider_view(verifier: &Verifier) -> ProviderView {
    let status = verifier.status();
    ProviderView {
        name: status.name,
        issuer: status.issuer,
        claim: status.claim,
        source: status.source.to_owned(),
        location: status.location,
        keys: status
            .keys
            .into_iter()
            .map(|key| ProviderKey {
                kid: key.kid,
                algorithm: key.algorithm.to_owned(),
            })
            .collect(),
        fetched_at: status.fetched_at.map(rfc3339),
        age_seconds: status.age.map(|age| age.as_secs()),
        failed_at: status.failure.as_ref().map(|failure| rfc3339(failure.at)),
        failure: status.failure.map(|failure| failure.reason),
        state: status.state.as_str().to_owned(),
    }
}

impl HostApi {
    fn identities(&self) -> Result<&Identities, Refusal> {
        self.identities.as_ref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "no directory is open on this process",
            )
        })
    }

    /// The active grants `principal` holds, in revision order.
    fn grants_of(&self, principal: &str) -> Vec<GrantView> {
        let now = self.time.now_secs();
        let mut grants: Vec<GrantView> = self
            .store
            .as_ref()
            .map(|store| store.records())
            .unwrap_or_default()
            .into_iter()
            .filter(|record| record.principal_id.as_str() == principal && record.is_active_at(now))
            .map(GrantView::from)
            .collect();
        grants.sort_by(|left, right| {
            (left.revision, &left.grant_id).cmp(&(right.revision, &right.grant_id))
        });
        grants
    }

    fn user_summary(&self, identities: &Identities, user: &User) -> UserSummary {
        let locked_for = identities.signin.as_ref().and_then(|signin| {
            signin
                .lockout()
                .locked_users()
                .into_iter()
                .find(|(name, _)| name == &user.name)
                .map(|(_, left)| left.as_secs())
        });
        UserSummary {
            name: user.name.clone(),
            email: user.email.clone(),
            display: user.display.clone(),
            status: user.status.as_str().to_owned(),
            password: user.password.is_some(),
            factor: user.factor.is_some(),
            links: user.links.iter().cloned().collect(),
            roles: identities.directory.roles_of(&user.principal()),
            locked_for,
            revision: user.revision,
        }
    }

    /// `GET /host/v1/roles`.
    pub fn roles(&self, actor: &Actor) -> Result<Roles, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        Ok(Roles {
            revision: identities.directory.revision(),
            roles: identities
                .directory
                .roles()
                .into_iter()
                .map(|role: Role| RoleSummary {
                    grants: self.grants_of(&role_principal(&role.name)).len(),
                    members: role.members.len(),
                    name: role.name,
                    description: role.description,
                    revision: role.revision,
                })
                .collect(),
        })
    }

    /// `GET /host/v1/roles/{name}`.
    pub fn role(&self, actor: &Actor, name: &str) -> Result<RoleDetail, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        let role = identities.directory.role(name).ok_or_else(|| {
            refusal_of(DirectoryError::NotFound(format!(
                "there is no role `{name}`"
            )))
        })?;
        Ok(RoleDetail {
            grants: self.grants_of(&role_principal(&role.name)),
            name: role.name,
            description: role.description,
            members: role.members.into_iter().collect(),
            revision: role.revision,
            directory_revision: identities.directory.revision(),
        })
    }

    /// `GET /host/v1/principals/{principal}/roles`.
    pub fn roles_of(&self, actor: &Actor, principal: &str) -> Result<Vec<String>, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        let issuer = crate::authz::issuer_of(principal);
        Ok(identities
            .directory
            .subjects(principal, issuer.as_deref())
            .into_iter()
            .filter_map(|role| role.as_str().strip_prefix("role:").map(str::to_owned))
            .collect())
    }

    /// `GET /host/v1/users`.
    pub fn users(&self, actor: &Actor) -> Result<Users, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        Ok(Users {
            revision: identities.directory.revision(),
            users: identities
                .directory
                .users()
                .iter()
                .map(|user| self.user_summary(identities, user))
                .collect(),
        })
    }

    /// `GET /host/v1/users/{name}`.
    pub fn user(&self, actor: &Actor, name: &str) -> Result<UserDetail, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        let user = identities.directory.user(name).ok_or_else(|| {
            refusal_of(DirectoryError::NotFound(format!(
                "there is no user `{name}`"
            )))
        })?;
        Ok(UserDetail {
            grants: self.grants_of(&user.principal()),
            user: self.user_summary(identities, &user),
            directory_revision: identities.directory.revision(),
        })
    }

    /// `GET /host/v1/providers`.
    pub fn providers(&self, actor: &Actor) -> Result<Providers, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        Ok(Providers {
            providers: identities
                .providers
                .iter()
                .map(|verifier| provider_view(verifier))
                .collect(),
        })
    }

    /// `POST /host/v1/providers/{name}/refresh`: wakes the provider's refresh task and answers
    /// how the provider stands once that fetch ended, or after twenty seconds. It waits: a
    /// transport calls it off its runtime's threads.
    pub fn refresh_provider(&self, actor: &Actor, name: &str) -> Result<ProviderView, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        let verifier = identities
            .providers
            .iter()
            .find(|verifier| verifier.name() == name)
            .ok_or_else(|| {
                refusal_of(DirectoryError::NotFound(format!(
                    "there is no identity provider `{name}`"
                )))
            })?;
        if !verifier.rule().keys.is_fetched() {
            return Err(invalid(format!(
                "the identity provider `{name}` reads a key file: nothing to fetch"
            )));
        }
        let before = verifier.status();
        verifier.ask_refresh();
        for _ in 0..80 {
            let now = verifier.status();
            if now.fetched_at != before.fetched_at || now.failure != before.failure {
                return Ok(provider_view(verifier));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(provider_view(verifier))
    }

    /// `POST /host/v1/users/{name}/unlock`: ends a lockout of failed sign-ins at once.
    pub fn unlock_user(&self, actor: &Actor, name: &str) -> Result<bool, Refusal> {
        let admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        let unlocked = identities
            .signin
            .as_ref()
            .is_some_and(|signin| signin.lockout().unlock(name));
        tracing::info!(
            event.name = "host.user_unlocked",
            component = super::COMPONENT,
            user = %name,
            by = %admitted.principal,
            unlocked,
            "an administrator ended a user's lockout"
        );
        Ok(unlocked)
    }

    /// Applies one directory change as one security mutation.
    async fn change_directory<R: Serialize>(
        &self,
        actor: &Actor,
        request: &R,
        request_id: &str,
        expected_revision: Option<u64>,
        change: Change,
        check: impl FnOnce(&Identities) -> Result<(), Refusal>,
    ) -> Result<Changed, Refusal> {
        let admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        let mutation = Mutation {
            request_id: request_id.to_owned(),
            expected_revision,
        };
        let (operation, action) = names(&change);
        let target = change.target().to_owned();
        let now = self.time.now_secs();
        let directory = Arc::clone(&identities.directory);
        let by = admitted.principal.as_str().to_owned();
        self.transact(
            MUTATION_DOMAIN,
            &admitted.principal,
            operation,
            action,
            &mutation,
            request,
            Some(target.clone()),
            || check(identities),
            |applying| {
                let written = directory
                    .apply(applying, change, &by, now, expected_revision)
                    .map_err(|error| failure(error, refusal_of))?;
                Ok(Applied {
                    revision: written.revision,
                    target: Some(target.clone()),
                    value: Changed {
                        receipt: self.receipt(applying.operation_id(), written.revision),
                        revision: written.revision,
                        changed: written.changed,
                    },
                })
            },
            |operation_id, revision, _| {
                Ok(Changed {
                    receipt: self.receipt(operation_id, revision),
                    revision,
                    changed: true,
                })
            },
        )
    }

    /// Refuses deleting `principal` while it holds active grants, naming them.
    fn holds_no_grants(&self, principal: &str) -> Result<(), Refusal> {
        let held = self.grants_of(principal);
        if held.is_empty() {
            return Ok(());
        }
        Err(Refusal::new(
            ErrorClass::Conflict,
            codes::common::CONFLICT,
            format!(
                "`{principal}` holds {} active grants ({}): revoke them first",
                held.len(),
                held.iter()
                    .map(|grant| grant.grant_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ))
    }

    pub async fn create_role(&self, actor: &Actor, create: CreateRole) -> Result<Changed, Refusal> {
        let change = Change::CreateRole {
            name: create.name.clone(),
            description: create.description.clone(),
        };
        self.change_directory(
            actor,
            &create,
            &create.request_id,
            create.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    pub async fn update_role(
        &self,
        actor: &Actor,
        name: &str,
        update: UpdateRole,
    ) -> Result<Changed, Refusal> {
        let change = Change::UpdateRole {
            name: name.to_owned(),
            description: update.description.clone(),
        };
        self.change_directory(
            actor,
            &(name, &update),
            &update.request_id,
            update.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    pub async fn delete_role(
        &self,
        actor: &Actor,
        name: &str,
        delete: Plain,
    ) -> Result<Changed, Refusal> {
        let change = Change::DeleteRole {
            name: name.to_owned(),
        };
        let principal = role_principal(name);
        self.change_directory(
            actor,
            &(name, &delete),
            &delete.request_id,
            delete.expected_revision,
            change,
            |_| self.holds_no_grants(&principal),
        )
        .await
    }

    pub async fn add_member(
        &self,
        actor: &Actor,
        role: &str,
        member: Member,
    ) -> Result<Changed, Refusal> {
        let change = Change::AddMember {
            role: role.to_owned(),
            member: member.member.clone(),
        };
        self.change_directory(
            actor,
            &(role, "add", &member),
            &member.request_id,
            member.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    pub async fn remove_member(
        &self,
        actor: &Actor,
        role: &str,
        member: Member,
    ) -> Result<Changed, Refusal> {
        let change = Change::RemoveMember {
            role: role.to_owned(),
            member: member.member.clone(),
        };
        self.change_directory(
            actor,
            &(role, "remove", &member),
            &member.request_id,
            member.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    /// Authorizes before a password is looked at: a caller without the grant learns nothing of
    /// the policy and never makes the Host spend an Argon2id hash. The mutation admits again,
    /// with its bound.
    fn authorized_first(&self, actor: &Actor) -> Result<(), Refusal> {
        self.authorization.authorize(
            actor,
            operations::AUTHZ_ADMIN,
            &permguard_core::authz::Resource::host(),
        )?;
        Ok(())
    }

    pub async fn create_user(&self, actor: &Actor, create: CreateUser) -> Result<Changed, Refusal> {
        self.authorized_first(actor)?;
        let identities = self.identities()?;
        let password = match &create.password {
            Some(password) => {
                crate::authz::password::check_policy(&create.name, password, identities.min_length)
                    .map_err(invalid)?;
                Some(crate::authz::password::hash(password).map_err(invalid)?)
            }
            None => None,
        };
        let change = Change::CreateUser {
            name: create.name.clone(),
            email: create.email.clone(),
            display: create.display.clone(),
            password,
        };
        // The request digest never covers the password: a replayed request is the same request.
        let digested = (
            &create.request_id,
            &create.name,
            &create.email,
            &create.display,
            create.password.is_some(),
        );
        self.change_directory(
            actor,
            &digested,
            &create.request_id,
            create.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    pub async fn update_user(
        &self,
        actor: &Actor,
        name: &str,
        update: UpdateUser,
    ) -> Result<Changed, Refusal> {
        let change = Change::UpdateUser {
            name: name.to_owned(),
            email: update.email.clone(),
            display: update.display.clone(),
        };
        self.change_directory(
            actor,
            &(name, &update),
            &update.request_id,
            update.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    /// Sets a user's password; every session of the user ends.
    pub async fn set_password(
        &self,
        actor: &Actor,
        name: &str,
        set: SetPassword,
    ) -> Result<Changed, Refusal> {
        self.authorized_first(actor)?;
        let identities = self.identities()?;
        crate::authz::password::check_policy(name, &set.password, identities.min_length)
            .map_err(invalid)?;
        let phc = crate::authz::password::hash(&set.password).map_err(invalid)?;
        let change = Change::SetPassword {
            name: name.to_owned(),
            password: phc,
        };
        let changed = self
            .change_directory(
                actor,
                &(name, "password", &set.request_id),
                &set.request_id,
                None,
                change,
                |_| Ok(()),
            )
            .await?;
        self.end_sessions(name);
        Ok(changed)
    }

    /// Enables or disables a user; disabling ends its sessions.
    pub async fn set_status(
        &self,
        actor: &Actor,
        name: &str,
        active: bool,
        plain: Plain,
    ) -> Result<Changed, Refusal> {
        let change = Change::SetStatus {
            name: name.to_owned(),
            active,
        };
        let changed = self
            .change_directory(
                actor,
                &(name, active, &plain),
                &plain.request_id,
                plain.expected_revision,
                change,
                |_| Ok(()),
            )
            .await?;
        if !active {
            self.end_sessions(name);
        }
        Ok(changed)
    }

    /// Resets a user's second factor: it enrolls again at its next sign-in, when one is asked.
    pub async fn reset_factor(
        &self,
        actor: &Actor,
        name: &str,
        plain: Plain,
    ) -> Result<Changed, Refusal> {
        let change = Change::SetFactor {
            name: name.to_owned(),
            factor: None,
        };
        self.change_directory(
            actor,
            &(name, "factor-reset", &plain),
            &plain.request_id,
            plain.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    pub async fn link_user(
        &self,
        actor: &Actor,
        name: &str,
        link: Link,
        linked: bool,
    ) -> Result<Changed, Refusal> {
        let change = if linked {
            Change::Link {
                name: name.to_owned(),
                subject: link.subject.clone(),
            }
        } else {
            Change::Unlink {
                name: name.to_owned(),
                subject: link.subject.clone(),
            }
        };
        self.change_directory(
            actor,
            &(name, linked, &link),
            &link.request_id,
            None,
            change,
            |_| Ok(()),
        )
        .await
    }

    /// Deletes a user that holds no active grant; its sessions end.
    pub async fn delete_user(
        &self,
        actor: &Actor,
        name: &str,
        delete: Plain,
    ) -> Result<Changed, Refusal> {
        let change = Change::DeleteUser {
            name: name.to_owned(),
        };
        let principal = user_principal(name);
        let changed = self
            .change_directory(
                actor,
                &(name, "delete", &delete),
                &delete.request_id,
                delete.expected_revision,
                change,
                |_| self.holds_no_grants(&principal),
            )
            .await?;
        self.end_sessions(name);
        Ok(changed)
    }

    fn end_sessions(&self, name: &str) {
        if let Some(signin) = self
            .identities
            .as_ref()
            .and_then(|identities| identities.signin.as_ref())
        {
            let ended = signin.sessions().end_user(name, None);
            if ended > 0 {
                tracing::info!(
                    event.name = "host.sessions_ended",
                    component = super::COMPONENT,
                    user = %name,
                    sessions = ended,
                    "a user's sessions ended"
                );
            }
        }
    }
}

/// Whether a user is active, for a caller reading [`UserSummary::status`].
pub fn is_active(summary: &UserSummary) -> bool {
    summary.status == UserStatus::Active.as_str()
}

/// What [`KeyState`] reads as on the wire.
pub fn key_state(state: KeyState) -> &'static str {
    state.as_str()
}
