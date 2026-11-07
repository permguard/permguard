// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The IAM Host's service accounts and their credentials (iteration 02, WP-11.2, `2-security/5`
//! Service accounts, `2-security/8` Service accounts): one facade both transports call, every
//! route `authz.admin`, every change one security mutation of the directory.
//!
//! A `client_secret` is drawn here and answered once, by the call that made it: the mutation
//! engine journals an answer to replay it, so the secret is attached after the engine answered,
//! never inside what it keeps. A retried request is answered without it.

use std::collections::BTreeMap;
use std::sync::Arc;

use permguard_core::authz::{Actor, operations};
use permguard_core::{ErrorClass, codes};
use serde::{Deserialize, Serialize};

use super::directory::{Changed, Identities, Plain};
use super::grants::{GrantView, rfc3339};
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::authz::credentials;
use crate::authz::directory::{
    Change, Credential, CredentialMaterial, DirectoryError, MUTATION_DOMAIN, ServiceAccount,
    service_account_principal,
};
use crate::identity::record::{uuid_text, uuid_v7};
use crate::operations::directory::{failure, names};
use crate::operations::mutation::Applied;

/// One service account in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountSummary {
    pub name: String,
    pub owner: String,
    pub description: String,
    pub status: String,
    /// Its live credentials.
    pub credentials: usize,
    pub roles: Vec<String>,
    pub revision: u64,
}

/// `GET /iam/v1/service-accounts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccounts {
    pub revision: u64,
    pub service_accounts: Vec<ServiceAccountSummary>,
}

/// One credential, never its secret: what proves it and how it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialView {
    pub id: String,
    pub kind: String,
    /// A `private_key_jwt`'s RFC 7638 thumbprint, the `kid` its assertions name.
    pub key_id: Option<String>,
    /// A `private_key_jwt`'s algorithm.
    pub algorithm: Option<String>,
    /// A `tls_client_auth`'s binding.
    pub binding: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub expires_at: Option<String>,
    /// `active`, `expired` or `revoked`.
    pub status: String,
    pub revoked_at: Option<String>,
}

/// `GET /iam/v1/service-accounts/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountDetail {
    pub service_account: ServiceAccountSummary,
    pub grants: Vec<GrantView>,
    pub credentials: Vec<CredentialView>,
    pub directory_revision: u64,
}

/// `GET /iam/v1/service-accounts/{name}/credentials`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub credentials: Vec<CredentialView>,
}

/// `POST /iam/v1/service-accounts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceAccount {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    pub name: String,
    pub owner: String,
    #[serde(default)]
    pub description: String,
}

/// `PATCH /iam/v1/service-accounts/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateServiceAccount {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// `POST /iam/v1/service-accounts/{name}/credentials`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCredential {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    /// `client_secret`, `private_key_jwt` or `tls_client_auth`.
    pub kind: String,
    /// A `private_key_jwt`'s public JWK, its members as text.
    #[serde(default)]
    pub public_key: Option<BTreeMap<String, String>>,
    /// A `tls_client_auth`'s `spki:sha256:<hex>` or SAN URI.
    #[serde(default)]
    pub certificate: Option<String>,
    /// RFC 3339.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// What making a credential answers: the secret only to the call that drew it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCreated {
    pub receipt: Receipt,
    pub revision: u64,
    pub credential: CredentialView,
    /// A `client_secret`, answered once.
    pub client_secret: Option<String>,
}

impl std::fmt::Debug for CredentialCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialCreated")
            .field("receipt", &self.receipt)
            .field("revision", &self.revision)
            .field("credential", &self.credential)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<secret>"),
            )
            .finish()
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        message,
    )
}

fn refusal_of(error: DirectoryError) -> Refusal {
    super::directory::refusal_of(error)
}

fn not_found(name: &str) -> Refusal {
    refusal_of(DirectoryError::NotFound(format!(
        "there is no service account `{name}`"
    )))
}

/// How `credential` stands at `now`.
fn credential_view(credential: &Credential, now: u64) -> CredentialView {
    let (key_id, algorithm, binding) = match &credential.material {
        CredentialMaterial::Secret { .. } => (None, None, None),
        CredentialMaterial::Key {
            algorithm, key_id, ..
        } => (Some(key_id.clone()), Some(algorithm.clone()), None),
        CredentialMaterial::Binding { binding } => (None, None, Some(binding.clone())),
    };
    let status = if credential.revoked_at.is_some() {
        "revoked"
    } else if credential.is_live_at(now) {
        "active"
    } else {
        "expired"
    };
    CredentialView {
        id: credential.id_text(),
        kind: credential.material.kind().to_owned(),
        key_id,
        algorithm,
        binding,
        created_at: rfc3339(credential.created_at),
        created_by: credential.created_by.clone(),
        expires_at: credential.expires_at.map(rfc3339),
        status: status.to_owned(),
        revoked_at: credential.revoked_at.map(rfc3339),
    }
}

impl HostApi {
    fn account_summary(
        &self,
        identities: &Identities,
        account: &ServiceAccount,
    ) -> ServiceAccountSummary {
        let now = self.time.now_secs();
        ServiceAccountSummary {
            name: account.name.clone(),
            owner: account.owner.clone(),
            description: account.description.clone(),
            status: account.status.as_str().to_owned(),
            credentials: account.live_credentials(now).count(),
            roles: identities.directory.roles_of(&account.principal()),
            revision: account.revision,
        }
    }

    fn held_account(&self, name: &str) -> Result<(&Identities, ServiceAccount), Refusal> {
        let identities = self.identities()?;
        let account = identities
            .directory
            .service_account(name)
            .ok_or_else(|| not_found(name))?;
        Ok((identities, account))
    }

    /// `GET /iam/v1/service-accounts`.
    pub fn service_accounts(&self, actor: &Actor) -> Result<ServiceAccounts, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        Ok(ServiceAccounts {
            revision: identities.directory.revision(),
            service_accounts: identities
                .directory
                .service_accounts()
                .iter()
                .map(|account| self.account_summary(identities, account))
                .collect(),
        })
    }

    /// `GET /iam/v1/service-accounts/{name}`.
    pub fn service_account(
        &self,
        actor: &Actor,
        name: &str,
    ) -> Result<ServiceAccountDetail, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let (identities, account) = self.held_account(name)?;
        let now = self.time.now_secs();
        Ok(ServiceAccountDetail {
            grants: self.grants_of(&account.principal()),
            credentials: account
                .credentials
                .iter()
                .map(|credential| credential_view(credential, now))
                .collect(),
            service_account: self.account_summary(identities, &account),
            directory_revision: identities.directory.revision(),
        })
    }

    /// `GET /iam/v1/service-accounts/{name}/credentials`.
    pub fn credentials(&self, actor: &Actor, name: &str) -> Result<Credentials, Refusal> {
        self.admit(actor, operations::AUTHZ_ADMIN)?;
        let (_, account) = self.held_account(name)?;
        let now = self.time.now_secs();
        Ok(Credentials {
            credentials: account
                .credentials
                .iter()
                .map(|credential| credential_view(credential, now))
                .collect(),
        })
    }

    pub async fn create_service_account(
        &self,
        actor: &Actor,
        create: CreateServiceAccount,
    ) -> Result<Changed, Refusal> {
        let change = Change::CreateServiceAccount {
            name: create.name.clone(),
            owner: create.owner.clone(),
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

    pub async fn update_service_account(
        &self,
        actor: &Actor,
        name: &str,
        update: UpdateServiceAccount,
    ) -> Result<Changed, Refusal> {
        let change = Change::UpdateServiceAccount {
            name: name.to_owned(),
            owner: update.owner.clone(),
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

    /// Suspends or resumes a service account: a suspended one obtains no token.
    pub async fn set_account_status(
        &self,
        actor: &Actor,
        name: &str,
        active: bool,
        plain: Plain,
    ) -> Result<Changed, Refusal> {
        let change = Change::SetAccountStatus {
            name: name.to_owned(),
            active,
        };
        self.change_directory(
            actor,
            &(name, active, &plain),
            &plain.request_id,
            plain.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }

    /// Deletes a service account that holds no active grant, with its credentials.
    pub async fn delete_service_account(
        &self,
        actor: &Actor,
        name: &str,
        delete: Plain,
    ) -> Result<Changed, Refusal> {
        let change = Change::DeleteServiceAccount {
            name: name.to_owned(),
        };
        let principal = service_account_principal(name);
        self.change_directory(
            actor,
            &(name, "delete", &delete),
            &delete.request_id,
            delete.expected_revision,
            change,
            |_| self.holds_no_grants(&principal),
        )
        .await
    }

    /// Makes a credential. A `client_secret` is drawn and hashed before the mutation, and
    /// answered only when this call's credential is the one the directory now holds.
    pub async fn create_credential(
        &self,
        actor: &Actor,
        name: &str,
        create: CreateCredential,
    ) -> Result<CredentialCreated, Refusal> {
        // Authorized before a secret is drawn or hashed: a caller without the grant costs the
        // Host no Argon2id.
        self.authorized_first(actor)?;
        let expires_at = create
            .expires_at
            .as_deref()
            .map(|text| {
                permguard_core::time::from_rfc3339(text)
                    .and_then(|seconds| u64::try_from(seconds).ok())
                    .ok_or_else(|| invalid(format!("`{text}` is not an RFC 3339 time")))
            })
            .transpose()?;
        let only = |present: bool, member: &str| {
            if present {
                Err(invalid(format!(
                    "`{member}` is not given for a `{}` credential",
                    create.kind
                )))
            } else {
                Ok(())
            }
        };
        let mut secret = None;
        let material =
            match create.kind.as_str() {
                credentials::CLIENT_SECRET => {
                    only(create.public_key.is_some(), "public_key")?;
                    only(create.certificate.is_some(), "certificate")?;
                    let drawn = credentials::draw_secret().map_err(invalid)?;
                    let phc = crate::authz::password::hash(&drawn).map_err(invalid)?;
                    secret = Some(drawn);
                    CredentialMaterial::Secret { phc }
                }
                credentials::PRIVATE_KEY_JWT => {
                    only(create.certificate.is_some(), "certificate")?;
                    let jwk = create.public_key.as_ref().ok_or_else(|| {
                        invalid("a `private_key_jwt` credential gives `public_key`")
                    })?;
                    let key = credentials::public_key(jwk).map_err(invalid)?;
                    CredentialMaterial::Key {
                        algorithm: key.algorithm.to_owned(),
                        key: key.key,
                        key_id: key.key_id,
                    }
                }
                credentials::TLS_CLIENT_AUTH => {
                    only(create.public_key.is_some(), "public_key")?;
                    let certificate = create.certificate.as_deref().ok_or_else(|| {
                        invalid("a `tls_client_auth` credential gives `certificate`")
                    })?;
                    CredentialMaterial::Binding {
                        binding: credentials::binding(certificate).map_err(invalid)?,
                    }
                }
                other => {
                    return Err(invalid(format!(
                        "`{other}` is not a credential kind: {}",
                        credentials::KINDS.join(", ")
                    )));
                }
            };
        let mut random = [0u8; 10];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .map_err(|_| invalid("the OS random source failed"))?;
        let id = uuid_v7(self.time.now_secs().saturating_mul(1000), random);
        let created = self.add_credential(actor, name, &create, id, material, expires_at)?;
        // Only the call whose drawn id the directory holds answers the secret: a retried
        // request answers the first call's credential, whose secret nobody keeps.
        let fresh = created.credential.id == uuid_text(&id);
        Ok(CredentialCreated {
            client_secret: secret.filter(|_| fresh),
            ..created
        })
    }

    fn add_credential(
        &self,
        actor: &Actor,
        name: &str,
        create: &CreateCredential,
        id: [u8; 16],
        material: CredentialMaterial,
        expires_at: Option<u64>,
    ) -> Result<CredentialCreated, Refusal> {
        let admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let identities = self.identities()?;
        let mutation = Mutation {
            request_id: create.request_id.clone(),
            expected_revision: create.expected_revision,
        };
        let change = Change::AddCredential {
            account: name.to_owned(),
            id,
            material: material.clone(),
            expires_at,
        };
        let (operation, action) = names(&change);
        let now = self.time.now_secs();
        let directory = Arc::clone(&identities.directory);
        let by = admitted.principal.as_str().to_owned();
        let target = name.to_owned();
        self.transact(
            MUTATION_DOMAIN,
            &admitted.principal,
            operation,
            action,
            &mutation,
            &(name, create),
            Some(target.clone()),
            || Ok(()),
            |applying| {
                let written = directory
                    .apply(applying, change, &by, now, create.expected_revision)
                    .map_err(|error| failure(error, refusal_of))?;
                // The credential as the transition just made it: read from what was written, not
                // from the directory again, which another operation may have changed since.
                let credential = credential_view(
                    &Credential {
                        id,
                        material,
                        created_revision: written.revision,
                        created_at: now,
                        created_by: by.clone(),
                        expires_at,
                        revoked_at: None,
                    },
                    now,
                );
                Ok(Applied {
                    revision: written.revision,
                    target: Some(target.clone()),
                    value: CredentialCreated {
                        receipt: self.receipt(applying.operation_id(), written.revision),
                        revision: written.revision,
                        credential,
                        client_secret: None,
                    },
                })
            },
            |operation_id, revision, _| {
                // Applied, its answer lost: the credential is the one that revision made.
                let account = directory
                    .service_account(name)
                    .ok_or_else(|| not_found(name))?;
                let credential = account
                    .credentials
                    .iter()
                    .find(|credential| credential.created_revision == revision)
                    .map(|credential| credential_view(credential, now))
                    .ok_or_else(|| not_found(name))?;
                Ok(CredentialCreated {
                    receipt: self.receipt(operation_id, revision),
                    revision,
                    credential,
                    client_secret: None,
                })
            },
        )
    }

    /// Revokes a credential: it proves nothing from now on.
    pub async fn revoke_credential(
        &self,
        actor: &Actor,
        name: &str,
        id: &str,
        plain: Plain,
    ) -> Result<Changed, Refusal> {
        // Authorized before the id is read: a caller without the grant learns nothing of it.
        self.authorized_first(actor)?;
        let parsed = crate::secrets::parse_uuid(id)
            .ok_or_else(|| invalid(format!("`{id}` is not a credential id")))?;
        let change = Change::RevokeCredential {
            account: name.to_owned(),
            id: parsed,
        };
        self.change_directory(
            actor,
            &(name, id, "revoke", &plain),
            &plain.request_id,
            plain.expected_revision,
            change,
            |_| Ok(()),
        )
        .await
    }
}
