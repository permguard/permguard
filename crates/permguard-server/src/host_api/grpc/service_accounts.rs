// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `ServiceAccountService` (iteration 02, WP-11.2): each rpc one call into the facade the REST
//! routes call. A client secret is answered once, by the call that drew it.

use tonic::{Request, Response};

use permguard_host::api::directory::Plain;
use permguard_host::api::service_accounts::{
    CreateCredential, CreateServiceAccount, CredentialView, ServiceAccountSummary,
    UpdateServiceAccount,
};

use super::super::iam_v1::{self, service_account_service_server::ServiceAccountService};
use super::super::v1;
use super::directory::changed;
use super::{Answer, Served, grant, receipt};

fn summary(summary: ServiceAccountSummary) -> iam_v1::ServiceAccountSummary {
    iam_v1::ServiceAccountSummary {
        name: summary.name,
        owner: summary.owner,
        description: summary.description,
        status: summary.status,
        credentials: u64::try_from(summary.credentials).unwrap_or(u64::MAX),
        roles: summary.roles,
        revision: summary.revision,
    }
}

fn credential(view: CredentialView) -> iam_v1::Credential {
    iam_v1::Credential {
        id: view.id,
        kind: view.kind,
        key_id: view.key_id,
        algorithm: view.algorithm,
        binding: view.binding,
        created_at: view.created_at,
        created_by: view.created_by,
        expires_at: view.expires_at,
        status: view.status,
        revoked_at: view.revoked_at,
    }
}

fn plain(request_id: String, expected_revision: Option<u64>) -> Plain {
    Plain {
        request_id,
        expected_revision,
    }
}

#[tonic::async_trait]
impl ServiceAccountService for Served {
    async fn list_service_accounts(
        &self,
        request: Request<iam_v1::ListServiceAccountsRequest>,
    ) -> Answer<iam_v1::ListServiceAccountsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self
            .api
            .service_accounts(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(iam_v1::ListServiceAccountsResponse {
            revision: listed.revision,
            service_accounts: listed.service_accounts.into_iter().map(summary).collect(),
        }))
    }

    async fn get_service_account(
        &self,
        request: Request<iam_v1::GetServiceAccountRequest>,
    ) -> Answer<iam_v1::GetServiceAccountResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let detail = self
            .api
            .service_account(&actor, &asked.name)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(iam_v1::GetServiceAccountResponse {
            service_account: Some(summary(detail.service_account)),
            grants: detail.grants.into_iter().map(grant).collect(),
            credentials: detail.credentials.into_iter().map(credential).collect(),
            directory_revision: detail.directory_revision,
        }))
    }

    async fn create_service_account(
        &self,
        request: Request<iam_v1::CreateServiceAccountRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .create_service_account(
                &actor,
                CreateServiceAccount {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    name: asked.name,
                    owner: asked.owner,
                    description: asked.description,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn update_service_account(
        &self,
        request: Request<iam_v1::UpdateServiceAccountRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .update_service_account(
                &actor,
                &asked.name,
                UpdateServiceAccount {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    owner: asked.owner,
                    description: asked.description,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn set_service_account_status(
        &self,
        request: Request<iam_v1::SetServiceAccountStatusRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .set_account_status(
                &actor,
                &asked.name,
                asked.active,
                plain(asked.request_id, asked.expected_revision),
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn delete_service_account(
        &self,
        request: Request<iam_v1::ServiceAccountPlainRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .delete_service_account(
                &actor,
                &asked.name,
                plain(asked.request_id, asked.expected_revision),
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }

    async fn list_credentials(
        &self,
        request: Request<iam_v1::ListCredentialsRequest>,
    ) -> Answer<iam_v1::ListCredentialsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let listed = self
            .api
            .credentials(&actor, &asked.name)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(iam_v1::ListCredentialsResponse {
            credentials: listed.credentials.into_iter().map(credential).collect(),
        }))
    }

    async fn create_credential(
        &self,
        request: Request<iam_v1::CreateCredentialRequest>,
    ) -> Answer<iam_v1::CreateCredentialResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let create = CreateCredential {
            request_id: asked.request_id,
            expected_revision: asked.expected_revision,
            kind: asked.kind,
            // An empty map is no key: proto3 cannot tell it from absent.
            public_key: (!asked.public_key.is_empty())
                .then(|| asked.public_key.into_iter().collect()),
            certificate: asked.certificate,
            expires_at: asked.expires_at,
        };
        let name = asked.name;
        // A client secret's Argon2id runs off the runtime's threads.
        let handle = tokio::runtime::Handle::current();
        let created = self
            .blocking(move |api| handle.block_on(api.create_credential(&actor, &name, create)))
            .await?;
        Ok(Response::new(iam_v1::CreateCredentialResponse {
            receipt: Some(receipt(created.receipt)),
            revision: created.revision,
            credential: Some(credential(created.credential)),
            client_secret: created.client_secret,
        }))
    }

    async fn revoke_credential(
        &self,
        request: Request<iam_v1::RevokeCredentialRequest>,
    ) -> Answer<v1::DirectoryChangeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .revoke_credential(
                &actor,
                &asked.name,
                &asked.id,
                plain(asked.request_id, asked.expected_revision),
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(changed(done)))
    }
}
