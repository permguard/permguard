// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The IAM Host's service accounts, their credentials and the access tokens it issued, as a
//! client sees them (iteration 02, TC-6): what `iam service-accounts`, `iam credentials` and
//! `iam tokens` reach, over REST and gRPC alike. A `client_secret` is answered once, by the call
//! that made it; a token is never answered at all, only its `jti` and status.

use permguard_host::api::directory::{Changed, Plain};
use permguard_host::api::service_accounts::{
    CreateCredential, CreateServiceAccount, CredentialCreated, CredentialView, Credentials,
    ServiceAccountDetail, ServiceAccountSummary, ServiceAccounts, UpdateServiceAccount,
};
use permguard_host::api::tokens::{RevokeToken, TokenList, TokenRevoked, TokenView};

use super::directory::changed;
use super::{GrpcHost, RestHost, json, segment};
use crate::catalog::Failure;
use crate::host_proto as map;
use crate::iam_v1 as iam;

/// The IAM Host's service accounts, credentials and access tokens.
pub trait Accounts {
    fn service_accounts(&self) -> Result<ServiceAccounts, Failure>;
    fn service_account(&self, name: &str) -> Result<ServiceAccountDetail, Failure>;
    fn create_service_account(&self, request: &CreateServiceAccount) -> Result<Changed, Failure>;
    fn update_service_account(
        &self,
        name: &str,
        request: &UpdateServiceAccount,
    ) -> Result<Changed, Failure>;
    /// Suspends (`active` false) or resumes the account: every token of it follows.
    fn set_service_account_status(
        &self,
        name: &str,
        active: bool,
        request: &Plain,
    ) -> Result<Changed, Failure>;
    fn delete_service_account(&self, name: &str, request: &Plain) -> Result<Changed, Failure>;
    fn credentials(&self, name: &str) -> Result<Credentials, Failure>;
    /// A new credential; a `client_secret` is in the answer, and only in this one.
    fn create_credential(
        &self,
        name: &str,
        request: &CreateCredential,
    ) -> Result<CredentialCreated, Failure>;
    fn revoke_credential(&self, name: &str, id: &str, request: &Plain) -> Result<Changed, Failure>;
    fn tokens(&self) -> Result<TokenList, Failure>;
    fn revoke_token(&self, jti: &str, request: &RevokeToken) -> Result<TokenRevoked, Failure>;
}

impl Accounts for RestHost {
    fn service_accounts(&self) -> Result<ServiceAccounts, Failure> {
        self.get("/iam/v1/service-accounts")
    }

    fn service_account(&self, name: &str) -> Result<ServiceAccountDetail, Failure> {
        self.get(&format!("/iam/v1/service-accounts/{}", segment(name)?))
    }

    fn create_service_account(&self, request: &CreateServiceAccount) -> Result<Changed, Failure> {
        self.post("/iam/v1/service-accounts", &json(request)?)
    }

    fn update_service_account(
        &self,
        name: &str,
        request: &UpdateServiceAccount,
    ) -> Result<Changed, Failure> {
        self.patch(
            &format!("/iam/v1/service-accounts/{}", segment(name)?),
            &json(request)?,
        )
    }

    fn set_service_account_status(
        &self,
        name: &str,
        active: bool,
        request: &Plain,
    ) -> Result<Changed, Failure> {
        let verb = if active { "resume" } else { "suspend" };
        self.post(
            &format!("/iam/v1/service-accounts/{}/{verb}", segment(name)?),
            &json(request)?,
        )
    }

    fn delete_service_account(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.post(
            &format!("/iam/v1/service-accounts/{}/delete", segment(name)?),
            &json(request)?,
        )
    }

    fn credentials(&self, name: &str) -> Result<Credentials, Failure> {
        self.get(&format!(
            "/iam/v1/service-accounts/{}/credentials",
            segment(name)?
        ))
    }

    fn create_credential(
        &self,
        name: &str,
        request: &CreateCredential,
    ) -> Result<CredentialCreated, Failure> {
        self.post(
            &format!("/iam/v1/service-accounts/{}/credentials", segment(name)?),
            &json(request)?,
        )
    }

    fn revoke_credential(&self, name: &str, id: &str, request: &Plain) -> Result<Changed, Failure> {
        self.post(
            &format!(
                "/iam/v1/service-accounts/{}/credentials/{}/revoke",
                segment(name)?,
                segment(id)?
            ),
            &json(request)?,
        )
    }

    fn tokens(&self) -> Result<TokenList, Failure> {
        self.get("/iam/v1/tokens")
    }

    fn revoke_token(&self, jti: &str, request: &RevokeToken) -> Result<TokenRevoked, Failure> {
        self.post(
            &format!("/iam/v1/tokens/{}/revoke", segment(jti)?),
            &json(request)?,
        )
    }
}

/// An answer missing what its message promises.
fn incomplete(detail: &str) -> Failure {
    Failure {
        class: "unavailable".to_owned(),
        reason: permguard_core::codes::common::UNAVAILABLE.to_owned(),
        detail: detail.to_owned(),
        usage: false,
    }
}

fn summary_in(account: iam::ServiceAccountSummary) -> ServiceAccountSummary {
    ServiceAccountSummary {
        name: account.name,
        owner: account.owner,
        description: account.description,
        status: account.status,
        credentials: usize::try_from(account.credentials).unwrap_or(usize::MAX),
        roles: account.roles,
        revision: account.revision,
    }
}

fn credential_in(credential: iam::Credential) -> CredentialView {
    CredentialView {
        id: credential.id,
        kind: credential.kind,
        key_id: credential.key_id,
        algorithm: credential.algorithm,
        binding: credential.binding,
        created_at: credential.created_at,
        created_by: credential.created_by,
        expires_at: credential.expires_at,
        status: credential.status,
        revoked_at: credential.revoked_at,
    }
}

fn token_in(token: iam::TokenSummary) -> TokenView {
    TokenView {
        jti: token.jti,
        subject: token.subject,
        client_id: token.client_id,
        family: token.family,
        audience: token.audience,
        scope: token.scope,
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        status: token.status,
        status_list: token.status_list,
        index: token.index,
        role: token.role,
    }
}

impl GrpcHost {
    fn accounts_client(
        &self,
    ) -> iam::service_account_service_client::ServiceAccountServiceClient<crate::grpc::AuthChannel>
    {
        iam::service_account_service_client::ServiceAccountServiceClient::new(self.0.channel())
    }

    fn tokens_client(
        &self,
    ) -> iam::token_service_client::TokenServiceClient<crate::grpc::AuthChannel> {
        iam::token_service_client::TokenServiceClient::new(self.0.channel())
    }
}

impl Accounts for GrpcHost {
    fn service_accounts(&self) -> Result<ServiceAccounts, Failure> {
        let answer = self
            .0
            .run(
                "ListServiceAccounts",
                self.accounts_client()
                    .list_service_accounts(iam::ListServiceAccountsRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(ServiceAccounts {
            revision: answer.revision,
            service_accounts: answer
                .service_accounts
                .into_iter()
                .map(summary_in)
                .collect(),
        })
    }

    fn service_account(&self, name: &str) -> Result<ServiceAccountDetail, Failure> {
        let answer = self
            .0
            .run(
                "GetServiceAccount",
                self.accounts_client()
                    .get_service_account(iam::GetServiceAccountRequest {
                        name: name.to_owned(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        let account = answer
            .service_account
            .ok_or_else(|| incomplete("the IAM Host answered no service account"))?;
        Ok(ServiceAccountDetail {
            service_account: summary_in(account),
            grants: answer
                .grants
                .into_iter()
                .map(|grant| map::grant_in(Some(grant)))
                .collect(),
            credentials: answer.credentials.into_iter().map(credential_in).collect(),
            directory_revision: answer.directory_revision,
        })
    }

    fn create_service_account(&self, request: &CreateServiceAccount) -> Result<Changed, Failure> {
        self.0
            .run(
                "CreateServiceAccount",
                self.accounts_client()
                    .create_service_account(iam::CreateServiceAccountRequest {
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                        name: request.name.clone(),
                        owner: request.owner.clone(),
                        description: request.description.clone(),
                    }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn update_service_account(
        &self,
        name: &str,
        request: &UpdateServiceAccount,
    ) -> Result<Changed, Failure> {
        self.0
            .run(
                "UpdateServiceAccount",
                self.accounts_client()
                    .update_service_account(iam::UpdateServiceAccountRequest {
                        name: name.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                        owner: request.owner.clone(),
                        description: request.description.clone(),
                    }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn set_service_account_status(
        &self,
        name: &str,
        active: bool,
        request: &Plain,
    ) -> Result<Changed, Failure> {
        self.0
            .run(
                "SetServiceAccountStatus",
                self.accounts_client().set_service_account_status(
                    iam::SetServiceAccountStatusRequest {
                        name: name.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                        active,
                    },
                ),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn delete_service_account(&self, name: &str, request: &Plain) -> Result<Changed, Failure> {
        self.0
            .run(
                "DeleteServiceAccount",
                self.accounts_client()
                    .delete_service_account(iam::ServiceAccountPlainRequest {
                        name: name.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                    }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn credentials(&self, name: &str) -> Result<Credentials, Failure> {
        let answer = self
            .0
            .run(
                "ListCredentials",
                self.accounts_client()
                    .list_credentials(iam::ListCredentialsRequest {
                        name: name.to_owned(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Credentials {
            credentials: answer.credentials.into_iter().map(credential_in).collect(),
        })
    }

    fn create_credential(
        &self,
        name: &str,
        request: &CreateCredential,
    ) -> Result<CredentialCreated, Failure> {
        let answer = self
            .0
            .run(
                "CreateCredential",
                self.accounts_client()
                    .create_credential(iam::CreateCredentialRequest {
                        name: name.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                        kind: request.kind.clone(),
                        public_key: request
                            .public_key
                            .clone()
                            .unwrap_or_default()
                            .into_iter()
                            .collect(),
                        certificate: request.certificate.clone(),
                        expires_at: request.expires_at.clone(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        let credential = answer
            .credential
            .ok_or_else(|| incomplete("the IAM Host answered no credential"))?;
        Ok(CredentialCreated {
            receipt: map::receipt(answer.receipt),
            revision: answer.revision,
            credential: credential_in(credential),
            client_secret: answer.client_secret,
        })
    }

    fn revoke_credential(&self, name: &str, id: &str, request: &Plain) -> Result<Changed, Failure> {
        self.0
            .run(
                "RevokeCredential",
                self.accounts_client()
                    .revoke_credential(iam::RevokeCredentialRequest {
                        name: name.to_owned(),
                        id: id.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_revision: request.expected_revision,
                    }),
            )
            .map(changed)
            .map_err(crate::grpc::failure_of)
    }

    fn tokens(&self) -> Result<TokenList, Failure> {
        let answer = self
            .0
            .run(
                "ListTokens",
                self.tokens_client().list_tokens(iam::ListTokensRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(TokenList {
            tokens: answer.tokens.into_iter().map(token_in).collect(),
        })
    }

    fn revoke_token(&self, jti: &str, request: &RevokeToken) -> Result<TokenRevoked, Failure> {
        let answer = self
            .0
            .run(
                "RevokeToken",
                self.tokens_client().revoke_token(iam::RevokeTokenRequest {
                    jti: jti.to_owned(),
                    request_id: request.request_id.clone(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(TokenRevoked {
            receipt: map::receipt(answer.receipt),
            changed: answer.changed,
        })
    }
}
