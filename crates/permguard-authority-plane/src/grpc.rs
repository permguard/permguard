// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The gRPC binding of the Authority Plane: `permguard.authority.v1`, each rpc one call into the
//! same facade the REST routes call.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use permguard_core::Disclosure;

use crate::authority::{
    AccountView, Authority, Change, CreateAccount, CreateKey, KeyView, Refusal, RevokeToken,
    ScopeView, ScopesView, SetScopes, TokenRefusal, TokenView, UpdateAccount,
};
use crate::v1;
use crate::wire;

type Answer<T> = Result<Response<T>, Status>;

/// What every rpc reaches.
#[derive(Clone)]
pub(crate) struct Served {
    pub(crate) authority: Arc<Authority>,
    pub(crate) disclosure: Disclosure,
    pub(crate) plane: Arc<crate::plane::PlaneInfo>,
}

impl Served {
    fn refuse(&self, refusal: &Refusal) -> Status {
        wire::grpc_refusal(refusal, self.disclosure)
    }

    async fn blocking<T: Send + 'static>(
        &self,
        call: impl FnOnce(&Authority) -> Result<T, Refusal> + Send + 'static,
    ) -> Result<T, Status> {
        let authority = Arc::clone(&self.authority);
        match tokio::task::spawn_blocking(move || call(&authority)).await {
            Ok(answered) => answered.map_err(|refusal| self.refuse(&refusal)),
            Err(error) => Err(Status::internal(format!(
                "the call did not finish: {error}"
            ))),
        }
    }
}

fn scope_out(scope: ScopeView) -> v1::Scope {
    v1::Scope {
        operations: scope.operations,
        selector: scope.selector,
    }
}

fn scope_in(scope: v1::Scope) -> ScopeView {
    ScopeView {
        operations: scope.operations,
        selector: scope.selector,
    }
}

fn key_out(key: KeyView) -> v1::AccessKey {
    v1::AccessKey {
        access_key: key.access_key,
        created_at: key.created_at,
        expires_at: key.expires_at,
        last_used_at: key.last_used_at,
        status: key.status,
    }
}

fn account_out(account: AccountView) -> v1::ServiceAccount {
    v1::ServiceAccount {
        name: account.name,
        description: account.description,
        status: account.status,
        scopes: account.scopes.into_iter().map(scope_out).collect(),
        keys: account.keys.into_iter().map(key_out).collect(),
        administrator: account.administrator,
        created_at: account.created_at,
        updated_at: account.updated_at,
        revision: account.revision,
    }
}

fn token_out(token: TokenView) -> v1::TokenSummary {
    v1::TokenSummary {
        jti: token.jti,
        subject: token.subject,
        account: token.account,
        access_key: token.access_key,
        scopes: token.scopes.into_iter().map(scope_out).collect(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        status: token.status,
        status_list: token.status_list,
        index: token.index,
    }
}

fn scopes_out(scopes: ScopesView) -> v1::ScopesResponse {
    v1::ScopesResponse {
        name: scopes.name,
        scopes: scopes.scopes.into_iter().map(scope_out).collect(),
        revision: scopes.revision,
        tokens_revoked: scopes.tokens_revoked,
    }
}

/// A token endpoint refusal over gRPC: the same `error` in the message, the class of its status.
fn token_status(refusal: &TokenRefusal) -> Status {
    let message = format!("{}: {}", refusal.error(), refusal.description());
    match refusal {
        TokenRefusal::InvalidClient => Status::unauthenticated(message),
        TokenRefusal::SlowDown(_) => Status::resource_exhausted(message),
        TokenRefusal::Unavailable(_) => Status::unavailable(message),
        _ => Status::invalid_argument(message),
    }
}

#[tonic::async_trait]
impl v1::authority_plane_server::AuthorityPlane for Served {
    async fn get_info(&self, _request: Request<v1::GetInfoRequest>) -> Answer<v1::GetInfoResponse> {
        Ok(Response::new(v1::GetInfoResponse {
            plane: crate::PLANE.to_owned(),
            product: self.plane.product.clone(),
            version: self.plane.version.clone(),
            commit: self.plane.commit.clone(),
            edition: crate::authority::EDITION.to_owned(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<v1::GetHealthRequest>,
    ) -> Answer<v1::GetHealthResponse> {
        let report = self.plane.health.report();
        Ok(Response::new(v1::GetHealthResponse {
            live: self.plane.health.is_live(),
            ready: self.plane.health.is_ready(),
            state: report.state.to_owned(),
            degraded: report
                .degraded
                .into_iter()
                .map(|item| v1::Degraded {
                    capability: item.capability,
                    reason: item.reason,
                })
                .collect(),
            components: report
                .components
                .into_iter()
                .map(|component| v1::Component {
                    component: component.component,
                    kind: component.kind.to_owned(),
                    state: component.state.to_owned(),
                    required: component.required,
                    stalled_since: component.stalled_since,
                    last_success: component.last_success,
                    next_attempt: component.next_attempt,
                    reason: component.reason,
                })
                .collect(),
        }))
    }

    async fn get_server_configuration(
        &self,
        _request: Request<v1::GetServerConfigurationRequest>,
    ) -> Answer<v1::GetServerConfigurationResponse> {
        Ok(Response::new(v1::GetServerConfigurationResponse {
            document_json: self.plane.document(),
        }))
    }
}

#[tonic::async_trait]
impl v1::token_service_server::TokenService for Served {
    async fn get_metadata(
        &self,
        _request: Request<v1::GetMetadataRequest>,
    ) -> Answer<v1::GetMetadataResponse> {
        Ok(Response::new(v1::GetMetadataResponse {
            document_json: self.authority.metadata().to_string(),
        }))
    }

    async fn issue_token(
        &self,
        request: Request<v1::IssueTokenRequest>,
    ) -> Answer<v1::IssueTokenResponse> {
        let source = request
            .extensions()
            .get::<Arc<permguard_transport::PeerAddress>>()
            .map_or_else(|| "unknown".to_owned(), |address| address.0.to_string());
        let asked = request.into_inner();
        let parsed = crate::authority::TokenRequest {
            grant_type: asked.grant_type,
            client_id: asked.client_id,
            client_secret: zeroize::Zeroizing::new(asked.client_secret),
            scope: (!asked.scope.trim().is_empty()).then_some(asked.scope),
            requested_lifetime: asked.requested_lifetime,
        };
        match crate::http::issue(&self.authority, parsed, source).await {
            Ok(answer) => Ok(Response::new(v1::IssueTokenResponse {
                access_token: answer.access_token,
                token_type: answer.token_type,
                expires_in: answer.expires_in,
                scope: answer.scope,
            })),
            Err(refusal) => Err(token_status(&refusal)),
        }
    }

    async fn get_keys(&self, _request: Request<v1::GetKeysRequest>) -> Answer<v1::GetKeysResponse> {
        self.authority
            .keys_document()
            .map(|document| {
                Response::new(v1::GetKeysResponse {
                    jwks_json: document.to_string(),
                })
            })
            .map_err(|refusal| self.refuse(&refusal))
    }

    async fn list_status_lists(
        &self,
        _request: Request<v1::ListStatusListsRequest>,
    ) -> Answer<v1::ListStatusListsResponse> {
        Ok(Response::new(v1::ListStatusListsResponse {
            lists: self.authority.list_ids(),
        }))
    }

    async fn get_status_list(
        &self,
        request: Request<v1::GetStatusListRequest>,
    ) -> Answer<v1::GetStatusListResponse> {
        self.authority
            .list_token(&request.into_inner().id)
            .map(|token| Response::new(v1::GetStatusListResponse { token }))
            .map_err(|refusal| self.refuse(&refusal))
    }

    async fn list_tokens(
        &self,
        request: Request<v1::ListTokensRequest>,
    ) -> Answer<v1::ListTokensResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        self.authority
            .list_tokens(&actor, Some(&asked.account), Some(&asked.status))
            .map(|tokens| {
                Response::new(v1::ListTokensResponse {
                    tokens: tokens.into_iter().map(token_out).collect(),
                })
            })
            .map_err(|refusal| self.refuse(&refusal))
    }

    async fn revoke_token(
        &self,
        request: Request<v1::RevokeTokenRequest>,
    ) -> Answer<v1::RevokeTokenResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let token = self
            .blocking(move |authority| {
                authority.revoke_token(
                    &actor,
                    &asked.jti,
                    RevokeToken {
                        request_id: asked.request_id,
                    },
                )
            })
            .await?;
        Ok(Response::new(v1::RevokeTokenResponse {
            token: Some(token_out(token)),
        }))
    }
}

fn account_response(account: AccountView) -> Response<v1::ServiceAccountResponse> {
    Response::new(v1::ServiceAccountResponse {
        account: Some(account_out(account)),
    })
}

#[tonic::async_trait]
impl v1::service_account_service_server::ServiceAccountService for Served {
    async fn list_service_accounts(
        &self,
        request: Request<v1::ListServiceAccountsRequest>,
    ) -> Answer<v1::ListServiceAccountsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        self.authority
            .list_accounts(&actor)
            .map(|accounts| {
                Response::new(v1::ListServiceAccountsResponse {
                    accounts: accounts.into_iter().map(account_out).collect(),
                })
            })
            .map_err(|refusal| self.refuse(&refusal))
    }

    async fn get_service_account(
        &self,
        request: Request<v1::GetServiceAccountRequest>,
    ) -> Answer<v1::ServiceAccountResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        self.authority
            .get_account(&actor, &request.into_inner().name)
            .map(account_response)
            .map_err(|refusal| self.refuse(&refusal))
    }

    async fn create_service_account(
        &self,
        request: Request<v1::CreateServiceAccountRequest>,
    ) -> Answer<v1::ServiceAccountResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let create = CreateAccount {
            request_id: asked.request_id,
            name: asked.name,
            description: asked.description,
            scopes: asked.scopes.into_iter().map(scope_in).collect(),
        };
        self.blocking(move |authority| authority.create_account(&actor, create))
            .await
            .map(account_response)
    }

    async fn update_service_account(
        &self,
        request: Request<v1::UpdateServiceAccountRequest>,
    ) -> Answer<v1::ServiceAccountResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let name = asked.name;
        let update = UpdateAccount {
            request_id: asked.request_id,
            description: asked.description,
            expected_revision: asked.expected_revision,
        };
        self.blocking(move |authority| authority.update_account(&actor, &name, update))
            .await
            .map(account_response)
    }

    async fn delete_service_account(
        &self,
        request: Request<v1::DeleteServiceAccountRequest>,
    ) -> Answer<v1::DeleteServiceAccountResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let name = asked.name;
        let change = Change {
            request_id: asked.request_id,
            expected_revision: asked.expected_revision,
        };
        let deleted = self
            .blocking(move |authority| authority.delete_account(&actor, &name, change))
            .await?;
        Ok(Response::new(v1::DeleteServiceAccountResponse {
            name: deleted.name,
            tokens_revoked: deleted.tokens_revoked,
        }))
    }

    async fn suspend_service_account(
        &self,
        request: Request<v1::ServiceAccountStatusRequest>,
    ) -> Answer<v1::ServiceAccountResponse> {
        self.status_change(request, true).await
    }

    async fn resume_service_account(
        &self,
        request: Request<v1::ServiceAccountStatusRequest>,
    ) -> Answer<v1::ServiceAccountResponse> {
        self.status_change(request, false).await
    }

    async fn get_scopes(
        &self,
        request: Request<v1::GetScopesRequest>,
    ) -> Answer<v1::ScopesResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        self.authority
            .get_scopes(&actor, &request.into_inner().name)
            .map(|scopes| Response::new(scopes_out(scopes)))
            .map_err(|refusal| self.refuse(&refusal))
    }

    async fn set_scopes(
        &self,
        request: Request<v1::SetScopesRequest>,
    ) -> Answer<v1::ScopesResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let name = asked.name;
        let set = SetScopes {
            request_id: asked.request_id,
            scopes: asked.scopes.into_iter().map(scope_in).collect(),
            expected_revision: asked.expected_revision,
            revoke_tokens: asked.revoke_tokens,
        };
        self.blocking(move |authority| authority.set_scopes(&actor, &name, set))
            .await
            .map(|scopes| Response::new(scopes_out(scopes)))
    }

    async fn list_access_keys(
        &self,
        request: Request<v1::ListAccessKeysRequest>,
    ) -> Answer<v1::ListAccessKeysResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        self.authority
            .list_keys(&actor, &request.into_inner().name)
            .map(|keys| {
                Response::new(v1::ListAccessKeysResponse {
                    keys: keys.into_iter().map(key_out).collect(),
                })
            })
            .map_err(|refusal| self.refuse(&refusal))
    }

    async fn create_access_key(
        &self,
        request: Request<v1::CreateAccessKeyRequest>,
    ) -> Answer<v1::CreateAccessKeyResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let name = asked.name;
        let create = CreateKey {
            request_id: asked.request_id,
            expires_at: asked.expires_at,
        };
        let created = self
            .blocking(move |authority| authority.create_key(&actor, &name, create))
            .await?;
        Ok(Response::new(v1::CreateAccessKeyResponse {
            key: Some(key_out(created.key.clone())),
            secret_key: created.secret_key.clone(),
        }))
    }

    async fn delete_access_key(
        &self,
        request: Request<v1::DeleteAccessKeyRequest>,
    ) -> Answer<v1::DeleteAccessKeyResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let (name, access_key) = (asked.name, asked.access_key);
        let change = Change {
            request_id: asked.request_id,
            expected_revision: asked.expected_revision,
        };
        let deleted = self
            .blocking(move |authority| authority.delete_key(&actor, &name, &access_key, change))
            .await?;
        Ok(Response::new(v1::DeleteAccessKeyResponse {
            access_key: deleted.access_key,
            tokens_revoked: deleted.tokens_revoked,
        }))
    }
}

impl Served {
    async fn status_change(
        &self,
        request: Request<v1::ServiceAccountStatusRequest>,
        suspended: bool,
    ) -> Answer<v1::ServiceAccountResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let name = asked.name;
        let change = Change {
            request_id: asked.request_id,
            expected_revision: asked.expected_revision,
        };
        self.blocking(move |authority| {
            authority.set_account_status(&actor, &name, suspended, change)
        })
        .await
        .map(account_response)
    }
}
