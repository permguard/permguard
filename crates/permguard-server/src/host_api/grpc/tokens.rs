// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `TokenService` (iteration 02, WP-11.5): each rpc one call into the facade the REST routes
//! call.

use tonic::{Request, Response};

use permguard_host::api::tokens::{RevokeToken, TokenView};

use super::super::iam_v1::{self, token_service_server::TokenService};
use super::{Answer, Served, receipt};

fn summary(view: TokenView) -> iam_v1::TokenSummary {
    iam_v1::TokenSummary {
        jti: view.jti,
        subject: view.subject,
        client_id: view.client_id,
        family: view.family,
        audience: view.audience,
        scope: view.scope,
        issued_at: view.issued_at,
        expires_at: view.expires_at,
        status: view.status,
        status_list: view.status_list,
        index: view.index,
    }
}

#[tonic::async_trait]
impl TokenService for Served {
    async fn get_status_list(
        &self,
        request: Request<iam_v1::GetStatusListRequest>,
    ) -> Answer<iam_v1::GetStatusListResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let token = self
            .api
            .status_list(&actor, &asked.id)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(iam_v1::GetStatusListResponse { token }))
    }

    async fn list_tokens(
        &self,
        request: Request<iam_v1::ListTokensRequest>,
    ) -> Answer<iam_v1::ListTokensResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self
            .api
            .token_list(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(iam_v1::ListTokensResponse {
            tokens: listed.tokens.into_iter().map(summary).collect(),
        }))
    }

    async fn revoke_token(
        &self,
        request: Request<iam_v1::RevokeTokenRequest>,
    ) -> Answer<iam_v1::RevokeTokenResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let revoked = self
            .api
            .revoke_token(
                &actor,
                &asked.jti,
                RevokeToken {
                    request_id: asked.request_id,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(iam_v1::RevokeTokenResponse {
            receipt: Some(receipt(revoked.receipt)),
            changed: revoked.changed,
        }))
    }
}
