// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use tonic::{Request, Response, Status};

use permguard_core::PlaneHealth;

use crate::v1::control_plane_server::ControlPlane;
use crate::v1::{
    GetHealthRequest, GetHealthResponse, GetInfoRequest, GetInfoResponse,
    GetServerConfigurationRequest, GetServerConfigurationResponse,
};

pub(crate) struct PlaneApi {
    pub(crate) plane: &'static str,
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) health: PlaneHealth,
    /// The discovery document after `plane` and `state`, which are written in front of it when it
    /// is answered: the same text the HTTP well-known answers (WP-7.4a).
    pub(crate) rest: String,
}

#[tonic::async_trait]
impl ControlPlane for PlaneApi {
    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        Ok(Response::new(GetInfoResponse {
            plane: self.plane.to_owned(),
            product: self.product.clone(),
            version: self.version.clone(),
            commit: self.commit.clone(),
        }))
    }

    async fn get_server_configuration(
        &self,
        _request: Request<GetServerConfigurationRequest>,
    ) -> Result<Response<GetServerConfigurationResponse>, Status> {
        // The same document the HTTP route answers, the phase as it is now (WP-7.4a).
        Ok(Response::new(GetServerConfigurationResponse {
            document_json: crate::service::plane_document(&self.rest, self.health.phase()),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<GetHealthRequest>,
    ) -> Result<Response<GetHealthResponse>, Status> {
        let report = self.health.report();
        Ok(Response::new(GetHealthResponse {
            live: self.health.is_live(),
            ready: self.health.is_ready(),
            state: report.state.to_owned(),
            degraded: report
                .degraded
                .into_iter()
                .map(|degraded| crate::v1::Degraded {
                    capability: degraded.capability,
                    reason: degraded.reason,
                })
                .collect(),
            components: report
                .components
                .into_iter()
                .map(|component| crate::v1::Component {
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::lifecycle::{Kind, Phase};

    use super::*;

    /// WP-7.4a: the gRPC server configuration is the HTTP document, `plane` and `state` in front of
    /// the rest, the state read when it is asked for.
    #[tokio::test]
    async fn the_grpc_server_configuration_carries_the_plane_phase() {
        let health = permguard_core::server::Health::default();
        let api = PlaneApi {
            plane: "control-plane",
            product: String::new(),
            version: String::new(),
            commit: String::new(),
            health: PlaneHealth::new(health.clone(), "control"),
            rest: "\"jwks_uri\":\"http://plane/keys\"}".to_owned(),
        };
        let ask = || async {
            let answer = api
                .get_server_configuration(Request::new(GetServerConfigurationRequest {}))
                .await
                .expect("answered")
                .into_inner();
            serde_json::from_str::<serde_json::Value>(&answer.document_json).expect("JSON")
        };
        assert_eq!(ask().await["state"], "bootstrap");
        health
            .lifecycle()
            .enter("control", Kind::Plane, true, Phase::Ready);
        let document = ask().await;
        assert_eq!(document["state"], "ready");
        assert_eq!(document["plane"], "control-plane");
        assert_eq!(document["jwks_uri"], "http://plane/keys");
    }
}
