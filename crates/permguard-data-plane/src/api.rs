// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use tonic::{Request, Response, Status};

use permguard_core::PlaneHealth;

use crate::v1::data_plane_server::DataPlane;
use crate::v1::{
    GetHealthRequest, GetHealthResponse, GetInfoRequest, GetInfoResponse, GetKeysRequest,
    GetKeysResponse, GetServerConfigurationRequest, GetServerConfigurationResponse,
    GetStreamsRequest, GetStreamsResponse,
};

pub(crate) struct PlaneApi {
    pub(crate) plane: &'static str,
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) health: PlaneHealth,
    /// The discovery document the HTTP well-known answers, its phase set when it is answered.
    pub(crate) configuration: permguard_server::plane::PlaneConfiguration,
    /// The plane's signing ring, when one is composed: what `/data-plane/v1/keys` publishes.
    pub(crate) keys: Option<std::sync::Arc<dyn permguard_core::keys::PublicSet>>,
    /// The `/streams/v1` document.
    pub(crate) streams: String,
}

#[tonic::async_trait]
impl DataPlane for PlaneApi {
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
        // The phase as it is now, as the HTTP route answers it (WP-7.4a).
        let mut document = self.configuration.clone();
        document.state = self.health.phase().as_str().to_owned();
        let document_json = serde_json::to_string(&document)
            .map_err(|error| Status::internal(format!("the document did not render: {error}")))?;
        Ok(Response::new(GetServerConfigurationResponse {
            document_json,
        }))
    }

    async fn get_keys(
        &self,
        _request: Request<GetKeysRequest>,
    ) -> Result<Response<GetKeysResponse>, Status> {
        // The three answers of the HTTP route: the set, the empty set without a ring, and a ring
        // that cannot be read refused rather than published empty.
        let published = match self.keys.as_ref() {
            None => Vec::new(),
            Some(keys) => keys.public_keys().map_err(|error| {
                tracing::warn!(
                    event.name = "plane.keys.unreadable",
                    component = crate::service::COMPONENT,
                    error = %error,
                    "the plane signing ring could not be read"
                );
                Status::unavailable("the signing ring could not be read")
            })?,
        };
        let jwks = serde_json::to_vec(&permguard_core::keys::JwkSet::new(published))
            .map_err(|error| Status::internal(format!("the key set did not render: {error}")))?;
        Ok(Response::new(GetKeysResponse { jwks }))
    }

    async fn get_streams(
        &self,
        _request: Request<GetStreamsRequest>,
    ) -> Result<Response<GetStreamsResponse>, Status> {
        Ok(Response::new(GetStreamsResponse {
            document_json: self.streams.clone(),
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

    fn api(health: &permguard_core::server::Health) -> PlaneApi {
        PlaneApi {
            plane: "data-plane",
            product: String::new(),
            version: String::new(),
            commit: String::new(),
            health: PlaneHealth::new(health.clone(), "data"),
            configuration: permguard_server::plane::plane_configuration(
                &permguard_core::Config::default(),
                permguard_server::plane::PlaneId::Data,
            ),
            keys: None,
            streams: permguard_server::plane::streams_document(&[]),
        }
    }

    /// The data plane's discovery, its keys and its streams over gRPC, the documents its HTTP
    /// routes answer: the phase read when it is asked for, the empty set without a ring.
    #[tokio::test]
    async fn the_discovery_keys_and_streams_answer_over_grpc() {
        let health = permguard_core::server::Health::default();
        let api = api(&health);
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
            .enter("data", Kind::Plane, true, Phase::Ready);
        assert_eq!(ask().await["state"], "ready");

        let keys = api
            .get_keys(Request::new(GetKeysRequest {}))
            .await
            .expect("answered")
            .into_inner();
        let set: serde_json::Value = serde_json::from_slice(&keys.jwks).expect("a JWKS");
        assert_eq!(set["keys"], serde_json::json!([]));

        let streams = api
            .get_streams(Request::new(GetStreamsRequest {}))
            .await
            .expect("answered")
            .into_inner();
        assert_eq!(streams.document_json, r#"{"streams":[]}"#);
    }
}
