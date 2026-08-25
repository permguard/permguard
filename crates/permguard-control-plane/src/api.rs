// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use tonic::{Request, Response, Status};

use permguard_core::Health;

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
    pub(crate) health: Health,
    /// The discovery document, byte-identical to the HTTP well-known answer.
    pub(crate) configuration: String,
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
        Ok(Response::new(GetServerConfigurationResponse {
            document_json: self.configuration.clone(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<GetHealthRequest>,
    ) -> Result<Response<GetHealthResponse>, Status> {
        Ok(Response::new(GetHealthResponse {
            live: self.health.is_live(),
            ready: self.health.is_ready(),
        }))
    }
}
