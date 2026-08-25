// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use tonic::{Request, Response, Status};

use permguard_core::Health;

use crate::v1::data_plane_server::DataPlane;
use crate::v1::{GetHealthRequest, GetHealthResponse, GetInfoRequest, GetInfoResponse};

pub(crate) struct PlaneApi {
    pub(crate) plane: &'static str,
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) health: Health,
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
