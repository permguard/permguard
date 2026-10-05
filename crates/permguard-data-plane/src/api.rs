// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use tonic::{Request, Response, Status};

use permguard_core::PlaneHealth;

use crate::v1::data_plane_server::DataPlane;
use crate::v1::{GetHealthRequest, GetHealthResponse, GetInfoRequest, GetInfoResponse};

pub(crate) struct PlaneApi {
    pub(crate) plane: &'static str,
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) health: PlaneHealth,
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
