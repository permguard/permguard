// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog's gRPC shape: the [`ZoneCatalog`] service, delegating everything.
//!
//! Each method converts the request's fields, calls the same domain function HTTP calls, and shapes
//! the answer through [`crate::wire`]. The only knowledge of its own is the protobuf field layout.

use tonic::{Request, Response, Status};

use crate::v1;
use crate::v1::zone_catalog_server::ZoneCatalog;
use crate::wire;

use super::{CatalogFacade, ledgers, zones};

fn wire_zone(zone: permguard_core::Zone) -> v1::Zone {
    v1::Zone {
        id: zone.id,
        name: zone.name,
        created_at: zone.created_at,
        updated_at: zone.updated_at,
    }
}

fn wire_ledger(ledger: permguard_core::Ledger) -> v1::Ledger {
    v1::Ledger {
        id: ledger.id,
        zone_id: ledger.zone_id,
        name: ledger.name,
        default_ref: ledger.default_ref,
        created_at: ledger.created_at,
        updated_at: ledger.updated_at,
    }
}

type Answer<T> = Result<Response<T>, Status>;

impl CatalogFacade {
    /// Shapes a domain refusal the one way every rpc does.
    fn refuse(&self, error: permguard_core::ApiError) -> Status {
        wire::grpc_error(&error, self.disclosure)
    }
}

#[tonic::async_trait]
impl ZoneCatalog for CatalogFacade {
    async fn create_zone(
        &self,
        request: Request<v1::CreateZoneRequest>,
    ) -> Answer<v1::ZoneResponse> {
        let zone = zones::create(self, &request.into_inner().name)
            .await
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ZoneResponse {
            zone: Some(wire_zone(zone)),
        }))
    }

    async fn list_zones(
        &self,
        request: Request<v1::ListZonesRequest>,
    ) -> Answer<v1::ListZonesResponse> {
        let asked = request.into_inner();
        let zones = zones::list(self, super::ListWindow::of(asked.page, asked.size))
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ListZonesResponse {
            zones: zones.into_iter().map(wire_zone).collect(),
        }))
    }

    async fn get_zone(&self, request: Request<v1::GetZoneRequest>) -> Answer<v1::ZoneResponse> {
        let zone =
            zones::get(self, &request.into_inner().zone).map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ZoneResponse {
            zone: Some(wire_zone(zone)),
        }))
    }

    async fn rename_zone(
        &self,
        request: Request<v1::RenameZoneRequest>,
    ) -> Answer<v1::ZoneResponse> {
        let request = request.into_inner();
        let zone = zones::rename(self, &request.zone, &request.name)
            .await
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ZoneResponse {
            zone: Some(wire_zone(zone)),
        }))
    }

    async fn delete_zone(
        &self,
        request: Request<v1::DeleteZoneRequest>,
    ) -> Answer<v1::ZoneResponse> {
        let zone = zones::delete(self, &request.into_inner().zone)
            .await
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ZoneResponse {
            zone: Some(wire_zone(zone)),
        }))
    }

    async fn create_ledger(
        &self,
        request: Request<v1::CreateLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let request = request.into_inner();
        let ledger = ledgers::create(self, &request.zone, &request.name)
            .await
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }

    async fn list_ledgers(
        &self,
        request: Request<v1::ListLedgersRequest>,
    ) -> Answer<v1::ListLedgersResponse> {
        let asked = request.into_inner();
        let ledgers = ledgers::list(
            self,
            &asked.zone,
            super::ListWindow::of(asked.page, asked.size),
        )
        .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ListLedgersResponse {
            ledgers: ledgers.into_iter().map(wire_ledger).collect(),
        }))
    }

    async fn get_ledger(
        &self,
        request: Request<v1::GetLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let request = request.into_inner();
        let ledger = ledgers::get(self, &request.zone, &request.ledger)
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }

    async fn rename_ledger(
        &self,
        request: Request<v1::RenameLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let request = request.into_inner();
        let ledger = ledgers::rename(self, &request.zone, &request.ledger, &request.name)
            .await
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }

    async fn delete_ledger(
        &self,
        request: Request<v1::DeleteLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let request = request.into_inner();
        let ledger = ledgers::delete(self, &request.zone, &request.ledger)
            .await
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }
}
