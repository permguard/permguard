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
    fn refuse(&self, refusal: wire::Refusal) -> Status {
        wire::grpc_refusal(&refusal, self.disclosure)
    }
}

#[tonic::async_trait]
impl ZoneCatalog for CatalogFacade {
    async fn create_zone(
        &self,
        request: Request<v1::CreateZoneRequest>,
    ) -> Answer<v1::ZoneResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let zone = zones::create(self, &actor, &request.into_inner().name)
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
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let zones = zones::list(self, &actor, super::ListWindow::of(asked.page, asked.size))
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ListZonesResponse {
            zones: zones.into_iter().map(wire_zone).collect(),
        }))
    }

    async fn get_zone(&self, request: Request<v1::GetZoneRequest>) -> Answer<v1::ZoneResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let zone = zones::get(self, &actor, &request.into_inner().zone)
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::ZoneResponse {
            zone: Some(wire_zone(zone)),
        }))
    }

    async fn rename_zone(
        &self,
        request: Request<v1::RenameZoneRequest>,
    ) -> Answer<v1::ZoneResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let zone = zones::rename(self, &actor, &request.zone, &request.name)
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
        let actor = permguard_transport::actor_of(request.extensions());
        let zone = zones::delete(self, &actor, &request.into_inner().zone)
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
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let ledger = ledgers::create(self, &actor, &request.zone, &request.name)
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
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let ledgers = ledgers::list(
            self,
            &actor,
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
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let ledger = ledgers::get(self, &actor, &request.zone, &request.ledger)
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }

    async fn rename_ledger(
        &self,
        request: Request<v1::RenameLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let ledger = ledgers::rename(self, &actor, &request.zone, &request.ledger, &request.name)
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
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let ledger = ledgers::delete(self, &actor, &request.zone, &request.ledger)
            .await
            .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use permguard_core::authz::{Actor, ActorContext, Credential, Principal, Selector, operations};
    use permguard_core::{Catalog as _, Disclosure};
    use permguard_host::authz::{GrantStore, Issue};
    use permguard_host::composition::Authorization;
    use permguard_std::catalog::FileCatalog;
    use tonic::Request;

    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "permguard-catalog-grpc-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the scratch directory is created");
        root
    }

    fn actor(principal: &str) -> Arc<Actor> {
        Arc::new(Actor::Authenticated(ActorContext::new(
            Principal::new(principal).expect("a principal"),
            Credential::SanUri,
            None,
        )))
    }

    /// F-21 and F-22 over gRPC: the actor the transport attached rides the request's
    /// extensions, and the facade decides exactly as it does over REST.
    #[tokio::test]
    async fn f21_f22_over_grpc_the_actor_rides_the_request_extensions() {
        let root = scratch("f22");
        let catalog = Arc::new(FileCatalog::new(root.join("zones")));
        let billing = catalog.create_zone("billing").expect("billing");
        let people = catalog.create_zone("people").expect("people");
        let volume = permguard_host::storage::volume::Volume::claim(
            &root.join("volume"),
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("opens");
        permguard_host::operations::grants::issue(
            &permguard_host::operations::mutation::Mutations::open_offline(&volume, "test")
                .expect("the mutation journal opens"),
            &store,
            permguard_host::operations::journal::Initiator::System("test".to_owned()),
            Issue {
                principal: Principal::new("spiffe://acme/billing").expect("p"),
                operations: vec![operations::CATALOG_READ.to_owned()],
                selector: Selector::parse(&format!("plane/control/zone/{}/*", billing.id))
                    .expect("a selector"),
                resource_types: vec!["*".to_owned()],
                constraints: Default::default(),
                issued_by: "test".to_owned(),
                expires_at: None,
            },
            1,
        )
        .expect("issued");
        let facade = CatalogFacade {
            catalog,
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::Metrics::none(),
            authorization: Arc::new(Authorization::new(store, &[])),
        };

        // Nobody: UNAUTHENTICATED, with the code as metadata and no class.
        let refused = facade
            .get_zone(Request::new(v1::GetZoneRequest {
                zone: billing.id.clone(),
            }))
            .await
            .expect_err("F-21");
        assert_eq!(refused.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            refused
                .metadata()
                .get(wire::GRPC_ERROR_CODE)
                .and_then(|v| v.to_str().ok()),
            Some("unauthenticated")
        );
        assert!(refused.metadata().get(wire::GRPC_ERROR_CLASS).is_none());

        // Billing reads billing.
        let mut request = Request::new(v1::GetZoneRequest {
            zone: "billing".to_owned(),
        });
        request
            .extensions_mut()
            .insert(actor("spiffe://acme/billing"));
        assert!(facade.get_zone(request).await.is_ok());

        // And cannot read people, nor tell it from a zone that is not there.
        let mut request = Request::new(v1::GetZoneRequest {
            zone: people.id.clone(),
        });
        request
            .extensions_mut()
            .insert(actor("spiffe://acme/billing"));
        let foreign = facade.get_zone(request).await.expect_err("F-22");
        assert_eq!(foreign.code(), tonic::Code::PermissionDenied);
        let mut request = Request::new(v1::GetZoneRequest {
            zone: "nowhere".to_owned(),
        });
        request
            .extensions_mut()
            .insert(actor("spiffe://acme/billing"));
        let unknown = facade.get_zone(request).await.expect_err("not disclosed");
        assert_eq!(unknown.code(), tonic::Code::PermissionDenied);
        assert_eq!(unknown.message(), foreign.message());
        std::mem::forget(volume);
    }
}
