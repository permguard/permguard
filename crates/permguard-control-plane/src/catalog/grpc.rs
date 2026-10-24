// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog's gRPC shape: the [`ZoneCatalog`] service, delegating everything.
//!
//! Each method converts the request's fields, calls the same domain function HTTP calls, and shapes
//! the answer through [`crate::wire`]. The only knowledge of its own is the protobuf field layout.

use permguard_core::{ApiError, ErrorClass, codes};
use tonic::{Request, Response, Status};

use crate::v1;
use crate::v1::zone_catalog_server::ZoneCatalog;
use crate::wire;

use super::{CatalogFacade, exports, imports, ledgers, zones};

fn wire_zone(zone: permguard_core::Zone) -> v1::Zone {
    v1::Zone {
        id: zone.id,
        name: zone.name,
        created_at: zone.created_at,
        updated_at: zone.updated_at,
        revision: zone.revision,
    }
}

/// A change's expected revision over gRPC, where 0 is none: required (WP-7.3a).
fn expected(revision: u64) -> Result<u64, wire::Refusal> {
    if revision == 0 {
        return Err(permguard_core::ApiError::new(
            permguard_core::ErrorClass::Validation,
            permguard_core::codes::common::INVALID_ARGUMENT,
            "a change of a record names its `expected_revision`, the revision it was read at",
        )
        .into());
    }
    Ok(revision)
}

fn wire_ledger(ledger: permguard_core::Ledger) -> v1::Ledger {
    v1::Ledger {
        id: ledger.id,
        zone_id: ledger.zone_id,
        name: ledger.name,
        default_ref: ledger.default_ref,
        created_at: ledger.created_at,
        updated_at: ledger.updated_at,
        serving_members: Vec::new(),
        revision: ledger.revision,
        state: ledger.state.as_str().to_owned(),
        provenance: ledger.provenance.map(|provenance| v1::LedgerProvenance {
            manifest_digest: provenance.manifest_digest,
            source_host_id: provenance.source_host_id,
            source_zone_id: provenance.source_zone_id,
            source_ledger_id: provenance.source_ledger_id,
            exported_at: provenance.exported_at,
        }),
    }
}

type Answer<T> = Result<Response<T>, Status>;

/// An export as gRPC answers it: what REST answers, the archive as bytes.
fn wire_export(exported: exports::Exported) -> v1::ExportResponse {
    let manifest = exported.manifest;
    v1::ExportResponse {
        archive: exported.archive,
        zone_id: manifest.zone_id,
        bundle_digest: manifest.bundle_digest.to_string(),
        bundle_bytes: manifest.bundle_bytes,
        exported_at: manifest.exported_at,
        ledgers: manifest
            .ledgers
            .into_iter()
            .map(|ledger| v1::ExportedLedger {
                refs: ledger.refs.len() as u64,
                id: ledger.id,
                name: ledger.name,
                objects: ledger.objects,
                statements: ledger.statements,
            })
            .collect(),
    }
}

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
        let request = request.into_inner();
        let zone = zones::create(self, &actor, &request.name, &request.request_id)
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
        let revision = expected(request.expected_revision).map_err(|error| self.refuse(error))?;
        let zone = zones::rename(
            self,
            &actor,
            &request.zone,
            &request.name,
            revision,
            &request.request_id,
        )
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
        let request = request.into_inner();
        let revision = expected(request.expected_revision).map_err(|error| self.refuse(error))?;
        let zone = zones::delete(self, &actor, &request.zone, revision, &request.request_id)
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
        let ledger = ledgers::create(
            self,
            &actor,
            &request.zone,
            &request.name,
            &request.request_id,
        )
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
        let served = ledgers::get_served(self, &actor, &request.zone, &request.ledger)
            .map_err(|error| self.refuse(error))?;
        let mut ledger = wire_ledger(served.ledger);
        ledger.serving_members = served
            .serving_members
            .into_iter()
            .map(super::serving::wire)
            .collect();

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(ledger),
        }))
    }

    async fn rename_ledger(
        &self,
        request: Request<v1::RenameLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let revision = expected(request.expected_revision).map_err(|error| self.refuse(error))?;
        let ledger = ledgers::rename(
            self,
            &actor,
            &request.zone,
            &request.ledger,
            &request.name,
            revision,
            &request.request_id,
        )
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
        let revision = expected(request.expected_revision).map_err(|error| self.refuse(error))?;
        let ledger = ledgers::delete(
            self,
            &actor,
            &request.zone,
            &request.ledger,
            revision,
            &request.request_id,
        )
        .await
        .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }

    async fn export_ledger(
        &self,
        request: Request<v1::ExportLedgerRequest>,
    ) -> Answer<v1::ExportResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let exported = exports::ledger(self, &actor, &request.zone, &request.ledger)
            .await
            .map_err(|error| self.refuse(error))?;
        Ok(Response::new(wire_export(exported)))
    }

    async fn import(&self, request: Request<v1::ImportRequest>) -> Answer<v1::ImportResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let mode = imports::Mode::parse(&request.mode).ok_or_else(|| {
            self.refuse(
                ApiError::new(
                    ErrorClass::Validation,
                    codes::common::INVALID_ARGUMENT,
                    "`mode` is `archive` or `re-home`",
                )
                .into(),
            )
        })?;
        let imported = imports::import(
            self,
            &actor,
            &request.zone,
            imports::Request {
                mode,
                name: (!request.name.is_empty()).then_some(request.name.as_str()),
                request_id: &request.request_id,
                archive: &request.archive,
                bundle_manifest: &request.bundle_manifest,
                bundle_items: &request.bundle_items,
                pin: &request.pin,
            },
        )
        .await
        .map_err(|error| self.refuse(error))?;
        Ok(Response::new(v1::ImportResponse {
            mode: imported.mode.to_owned(),
            manifest_digest: imported.manifest_digest,
            source_host_id: imported.source_host_id,
            source_zone_id: imported.source_zone_id,
            archive: imported.archive.map(|record| v1::ArchiveRecord {
                id: record.id,
                name: record.name,
                imported_at: record.imported_at,
                manifest_digest: record.manifest_digest,
                source_host_id: record.source_host_id,
                source_zone_id: record.source_zone_id,
                source_zone_name: record.source_zone_name,
                ledgers: record
                    .ledgers
                    .into_iter()
                    .map(|ledger| v1::ExportedLedger {
                        id: ledger.id,
                        name: ledger.name,
                        refs: ledger.refs,
                        objects: ledger.objects,
                        statements: ledger.statements,
                    })
                    .collect(),
            }),
            ledgers: imported.ledgers.into_iter().map(wire_ledger).collect(),
        }))
    }

    async fn export_zone(
        &self,
        request: Request<v1::ExportZoneRequest>,
    ) -> Answer<v1::ExportResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let exported = exports::zone(self, &actor, &request.zone)
            .await
            .map_err(|error| self.refuse(error))?;
        Ok(Response::new(wire_export(exported)))
    }

    async fn archive_ledger(
        &self,
        request: Request<v1::ArchiveLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let revision = expected(request.expected_revision).map_err(|error| self.refuse(error))?;
        let ledger = ledgers::archive(
            self,
            &actor,
            &request.zone,
            &request.ledger,
            revision,
            &request.request_id,
        )
        .await
        .map_err(|error| self.refuse(error))?;

        Ok(Response::new(v1::LedgerResponse {
            ledger: Some(wire_ledger(ledger)),
        }))
    }

    async fn restore_ledger(
        &self,
        request: Request<v1::RestoreLedgerRequest>,
    ) -> Answer<v1::LedgerResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let revision = expected(request.expected_revision).map_err(|error| self.refuse(error))?;
        let ledger = ledgers::restore(
            self,
            &actor,
            &request.zone,
            &request.ledger,
            revision,
            &request.request_id,
        )
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

    /// WP-7.3a over gRPC: a change without a request id, or naming revision 0, the field's default
    /// that names none, is `invalid_argument`; a stale revision is `revision_conflict`,
    /// `FAILED_PRECONDITION` as every catalog conflict but `name_taken`; the record answers its
    /// revision.
    #[tokio::test]
    async fn over_grpc_a_change_names_its_request_id_and_a_revision() {
        let root = scratch("revision");
        let facade = CatalogFacade {
            host: None,
            authorization: Arc::new(Authorization::permissive()),
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
            catalog: Arc::new(FileCatalog::new(root.join("zones"))),
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::Metrics::none(),
            exports: None,
        };
        fn request<T>(inner: T) -> Request<T> {
            let mut request = Request::new(inner);
            request.extensions_mut().insert(Arc::new(Actor::Anonymous));
            request
        }
        let code = |status: tonic::Status| {
            status
                .metadata()
                .get(crate::wire::GRPC_ERROR_CODE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };

        let refused = facade
            .create_zone(request(v1::CreateZoneRequest {
                name: "billing".to_owned(),
                request_id: String::new(),
            }))
            .await
            .expect_err("no request id");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        let created = facade
            .create_zone(request(v1::CreateZoneRequest {
                name: "billing".to_owned(),
                request_id: "r-1".to_owned(),
            }))
            .await
            .expect("created")
            .into_inner()
            .zone
            .expect("a zone");
        assert_eq!(created.revision, 1);

        let rename = |expected_revision, request_id: &str| v1::RenameZoneRequest {
            zone: "billing".to_owned(),
            name: "finance".to_owned(),
            request_id: request_id.to_owned(),
            expected_revision,
        };
        let refused = facade
            .rename_zone(request(rename(0, "r-2")))
            .await
            .expect_err("revision 0 names none");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        assert_eq!(code(refused), "invalid_argument");
        let refused = facade
            .rename_zone(request(rename(2, "r-3")))
            .await
            .expect_err("stale");
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(code(refused), "revision_conflict");
        let renamed = facade
            .rename_zone(request(rename(1, "r-4")))
            .await
            .expect("renamed")
            .into_inner()
            .zone
            .expect("a zone");
        assert_eq!((renamed.name.as_str(), renamed.revision), ("finance", 2));

        let refused = facade
            .delete_zone(request(v1::DeleteZoneRequest {
                zone: "finance".to_owned(),
                request_id: "r-5".to_owned(),
                expected_revision: 1,
            }))
            .await
            .expect_err("stale");
        assert_eq!(code(refused), "revision_conflict");
    }

    /// WP-7.3a, after the review: a change is authorized before anything about it is looked at,
    /// its replay window included; nobody is `UNAUTHENTICATED` whatever the request carries.
    #[tokio::test]
    async fn a_change_is_authorized_before_its_request_is_looked_at() {
        let root = scratch("closed");
        let facade = CatalogFacade {
            host: None,
            authorization: Arc::new(Authorization::closed()),
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
            catalog: Arc::new(FileCatalog::new(root.join("zones"))),
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::Metrics::none(),
            exports: None,
        };
        fn anonymous<T>(inner: T) -> Request<T> {
            let mut request = Request::new(inner);
            request.extensions_mut().insert(Arc::new(Actor::Anonymous));
            request
        }
        let codes = [
            facade
                .delete_zone(anonymous(v1::DeleteZoneRequest {
                    zone: "billing".to_owned(),
                    request_id: String::new(),
                    expected_revision: 1,
                }))
                .await
                .expect_err("closed")
                .code(),
            facade
                .rename_zone(anonymous(v1::RenameZoneRequest {
                    zone: "billing".to_owned(),
                    name: "finance".to_owned(),
                    request_id: String::new(),
                    expected_revision: 1,
                }))
                .await
                .expect_err("closed")
                .code(),
            facade
                .delete_ledger(anonymous(v1::DeleteLedgerRequest {
                    zone: "billing".to_owned(),
                    ledger: "invoices".to_owned(),
                    request_id: String::new(),
                    expected_revision: 1,
                }))
                .await
                .expect_err("closed")
                .code(),
        ];
        assert_eq!(codes, [tonic::Code::Unauthenticated; 3]);
    }

    /// WP-7.3a: the replay window is keyed by the principal, so two callers that chose the same
    /// request id make two changes, and neither learns the other's answer.
    #[tokio::test]
    async fn the_same_request_id_from_two_principals_is_two_changes() {
        let root = scratch("principals");
        let facade = CatalogFacade {
            host: None,
            authorization: Arc::new(Authorization::permissive()),
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
            catalog: Arc::new(FileCatalog::new(root.join("zones"))),
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::Metrics::none(),
            exports: None,
        };
        let create = |principal: &str, name: &str| {
            let mut request = Request::new(v1::CreateZoneRequest {
                name: name.to_owned(),
                request_id: "r-shared".to_owned(),
            });
            request.extensions_mut().insert(actor(principal));
            request
        };

        let billing = facade
            .create_zone(create("spiffe://acme/billing", "billing"))
            .await
            .expect("billing's change")
            .into_inner()
            .zone
            .expect("a zone");
        let people = facade
            .create_zone(create("spiffe://acme/people", "people"))
            .await
            .expect("people's change, not a reused id")
            .into_inner()
            .zone
            .expect("a zone");
        assert_ne!(billing.id, people.id);
        assert_eq!(people.name, "people");
        let again = facade
            .create_zone(create("spiffe://acme/billing", "billing"))
            .await
            .expect("billing's retry")
            .into_inner()
            .zone
            .expect("a zone");
        assert_eq!(again.id, billing.id, "billing's own first answer");
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
            host: None,
            catalog,
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
            recorder: None,
            disclosure: Disclosure::Minimal,
            audit_refusals: false,
            metrics: permguard_core::Metrics::none(),
            authorization: Arc::new(Authorization::new(store, &[])),
            exports: None,
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
