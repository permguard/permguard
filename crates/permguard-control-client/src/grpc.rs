// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The gRPC transport: how the CLI reaches a server whose remote is written
//! `grpc://` or `grpcs://`.
//!
//! One URL, and the scheme *is* the transport — the same rule as HTTP. Both
//! transports serve the same domain from the same facade on the server, so
//! everything here is translation: the generated wire types of [`crate::v1`]
//! in, the CLI's own vocabulary out. The CLI is a
//! synchronous program; tonic is not — a private current-thread runtime
//! bridges the two, and never leaks past this module.

use std::cell::RefCell;

use crate::pdp_v1 as pdp;
use crate::remote::{RefAnswer, Remote};
use crate::v1 as proto;
use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    UploadObjectsRequest, UploadObjectsResponse,
};
use permguard_objects::digest::Digest;
use permguard_objects::{compress, limits};
use tonic::metadata::{AsciiMetadataValue, MetadataValue};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::catalog::{Failure as CatalogFailure, Ledger, Zone};
use crate::narrate::Narrator;
use crate::tls::TlsOptions;

/// Which plane a probe asks: each answers `GetInfo` and `GetHealth` on its own service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Control,
    Data,
}

/// What a plane says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneInfo {
    pub plane: String,
    pub product: String,
    pub version: String,
    pub commit: String,
}

/// How a plane says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneHealth {
    pub live: bool,
    pub ready: bool,
    /// Its lifecycle phase (WP-7.4b).
    pub state: String,
}

/// The local reason a failed call is reported under (TC-1): a deadline, an endpoint that could
/// not be reached, or a transport failure after it was.
pub fn reason_of(status: &tonic::Status) -> &'static str {
    match status.code() {
        tonic::Code::DeadlineExceeded => permguard_core::codes::client::TIMEOUT,
        tonic::Code::Unavailable => permguard_core::codes::client::CONNECT_FAILED,
        _ => permguard_core::codes::client::TRANSPORT_FAILED,
    }
}

/// Adds the operator's bearer token to every call on a channel (TC-1): one interceptor, so no
/// client generated from a contract can forget it.
#[derive(Clone)]
pub struct Authorize(Option<AsciiMetadataValue>);

impl tonic::service::Interceptor for Authorize {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(value) = &self.0 {
            request
                .metadata_mut()
                .insert("authorization", value.clone());
        }
        Ok(request)
    }
}

/// A channel every call on which carries the operator's token, when there is one.
pub type AuthChannel = InterceptedService<Channel, Authorize>;

/// A connected gRPC endpoint: the channel, the runtime that drives it, and
/// how exchanges are narrated.
pub struct GrpcChannel {
    runtime: tokio::runtime::Runtime,
    channel: AuthChannel,
    narrator: Box<dyn Narrator>,
}

impl GrpcChannel {
    /// Connects to `grpc://host[:port]` or `grpcs://host[:port]`.
    ///
    /// Connection is lazy — the first call dials — so building a channel is
    /// cheap and the failure surfaces where it can be reported per command.
    pub fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn Narrator>,
    ) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| "a gRPC endpoint is grpc://host:port or grpcs://host:port".to_owned())?;
        let secure = match scheme {
            "grpc" => false,
            "grpcs" => true,
            other => return Err(format!("`{other}` is not a gRPC scheme: use grpc or grpcs")),
        };
        if rest.contains('/') {
            return Err("a gRPC endpoint is a host and a port only — no path".to_owned());
        }
        tls.token_allowed(secure)?;
        if tls.skip_verify {
            // tonic verifies or refuses; there is no insecure TLS mode, and
            // pretending otherwise would be worse than saying so.
            return Err(
                "--tls-skip-verify is not supported over grpcs: trust the CA with --tls-ca-file"
                    .to_owned(),
            );
        }

        let uri = format!("{}://{rest}", if secure { "https" } else { "http" });
        let mut endpoint = Channel::from_shared(uri).map_err(|error| error.to_string())?;

        if secure {
            // The same trust rule as the HTTP client: a named authority
            // replaces the platform store, it never widens it.
            let mut config = match &tls.ca_file {
                Some(ca) => {
                    let pem = std::fs::read(ca)
                        .map_err(|error| format!("reading {}: {error}", ca.display()))?;
                    ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem))
                }
                None => ClientTlsConfig::new().with_native_roots(),
            };
            match (&tls.cert_file, tls.key_pem_bytes()?) {
                (Some(cert), Some(key)) => {
                    let cert = std::fs::read(cert)
                        .map_err(|error| format!("reading {}: {error}", cert.display()))?;
                    config = config.identity(Identity::from_pem(cert, key));
                }
                (None, None) => {}
                // Half an identity is a typo, as over HTTP.
                (Some(_), None) => return Err("a client certificate needs its key".to_owned()),
                (None, Some(_)) => return Err("a client key needs its certificate".to_owned()),
            }
            if let Some(name) = &tls.server_name {
                config = config.domain_name(name.clone());
            }
            endpoint = endpoint
                .tls_config(config)
                .map_err(|error| error.to_string())?;
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("starting the gRPC runtime: {error}"))?;
        // Building the channel captures the runtime handle; every call runs
        // on this same runtime, so enter it here too.
        let authorize = Authorize(
            tls.bearer()?
                .map(|value| MetadataValue::try_from(value.as_str()))
                .transpose()
                .map_err(|_| "the token cannot travel as gRPC metadata".to_owned())?,
        );
        let channel = {
            let _entered = runtime.enter();
            InterceptedService::new(endpoint.connect_lazy(), authorize)
        };

        Ok(Self {
            runtime,
            channel,
            narrator,
        })
    }

    /// The channel itself, for a client generated from another contract.
    ///
    /// Cloning a channel is cheap and shares the connection, so a second
    /// service on the same endpoint costs nothing extra.
    pub fn channel(&self) -> AuthChannel {
        self.channel.clone()
    }

    /// Runs one RPC on this endpoint's runtime, narrating it.
    ///
    /// Public so a client built from another contract answers on the same
    /// runtime: two runtimes on one connection is how a synchronous CLI ends
    /// up deadlocked on its own channel.
    pub fn run<T, F>(&self, rpc: &str, future: F) -> Result<T, tonic::Status>
    where
        F: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        self.call(rpc, future)
    }

    /// One finished RPC, told to whoever is listening.
    fn narrate(&self, rpc: &str, outcome: &str) {
        self.narrator.exchange("rpc", rpc, 0, outcome, 0);
    }

    /// Runs one RPC to completion on the private runtime, narrating it.
    fn call<T, F>(&self, rpc: &str, future: F) -> Result<T, tonic::Status>
    where
        F: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        // Never from a decision (TS-4): the channel dials on its first call, so the call is where
        // the network would be reached.
        if let Err(refused) =
            permguard_core::egress::check(permguard_core::egress::Target::ControlPlane)
        {
            self.narrate(rpc, "refused on the decision path");
            return Err(tonic::Status::unavailable(refused.to_string()));
        }
        match self.runtime.block_on(future) {
            Ok(response) => {
                self.narrate(rpc, "OK");
                Ok(response.into_inner())
            }
            Err(status) => {
                self.narrate(rpc, &format!("{:?}", status.code()));
                Err(status)
            }
        }
    }

    /// What the `plane` says it is and how it is (`GetInfo`, then `GetHealth`), each answered
    /// within `within` (TC-1): `inspect` over gRPC reads them where it reads `/version` and
    /// `/health` over HTTP. Each plane answers them on its own service.
    pub fn probe(
        &self,
        plane: Plane,
        within: std::time::Duration,
    ) -> Result<(PlaneInfo, Result<PlaneHealth, tonic::Status>), tonic::Status> {
        match plane {
            Plane::Control => {
                let mut client =
                    proto::control_plane_client::ControlPlaneClient::new(self.channel.clone());
                let info =
                    self.call_within("GetInfo", within, client.get_info(proto::GetInfoRequest {}))?;
                let health = self
                    .call_within(
                        "GetHealth",
                        within,
                        client.get_health(proto::GetHealthRequest {}),
                    )
                    .map(|health| PlaneHealth {
                        live: health.live,
                        ready: health.ready,
                        state: health.state,
                    });
                Ok((
                    PlaneInfo {
                        plane: info.plane,
                        product: info.product,
                        version: info.version,
                        commit: info.commit,
                    },
                    health,
                ))
            }
            Plane::Data => {
                let mut client = pdp::data_plane_client::DataPlaneClient::new(self.channel.clone());
                let info =
                    self.call_within("GetInfo", within, client.get_info(pdp::GetInfoRequest {}))?;
                let health = self
                    .call_within(
                        "GetHealth",
                        within,
                        client.get_health(pdp::GetHealthRequest {}),
                    )
                    .map(|health| PlaneHealth {
                        live: health.live,
                        ready: health.ready,
                        state: health.state,
                    });
                Ok((
                    PlaneInfo {
                        plane: info.plane,
                        product: info.product,
                        version: info.version,
                        commit: info.commit,
                    },
                    health,
                ))
            }
        }
    }

    /// One RPC bounded by `within`: an endpoint that drops packets costs the deadline, not a hang.
    fn call_within<T, F>(
        &self,
        rpc: &str,
        within: std::time::Duration,
        future: F,
    ) -> Result<T, tonic::Status>
    where
        F: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        self.call(rpc, async move {
            tokio::time::timeout(within, future)
                .await
                .unwrap_or_else(|_| Err(tonic::Status::deadline_exceeded("no answer in time")))
        })
    }

    /// The discovery document — the proof this endpoint is a Permguard
    /// control plane — before the remote is remembered.
    pub fn verify_discovery(&self) -> Result<(), String> {
        let mut client = proto::control_plane_client::ControlPlaneClient::new(self.channel.clone());
        let answer = self
            .call(
                "GetServerConfiguration",
                client.get_server_configuration(proto::GetServerConfigurationRequest {}),
            )
            .map_err(|status| status.message().to_owned())?;
        let value: serde_json::Value = serde_json::from_str(&answer.document_json)
            .map_err(|error| format!("the discovery document does not parse: {error}"))?;
        if value
            .get("plane")
            .and_then(|plane| plane.as_str())
            .is_none()
        {
            return Err("this endpoint answers, but not with a Permguard plane".to_owned());
        }
        Ok(())
    }
}

/// A tonic status, in the same sentence shape HTTP refusals take, so scripts
/// and people read one vocabulary whatever the transport.
/// The metadata keys the server puts the structured half of a refusal in —
/// the same two the planes write, so a client reads one convention.
pub use permguard_core::{GRPC_ERROR_CLASS, GRPC_ERROR_CODE};

/// A refusal, in the **same shape both transports produce**: the sentence, then
/// the class and the stable code in parentheses.
///
/// That symmetry is not cosmetic. A caller that has to tell "this ref does not
/// exist yet" from "this failed" reads the code, and a transport that spelled
/// its refusals differently would make every such caller wrong on one of the
/// two. The class and the code ride as metadata (the server sets them); when
/// they are absent — an older server, or a status tonic produced itself — they
/// are derived from the gRPC code rather than left out.
fn refusal(status: &tonic::Status) -> String {
    let metadata = |key: &str| {
        status
            .metadata()
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    };
    let (derived_class, derived_code) = classify(status.code());
    let class = metadata(GRPC_ERROR_CLASS).unwrap_or_else(|| derived_class.to_owned());
    let code = metadata(GRPC_ERROR_CODE).unwrap_or_else(|| derived_code.to_owned());

    format!("{} ({class}/{code})", status.message())
}

/// The class and code a gRPC status means, when the server named neither.
fn classify(code: tonic::Code) -> (&'static str, &'static str) {
    match code {
        tonic::Code::InvalidArgument => (
            "validation",
            permguard_core::codes::common::INVALID_ARGUMENT,
        ),
        tonic::Code::AlreadyExists => ("conflict", permguard_core::codes::catalog::NAME_TAKEN),
        tonic::Code::Aborted | tonic::Code::FailedPrecondition => ("conflict", "conflict"),
        tonic::Code::NotFound => ("not_found", "not_found"),
        tonic::Code::Unavailable => ("unavailable", "unavailable"),
        tonic::Code::ResourceExhausted => ("unavailable", "exhausted"),
        // A denial carries a code and no class, as over REST (TC-1).
        tonic::Code::Unauthenticated => ("", permguard_core::codes::common::UNAUTHENTICATED),
        tonic::Code::PermissionDenied => ("", permguard_core::codes::common::FORBIDDEN),
        _ => ("internal", "internal"),
    }
}

// ---- the catalog, over gRPC --------------------------------------------------------------------

/// Zones and ledgers over gRPC: the same verbs `zones.rs` speaks over HTTP.
pub struct GrpcAdmin(pub GrpcChannel);

impl crate::catalog::Catalog for GrpcAdmin {
    fn list_zones(
        &self,
        page: Option<u32>,
        size: Option<u32>,
    ) -> Result<Vec<Zone>, CatalogFailure> {
        GrpcAdmin::list_zones(self, page, size)
    }

    fn get_zone(&self, zone: &str) -> Result<Zone, CatalogFailure> {
        GrpcAdmin::get_zone(self, zone)
    }

    fn list_ledgers(
        &self,
        zone: &str,
        page: Option<u32>,
        size: Option<u32>,
    ) -> Result<Vec<Ledger>, CatalogFailure> {
        GrpcAdmin::list_ledgers(self, zone, page, size)
    }

    fn get_ledger(&self, zone: &str, ledger: &str) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::get_ledger(self, zone, ledger)
    }

    fn create_zone(&self, name: &str) -> Result<Zone, CatalogFailure> {
        GrpcAdmin::create_zone(self, name)
    }

    fn rename_zone(
        &self,
        zone: &str,
        name: &str,
        expected_revision: u64,
    ) -> Result<Zone, CatalogFailure> {
        GrpcAdmin::rename_zone(self, zone, name, expected_revision)
    }

    fn delete_zone(&self, zone: &str, expected_revision: u64) -> Result<Zone, CatalogFailure> {
        GrpcAdmin::delete_zone(self, zone, expected_revision)
    }

    fn create_ledger(&self, zone: &str, name: &str) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::create_ledger(self, zone, name)
    }

    fn rename_ledger(
        &self,
        zone: &str,
        ledger: &str,
        name: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::rename_ledger(self, zone, ledger, name, expected_revision)
    }

    fn delete_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::delete_ledger(self, zone, ledger, expected_revision)
    }

    fn archive_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::archive_ledger(self, zone, ledger, expected_revision)
    }

    fn restore_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::restore_ledger(self, zone, ledger, expected_revision)
    }

    fn export_ledger(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<crate::catalog::Export, CatalogFailure> {
        let mut client = self.catalog();
        let answer = self
            .0
            .call(
                "ExportLedger",
                client.export_ledger(proto::ExportLedgerRequest {
                    zone: zone.to_owned(),
                    ledger: ledger.to_owned(),
                }),
            )
            .map_err(Self::failure)?;
        Ok(Self::export(answer))
    }

    fn import(
        &self,
        zone: &str,
        request: &crate::catalog::ImportRequest,
    ) -> Result<crate::catalog::Imported, CatalogFailure> {
        let mut client = self.catalog();
        let answer = self
            .0
            .call(
                "Import",
                client.import(proto::ImportRequest {
                    zone: zone.to_owned(),
                    request_id: crate::catalog::request_id()?,
                    mode: request.mode.clone(),
                    name: request.name.clone().unwrap_or_default(),
                    archive: request.archive.clone(),
                    bundle_manifest: request.bundle_manifest.clone(),
                    bundle_items: request.bundle_items.clone(),
                    pin: request.pin.clone(),
                }),
            )
            .map_err(Self::failure)?;
        let ledger = |ledger: proto::Ledger| Ledger {
            id: ledger.id,
            zone_id: ledger.zone_id,
            name: ledger.name,
            default_ref: ledger.default_ref,
            created_at: ledger.created_at,
            updated_at: ledger.updated_at,
            revision: ledger.revision,
            state: active_unless_said(ledger.state),
            provenance: ledger.provenance.map(provenance_of),
            serving_members: Vec::new(),
        };
        Ok(crate::catalog::Imported {
            mode: answer.mode,
            manifest_digest: answer.manifest_digest,
            source_host_id: answer.source_host_id,
            source_zone_id: answer.source_zone_id,
            archive: answer.archive.map(|record| crate::catalog::ArchiveRecord {
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
                    .map(|ledger| crate::catalog::ExportedLedger {
                        id: ledger.id,
                        name: ledger.name,
                        refs: ledger.refs,
                        objects: ledger.objects,
                        statements: ledger.statements,
                    })
                    .collect(),
            }),
            ledgers: answer.ledgers.into_iter().map(ledger).collect(),
        })
    }

    fn export_zone(&self, zone: &str) -> Result<crate::catalog::Export, CatalogFailure> {
        let mut client = self.catalog();
        let answer = self
            .0
            .call(
                "ExportZone",
                client.export_zone(proto::ExportZoneRequest {
                    zone: zone.to_owned(),
                }),
            )
            .map_err(Self::failure)?;
        Ok(Self::export(answer))
    }
}

/// The refusal a gRPC status carries, as every client here reports it (TC-1): the class and
/// stable code from the metadata the server sent, or what the gRPC code means when it sent none.
pub(crate) fn failure_of(status: tonic::Status) -> CatalogFailure {
    // The class and the stable code the server sent as metadata, when it sent them: a script
    // that branches on either reads the same value whichever transport carried the refusal.
    // Only a status without them — an older server, or one tonic produced itself — falls back
    // to what its gRPC code means, through the same mapping every gRPC refusal here uses.
    let metadata = |key: &str| {
        status
            .metadata()
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    };
    // A denial at the listener's gate carries a code and no class, as over REST (TC-1).
    if matches!(
        status.code(),
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
    ) && metadata(GRPC_ERROR_CLASS).is_none()
    {
        let fallback = if status.code() == tonic::Code::Unauthenticated {
            permguard_core::codes::common::UNAUTHENTICATED
        } else {
            permguard_core::codes::common::FORBIDDEN
        };
        return CatalogFailure {
            class: String::new(),
            reason: metadata(GRPC_ERROR_CODE).unwrap_or_else(|| fallback.to_owned()),
            detail: status.message().to_owned(),
            usage: true,
        };
    }
    let (derived_class, derived_code) = classify(status.code());
    let class = metadata(GRPC_ERROR_CLASS).unwrap_or_else(|| derived_class.to_owned());
    let reason = metadata(GRPC_ERROR_CODE).unwrap_or_else(|| derived_code.to_owned());
    // A usage error is a mistake in what was asked; the other classes are the world's.
    let usage = matches!(class.as_str(), "validation" | "conflict" | "not_found");

    CatalogFailure {
        class,
        reason,
        detail: status.message().to_owned(),
        usage,
    }
}

impl GrpcAdmin {
    fn catalog(&self) -> proto::zone_catalog_client::ZoneCatalogClient<AuthChannel> {
        proto::zone_catalog_client::ZoneCatalogClient::new(self.0.channel.clone())
            // An export's archive is as large as the server lets one message be (WP-7.10): the
            // same ceiling REST reads under.
            .max_decoding_message_size(crate::MAX_RESPONSE_BYTES as usize)
    }

    fn failure(status: tonic::Status) -> CatalogFailure {
        failure_of(status)
    }

    fn export(answer: proto::ExportResponse) -> crate::catalog::Export {
        crate::catalog::Export {
            archive: answer.archive,
            zone_id: answer.zone_id,
            bundle_digest: answer.bundle_digest,
            bundle_bytes: answer.bundle_bytes,
            exported_at: answer.exported_at,
            ledgers: answer
                .ledgers
                .into_iter()
                .map(|ledger| crate::catalog::ExportedLedger {
                    id: ledger.id,
                    name: ledger.name,
                    refs: ledger.refs,
                    objects: ledger.objects,
                    statements: ledger.statements,
                })
                .collect(),
        }
    }

    fn zone(answer: proto::ZoneResponse) -> Result<Zone, CatalogFailure> {
        let zone = answer.zone.ok_or_else(|| CatalogFailure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: "the answer carries no zone".to_owned(),
            usage: false,
        })?;
        Ok(Zone {
            id: zone.id,
            name: zone.name,
            created_at: zone.created_at,
            updated_at: zone.updated_at,
            revision: zone.revision,
        })
    }

    fn ledger(answer: proto::LedgerResponse) -> Result<Ledger, CatalogFailure> {
        let ledger = answer.ledger.ok_or_else(|| CatalogFailure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: "the answer carries no ledger".to_owned(),
            usage: false,
        })?;
        Ok(Ledger {
            id: ledger.id,
            zone_id: ledger.zone_id,
            name: ledger.name,
            default_ref: ledger.default_ref,
            created_at: ledger.created_at,
            updated_at: ledger.updated_at,
            revision: ledger.revision,
            state: active_unless_said(ledger.state),
            provenance: ledger.provenance.map(provenance_of),
            serving_members: ledger
                .serving_members
                .into_iter()
                .map(serving_member_of)
                .collect(),
        })
    }

    pub fn create_zone(&self, name: &str) -> Result<Zone, CatalogFailure> {
        let mut client = self.catalog();
        let name = name.to_owned();
        Self::zone(
            self.0
                .call(
                    "CreateZone",
                    client.create_zone(proto::CreateZoneRequest {
                        name,
                        request_id: crate::catalog::request_id()?,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn list_zones(
        &self,
        page: Option<u32>,
        size: Option<u32>,
    ) -> Result<Vec<Zone>, CatalogFailure> {
        let mut client = self.catalog();
        let answer = self
            .0
            .call(
                "ListZones",
                client.list_zones(proto::ListZonesRequest { page, size }),
            )
            .map_err(Self::failure)?;
        Ok(answer
            .zones
            .into_iter()
            .map(|zone| Zone {
                id: zone.id,
                name: zone.name,
                created_at: zone.created_at,
                updated_at: zone.updated_at,
                revision: zone.revision,
            })
            .collect())
    }

    pub fn get_zone(&self, zone: &str) -> Result<Zone, CatalogFailure> {
        let mut client = self.catalog();
        let zone = zone.to_owned();
        Self::zone(
            self.0
                .call("GetZone", client.get_zone(proto::GetZoneRequest { zone }))
                .map_err(Self::failure)?,
        )
    }

    pub fn rename_zone(
        &self,
        zone: &str,
        name: &str,
        expected_revision: u64,
    ) -> Result<Zone, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, name) = (zone.to_owned(), name.to_owned());
        Self::zone(
            self.0
                .call(
                    "RenameZone",
                    client.rename_zone(proto::RenameZoneRequest {
                        zone,
                        name,
                        request_id: crate::catalog::request_id()?,
                        expected_revision,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn delete_zone(&self, zone: &str, expected_revision: u64) -> Result<Zone, CatalogFailure> {
        let mut client = self.catalog();
        let zone = zone.to_owned();
        Self::zone(
            self.0
                .call(
                    "DeleteZone",
                    client.delete_zone(proto::DeleteZoneRequest {
                        zone,
                        request_id: crate::catalog::request_id()?,
                        expected_revision,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn create_ledger(&self, zone: &str, name: &str) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, name) = (zone.to_owned(), name.to_owned());
        Self::ledger(
            self.0
                .call(
                    "CreateLedger",
                    client.create_ledger(proto::CreateLedgerRequest {
                        zone,
                        name,
                        request_id: crate::catalog::request_id()?,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn list_ledgers(
        &self,
        zone: &str,
        page: Option<u32>,
        size: Option<u32>,
    ) -> Result<Vec<Ledger>, CatalogFailure> {
        let mut client = self.catalog();
        let zone = zone.to_owned();
        let answer = self
            .0
            .call(
                "ListLedgers",
                client.list_ledgers(proto::ListLedgersRequest { zone, page, size }),
            )
            .map_err(Self::failure)?;
        Ok(answer
            .ledgers
            .into_iter()
            .map(|ledger| Ledger {
                id: ledger.id,
                zone_id: ledger.zone_id,
                name: ledger.name,
                default_ref: ledger.default_ref,
                created_at: ledger.created_at,
                updated_at: ledger.updated_at,
                revision: ledger.revision,
                state: active_unless_said(ledger.state),
                provenance: ledger.provenance.map(provenance_of),
                serving_members: Vec::new(),
            })
            .collect())
    }

    pub fn get_ledger(&self, zone: &str, ledger: &str) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, ledger) = (zone.to_owned(), ledger.to_owned());
        Self::ledger(
            self.0
                .call(
                    "GetLedger",
                    client.get_ledger(proto::GetLedgerRequest { zone, ledger }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn rename_ledger(
        &self,
        zone: &str,
        ledger: &str,
        name: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, ledger, name) = (zone.to_owned(), ledger.to_owned(), name.to_owned());
        Self::ledger(
            self.0
                .call(
                    "RenameLedger",
                    client.rename_ledger(proto::RenameLedgerRequest {
                        zone,
                        ledger,
                        name,
                        request_id: crate::catalog::request_id()?,
                        expected_revision,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn delete_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, ledger) = (zone.to_owned(), ledger.to_owned());
        Self::ledger(
            self.0
                .call(
                    "DeleteLedger",
                    client.delete_ledger(proto::DeleteLedgerRequest {
                        zone,
                        ledger,
                        request_id: crate::catalog::request_id()?,
                        expected_revision,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }

    /// Archives a ledger (WP-7.3b).
    pub fn archive_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, ledger) = (zone.to_owned(), ledger.to_owned());
        Self::ledger(
            self.0
                .call(
                    "ArchiveLedger",
                    client.archive_ledger(proto::ArchiveLedgerRequest {
                        zone,
                        ledger,
                        request_id: crate::catalog::request_id()?,
                        expected_revision,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }

    /// Restores an archived ledger (WP-7.3b).
    pub fn restore_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, ledger) = (zone.to_owned(), ledger.to_owned());
        Self::ledger(
            self.0
                .call(
                    "RestoreLedger",
                    client.restore_ledger(proto::RestoreLedgerRequest {
                        zone,
                        ledger,
                        request_id: crate::catalog::request_id()?,
                        expected_revision,
                    }),
                )
                .map_err(Self::failure)?,
        )
    }
}

/// A serving member as `GetLedger` carries it on gRPC (TC-5).
fn serving_member_of(member: proto::ServingMember) -> crate::catalog::ServingMember {
    crate::catalog::ServingMember {
        host_id: member.host_id,
        membership_id: member.membership_id,
        task_id: member.task_id,
        declared_assurance: member.declared_assurance,
        assurance: member.assurance_binding_status.map(|assurance| {
            crate::catalog::ServingAssurance {
                verdict: assurance.verdict,
                current: assurance.current,
                policy_revision: assurance.policy_revision,
                claims: assurance
                    .claims
                    .into_iter()
                    .map(|claim| crate::catalog::ServingClaim {
                        control: claim.control,
                        class: claim.class,
                        by: claim.by,
                    })
                    .collect(),
                expires_at: assurance.expires_at,
            }
        }),
        lease_state: member.lease_state,
        last_session_at: member.last_session_at,
        progress: member
            .progress
            .map(|progress| crate::catalog::ServingProgress {
                report_seq: progress.report_seq,
                reported_at: progress.reported_at,
                received_at: progress.received_at,
                state: progress.state,
                checkpoint_digest: progress.checkpoint_digest,
                stale: progress.stale,
            }),
    }
}

/// A re-homed ledger's provenance as the wire carries it (WP-7.10).
fn provenance_of(provenance: proto::LedgerProvenance) -> permguard_core::Provenance {
    permguard_core::Provenance {
        manifest_digest: provenance.manifest_digest,
        source_host_id: provenance.source_host_id,
        source_zone_id: provenance.source_zone_id,
        source_ledger_id: provenance.source_ledger_id,
        exported_at: provenance.exported_at,
    }
}

/// A ledger's state as gRPC carries it: a server older than states sends none, which reads as
/// `active`, as it does over REST (WP-7.3b).
fn active_unless_said(state: String) -> String {
    if state.is_empty() {
        "active".to_owned()
    } else {
        state
    }
}

// ---- the git-like store, over gRPC --------------------------------------------------------------

/// A remote ledger over gRPC — the same [`Remote`] contract the HTTP
/// implementation satisfies, so the workspace engine cannot tell them apart.
pub struct GrpcRemote {
    channel: GrpcChannel,
    /// The resolved (zone GUID, ledger GUID), set by `resolve` or pre-bound.
    ids: RefCell<Option<(String, String)>>,
    /// The batch compression the last negotiation advertised — the transport
    /// concern, exactly as on HTTP.
    compression: RefCell<Option<String>>,
}

impl GrpcRemote {
    pub fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn Narrator>,
    ) -> Result<Self, String> {
        Ok(Self {
            channel: GrpcChannel::connect(url, tls, narrator)?,
            ids: RefCell::new(None),
            compression: RefCell::new(None),
        })
    }

    /// Pre-binds the resolved GUIDs, for workspaces that already carry them.
    pub fn bind(&self, zone_id: &str, ledger_id: &str) {
        *self.ids.borrow_mut() = Some((zone_id.to_owned(), ledger_id.to_owned()));
    }

    /// The discovery check `remote add` runs before remembering the remote.
    pub fn verify_discovery(&self) -> Result<(), String> {
        self.channel.verify_discovery()
    }

    fn store(&self) -> proto::git_like_store_client::GitLikeStoreClient<AuthChannel> {
        proto::git_like_store_client::GitLikeStoreClient::new(self.channel.channel.clone())
            // Above tonic's 4 MiB default, deliberately: a fetch batch is as
            // large as the server negotiated, and the negotiation is the
            // authority — bounded by the crate-wide response ceiling.
            .max_decoding_message_size(crate::MAX_RESPONSE_BYTES as usize)
    }

    fn bound(&self) -> Result<(String, String), String> {
        self.ids
            .borrow()
            .clone()
            .ok_or_else(|| "the remote is not bound to a ledger yet".to_owned())
    }

    fn remember_compression(&self, advertised: &str) {
        *self.compression.borrow_mut() =
            (advertised == compress::DEFLATE).then(|| advertised.to_owned());
    }
}

fn parse_digest(text: &str) -> Result<Digest, String> {
    Digest::parse(text).map_err(|error| error.to_string())
}

fn parse_digests(list: Vec<String>) -> Result<Vec<Digest>, String> {
    list.iter().map(|text| parse_digest(text)).collect()
}

/// A ref state the client names, in its proto shape.
fn expected_ref(expected: &permguard_notp::ExpectedRef) -> proto::ExpectedRef {
    proto::ExpectedRef {
        counter: expected.counter,
        digest: expected.digest.to_string(),
    }
}

/// A transfer session id the server issued: exactly 16 bytes.
fn transfer_id(bytes: &[u8]) -> Result<permguard_notp::TransferId, String> {
    bytes
        .try_into()
        .map_err(|_| "the server issued a transfer id that is not 16 bytes".to_owned())
}

impl Remote for GrpcRemote {
    fn resolve(&self, zone: &str, ledger: &str) -> Result<(String, String), String> {
        // The zone catalog over the same channel, same runtime.
        let mut client =
            proto::zone_catalog_client::ZoneCatalogClient::new(self.channel.channel.clone());
        let zone = self
            .channel
            .call(
                "GetZone",
                client.get_zone(proto::GetZoneRequest {
                    zone: zone.to_owned(),
                }),
            )
            .map_err(|status| refusal(&status))?
            .zone
            .ok_or_else(|| "the answer carries no zone".to_owned())?;
        let ledger = self
            .channel
            .call(
                "GetLedger",
                client.get_ledger(proto::GetLedgerRequest {
                    zone: zone.id.clone(),
                    ledger: ledger.to_owned(),
                }),
            )
            .map_err(|status| refusal(&status))?
            .ledger
            .ok_or_else(|| "the answer carries no ledger".to_owned())?;
        self.bind(&zone.id, &ledger.id);
        Ok((zone.id, ledger.id))
    }

    fn keyring(&self) -> Result<Vec<u8>, String> {
        let mut client = self.store();
        let answer = self
            .channel
            .call(
                "GetKeyRing",
                client.get_key_ring(proto::GetKeyRingRequest {}),
            )
            .map_err(|status| refusal(&status))?;
        Ok(answer.jwks)
    }

    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String> {
        let (zone, ledger) = self.bound()?;
        let mut client = self.store();
        let request = proto::GetRefRequest {
            zone,
            ledger,
            r#ref: r#ref.to_owned(),
        };
        match self.channel.call("GetRef", client.get_ref(request)) {
            Ok(answer) => Ok(Some(RefAnswer {
                head: answer.head,
                counter: answer.counter,
                statement: answer.statement,
                ref_digest: parse_digest(&answer.ref_digest)?.to_string(),
            })),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(refusal(&status)),
        }
    }

    fn negotiate_push(
        &self,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String> {
        let (zone, ledger) = self.bound()?;
        let mut client = self.store();
        let wire = proto::NegotiatePushRequest {
            zone,
            ledger,
            r#ref: request.r#ref.clone(),
            new_head: request.new_head.to_string(),
            expected_ref: request.expected_ref.as_ref().map(expected_ref),
            closure: request
                .closure
                .iter()
                .map(|claim| proto::ObjectClaim {
                    digest: claim.digest.to_string(),
                    size: claim.size,
                })
                .collect(),
            request_id: request.request_id.clone(),
        };
        let answer = self
            .channel
            .call("NegotiatePush", client.negotiate_push(wire))
            .map_err(|status| refusal(&status))?;
        self.remember_compression(&answer.compression);
        Ok(NegotiatePushResponse {
            missing: parse_digests(answer.missing)?,
            max_batch_bytes: answer.max_batch_bytes,
            max_batch_objects: answer.max_batch_objects,
            compression: (!answer.compression.is_empty()).then_some(answer.compression),
            transfer_id: transfer_id(&answer.transfer_id)?,
            reservation: answer.reservation,
            expiry: answer.expiry,
        })
    }

    fn upload(&self, request: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String> {
        let (zone, ledger) = self.bound()?;
        let mut client = self.store();
        let (objects, compression) = match &*self.compression.borrow() {
            Some(algorithm) => (
                request
                    .objects
                    .iter()
                    .map(|o| compress::deflate(o))
                    .collect(),
                algorithm.clone(),
            ),
            None => (request.objects.clone(), String::new()),
        };
        let wire = proto::UploadObjectsRequest {
            zone,
            ledger,
            objects,
            compression,
            transfer_id: request.transfer_id.to_vec(),
        };
        let answer = self
            .channel
            .call("UploadObjects", client.upload_objects(wire))
            .map_err(|status| refusal(&status))?;
        Ok(UploadObjectsResponse {
            received: parse_digests(answer.received)?,
            remaining: answer.remaining,
        })
    }

    fn commit_push(&self, request: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        let (zone, ledger) = self.bound()?;
        let mut client = self.store();
        let wire = proto::CommitPushRequest {
            zone,
            ledger,
            r#ref: request.r#ref.clone(),
            new_head: request.new_head.to_string(),
            expected_ref: request.expected_ref.as_ref().map(expected_ref),
            transfer_id: request.transfer_id.to_vec(),
            request_id: request.request_id.clone(),
        };
        let answer = self
            .channel
            .call("CommitPush", client.commit_push(wire))
            .map_err(|status| refusal(&status))?;
        Ok(CommitPushResponse {
            head: parse_digest(&answer.head)?,
            counter: answer.counter,
            statement: answer.statement,
            ref_digest: parse_digest(&answer.ref_digest)?,
        })
    }

    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        let (zone, ledger) = self.bound()?;
        let mut client = self.store();
        let wire = proto::NegotiatePullRequest {
            zone,
            ledger,
            r#ref: request.r#ref.clone(),
            at: request
                .at
                .as_ref()
                .map(|digest| digest.to_string())
                .unwrap_or_default(),
            have: request
                .have
                .iter()
                .map(|digest| digest.to_string())
                .collect(),
            checkpoint: request.checkpoint.as_ref().map(expected_ref),
        };
        let answer = self
            .channel
            .call("NegotiatePull", client.negotiate_pull(wire))
            .map_err(|status| refusal(&status))?;
        self.remember_compression(&answer.compression);
        Ok(NegotiatePullResponse {
            head: parse_digest(&answer.head)?,
            counter: answer.counter,
            statement: answer.statement,
            missing: parse_digests(answer.missing)?,
            max_batch_bytes: answer.max_batch_bytes,
            max_batch_objects: answer.max_batch_objects,
            compression: (!answer.compression.is_empty()).then_some(answer.compression),
            transfer_id: transfer_id(&answer.transfer_id)?,
            ref_digest: parse_digest(&answer.ref_digest)?,
            expiry: answer.expiry,
        })
    }

    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        let (zone, ledger) = self.bound()?;
        let mut client = self.store();
        let wire = proto::FetchObjectsRequest {
            zone,
            ledger,
            digests: request
                .digests
                .iter()
                .map(|digest| digest.to_string())
                .collect(),
            accept_compression: self.compression.borrow().clone().unwrap_or_default(),
            transfer_id: request.transfer_id.to_vec(),
        };
        let mut answer = self
            .channel
            .call("FetchObjects", client.fetch_objects(wire))
            .map_err(|status| refusal(&status))?;
        if !answer.compression.is_empty() {
            if answer.compression != compress::DEFLATE {
                return Err(format!(
                    "the server compressed with `{}`, which was not asked for",
                    answer.compression
                ));
            }
            answer.objects = answer
                .objects
                .iter()
                .map(|bytes| compress::inflate(bytes, limits::MAX_OBJECT_BYTES))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("a fetched object does not decompress: {error}"))?;
        }
        Ok(FetchObjectsResponse {
            objects: answer.objects,
            compression: None,
            expiry: answer.expiry,
        })
    }
}

/// The data plane's decision endpoint over gRPC.
///
/// It lives beside the channel because that is where the runtime, the TLS
/// material and the narration already are; what a payload *means* lives in
/// [`crate::pdp`], with the trait both transports implement. So this file
/// carries the RPCs and nothing about the contract.
pub struct GrpcPdp(GrpcChannel);

impl GrpcPdp {
    /// Connects to `grpc://host:port` or `grpcs://host:port`.
    pub fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn Narrator>,
    ) -> Result<Self, String> {
        Ok(Self(GrpcChannel::connect(url, tls, narrator)?))
    }

    fn client(&self) -> pdp::policy_decision_point_client::PolicyDecisionPointClient<AuthChannel> {
        pdp::policy_decision_point_client::PolicyDecisionPointClient::new(self.0.channel.clone())
    }
}

impl crate::pdp::Pdp for GrpcPdp {
    fn evaluate(&self, payload: &serde_json::Value) -> Result<serde_json::Value, CatalogFailure> {
        let mut client = self.client();
        // Refused here rather than carried across as less than it says: a payload this transport
        // cannot represent is a bad request, and the caller hears the same thing HTTP tells them.
        // The code is the contract's own — `field_removed` for a field this contract retired,
        // `payload_malformed` for a body its types would not read — so a caller switching on it
        // hears the same word whichever transport carried the request. A field the generated
        // message has no tag for would otherwise be *dropped* here and the plane would answer a
        // request it never saw the whole of.
        let request = request_of(payload).map_err(|why| CatalogFailure {
            class: "validation".to_owned(),
            reason: why.code.to_owned(),
            detail: why.message,
            usage: true,
        })?;
        // The boxcarred RPC when the caller boxcarred, the single one otherwise — the same rule
        // the HTTP client applies to its two paths, and for the same reasons. The server answers
        // both with one handler today, so the verdict does not depend on this; what does is
        // everything *around* it: which RPC a capture shows, which method a metric counts, and
        // which method a future per-method authorization or rate limit is written against. A
        // client that always said `EvaluateMany` would make a single check indistinguishable from
        // a batch of one in every one of those.
        let boxcarred = payload
            .get("evaluations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|evaluations| !evaluations.is_empty());
        let answer = if boxcarred {
            self.0
                .call("EvaluateMany", client.evaluate_many(request))
                .map_err(GrpcAdmin::failure)?
        } else {
            self.0
                .call("Evaluate", client.evaluate(request))
                .map_err(GrpcAdmin::failure)?
        };

        Ok(answer_of(answer))
    }

    /// What `permguard.api.pdp.native.v1` offers here, shaped exactly as the HTTP document — so a caller
    /// reading it cannot tell which transport fetched it.
    fn configuration(&self) -> Result<serde_json::Value, CatalogFailure> {
        let mut client = self.client();
        let answer = self
            .0
            .call(
                "GetConfiguration",
                client.get_configuration(pdp::GetConfigurationRequest {}),
            )
            .map_err(GrpcAdmin::failure)?;
        let endpoints = answer.endpoints.unwrap_or_default();
        let scope = answer.store_scope.unwrap_or_default();

        let mut document = serde_json::json!({
            "interface": answer.r#interface,
            "pdp": answer.pdp,
            "endpoints": {
                "evaluation": endpoints.evaluation,
                "evaluations": endpoints.evaluations,
            },
            "capabilities": answer.capabilities,
            "store_scope": {
                "in": scope.r#in,
                "zone": scope.zone,
                "ledger": scope.ledger,
                "profile": scope.profile,
            },
        });
        header_json(
            &mut document,
            answer.version,
            answer.component,
            answer.state,
            answer.stage,
            answer.sunset,
            answer.limits,
        );
        // The closed `response_signing` object as the HTTP document writes it (WP-6.6b): the two
        // numbers only when signing is offered.
        if let (Some(object), Some(signing)) = (document.as_object_mut(), answer.response_signing) {
            let state = if signing.state == "optional" {
                serde_json::json!({
                    "state": signing.state,
                    "validity_seconds": signing.validity_seconds,
                    "clock_skew_seconds": signing.clock_skew_seconds,
                })
            } else {
                serde_json::json!({ "state": signing.state })
            };
            object.insert("response_signing".to_owned(), state);
        }
        Ok(document)
    }
}

/// The common header a gRPC configuration answer carries, as the HTTP document spells it
/// (WP-7.4a): `sunset` only when there is one, `limits` by name.
pub(crate) fn header_json(
    document: &mut serde_json::Value,
    version: String,
    component: String,
    state: String,
    stage: String,
    sunset: Option<String>,
    limits: std::collections::HashMap<String, u64>,
) {
    let Some(object) = document.as_object_mut() else {
        return;
    };
    object.insert("version".to_owned(), version.into());
    object.insert("component".to_owned(), component.into());
    object.insert("state".to_owned(), state.into());
    object.insert("stage".to_owned(), stage.into());
    if let Some(sunset) = sunset {
        object.insert("sunset".to_owned(), sunset.into());
    }
    object.insert(
        "limits".to_owned(),
        limits
            .into_iter()
            .map(|(name, value)| (name, serde_json::Value::from(value)))
            .collect::<serde_json::Map<_, _>>()
            .into(),
    );
}

/// The proto request a JSON payload means, **or a refusal**.
///
/// # One validation, not two
///
/// The payload is first read into `permguard_languages::request::CheckRequest` — **the very type
/// the data plane deserializes an HTTP body into** — and only then mapped onto the generated
/// message. That ordering is the whole point. This function used to walk the JSON itself, and a
/// hand-written walk is partial by construction: it answered a payload it could not represent by
/// dropping the part it could not, and it drifted from the HTTP reading every time either side
/// gained a field. `context` that was not an object became no context; `evaluations: null` became
/// no evaluations; an unknown `evaluations_semantic` became the default. Each of those was a
/// request refused on one transport and quietly answered against less than it said on the other,
/// which is the contract differing by transport rather than the transport differing.
///
/// What remains here is the one thing serde cannot know: proto carries a single IEEE-754 double,
/// so an integer past 2^53 cannot cross and come back as itself.
fn request_of(
    payload: &serde_json::Value,
) -> Result<pdp::EvaluateRequest, permguard_languages::Malformed> {
    let request: permguard_languages::CheckRequest = serde_json::from_value(payload.clone())
        .map_err(|error| permguard_languages::Malformed {
            code: permguard_core::codes::notp::PAYLOAD_MALFORMED,
            message: error.to_string(),
        })?;
    // Carried with its own code, not flattened into one. A caller that switches on `field_removed`
    // over HTTP switches on `field_removed` over gRPC: a structured refusal whose code depended on
    // the transport would be two contracts with one name.
    request.removed()?;

    // `to_proto` fails only on a number the transport cannot carry exactly: refused with the
    // code both servers answer for it (WP-7.5b, IFACE-06), so the client says what REST says.
    to_proto(&request).map_err(|message| permguard_languages::Malformed {
        code: permguard_core::codes::notp::VALUE_UNREPRESENTABLE,
        message,
    })
}

/// The generated message a contract request means. Total, and fallible only on numbers.
fn to_proto(request: &permguard_languages::CheckRequest) -> Result<pdp::EvaluateRequest, String> {
    Ok(pdp::EvaluateRequest {
        zone: text(&request.zone),
        ledger: text(&request.ledger),
        profile: text(&request.profile),
        subject: entity_of(request.subject.as_ref())?,
        resource: entity_of(request.resource.as_ref())?,
        action: action_of(request.action.as_ref())?,
        context: structure(request.context.as_ref())?,
        principal: entity_of(request.principal.as_ref())?,
        partition_inputs: inputs_of(&request.partition_inputs)?,
        evaluations: request
            .evaluations
            .iter()
            .map(evaluation_of)
            .collect::<Result<Vec<pdp::Evaluation>, String>>()?,
        evaluations_semantic: semantic_of(request),
        request_id: text(&request.request_id),
        request_nonce: text(&request.request_nonce),
    })
}

/// An absent string is an empty one: proto3 has no other way to say it, and the contract's
/// "absent" and "empty" mean the same thing for a name nobody wrote.
fn text(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

/// One JSON value, as proto carries values.
///
/// proto has one number type, an IEEE-754 double. Past 2^53 a double no longer counts one at a
/// time, so an integer beyond it cannot cross and come back as itself — refused rather than
/// rounded, because a number a policy compares against is not a number to approximate.
fn proto_value(value: &serde_json::Value) -> Result<prost_types::Value, String> {
    use prost_types::value::Kind;

    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(held) => Kind::BoolValue(*held),
        serde_json::Value::Number(held) => {
            // Checked on the integer, not on the double: converting first is what loses the
            // information the check is for — 2^53+1 becomes 2^53 on the way, and a test of the
            // result would say it fits.
            const EXACT: u64 = 9_007_199_254_740_992; // 2^53
            let beyond = match (held.as_i64(), held.as_u64()) {
                (Some(value), _) => value.unsigned_abs() > EXACT,
                (None, Some(value)) => value > EXACT,
                // Not an integer at all: a double either way, and it crosses as itself.
                (None, None) => false,
            };
            if beyond {
                return Err(format!(
                    "`{held}` is beyond the largest integer this transport represents exactly \
                     (2^53): it would arrive as a different number"
                ));
            }

            Kind::NumberValue(
                held.as_f64()
                    .ok_or_else(|| format!("`{held}` is not a number this transport carries"))?,
            )
        }
        serde_json::Value::String(held) => Kind::StringValue(held.clone()),
        serde_json::Value::Array(items) => Kind::ListValue(prost_types::ListValue {
            values: items
                .iter()
                .map(proto_value)
                .collect::<Result<Vec<prost_types::Value>, String>>()?,
        }),
        serde_json::Value::Object(held) => Kind::StructValue(prost_types::Struct {
            fields: held
                .iter()
                .map(|(key, value)| Ok((key.clone(), proto_value(value)?)))
                .collect::<Result<_, String>>()?,
        }),
    };

    Ok(prost_types::Value { kind: Some(kind) })
}

pub(crate) fn structure(
    map: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Result<Option<prost_types::Struct>, String> {
    let Some(map) = map else {
        return Ok(None);
    };

    Ok(Some(prost_types::Struct {
        fields: map
            .iter()
            .map(|(key, value)| Ok((key.clone(), proto_value(value)?)))
            .collect::<Result<_, String>>()?,
    }))
}

fn entity_of(
    entity: Option<&permguard_languages::request::EntityBody>,
) -> Result<Option<pdp::Entity>, String> {
    let Some(entity) = entity else {
        return Ok(None);
    };

    Ok(Some(pdp::Entity {
        r#type: text(&entity.kind),
        id: text(&entity.id),
        properties: structure(entity.properties.as_ref())?,
    }))
}

fn action_of(
    action: Option<&permguard_languages::request::ActionBody>,
) -> Result<Option<pdp::Action>, String> {
    let Some(action) = action else {
        return Ok(None);
    };

    Ok(Some(pdp::Action {
        name: text(&action.name),
        properties: structure(action.properties.as_ref())?,
    }))
}

/// The partition inputs, by the name each is addressed to.
///
/// Carried whole, because a transport that dropped one would change which world a partition
/// decides against — the same request answered differently depending on how it travelled.
fn inputs_of(
    inputs: &std::collections::BTreeMap<String, permguard_languages::PartitionInputBody>,
) -> Result<std::collections::HashMap<String, pdp::PartitionInput>, String> {
    inputs
        .iter()
        .map(|(name, held)| {
            Ok((
                name.clone(),
                pdp::PartitionInput {
                    r#type: text(&held.kind),
                    data: held.data.as_ref().map(proto_value).transpose()?,
                },
            ))
        })
        .collect()
}

fn evaluation_of(
    evaluation: &permguard_languages::request::EvaluationBody,
) -> Result<pdp::Evaluation, String> {
    Ok(pdp::Evaluation {
        subject: entity_of(evaluation.subject.as_ref())?,
        resource: entity_of(evaluation.resource.as_ref())?,
        action: action_of(evaluation.action.as_ref())?,
        context: structure(evaluation.context.as_ref())?,
        // Wrapped, so that "states none" survives the trip. An evaluation carrying `{}` replaces
        // the request's defaults with nothing; one carrying no inputs at all inherits them. A
        // bare map cannot tell those apart, and the plane read `{}` as "inherit".
        partition_inputs: match &evaluation.partition_inputs {
            Some(inputs) => Some(pdp::PartitionInputs {
                inputs: inputs_of(inputs)?,
            }),
            None => None,
        },
        request_id: text(&evaluation.request_id),
    })
}

fn semantic_of(request: &permguard_languages::CheckRequest) -> i32 {
    match request
        .options
        .as_ref()
        .and_then(|options| options.evaluations_semantic)
    {
        Some(permguard_languages::Semantic::DenyOnFirstDeny) => {
            pdp::EvaluationsSemantic::DenyOnFirstDeny as i32
        }
        Some(permguard_languages::Semantic::PermitOnFirstPermit) => {
            pdp::EvaluationsSemantic::PermitOnFirstPermit as i32
        }
        Some(permguard_languages::Semantic::ExecuteAll) => {
            pdp::EvaluationsSemantic::ExecuteAll as i32
        }
        // Absent, which the server reads as the default. An unknown spelling never reaches here:
        // the contract's own enum refused it while the payload was being read.
        None => pdp::EvaluationsSemantic::Unspecified as i32,
    }
}

/// The answer, back as the profile's JSON — so a caller cannot tell which
/// transport carried it, and `-o json` prints the server's decision rather
/// than this client's idea of it.
fn answer_of(answer: pdp::EvaluateResponse) -> serde_json::Value {
    use serde_json::{Map, Value};

    let mut object = Map::new();
    object.insert("decision".to_owned(), Value::Bool(answer.decision));
    if !answer.request_id.is_empty() {
        object.insert("request_id".to_owned(), Value::String(answer.request_id));
    }
    if let Some(context) = answer.context {
        object.insert("context".to_owned(), context_of(context));
    }
    if !answer.evaluations.is_empty() {
        object.insert(
            "evaluations".to_owned(),
            Value::Array(
                answer
                    .evaluations
                    .into_iter()
                    .map(|decision| {
                        let mut entry = Map::new();
                        entry.insert("decision".to_owned(), Value::Bool(decision.decision));
                        if !decision.request_id.is_empty() {
                            entry.insert(
                                "request_id".to_owned(),
                                Value::String(decision.request_id),
                            );
                        }
                        if let Some(context) = decision.context {
                            entry.insert("context".to_owned(), context_of(context));
                        }

                        Value::Object(entry)
                    })
                    .collect(),
            ),
        );
    }

    // The signed response, as the REST answer carries it (WP-6.6b).
    if let Some(attestation) = answer.attestation {
        object.insert(
            "attestation".to_owned(),
            serde_json::json!({
                "protected": attestation.protected,
                "payload": attestation.payload,
                "signature": attestation.signature,
            }),
        );
    }

    Value::Object(object)
}

fn context_of(context: pdp::DecisionContext) -> serde_json::Value {
    use serde_json::{Map, Value};

    let mut object = Map::new();
    if !context.id.is_empty() {
        object.insert("id".to_owned(), Value::String(context.id));
    }
    for (name, reason) in [
        ("reason_admin", context.reason_admin),
        ("reason_user", context.reason_user),
    ] {
        if let Some(reason) = reason {
            object.insert(
                name.to_owned(),
                serde_json::json!({"code": reason.code, "message": reason.message}),
            );
        }
    }
    if !context.policies.is_empty() {
        object.insert(
            "policies".to_owned(),
            Value::Array(context.policies.into_iter().map(Value::String).collect()),
        );
    }
    if !context.absent_inputs.is_empty() {
        object.insert(
            "absent_inputs".to_owned(),
            Value::Array(
                context
                    .absent_inputs
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    // The evidence object as the REST answer writes it: every member, `null` where it names
    // nothing (WP-6.6).
    if let Some(evidence) = context.evidence {
        object.insert(
            "evidence".to_owned(),
            serde_json::json!({
                "mode": evidence.mode,
                "status": evidence.status,
                "record_id": evidence.record_id,
                "position": evidence.position.map(|position| serde_json::json!({
                    "host_id": position.host_id,
                    "run": position.run,
                    "sequence": position.sequence,
                })),
            }),
        );
    }

    Value::Object(object)
}

#[cfg(test)]
mod request_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    fn payload(extra: serde_json::Value) -> serde_json::Value {
        let mut body = json!({
            "zone": "z", "ledger": "l",
            "subject": {"type": "User", "id": "alice"},
            "resource": {"type": "Document", "id": "budget"},
            "action": {"name": "read"}
        });
        for (key, value) in extra.as_object().expect("an object") {
            body[key] = value.clone();
        }

        body
    }

    /// proto carries one number type, an IEEE-754 double. Up to 2^53 a double counts one at a
    /// time; past it, it does not — so an integer beyond that cannot cross and come back as
    /// itself. Refused, rather than arriving at a policy as a different number.
    #[test]
    fn an_integer_this_transport_cannot_carry_exactly_is_refused() {
        const EXACT: i64 = 9_007_199_254_740_992; // 2^53

        for carried in [0, 1, -1, 42, EXACT - 1, EXACT, -EXACT] {
            let request = request_of(&payload(json!({"context": {"n": carried}})))
                .unwrap_or_else(|why| panic!("{carried} must cross: {why}"));
            let held = request
                .context
                .expect("a context")
                .fields
                .remove("n")
                .expect("the number");
            match held.kind {
                Some(prost_types::value::Kind::NumberValue(value)) => {
                    assert_eq!(value as i64, carried, "{carried} changed on the way")
                }
                other => panic!("{carried} became {other:?}"),
            }
        }

        for refused in [EXACT + 1, i64::MAX, i64::MIN] {
            let why = request_of(&payload(json!({"context": {"n": refused}})))
                .expect_err("{refused} cannot cross exactly");
            assert!(why.message.contains("2^53"), "{refused}: {}", why.message);
            // The code both servers answer for it (WP-7.5b), never a generic malformed payload.
            assert_eq!(why.code, permguard_core::codes::notp::VALUE_UNREPRESENTABLE);
        }

        // `u64::MAX` and 2^64 are the pair that used to slip through: `u64::MAX as f64` rounds up
        // to 2^64, so a bound written that way accepted 2^64 and the cast saturated it back.
        let big = serde_json::Number::from(u64::MAX);
        let why = request_of(&payload(json!({"context": {"n": big}})))
            .expect_err("u64::MAX cannot cross exactly");
        assert!(why.message.contains("2^53"), "{}", why.message);

        // A fraction is a double either way, and crosses unchanged.
        let request = request_of(&payload(json!({"context": {"n": 1.5}}))).expect("1.5 crosses");
        assert!(request.context.is_some());
    }

    /// A shape the contract does not accept is refused, not emptied. Every one of these is
    /// refused by the HTTP binding, because both bindings now read the payload with the same
    /// type: answering any of them over gRPC against less than the caller said would be the
    /// contract differing by transport.
    #[test]
    fn a_shape_the_contract_does_not_accept_is_refused_rather_than_dropped() {
        for (what, extra) in [
            (
                "a context that is not an object",
                json!({"context": "nope"}),
            ),
            ("a subject that is not an object", json!({"subject": 7})),
            (
                "a name that is not a string",
                json!({"action": {"name": 7}}),
            ),
            ("evaluations that are not a list", json!({"evaluations": 7})),
            // `null` for a list is not an empty list. It used to become one here and was refused
            // over HTTP: serde applies a default to a *missing* field, never to a stated null.
            ("evaluations that are null", json!({"evaluations": null})),
            (
                "an evaluation that is not an object",
                json!({"evaluations": [7]}),
            ),
            ("options that are not an object", json!({"options": 7})),
            (
                "a semantic nobody defined",
                json!({"options": {"evaluations_semantic": "whatever_i_like"}}),
            ),
            (
                "a semantic that is not a string",
                json!({"options": {"evaluations_semantic": 7}}),
            ),
            (
                "properties that are not an object",
                json!({"subject": {"type": "User", "id": "a", "properties": 7}}),
            ),
            (
                "partition inputs that are not an object",
                json!({"partition_inputs": 7}),
            ),
            (
                "a partition input that is not an object",
                json!({"partition_inputs": {"p": 7}}),
            ),
            (
                "a partition input type that is not a string",
                json!({"partition_inputs": {"p": {"type": 7, "data": {}}}}),
            ),
            (
                "partition inputs that are null",
                json!({"partition_inputs": null}),
            ),
        ] {
            assert!(
                request_of(&payload(extra)).is_err(),
                "{what} was carried across as something else"
            );
        }
    }

    /// And what the contract does accept still crosses, whole and by name.
    #[test]
    fn a_request_this_transport_can_represent_crosses_whole() {
        let request = request_of(&payload(json!({
            "context": {"branch": "main"},
            "action": {"name": "release:signoff", "properties": {"risk": "high"}},
            "options": {"evaluations_semantic": "deny_on_first_deny"},
            "partition_inputs": {
                "admin-cedar": {
                    "type": "permguard.cedar.entities.v1",
                    "data": [{"uid": {"type": "Group", "id": "finance"}}]
                },
                "admin-rego": {
                    "type": "permguard.rego.data.v1",
                    "data": {"frozen_services": ["payments-api"]}
                }
            }
        })))
        .expect("every part of this is representable");

        assert_eq!(
            request.evaluations_semantic,
            pdp::EvaluationsSemantic::DenyOnFirstDeny as i32
        );
        let cedar = request
            .partition_inputs
            .get("admin-cedar")
            .expect("the store");
        assert_eq!(cedar.r#type, "permguard.cedar.entities.v1");
        assert!(matches!(
            cedar.data.as_ref().and_then(|held| held.kind.as_ref()),
            Some(prost_types::value::Kind::ListValue(_))
        ));
        let rego = request
            .partition_inputs
            .get("admin-rego")
            .expect("the document");
        assert_eq!(rego.r#type, "permguard.rego.data.v1");
        assert!(matches!(
            rego.data.as_ref().and_then(|held| held.kind.as_ref()),
            Some(prost_types::value::Kind::StructValue(_))
        ));
        assert!(request.action.expect("an action").properties.is_some());
    }

    /// The removed extension is refused **here**, with the contract's own code.
    ///
    /// It has no tag in the generated message, so a conversion that did not check would drop it
    /// and the plane would answer a request it never saw the whole of: `permit`, against an empty
    /// world, over gRPC — and `field_removed` over HTTP. Same field, same code, either way.
    #[test]
    fn the_old_entities_field_does_not_cross_this_transport_either() {
        let refused = request_of(&payload(
            json!({"entities": {"schema": "cedar", "items": []}}),
        ))
        .expect_err("the field is gone");

        assert_eq!(refused.code, "field_removed");
        assert!(
            refused.message.contains("partition_inputs"),
            "{}",
            refused.message
        );

        // And inside a boxcarred evaluation, where a per-transport check would most easily miss it.
        let refused = request_of(&payload(json!({
            "evaluations": [{"request_id": "one", "entities": {"items": []}}]
        })))
        .expect_err("the field is gone there too");
        assert_eq!(refused.code, "field_removed");
    }

    /// Boxcarred evaluations carry their own inputs across, and the three cases stay apart:
    /// stating nothing inherits, stating something replaces, and stating `{}` replaces with
    /// nothing. A bare map on the wire collapsed the last two — see the wrapper in the proto.
    #[test]
    fn a_boxcarred_evaluation_carries_its_own_inputs() {
        let request = request_of(&payload(json!({
            "partition_inputs": {"p": {"type": "permguard.rego.data.v1", "data": {"from": "top"}}},
            "evaluations": [
                {"request_id": "inherits"},
                {"request_id": "its-own",
                 "partition_inputs": {
                     "p": {"type": "permguard.rego.data.v1", "data": {"from": "the evaluation"}}
                 }},
                {"request_id": "states-none", "partition_inputs": {}}
            ]
        })))
        .expect("it is representable");

        assert!(
            request.evaluations[0].partition_inputs.is_none(),
            "an evaluation that states nothing inherits: the defaults are the request's"
        );
        assert_eq!(
            request.evaluations[1]
                .partition_inputs
                .as_ref()
                .expect("its own")
                .inputs
                .get("p")
                .expect("its own")
                .r#type,
            "permguard.rego.data.v1"
        );
        // Present with no entries: it crosses as present, because "replace the defaults with
        // nothing" is a thing a caller can mean and a bare map could not say.
        let states_none = request.evaluations[2]
            .partition_inputs
            .as_ref()
            .expect("stated, and empty");
        assert!(states_none.inputs.is_empty());
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;

    fn with(mut status: tonic::Status, class: &str, code: &str) -> tonic::Status {
        status
            .metadata_mut()
            .insert(GRPC_ERROR_CLASS, class.parse().expect("ascii"));
        status
            .metadata_mut()
            .insert(GRPC_ERROR_CODE, code.parse().expect("ascii"));
        status
    }

    #[test]
    fn test_a_refusal_carries_the_class_and_code_the_server_named() {
        let failure = GrpcAdmin::failure(with(
            tonic::Status::failed_precondition("the zone holds ledgers"),
            "conflict",
            "zone_not_empty",
        ));

        assert_eq!(failure.class, "conflict", "the metadata, not the gRPC code");
        assert_eq!(failure.reason, "zone_not_empty");
        assert!(failure.usage, "a conflict is the caller's to resolve");
    }

    #[test]
    fn test_without_metadata_the_class_and_code_follow_the_grpc_code() {
        let precondition = GrpcAdmin::failure(tonic::Status::failed_precondition("x"));
        assert_eq!(
            (precondition.class.as_str(), precondition.reason.as_str()),
            ("conflict", "conflict")
        );
        let unavailable = GrpcAdmin::failure(tonic::Status::unavailable("x"));
        assert_eq!(unavailable.class, "unavailable");
        assert!(
            !unavailable.usage,
            "an unavailable server is the world's problem"
        );
        let unknown = GrpcAdmin::failure(tonic::Status::unknown("x"));
        assert_eq!(unknown.class, "internal");
    }
}
