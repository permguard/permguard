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
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::catalog::{Failure as CatalogFailure, Ledger, Zone};
use crate::narrate::Narrator;
use crate::tls::TlsOptions;

/// A connected gRPC endpoint: the channel, the runtime that drives it, and
/// how exchanges are narrated.
pub struct GrpcChannel {
    runtime: tokio::runtime::Runtime,
    channel: Channel,
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
            if let (Some(cert), Some(key)) = (&tls.cert_file, &tls.key_file) {
                let cert = std::fs::read(cert)
                    .map_err(|error| format!("reading {}: {error}", cert.display()))?;
                let key = std::fs::read(key)
                    .map_err(|error| format!("reading {}: {error}", key.display()))?;
                config = config.identity(Identity::from_pem(cert, key));
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
        let channel = {
            let _entered = runtime.enter();
            endpoint.connect_lazy()
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
    pub fn channel(&self) -> Channel {
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
pub const GRPC_ERROR_CLASS: &str = "x-permguard-error-class";
pub const GRPC_ERROR_CODE: &str = "x-permguard-error-code";

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
        tonic::Code::InvalidArgument => ("validation", "invalid_argument"),
        tonic::Code::AlreadyExists => ("conflict", "name_taken"),
        tonic::Code::Aborted | tonic::Code::FailedPrecondition => ("conflict", "conflict"),
        tonic::Code::NotFound => ("not_found", "not_found"),
        tonic::Code::Unavailable => ("unavailable", "unavailable"),
        tonic::Code::ResourceExhausted => ("unavailable", "exhausted"),
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

    fn rename_zone(&self, zone: &str, name: &str) -> Result<Zone, CatalogFailure> {
        GrpcAdmin::rename_zone(self, zone, name)
    }

    fn delete_zone(&self, zone: &str) -> Result<Zone, CatalogFailure> {
        GrpcAdmin::delete_zone(self, zone)
    }

    fn create_ledger(&self, zone: &str, name: &str) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::create_ledger(self, zone, name)
    }

    fn rename_ledger(
        &self,
        zone: &str,
        ledger: &str,
        name: &str,
    ) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::rename_ledger(self, zone, ledger, name)
    }

    fn delete_ledger(&self, zone: &str, ledger: &str) -> Result<Ledger, CatalogFailure> {
        GrpcAdmin::delete_ledger(self, zone, ledger)
    }
}

impl GrpcAdmin {
    fn catalog(&self) -> proto::zone_catalog_client::ZoneCatalogClient<Channel> {
        proto::zone_catalog_client::ZoneCatalogClient::new(self.0.channel.clone())
    }

    fn failure(status: tonic::Status) -> CatalogFailure {
        // The one taxonomy of every surface: the gRPC code maps onto the
        // same classes the HTTP refusals carry, so scripts read one language.
        let (class, usage) = match status.code() {
            tonic::Code::InvalidArgument => ("validation", true),
            tonic::Code::AlreadyExists | tonic::Code::Aborted => ("conflict", true),
            tonic::Code::NotFound => ("not_found", true),
            tonic::Code::Unavailable | tonic::Code::ResourceExhausted => ("unavailable", false),
            _ => ("internal", false),
        };
        // The stable code the server sent as metadata, when it sent one: a
        // script that branches on `reason` should read the same value whichever
        // transport carried the refusal.
        let reason = status
            .metadata()
            .get(GRPC_ERROR_CODE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| classify(status.code()).1.to_owned());

        CatalogFailure {
            class: class.to_owned(),
            reason,
            detail: status.message().to_owned(),
            usage,
        }
    }

    fn zone(answer: proto::ZoneResponse) -> Result<Zone, CatalogFailure> {
        let zone = answer.zone.ok_or_else(|| CatalogFailure {
            class: "internal".to_owned(),
            reason: "decode_failed".to_owned(),
            detail: "the answer carries no zone".to_owned(),
            usage: false,
        })?;
        Ok(Zone {
            id: zone.id,
            name: zone.name,
            created_at: zone.created_at,
            updated_at: zone.updated_at,
        })
    }

    fn ledger(answer: proto::LedgerResponse) -> Result<Ledger, CatalogFailure> {
        let ledger = answer.ledger.ok_or_else(|| CatalogFailure {
            class: "internal".to_owned(),
            reason: "decode_failed".to_owned(),
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
        })
    }

    pub fn create_zone(&self, name: &str) -> Result<Zone, CatalogFailure> {
        let mut client = self.catalog();
        let name = name.to_owned();
        Self::zone(
            self.0
                .call(
                    "CreateZone",
                    client.create_zone(proto::CreateZoneRequest { name }),
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
                client.list_zones(proto::ListZonesRequest {
                    page: page.unwrap_or(0),
                    size: size.unwrap_or(0),
                }),
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

    pub fn rename_zone(&self, zone: &str, name: &str) -> Result<Zone, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, name) = (zone.to_owned(), name.to_owned());
        Self::zone(
            self.0
                .call(
                    "RenameZone",
                    client.rename_zone(proto::RenameZoneRequest { zone, name }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn delete_zone(&self, zone: &str) -> Result<Zone, CatalogFailure> {
        let mut client = self.catalog();
        let zone = zone.to_owned();
        Self::zone(
            self.0
                .call(
                    "DeleteZone",
                    client.delete_zone(proto::DeleteZoneRequest { zone }),
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
                    client.create_ledger(proto::CreateLedgerRequest { zone, name }),
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
                client.list_ledgers(proto::ListLedgersRequest {
                    zone,
                    page: page.unwrap_or(0),
                    size: size.unwrap_or(0),
                }),
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
    ) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, ledger, name) = (zone.to_owned(), ledger.to_owned(), name.to_owned());
        Self::ledger(
            self.0
                .call(
                    "RenameLedger",
                    client.rename_ledger(proto::RenameLedgerRequest { zone, ledger, name }),
                )
                .map_err(Self::failure)?,
        )
    }

    pub fn delete_ledger(&self, zone: &str, ledger: &str) -> Result<Ledger, CatalogFailure> {
        let mut client = self.catalog();
        let (zone, ledger) = (zone.to_owned(), ledger.to_owned());
        Self::ledger(
            self.0
                .call(
                    "DeleteLedger",
                    client.delete_ledger(proto::DeleteLedgerRequest { zone, ledger }),
                )
                .map_err(Self::failure)?,
        )
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

    fn store(&self) -> proto::git_like_store_client::GitLikeStoreClient<Channel> {
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
            expected_old: request
                .expected_old
                .as_ref()
                .map(|digest| digest.to_string())
                .unwrap_or_default(),
            closure: request
                .closure
                .iter()
                .map(|claim| proto::ObjectClaim {
                    digest: claim.digest.to_string(),
                    size: claim.size,
                })
                .collect(),
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
        };
        let answer = self
            .channel
            .call("UploadObjects", client.upload_objects(wire))
            .map_err(|status| refusal(&status))?;
        Ok(UploadObjectsResponse {
            received: parse_digests(answer.received)?,
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
            expected_old: request
                .expected_old
                .as_ref()
                .map(|digest| digest.to_string())
                .unwrap_or_default(),
        };
        let answer = self
            .channel
            .call("CommitPush", client.commit_push(wire))
            .map_err(|status| refusal(&status))?;
        Ok(CommitPushResponse {
            head: parse_digest(&answer.head)?,
            counter: answer.counter,
            statement: answer.statement,
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

    fn client(&self) -> pdp::policy_decision_point_client::PolicyDecisionPointClient<Channel> {
        pdp::policy_decision_point_client::PolicyDecisionPointClient::new(self.0.channel.clone())
    }
}

impl crate::pdp::Pdp for GrpcPdp {
    fn evaluate(&self, payload: &serde_json::Value) -> Result<serde_json::Value, CatalogFailure> {
        let mut client = self.client();
        let request = request_of(payload);
        let answer = self
            .0
            .call("Evaluate", client.evaluate_many(request))
            .map_err(GrpcAdmin::failure)?;

        Ok(answer_of(answer))
    }

    fn metadata(&self) -> Result<serde_json::Value, CatalogFailure> {
        let mut client = self.client();
        let answer = self
            .0
            .call(
                "GetMetadata",
                client.get_metadata(pdp::GetMetadataRequest {}),
            )
            .map_err(GrpcAdmin::failure)?;

        Ok(serde_json::json!({
            "policy_decision_point": answer.policy_decision_point,
            "access_evaluation_endpoint": answer.access_evaluation_endpoint,
            "access_evaluations_endpoint": answer.access_evaluations_endpoint,
            "capabilities": answer.capabilities,
            "permguard_profile": answer.permguard_profile,
            "permguard_store_scope": answer.permguard_store_scope,
        }))
    }
}

/// The payload, as the generated request. Total: every field of the profile
/// has a field here, which is what makes the two transports one contract.
fn request_of(payload: &serde_json::Value) -> pdp::EvaluateRequest {
    use crate::pdp::json::{structure, text};

    pdp::EvaluateRequest {
        zone: text(payload, "zone"),
        ledger: text(payload, "ledger"),
        profile: text(payload, "profile"),
        subject: entity_of(payload.get("subject")),
        resource: entity_of(payload.get("resource")),
        action: action_of(payload.get("action")),
        context: structure(payload.get("context")),
        principal: entity_of(payload.get("principal")),
        entities: entities_of(payload.get("entities")),
        evaluations: payload
            .get("evaluations")
            .and_then(serde_json::Value::as_array)
            .map(|items| items.iter().map(evaluation_of).collect())
            .unwrap_or_default(),
        evaluations_semantic: semantic_of(payload),
        request_id: text(payload, "request_id"),
    }
}

fn entity_of(value: Option<&serde_json::Value>) -> Option<pdp::Entity> {
    use crate::pdp::json::{structure, text};
    let value = value?;

    Some(pdp::Entity {
        r#type: text(value, "type"),
        id: text(value, "id"),
        properties: structure(value.get("properties")),
    })
}

fn action_of(value: Option<&serde_json::Value>) -> Option<pdp::Action> {
    use crate::pdp::json::{structure, text};
    let value = value?;

    Some(pdp::Action {
        name: text(value, "name"),
        properties: structure(value.get("properties")),
    })
}

fn entities_of(value: Option<&serde_json::Value>) -> Option<pdp::Entities> {
    use crate::pdp::json::{proto_value, text};
    let value = value?;

    Some(pdp::Entities {
        schema: text(value, "schema"),
        items: value
            .get("items")
            .and_then(serde_json::Value::as_array)
            .map(|items| items.iter().map(proto_value).collect())
            .unwrap_or_default(),
    })
}

fn evaluation_of(value: &serde_json::Value) -> pdp::Evaluation {
    use crate::pdp::json::{structure, text};

    pdp::Evaluation {
        subject: entity_of(value.get("subject")),
        resource: entity_of(value.get("resource")),
        action: action_of(value.get("action")),
        context: structure(value.get("context")),
        entities: entities_of(value.get("entities")),
        request_id: text(value, "request_id"),
    }
}

fn semantic_of(payload: &serde_json::Value) -> i32 {
    let named = payload
        .get("options")
        .and_then(|options| options.get("evaluations_semantic"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    match named {
        "deny_on_first_deny" => pdp::EvaluationsSemantic::DenyOnFirstDeny as i32,
        "permit_on_first_permit" => pdp::EvaluationsSemantic::PermitOnFirstPermit as i32,
        "execute_all" => pdp::EvaluationsSemantic::ExecuteAll as i32,
        // Absent, which the server reads as the default.
        _ => pdp::EvaluationsSemantic::Unspecified as i32,
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

    Value::Object(object)
}
