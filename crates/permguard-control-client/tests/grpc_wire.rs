// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The gRPC transport against a fake plane on a real socket.
//!
//! Both halves are generated from the same `proto/`, so what this proves is
//! what a wire test can prove and a mock cannot: the client encodes what the
//! contract says, the compression it negotiated is applied and undone, and a
//! `Status` becomes the same refusal vocabulary the HTTP surface produces.
//!
//! The client is blocking (it owns a private runtime); the fake plane runs on
//! a runtime of its own, on another thread — exactly the arrangement the CLI
//! and a sidecar have in production.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::TcpListener;

use permguard_control_client::narrate::Silent;
use permguard_control_client::remote::Remote;
use permguard_control_client::tls::TlsOptions;
use permguard_control_client::v1::control_plane_server::{ControlPlane, ControlPlaneServer};
use permguard_control_client::v1::git_like_store_server::{GitLikeStore, GitLikeStoreServer};
use permguard_control_client::v1::zone_catalog_server::{ZoneCatalog, ZoneCatalogServer};
use permguard_control_client::v1::{self as proto};
use permguard_control_client::{catalog, grpc};
use permguard_notp::{
    CommitPushRequest, FetchObjectsRequest, NegotiatePullRequest, NegotiatePushRequest,
    ObjectClaim, UploadObjectsRequest,
};
use permguard_objects::compress;
use permguard_objects::digest::Digest;
use tonic::{Request, Response, Status};

/// The uploads a fake plane saw: the objects as they arrived, and the
/// encoding the client said it used.
type Uploads = std::sync::Arc<std::sync::Mutex<Vec<(Vec<Vec<u8>>, String)>>>;

/// A plane that answers what the tests need, and remembers the upload it saw.
#[derive(Default)]
struct FakePlane {
    uploaded: Uploads,
}

#[tonic::async_trait]
impl ControlPlane for FakePlane {
    async fn get_info(
        &self,
        _request: Request<proto::GetInfoRequest>,
    ) -> Result<Response<proto::GetInfoResponse>, Status> {
        Ok(Response::new(proto::GetInfoResponse {
            plane: "control-plane".into(),
            product: "Permguard".into(),
            version: "0.1.0".into(),
            commit: "test".into(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<proto::GetHealthRequest>,
    ) -> Result<Response<proto::GetHealthResponse>, Status> {
        Ok(Response::new(proto::GetHealthResponse {
            live: true,
            ready: true,
        }))
    }

    async fn get_server_configuration(
        &self,
        _request: Request<proto::GetServerConfigurationRequest>,
    ) -> Result<Response<proto::GetServerConfigurationResponse>, Status> {
        Ok(Response::new(proto::GetServerConfigurationResponse {
            document_json: r#"{"plane":"control-plane","transports":{"http":true,"grpc":true}}"#
                .into(),
        }))
    }
}

fn zone(id: &str, name: &str) -> proto::Zone {
    proto::Zone {
        id: id.into(),
        name: name.into(),
        created_at: 1,
        updated_at: 1,
    }
}

fn ledger(id: &str, zone_id: &str, name: &str) -> proto::Ledger {
    proto::Ledger {
        id: id.into(),
        zone_id: zone_id.into(),
        name: name.into(),
        created_at: 1,
        updated_at: 1,
        default_ref: "main".into(),
    }
}

#[tonic::async_trait]
impl ZoneCatalog for FakePlane {
    async fn create_zone(
        &self,
        request: Request<proto::CreateZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        Ok(Response::new(proto::ZoneResponse {
            zone: Some(zone("z-new", &request.into_inner().name)),
        }))
    }

    async fn list_zones(
        &self,
        _request: Request<proto::ListZonesRequest>,
    ) -> Result<Response<proto::ListZonesResponse>, Status> {
        Ok(Response::new(proto::ListZonesResponse {
            zones: vec![zone("z-1", "acme"), zone("z-2", "beta")],
        }))
    }

    async fn get_zone(
        &self,
        request: Request<proto::GetZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        let asked = request.into_inner().zone;
        if asked == "missing" {
            return Err(Status::not_found("nothing answers to missing"));
        }
        Ok(Response::new(proto::ZoneResponse {
            zone: Some(zone("z-1", &asked)),
        }))
    }

    async fn rename_zone(
        &self,
        request: Request<proto::RenameZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        Ok(Response::new(proto::ZoneResponse {
            zone: Some(zone("z-1", &request.into_inner().name)),
        }))
    }

    async fn delete_zone(
        &self,
        _request: Request<proto::DeleteZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        Ok(Response::new(proto::ZoneResponse {
            zone: Some(zone("z-1", "acme")),
        }))
    }

    async fn create_ledger(
        &self,
        request: Request<proto::CreateLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        let asked = request.into_inner();
        Ok(Response::new(proto::LedgerResponse {
            ledger: Some(ledger("l-1", &asked.zone, &asked.name)),
        }))
    }

    async fn list_ledgers(
        &self,
        request: Request<proto::ListLedgersRequest>,
    ) -> Result<Response<proto::ListLedgersResponse>, Status> {
        let zone_id = request.into_inner().zone;
        Ok(Response::new(proto::ListLedgersResponse {
            ledgers: vec![
                ledger("l-1", &zone_id, "main-ledger"),
                ledger("l-2", &zone_id, "staging"),
            ],
        }))
    }

    async fn get_ledger(
        &self,
        request: Request<proto::GetLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        let asked = request.into_inner();
        Ok(Response::new(proto::LedgerResponse {
            ledger: Some(ledger("l-1", &asked.zone, &asked.ledger)),
        }))
    }

    async fn rename_ledger(
        &self,
        request: Request<proto::RenameLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        let asked = request.into_inner();
        Ok(Response::new(proto::LedgerResponse {
            ledger: Some(ledger("l-1", &asked.zone, &asked.name)),
        }))
    }

    async fn delete_ledger(
        &self,
        _request: Request<proto::DeleteLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        Ok(Response::new(proto::LedgerResponse {
            ledger: Some(ledger("l-1", "z-1", "main-ledger")),
        }))
    }
}

#[tonic::async_trait]
impl GitLikeStore for FakePlane {
    async fn get_ref(
        &self,
        request: Request<proto::GetRefRequest>,
    ) -> Result<Response<proto::GetRefResponse>, Status> {
        if request.into_inner().r#ref == "feature/none" {
            return Err(Status::not_found("no such ref"));
        }
        Ok(Response::new(proto::GetRefResponse {
            head: Digest::compute(b"head").to_string(),
            counter: 4,
            statement: b"envelope".to_vec(),
        }))
    }

    async fn negotiate_push(
        &self,
        _request: Request<proto::NegotiatePushRequest>,
    ) -> Result<Response<proto::NegotiatePushResponse>, Status> {
        Ok(Response::new(proto::NegotiatePushResponse {
            missing: vec![Digest::compute(b"1").to_string()],
            max_batch_bytes: 8 * 1024 * 1024,
            max_batch_objects: 1000,
            compression: "deflate".into(),
        }))
    }

    async fn upload_objects(
        &self,
        request: Request<proto::UploadObjectsRequest>,
    ) -> Result<Response<proto::UploadObjectsResponse>, Status> {
        let asked = request.into_inner();
        if let Ok(mut seen) = self.uploaded.lock() {
            seen.push((asked.objects.clone(), asked.compression.clone()));
        }
        Ok(Response::new(proto::UploadObjectsResponse {
            received: vec![Digest::compute(b"1").to_string()],
        }))
    }

    async fn commit_push(
        &self,
        _request: Request<proto::CommitPushRequest>,
    ) -> Result<Response<proto::CommitPushResponse>, Status> {
        Err(Status::aborted(
            "the ref moved: negotiate again from the current head",
        ))
    }

    async fn negotiate_pull(
        &self,
        _request: Request<proto::NegotiatePullRequest>,
    ) -> Result<Response<proto::NegotiatePullResponse>, Status> {
        Ok(Response::new(proto::NegotiatePullResponse {
            head: Digest::compute(b"head").to_string(),
            counter: 1,
            statement: b"envelope".to_vec(),
            missing: vec![Digest::compute(b"object").to_string()],
            max_batch_bytes: 8 * 1024 * 1024,
            max_batch_objects: 1000,
            compression: "deflate".into(),
        }))
    }

    async fn fetch_objects(
        &self,
        _request: Request<proto::FetchObjectsRequest>,
    ) -> Result<Response<proto::FetchObjectsResponse>, Status> {
        Ok(Response::new(proto::FetchObjectsResponse {
            objects: vec![compress::deflate(b"object")],
            compression: "deflate".into(),
        }))
    }

    async fn get_key_ring(
        &self,
        _request: Request<proto::GetKeyRingRequest>,
    ) -> Result<Response<proto::GetKeyRingResponse>, Status> {
        Ok(Response::new(proto::GetKeyRingResponse {
            jwks: br#"{"keys":[]}"#.to_vec(),
        }))
    }
}

/// Starts the fake plane on an ephemeral port and answers its address.
fn serve() -> (String, Uploads) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port is free");
    let address = listener.local_addr().expect("the address is known");
    listener
        .set_nonblocking(true)
        .expect("the listener goes non-blocking for tokio");

    let plane = FakePlane::default();
    let uploaded = std::sync::Arc::clone(&plane.uploaded);
    let served = FakePlane {
        uploaded: std::sync::Arc::clone(&uploaded),
    };

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the server runtime starts");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio adopts it");
            let incoming = tokio_stream_of(listener);
            let _ = tonic::transport::Server::builder()
                .add_service(ControlPlaneServer::new(FakePlane::default()))
                .add_service(ZoneCatalogServer::new(FakePlane::default()))
                .add_service(GitLikeStoreServer::new(served))
                .serve_with_incoming(incoming)
                .await;
        });
    });

    (format!("grpc://{address}"), uploaded)
}

/// The accept loop as a stream, so tonic can serve an already-bound socket.
fn tokio_stream_of(
    listener: tokio::net::TcpListener,
) -> impl futures_core::Stream<Item = std::io::Result<tokio::net::TcpStream>> {
    async_stream::stream! {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => yield Ok(stream),
                Err(error) => yield Err(error),
            }
        }
    }
}

fn remote(url: &str) -> grpc::GrpcRemote {
    let remote = grpc::GrpcRemote::connect(url, &TlsOptions::default(), Box::new(Silent))
        .expect("the endpoint parses");
    remote.bind("z-1", "l-1");
    remote
}

#[test]
fn discovery_answers_over_grpc_without_touching_http() {
    let (url, _) = serve();
    remote(&url)
        .verify_discovery()
        .expect("the plane describes itself over its own transport");
}

#[test]
fn the_catalog_answers_over_grpc() {
    let (url, _) = serve();
    let admin = grpc::GrpcAdmin(
        grpc::GrpcChannel::connect(&url, &TlsOptions::default(), Box::new(Silent))
            .expect("the endpoint parses"),
    );

    let zones = admin.list_zones(None, None).expect("zones list");
    assert_eq!(zones.len(), 2);
    assert_eq!(zones[0].name, "acme");

    let created = admin.create_zone("gamma").expect("a zone is created");
    assert_eq!(created.name, "gamma");

    let ledgers = admin.list_ledgers("z-1", None, None).expect("ledgers list");
    assert_eq!(ledgers.len(), 2);
    assert_eq!(ledgers[0].default_ref, "main");

    let renamed = admin
        .rename_ledger("z-1", "l-1", "renamed")
        .expect("a ledger is renamed");
    assert_eq!(renamed.name, "renamed");

    assert!(admin.delete_zone("z-1").is_ok());
    assert!(admin.get_ledger("z-1", "l-1").is_ok());

    // A refusal keeps the server's words and lands in the shared taxonomy.
    let refusal: catalog::Failure = admin.get_zone("missing").expect_err("not found");
    assert_eq!(refusal.class, "not_found");
    assert!(refusal.usage, "a lookup miss is the caller's to fix");
    assert!(refusal.detail.contains("nothing answers"), "{refusal:?}");
}

#[test]
fn resolve_walks_zone_then_ledger_to_their_guids() {
    let (url, _) = serve();
    let resolved = remote(&url)
        .resolve("acme", "main-ledger")
        .expect("names resolve");
    assert_eq!(resolved, ("z-1".to_owned(), "l-1".to_owned()));
}

#[test]
fn an_absent_ref_is_none_and_a_present_one_is_read() {
    let (url, _) = serve();
    let remote = remote(&url);

    let answered = remote
        .get_ref("main")
        .expect("the call answers")
        .expect("the ref exists");
    assert_eq!(answered.counter, 4);
    assert_eq!(answered.statement, b"envelope");

    assert!(remote.get_ref("feature/none").expect("answers").is_none());
}

#[test]
fn a_push_negotiates_compression_and_the_upload_honours_it() {
    let (url, uploaded) = serve();
    let remote = remote(&url);
    let digest = Digest::compute(b"1");

    let negotiated = remote
        .negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: digest.clone(),
            expected_old: None,
            closure: vec![ObjectClaim {
                digest: digest.clone(),
                size: 3,
            }],
        })
        .expect("the negotiation answers");
    assert_eq!(negotiated.missing, vec![digest]);
    assert_eq!(negotiated.compression.as_deref(), Some("deflate"));

    let payload = b"permit(principal, action, resource); // compressible".repeat(4);
    remote
        .upload(&UploadObjectsRequest {
            objects: vec![payload.clone()],
            compression: None,
        })
        .expect("the upload lands");

    let seen = uploaded.lock().expect("the plane recorded");
    let (objects, compression) = seen.first().expect("an upload arrived");
    assert_eq!(
        compression, "deflate",
        "the client echoed what was advertised"
    );
    let inflated = compress::inflate(&objects[0], 1 << 20).expect("it inflates");
    assert_eq!(inflated, payload);
    assert!(objects[0].len() < payload.len());
}

#[test]
fn a_pull_undoes_what_the_plane_compressed() {
    let (url, _) = serve();
    let remote = remote(&url);

    let negotiated = remote
        .negotiate_pull(&NegotiatePullRequest {
            r#ref: "main".into(),
            at: None,
            have: Vec::new(),
        })
        .expect("the negotiation answers");
    assert_eq!(negotiated.counter, 1);

    let fetched = remote
        .fetch(&FetchObjectsRequest {
            digests: vec![Digest::compute(b"object")],
            accept_compression: None,
        })
        .expect("the fetch answers");
    assert_eq!(
        fetched.objects,
        vec![b"object".to_vec()],
        "the caller sees raw canonical bytes"
    );
}

#[test]
fn a_status_becomes_the_same_refusal_vocabulary_http_produces() {
    let (url, _) = serve();
    let error = remote(&url)
        .commit_push(&CommitPushRequest {
            r#ref: "main".into(),
            new_head: Digest::compute(b"new"),
            expected_old: Some(Digest::compute(b"old")),
        })
        .expect_err("the plane aborts the commit");

    // The sentence, then the class and the stable code in parentheses —
    // exactly the shape the HTTP binding produces. That symmetry is the point
    // of the test: a caller that has to tell "no such ref" from "this failed"
    // reads the code, and a transport that spelled refusals its own way would
    // make every such caller wrong on one of the two.
    assert!(error.contains("the ref moved"), "{error}");
    assert!(error.contains("(conflict/"), "{error}");
}

#[test]
fn the_key_ring_comes_over_the_same_channel() {
    let (url, _) = serve();
    let jwks = remote(&url).keyring().expect("the ring is served");
    assert!(String::from_utf8_lossy(&jwks).contains("keys"));
}

#[test]
fn skip_verify_over_grpcs_is_refused_with_the_alternative() {
    let outcome = grpc::GrpcRemote::connect(
        "grpcs://127.0.0.1:1",
        &TlsOptions {
            skip_verify: true,
            ..Default::default()
        },
        Box::new(Silent),
    );
    let error = match outcome {
        Err(error) => error,
        Ok(_) => panic!("there is no insecure TLS mode"),
    };
    assert!(error.contains("--tls-ca-file"), "{error}");
}
