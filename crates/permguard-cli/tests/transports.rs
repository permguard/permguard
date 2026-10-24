// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every network command over `https` and over `grpcs`, against one fake plane serving both on
//! one TLS port (TC-1, owner decisions of 2026-10-10).
//!
//! The plane answers the same data on both transports: JSON over REST, the generated messages
//! over gRPC. Each command runs twice, once per scheme, and its report and exit status must be the
//! same once the endpoint itself is set aside. The operator's token travels as a bearer on every
//! request of both transports, and never appears in what the command prints.
//!
//! Pull, push and clone are covered at the client by the wire tests of
//! `permguard-control-client`, the Control Plane's NOTP routers being private (owner decision).
//! The Host facade of the client is run here against the real Host API on its own listener.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::routing::{get, post};
use permguard_control_client::pdp_v1 as pdp;
use permguard_control_client::pdp_v1::policy_decision_point_server::{
    PolicyDecisionPoint, PolicyDecisionPointServer,
};
use permguard_control_client::v1 as proto;
use permguard_control_client::v1::control_plane_server::{ControlPlane, ControlPlaneServer};
use permguard_control_client::v1::decision_log_server::{DecisionLog, DecisionLogServer};
use permguard_control_client::v1::event_log_server::{EventLog, EventLogServer};
use permguard_control_client::v1::zone_catalog_server::{ZoneCatalog, ZoneCatalogServer};
use permguard_core::TlsSettings;
use serde_json::Value;
use tonic::{Request, Response, Status};

const TOKEN: &str = "op-token-0123456789abcdef";
const DECISION: &str = r#"{"kind":"decision","seq":1,"id":"d-1","at":"2026-01-01T00:00:00Z"}"#;
const EVENT: &str = r#"{"kind":"request","seq":1,"id":"e-1","at":"2026-01-01T00:00:00Z"}"#;
const DISCOVERY: &str = r#"{"plane":"control-plane","transports":{"http":true,"grpc":true}}"#;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-cli-transports-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// A certificate authority and the certificate of `localhost` it signed, written under `dir`.
struct Pki {
    authority: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
    /// An operator's client certificate the same authority signed, and its key's PEM.
    client_certificate: PathBuf,
    client_key_pem: String,
}

fn pki(dir: &Path) -> Pki {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("parameters");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let authority_key = rcgen::KeyPair::generate().expect("a key");
    let authority = params.self_signed(&authority_key).expect("self-signed");
    let issuer = rcgen::Issuer::from_params(&params, &authority_key);
    let server = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("parameters");
    let server_key = rcgen::KeyPair::generate().expect("a key");
    let signed = server.signed_by(&server_key, &issuer).expect("signed");
    let write = |name: &str, text: &str| {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("written");
        path
    };
    let client = rcgen::CertificateParams::new(vec!["operator".to_owned()]).expect("parameters");
    let client_key = rcgen::KeyPair::generate().expect("a key");
    let client_signed = client.signed_by(&client_key, &issuer).expect("signed");
    Pki {
        authority: write("ca.pem", &authority.pem()),
        certificate: write("server.pem", &signed.pem()),
        key: write("server.key", &server_key.serialize_pem()),
        client_certificate: write("client.pem", &client_signed.pem()),
        client_key_pem: client_key.serialize_pem(),
    }
}

/// Every `authorization` value the plane received, over either transport.
type Seen = Arc<Mutex<Vec<Option<String>>>>;

/// Serves `router` over TLS on a loopback port, on a runtime of its own; the address it bound.
fn serve(router: Router, pki: &Pki, seen: Seen) -> SocketAddr {
    serve_with(
        router,
        TlsSettings::new(&pki.certificate, &pki.key),
        seen,
        Arc::new(Bearers),
    )
}

/// Serves `router` under `settings`, `authenticator` deciding who each bearer is.
fn serve_with(
    router: Router,
    settings: TlsSettings,
    seen: Seen,
    authenticator: Arc<dyn permguard_core::authz::Authenticator>,
) -> SocketAddr {
    let (bound, address) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the plane's runtime starts");
        runtime.block_on(async move {
            let recorded = router.layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let seen = Arc::clone(&seen);
                    async move {
                        seen.lock().unwrap().push(
                            request
                                .headers()
                                .get("authorization")
                                .and_then(|value| value.to_str().ok())
                                .map(ToOwned::to_owned),
                        );
                        next.run(request).await
                    }
                },
            ));
            let surface =
                permguard_transport::Surface::listener("fake-plane", "127.0.0.1:0", recorded)
                    .tls(Some(&settings))
                    .authenticator(Some(authenticator))
                    .start()
                    .await
                    .expect("the plane binds");
            bound.send(surface.address()).expect("the test waits");
            std::future::pending::<()>().await;
            drop(surface);
        });
    });
    address.recv().expect("the plane started")
}

/// The fake plane: the same answers over REST and over gRPC.
#[derive(Clone, Default)]
struct Plane;

fn zone(id: &str, name: &str) -> proto::Zone {
    proto::Zone {
        id: id.into(),
        name: name.into(),
        created_at: 1,
        updated_at: 1,
        revision: 1,
    }
}

fn ledger() -> proto::Ledger {
    proto::Ledger {
        serving_members: Vec::new(),
        id: "l-1".into(),
        zone_id: "z-1".into(),
        name: "main-ledger".into(),
        created_at: 1,
        updated_at: 1,
        default_ref: "main".into(),
        revision: 1,
        state: "active".into(),
    }
}

fn rest() -> Router {
    let zones = r#"[{"id":"z-1","name":"acme","created_at":1,"updated_at":1,"revision":1},{"id":"z-2","name":"beta","created_at":1,"updated_at":1,"revision":1}]"#;
    let ledgers = r#"[{"id":"l-1","zone_id":"z-1","name":"main-ledger","default_ref":"main","created_at":1,"updated_at":1,"revision":1,"state":"active"}]"#;
    let json = |body: String| {
        move || {
            let body = body.clone();
            async move { ([("content-type", "application/json")], body) }
        }
    };
    let page = |record: &str| {
        format!(r#"{{"records":[{record}],"next":"n-1","more":false,"high_watermark":"h-1"}}"#)
    };
    Router::new()
        .route("/v1/zones", get(json(zones.to_owned())))
        .route("/v1/zones/acme/ledgers", get(json(ledgers.to_owned())))
        .route(
            "/v1/zones/acme/ledgers/main-ledger/export",
            post(|| async {
                use base64::Engine as _;
                let answer = exported();
                let body = serde_json::json!({
                    "archive": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&answer.archive),
                    "zone_id": answer.zone_id,
                    "bundle_digest": answer.bundle_digest,
                    "bundle_bytes": answer.bundle_bytes,
                    "exported_at": answer.exported_at,
                    "ledgers": [{"id": "l-1", "name": "main-ledger", "refs": 1, "objects": 4, "statements": 1}],
                });
                ([("content-type", "application/json")], body.to_string())
            }),
        )
        .route(
            "/.well-known/server-configuration",
            get(json(DISCOVERY.to_owned())),
        )
        .route(
            "/version",
            get(json(
                r#"{"plane":"control-plane","product":"Permguard","version":"0.1.0","commit":"abc"}"#
                    .to_owned(),
            )),
        )
        .route("/health", get(json(r#"{"live":true,"ready":true}"#.to_owned())))
        .route(
            "/access/v1/evaluation",
            post(json(
                r#"{"decision":true,"context":{"id":"01","policies":["readers"]}}"#.to_owned(),
            )),
        )
        .route(
            "/zones/acme/ledgers/main-ledger/decisions/v1/records",
            get(json(page(DECISION))),
        )
        .route(
            "/v1/zones/acme/ledgers/main-ledger/events/v1alpha1/records",
            get(json(page(EVENT))),
        )
        .route(
            "/v1/zones/z/ledgers/l/notp/push/negotiate",
            post(|| async {
                (
                    [("content-type", "application/cbor")],
                    permguard_notp::NegotiatePushResponse {
                        missing: Vec::new(),
                        max_batch_bytes: 8 * 1024 * 1024,
                        max_batch_objects: 1000,
                        compression: None,
                        transfer_id: [0x7a; 16],
                        reservation: 3,
                        expiry: 1_800_000_000,
                    }
                    .encode()
                    .expect("it encodes"),
                )
            }),
        )
}

fn grpc() -> Router {
    let mut routes = tonic::service::RoutesBuilder::default();
    routes.add_service(ControlPlaneServer::new(Plane));
    routes.add_service(pdp::data_plane_server::DataPlaneServer::new(Plane));
    routes.add_service(ZoneCatalogServer::new(Plane));
    routes.add_service(PolicyDecisionPointServer::new(Plane));
    routes.add_service(DecisionLogServer::new(Plane));
    routes.add_service(EventLogServer::new(Plane));
    routes.routes().into_axum_router()
}

#[tonic::async_trait]
impl ControlPlane for Plane {
    async fn get_info(
        &self,
        _request: Request<proto::GetInfoRequest>,
    ) -> Result<Response<proto::GetInfoResponse>, Status> {
        Ok(Response::new(proto::GetInfoResponse {
            plane: "control-plane".into(),
            product: "Permguard".into(),
            version: "0.1.0".into(),
            commit: "abc".into(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<proto::GetHealthRequest>,
    ) -> Result<Response<proto::GetHealthResponse>, Status> {
        Ok(Response::new(proto::GetHealthResponse {
            live: true,
            ready: true,
            ..Default::default()
        }))
    }

    async fn get_server_configuration(
        &self,
        _request: Request<proto::GetServerConfigurationRequest>,
    ) -> Result<Response<proto::GetServerConfigurationResponse>, Status> {
        Ok(Response::new(proto::GetServerConfigurationResponse {
            document_json: DISCOVERY.into(),
        }))
    }
}

/// The data plane's own identity and health service: the same answers as `/version` and
/// `/health`, the fake being one process.
#[tonic::async_trait]
impl pdp::data_plane_server::DataPlane for Plane {
    async fn get_info(
        &self,
        _request: Request<pdp::GetInfoRequest>,
    ) -> Result<Response<pdp::GetInfoResponse>, Status> {
        Ok(Response::new(pdp::GetInfoResponse {
            plane: "control-plane".into(),
            product: "Permguard".into(),
            version: "0.1.0".into(),
            commit: "abc".into(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<pdp::GetHealthRequest>,
    ) -> Result<Response<pdp::GetHealthResponse>, Status> {
        Ok(Response::new(pdp::GetHealthResponse {
            live: true,
            ready: true,
            ..Default::default()
        }))
    }
}

/// What the fake does not serve.
fn unserved<T>() -> Result<Response<T>, Status> {
    Err(Status::unimplemented("the fake plane does not serve this"))
}

#[tonic::async_trait]
impl ZoneCatalog for Plane {
    async fn create_zone(
        &self,
        _request: Request<proto::CreateZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        unserved()
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
        _request: Request<proto::GetZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        unserved()
    }

    async fn rename_zone(
        &self,
        _request: Request<proto::RenameZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        unserved()
    }

    async fn delete_zone(
        &self,
        _request: Request<proto::DeleteZoneRequest>,
    ) -> Result<Response<proto::ZoneResponse>, Status> {
        unserved()
    }

    async fn create_ledger(
        &self,
        _request: Request<proto::CreateLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        unserved()
    }

    async fn list_ledgers(
        &self,
        _request: Request<proto::ListLedgersRequest>,
    ) -> Result<Response<proto::ListLedgersResponse>, Status> {
        Ok(Response::new(proto::ListLedgersResponse {
            ledgers: vec![ledger()],
        }))
    }

    async fn get_ledger(
        &self,
        _request: Request<proto::GetLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        unserved()
    }

    async fn rename_ledger(
        &self,
        _request: Request<proto::RenameLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        unserved()
    }

    async fn delete_ledger(
        &self,
        _request: Request<proto::DeleteLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        unserved()
    }

    async fn archive_ledger(
        &self,
        _request: Request<proto::ArchiveLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        unserved()
    }

    async fn restore_ledger(
        &self,
        _request: Request<proto::RestoreLedgerRequest>,
    ) -> Result<Response<proto::LedgerResponse>, Status> {
        unserved()
    }

    async fn export_ledger(
        &self,
        request: Request<proto::ExportLedgerRequest>,
    ) -> Result<Response<proto::ExportResponse>, Status> {
        let request = request.into_inner();
        assert_eq!(
            (request.zone.as_str(), request.ledger.as_str()),
            ("acme", "main-ledger")
        );
        Ok(Response::new(exported()))
    }

    async fn export_zone(
        &self,
        _request: Request<proto::ExportZoneRequest>,
    ) -> Result<Response<proto::ExportResponse>, Status> {
        unserved()
    }
}

/// What the fake answers an export: an archive of a few bytes, and what it binds.
fn exported() -> proto::ExportResponse {
    proto::ExportResponse {
        archive: ARCHIVE.to_vec(),
        zone_id: "z-1".to_owned(),
        bundle_digest: format!("sha256:{}", "ab".repeat(32)),
        bundle_bytes: 3,
        exported_at: 1_800_000_000,
        ledgers: vec![proto::ExportedLedger {
            id: "l-1".to_owned(),
            name: "main-ledger".to_owned(),
            refs: 1,
            objects: 4,
            statements: 1,
        }],
    }
}

/// The archive bytes the fake answers.
const ARCHIVE: &[u8] = &[0xa2, 0x01, 0x40, 0x02, 0x40, 0xff];

#[tonic::async_trait]
impl PolicyDecisionPoint for Plane {
    async fn evaluate(
        &self,
        _request: Request<pdp::EvaluateRequest>,
    ) -> Result<Response<pdp::EvaluateResponse>, Status> {
        Ok(Response::new(pdp::EvaluateResponse {
            decision: true,
            context: Some(pdp::DecisionContext {
                id: "01".into(),
                policies: vec!["readers".into()],
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    async fn evaluate_many(
        &self,
        request: Request<pdp::EvaluateRequest>,
    ) -> Result<Response<pdp::EvaluateResponse>, Status> {
        self.evaluate(request).await
    }

    async fn get_configuration(
        &self,
        _request: Request<pdp::GetConfigurationRequest>,
    ) -> Result<Response<pdp::GetConfigurationResponse>, Status> {
        unserved()
    }
}

#[tonic::async_trait]
impl DecisionLog for Plane {
    async fn ship(
        &self,
        _request: Request<proto::ShipRequest>,
    ) -> Result<Response<proto::ShipResponse>, Status> {
        unserved()
    }

    async fn read(
        &self,
        _request: Request<proto::ReadRequest>,
    ) -> Result<Response<proto::ReadResponse>, Status> {
        Ok(Response::new(proto::ReadResponse {
            records: vec![DECISION.as_bytes().to_vec()],
            next: "n-1".into(),
            more: false,
            high_watermark: "h-1".into(),
            ..Default::default()
        }))
    }

    async fn get_signers(
        &self,
        _request: Request<proto::GetDecisionSignersRequest>,
    ) -> Result<Response<proto::GetDecisionSignersResponse>, Status> {
        unserved()
    }
}

#[tonic::async_trait]
impl EventLog for Plane {
    async fn ingest_batch(
        &self,
        _request: Request<proto::IngestBatchRequest>,
    ) -> Result<Response<proto::IngestBatchResponse>, Status> {
        unserved()
    }

    async fn list_records(
        &self,
        _request: Request<proto::ListRecordsRequest>,
    ) -> Result<Response<proto::ListRecordsResponse>, Status> {
        Ok(Response::new(proto::ListRecordsResponse {
            records: vec![EVENT.as_bytes().to_vec()],
            next: "n-1".into(),
            more: false,
            high_watermark: "h-1".into(),
            ..Default::default()
        }))
    }

    async fn get_record(
        &self,
        _request: Request<proto::GetRecordRequest>,
    ) -> Result<Response<proto::GetRecordResponse>, Status> {
        unserved()
    }

    async fn get_event_configuration(
        &self,
        _request: Request<proto::GetEventConfigurationRequest>,
    ) -> Result<Response<proto::GetEventConfigurationResponse>, Status> {
        unserved()
    }

    async fn get_signers(
        &self,
        _request: Request<proto::GetSignersRequest>,
    ) -> Result<Response<proto::GetSignersResponse>, Status> {
        unserved()
    }
}

/// The CLI, without the `PERMGUARD_*` variables of the shell running the tests.
fn cli(workdir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(workdir)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .args(args)
        .output()
        .expect("the CLI runs")
}

/// A token file readable by its owner only.
fn token_file(dir: &Path) -> PathBuf {
    let path = dir.join("token");
    let mut file = std::fs::File::create(&path).expect("created");
    writeln!(file, "{TOKEN}").expect("written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    path
}

/// The report with what differs by nature set aside: the endpoint, and the instants.
fn normalized(text: &str, endpoint: &str) -> Value {
    let mut value: Value = serde_json::from_str(&text.replace(endpoint, "ENDPOINT"))
        .unwrap_or_else(|_| Value::String(text.replace(endpoint, "ENDPOINT")));
    fn strip(value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.remove("latency_ms");
                map.remove("checked_at");
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut value);
    value
}

/// A workspace with one Cedar policy and one case, for `test --remote`.
fn workspace(dir: &Path) {
    std::fs::create_dir_all(dir.join("cedar")).unwrap();
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    std::fs::create_dir_all(dir.join("requests")).unwrap();
    std::fs::write(
        dir.join("cedar/readers.cedar"),
        "@alias(\"readers\")\npermit (principal, action == Action::\"read\", resource);\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("requests/read.json"),
        r#"{"subject":{"type":"User","id":"alice"},"action":{"name":"read"},
            "resource":{"type":"Document","id":"budget"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: alice reads\n  request: ../requests/read.json\n  expect: { decision: permit, policies: [readers] }\n",
    )
    .unwrap();
    let init = cli(dir, &["init", "remote-cases"]);
    assert!(init.status.success(), "{init:?}");
}

#[test]
fn every_network_command_answers_the_same_over_https_and_grpcs() {
    let dir = scratch("parity");
    let pki = pki(&dir);
    let seen = Seen::default();
    let address = serve(rest().merge(grpc()), &pki, Arc::clone(&seen));
    let token = token_file(&dir);
    std::fs::write(
        dir.join("check.json"),
        r#"{"subject":{"type":"User","id":"alice"},"action":{"name":"read"},"resource":{"type":"Document","id":"budget"}}"#,
    )
    .unwrap();
    let cases = dir.join("cases");
    std::fs::create_dir_all(&cases).unwrap();
    workspace(&cases);
    let remote = dir.join("remote-ws");
    std::fs::create_dir_all(&remote).unwrap();
    assert!(cli(&remote, &["init", "remote-ws"]).status.success());

    let port = address.port();
    let commands: Vec<(&str, &Path, Vec<String>)> = vec![
        (
            "zones list",
            &dir,
            vec!["zones".into(), "list".into(), "--control-endpoint".into()],
        ),
        (
            "ledgers list",
            &dir,
            vec![
                "ledgers".into(),
                "list".into(),
                "--zone".into(),
                "acme".into(),
                "--control-endpoint".into(),
            ],
        ),
        (
            "check",
            &dir,
            vec![
                "check".into(),
                "--file".into(),
                "check.json".into(),
                "--zone".into(),
                "acme".into(),
                "--ledger".into(),
                "main-ledger".into(),
                "--data-endpoint".into(),
            ],
        ),
        (
            "test --remote",
            &cases,
            vec![
                "test".into(),
                "--remote".into(),
                "--zone".into(),
                "acme".into(),
                "--ledger".into(),
                "main-ledger".into(),
                "--data-endpoint".into(),
            ],
        ),
        (
            "decisions list",
            &dir,
            vec![
                "decisions".into(),
                "list".into(),
                "--zone".into(),
                "acme".into(),
                "--ledger".into(),
                "main-ledger".into(),
                "--control-endpoint".into(),
            ],
        ),
        (
            "events list",
            &dir,
            vec![
                "events".into(),
                "list".into(),
                "--zone".into(),
                "acme".into(),
                "--ledger".into(),
                "main-ledger".into(),
                "--control-endpoint".into(),
            ],
        ),
        (
            "remote add",
            &remote,
            vec!["remote".into(), "add".into(), "origin".into()],
        ),
        (
            "inspect",
            &dir,
            vec!["inspect".into(), "--control-endpoint".into()],
        ),
    ];
    for (name, workdir, args) in commands {
        let mut answers = Vec::new();
        for scheme in ["https", "grpcs"] {
            let endpoint = format!("{scheme}://localhost:{port}");
            let mut full: Vec<String> = vec![
                "-o".into(),
                "json".into(),
                "--tls-ca-file".into(),
                pki.authority.display().to_string(),
                "--token-file".into(),
                token.display().to_string(),
            ];
            full.extend(args.iter().cloned());
            full.push(endpoint.clone());
            if name == "inspect" {
                full.push("--data-endpoint".into());
                full.push(endpoint.clone());
            }
            if name == "remote add" {
                // A remote is remembered once: the second scheme replaces the first.
                let _ = cli(workdir, &["remote", "remove", "origin"]);
            }
            let refs: Vec<&str> = full.iter().map(String::as_str).collect();
            let before = seen.lock().unwrap().len();
            let output = cli(workdir, &refs);
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                !stdout.contains(TOKEN) && !stderr.contains(TOKEN),
                "{name} over {scheme} printed the token"
            );
            let received: Vec<Option<String>> = seen.lock().unwrap()[before..].to_vec();
            // `inspect` asks both planes, each at least its identity: two requests or more.
            let least = if name == "inspect" { 2 } else { 1 };
            assert!(
                received.len() >= least,
                "{name} over {scheme} reached the plane {} times: {stderr}",
                received.len()
            );
            assert!(
                received
                    .iter()
                    .all(|value| value.as_deref() == Some(&format!("Bearer {TOKEN}"))),
                "{name} over {scheme} sent {received:?}"
            );
            answers.push((output.status.code(), normalized(&stdout, &endpoint), stderr));
        }
        let (https, grpcs) = (&answers[0], &answers[1]);
        assert_eq!(
            https.0, grpcs.0,
            "{name}: exits differ: {} / {}",
            https.2, grpcs.2
        );
        assert_eq!(https.1, grpcs.1, "{name}: reports differ");
        // The fake cites a policy by a name the workspace does not hold, so `test --remote` is a
        // completed negative check on both transports alike: exit 2.
        let expected = if name == "test --remote" { 2 } else { 0 };
        assert_eq!(https.0, Some(expected), "{name}: {} {}", https.2, https.1);
    }
}

/// WP-7.10: `ledgers export` writes the archive the plane answers, byte for byte, to a new file
/// only its owner reads, and reports what it binds alike on both transports; a file already there
/// is refused.
#[test]
fn a_ledger_export_writes_the_archive_on_both_transports() {
    let dir = scratch("export");
    let pki = pki(&dir);
    let address = serve(rest().merge(grpc()), &pki, Seen::default());
    let mut reports = Vec::new();
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://localhost:{}", address.port());
        let file = dir.join(format!("{scheme}.export"));
        let args = [
            "-o",
            "json",
            "--tls-ca-file",
            &pki.authority.display().to_string(),
            "ledgers",
            "export",
            "--zone",
            "acme",
            "main-ledger",
            "--out",
            &file.display().to_string(),
            "--control-endpoint",
            &endpoint,
        ];
        let output = cli(&dir, &args);
        assert!(output.status.success(), "{scheme}: {output:?}");
        assert_eq!(std::fs::read(&file).expect("written"), ARCHIVE, "{scheme}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file)
                .expect("written")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{scheme}: the owner's alone");
        }
        let mut report: Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(report["ledgers"][0]["objects"], 4, "{scheme}");
        report["path"] = Value::Null;
        reports.push(report);
        let again = cli(&dir, &args);
        assert!(
            !again.status.success(),
            "{scheme}: an existing file is kept"
        );
        assert_eq!(std::fs::read(&file).expect("kept"), ARCHIVE);
    }
    assert_eq!(reports[0], reports[1], "the transports report alike");
}

#[test]
fn an_unreachable_single_target_exits_sixty_nine() {
    let dir = scratch("unreachable");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://127.0.0.1:{port}");
        let output = cli(&dir, &["zones", "list", "--control-endpoint", &endpoint]);
        assert_eq!(output.status.code(), Some(69), "{scheme}: {output:?}");
    }
}

#[test]
fn the_token_travels_as_a_bearer_on_both_transports_and_never_in_a_report() {
    // The verbose trace names the token file, never its content.
    let dir = scratch("token");
    let pki = pki(&dir);
    let seen = Seen::default();
    let address = serve(rest().merge(grpc()), &pki, Arc::clone(&seen));
    let token = token_file(&dir);
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://localhost:{}", address.port());
        let output = cli(
            &dir,
            &[
                "-v",
                "--tls-ca-file",
                &pki.authority.display().to_string(),
                "--token-file",
                &token.display().to_string(),
                "zones",
                "list",
                "--control-endpoint",
                &endpoint,
            ],
        );
        assert!(output.status.success(), "{output:?}");
        let printed = String::from_utf8_lossy(&output.stdout).into_owned()
            + String::from_utf8_lossy(&output.stderr).as_ref();
        assert!(printed.contains(&token.display().to_string()), "{printed}");
        assert!(!printed.contains(TOKEN), "{printed}");
    }
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|value| value.as_deref() == Some(&format!("Bearer {TOKEN}")))
    );
}

/// The Host facade of the client, against the real Host API on its own listener: status, identity
/// and grants read the same over `https` and `grpcs`; an absent membership service refuses alike.
#[test]
fn the_host_facade_reads_the_same_over_https_and_grpcs() {
    use permguard_control_client::host;
    use permguard_control_client::narrate::Silent;
    use permguard_control_client::tls::{Credential, TlsOptions};

    let dir = scratch("host");
    let pki = pki(&dir);
    let address = host_listener(&dir, &pki);
    let admin_token = dir.join("admin-token");
    std::fs::write(&admin_token, ADMIN).expect("the administrator token writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&admin_token, std::fs::Permissions::from_mode(0o600))
            .expect("the token is private");
    }
    let tls = |token: Option<&str>| TlsOptions {
        ca_file: Some(pki.authority.clone()),
        token: token.map(|token| Credential::new(token.as_bytes().to_vec())),
        ..TlsOptions::default()
    };
    let mut statuses = Vec::new();
    let mut identities = Vec::new();
    let mut grants = Vec::new();
    let mut members_refused = Vec::new();
    let mut verify_refused = Vec::new();
    let mut cli_identities = Vec::new();
    let mut cli_grants = Vec::new();
    for scheme in ["https", "grpcs"] {
        let url = format!("{scheme}://localhost:{}", address.port());
        let client = host::client(&url, &tls(Some(ADMIN)), Box::new(Silent)).expect("a client");
        statuses.push(client.status().expect("the status"));
        identities.push(client.identity().expect("the identity"));
        grants.push(client.grants(None, None).expect("the grants"));
        members_refused.push(
            client
                .members(None)
                .expect_err("this fixture composes no membership service"),
        );
        verify_refused.push(
            client
                .verify_member(
                    "0198f2aa-0000-7000-8000-000000000002",
                    &permguard_host::api::members::VerifyMember {
                        request_id: "transport-verify".to_owned(),
                    },
                )
                .expect_err("this fixture composes no membership service"),
        );
        // Nobody: refused the same way on both.
        let anonymous = host::client(&url, &tls(None), Box::new(Silent)).expect("a client");
        let refused = anonymous.status().expect_err("nobody reads the status");
        assert_eq!(refused.reason, "unauthenticated", "{scheme}: {refused:?}");

        for (command, answers) in [
            (["host", "identity", "show"].as_slice(), &mut cli_identities),
            (["host", "grants", "list"].as_slice(), &mut cli_grants),
        ] {
            let output = cli(
                &dir,
                &[
                    "-o",
                    "json",
                    "--host-endpoint",
                    &url,
                    "--tls-ca-file",
                    pki.authority.to_str().expect("a UTF-8 path"),
                    "--token-file",
                    admin_token.to_str().expect("a UTF-8 path"),
                    command[0],
                    command[1],
                    command[2],
                ],
            );
            assert!(output.status.success(), "{scheme}: {output:?}");
            answers.push(
                serde_json::from_slice::<Value>(&output.stdout).expect("the CLI answers JSON"),
            );
        }
    }
    assert_eq!(statuses[0], statuses[1]);
    assert_eq!(identities[0], identities[1]);
    assert_eq!(grants[0], grants[1]);
    assert_eq!(members_refused[0].reason, members_refused[1].reason);
    assert_eq!(verify_refused[0].reason, verify_refused[1].reason);
    assert_eq!(cli_identities[0], cli_identities[1]);
    for shown in &cli_identities {
        assert!(shown["host_id"].as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(shown["epoch"], 1);
        assert!(
            shown["fingerprint"]
                .as_str()
                .is_some_and(|fingerprint| fingerprint.starts_with("sha256:"))
        );
    }
    assert_eq!(cli_grants[0], cli_grants[1]);
    assert!(!identities[0].document.is_empty());
}

const ADMIN: &str = "spiffe://acme/operator";

/// `Bearer <name>` is the principal `<name>`; nothing else authenticates.
struct Bearers;

impl permguard_core::authz::Authenticator for Bearers {
    fn authenticate(
        &self,
        _peer: Option<&permguard_core::PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<permguard_core::authz::Actor, permguard_core::AccessDenial> {
        use permguard_core::authz::{Actor, ActorContext, Credential, Principal};
        Ok(match bearer {
            Some(name) => Actor::Authenticated(ActorContext::new(
                Principal::new(name).expect("a principal"),
                Credential::Oidc,
                None,
            )),
            None => Actor::Anonymous,
        })
    }
}

/// A Host API over its own volume, its one administrator holding every operation, served on a
/// TLS listener with [`Bearers`].
fn host_listener(dir: &Path, pki: &Pki) -> SocketAddr {
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::authz::{Principal, Resource, Selector, operations};
    use permguard_host::api::{Assurance, Composition, Effective, HostApi, Replay};
    use permguard_host::authz::{Authorization, GrantStore, Issue};
    use permguard_host::storage::volume::Volume;

    let volume =
        Volume::claim(&dir.join("volume"), AssuranceProfile::Development).expect("claimed");
    let (store, _) = GrantStore::open(&volume).expect("the grant store");
    let mutations = Arc::new(
        permguard_host::operations::mutation::Mutations::open_offline(&volume, "test")
            .expect("the mutation journal"),
    );
    let identity = Arc::new(
        permguard_host::identity::Identity::provision(
            &volume,
            Arc::new(permguard_host::keys::FileKeyProvider::new(
                permguard_host::identity::directories(&volume)
                    .expect("the identity directory")
                    .1,
            )),
            permguard_host::identity::Suite::Ed25519Sha256V1,
            permguard_host::authz::store::now(),
            permguard_host::authz::store::now() * 1000,
        )
        .expect("provisioned"),
    );
    permguard_host::operations::grants::issue(
        &mutations,
        &store,
        permguard_host::operations::journal::Initiator::System("test".to_owned()),
        Issue {
            principal: Principal::new(ADMIN).expect("a principal"),
            operations: operations::ALL.iter().map(|op| (*op).to_owned()).collect(),
            selector: Selector::under(Resource::host()),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            issued_by: "test".to_owned(),
            expires_at: None,
        },
        permguard_host::authz::store::now(),
    )
    .expect("the administrator");
    let (replay, _) =
        Replay::open(&volume, permguard_host::authz::store::now()).expect("the replay");
    let api = Arc::new(HostApi::new(Composition {
        authorization: Arc::new(Authorization::new(Arc::clone(&store), &[])),
        store: Some(store),
        replay,
        keys: Arc::new(permguard_host::keys::registry::Registry::new(
            Some(Arc::clone(&identity)),
            Vec::new(),
        )),
        health: permguard_core::Health::new(),
        assurance: Assurance::of(
            &permguard_core::assurance::Assurance::new(AssuranceProfile::Development, [])
                .report(&[]),
        ),
        effective: Effective {
            revision: 0,
            settings: Vec::new(),
        },
        trail: "test".to_owned(),
        mutations: Some(mutations),
        identity: Some(identity),
        time: Arc::new(permguard_host::time::TimeGuard::system(
            std::time::Duration::from_secs(30),
        )),
        peer_sessions: permguard_host::api::sessions::PeerSessions::none(),
        listeners: vec![permguard_core::ListenerReport::of(
            "host-api",
            permguard_core::ListenerClass::Host,
            Some(&TlsSettings::new("c", "k")),
            false,
            false,
        )],
        audit: None,
        memberships: None,
    }));
    std::mem::forget(volume);
    let settings = TlsSettings::new(&pki.certificate, &pki.key);
    let (bound, address) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the Host's runtime");
        runtime.block_on(async move {
            let surface = permguard_transport::Surface::listener(
                "host-api",
                "127.0.0.1:0",
                permguard_server::host_api::routes(api, permguard_core::Disclosure::Full),
            )
            .tls(Some(&settings))
            .authenticator(Some(Arc::new(Bearers)))
            .start()
            .await
            .expect("the Host listener binds");
            bound.send(surface.address()).expect("the test waits");
            std::future::pending::<()>().await;
            drop(surface);
        });
    });
    address.recv().expect("the Host listener started")
}

/// TC-1: a decision read asked to verify, whose records no inclusion path accounts for, ran and
/// did not pass: exit 2 with `decisions_unverified`, over both transports alike.
#[test]
fn a_decision_read_that_does_not_verify_exits_two_over_both_transports() {
    let dir = scratch("decisions-verify");
    let pki = pki(&dir);
    let address = serve(rest().merge(grpc()), &pki, Seen::default());
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://localhost:{}", address.port());
        let output = cli(
            &dir,
            &[
                "-o",
                "json",
                "--tls-ca-file",
                &pki.authority.display().to_string(),
                "decisions",
                "list",
                "--zone",
                "acme",
                "--ledger",
                "main-ledger",
                "--verify",
                "--control-endpoint",
                &endpoint,
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{scheme}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("decisions_unverified"),
            "{scheme}: {stderr}"
        );
        // The report is printed before the refusal: what did not verify is shown.
        assert!(!output.stdout.is_empty(), "{scheme}");
    }
}

/// The CLI with `env` set, beside the hermetic environment of [`cli`].
fn cli_with(workdir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(workdir)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .envs(env.iter().copied())
        .args(args)
        .output()
        .expect("the CLI runs")
}

/// TC-1: a push over REST, on TLS, carries the operator's token (the gRPC case is the client's
/// wire test): the same writer every NOTP verb shares.
#[test]
fn a_push_over_https_carries_the_operators_token() {
    use permguard_control_client::remote::Remote as _;

    let dir = scratch("notp-https");
    let pki = pki(&dir);
    let seen = Seen::default();
    let address = serve(rest().merge(grpc()), &pki, Arc::clone(&seen));
    let remote = permguard_control_client::remote_http::HttpRemote::connect(
        &format!("https://localhost:{}", address.port()),
        &permguard_control_client::tls::TlsOptions {
            ca_file: Some(pki.authority.clone()),
            token: Some(permguard_control_client::tls::Credential::new(
                TOKEN.as_bytes().to_vec(),
            )),
            ..Default::default()
        },
        Box::new(permguard_control_client::narrate::Silent),
    )
    .expect("connects");
    remote.bind("z", "l");
    let digest = permguard_objects::digest::Digest::compute(b"1");
    remote
        .negotiate_push(&permguard_notp::NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: digest.clone(),
            expected_ref: None,
            closure: vec![permguard_notp::ObjectClaim { digest, size: 3 }],
            request_id: "push-1".into(),
        })
        .expect("the negotiation answers over TLS");
    assert_eq!(*seen.lock().unwrap(), vec![Some(format!("Bearer {TOKEN}"))]);
}

/// `Bearer denied-token` is refused at the gate; anyone else passes.
struct Refusing;

impl permguard_core::authz::Authenticator for Refusing {
    fn authenticate(
        &self,
        peer: Option<&permguard_core::PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<permguard_core::authz::Actor, permguard_core::AccessDenial> {
        if bearer == Some("denied-token") {
            return Err(permguard_core::AccessDenial::unauthenticated(
                "this credential maps to nobody",
            ));
        }
        Bearers.authenticate(peer, bearer)
    }
}

/// TC-1: a denial at the gate reads the same over both transports: no class, the code
/// `unauthenticated`, the operator's to fix (64).
#[test]
fn a_denial_reads_the_same_over_https_and_grpcs() {
    let dir = scratch("denial");
    let pki = pki(&dir);
    let address = serve_with(
        rest().merge(grpc()),
        TlsSettings::new(&pki.certificate, &pki.key),
        Seen::default(),
        Arc::new(Refusing),
    );
    let token = dir.join("denied");
    std::fs::write(&token, "denied-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(
        dir.join("check.json"),
        r#"{"subject":{"type":"User","id":"alice"},"action":{"name":"read"},"resource":{"type":"Document","id":"budget"}}"#,
    )
    .unwrap();
    for (command, flag) in [
        (vec!["zones", "list"], "--control-endpoint"),
        (
            vec![
                "check",
                "--file",
                "check.json",
                "--zone",
                "acme",
                "--ledger",
                "main-ledger",
            ],
            "--data-endpoint",
        ),
    ] {
        let mut answers = Vec::new();
        for scheme in ["https", "grpcs"] {
            let endpoint = format!("{scheme}://localhost:{}", address.port());
            let mut args = vec![
                "-o",
                "json",
                "--tls-ca-file",
                pki.authority.to_str().unwrap(),
                "--token-file",
                token.to_str().unwrap(),
            ];
            args.extend(command.iter().copied());
            args.push(flag);
            args.push(&endpoint);
            let output = cli(&dir, &args);
            let failure: Value = serde_json::from_slice(&output.stderr)
                .unwrap_or_else(|_| panic!("{command:?} {scheme}: {output:?}"));
            answers.push((
                output.status.code(),
                failure["class"].clone(),
                failure["code"].clone(),
            ));
        }
        assert_eq!(answers[0], answers[1], "{command:?}");
        assert_eq!(
            answers[0],
            (Some(64), Value::from(""), Value::from("unauthenticated")),
            "{command:?}"
        );
    }
}

/// TC-1: the token and the client key from the configuration: `auth.token_file` relative to the
/// configuration file's directory (a token planted where the command runs is not read), and the
/// key by `tls.key_ref: env:NAME`, presented in a real mutual-TLS handshake over both transports.
#[test]
fn the_configuration_names_the_token_and_the_key_by_reference() {
    let dir = scratch("configured");
    let pki = pki(&dir);
    let seen = Seen::default();
    let address = serve_with(
        rest().merge(grpc()),
        TlsSettings::new(&pki.certificate, &pki.key).with_client_ca(&pki.authority),
        Arc::clone(&seen),
        Arc::new(Bearers),
    );
    let conf = dir.join("conf");
    std::fs::create_dir_all(&conf).unwrap();
    let configured = token_file(&conf);
    assert!(configured.starts_with(&conf));
    // A token where the command runs, which the relative path must not reach.
    std::fs::write(dir.join("token"), "planted-token\n").unwrap();
    std::fs::write(
        conf.join("cli-config.yml"),
        "auth:\n  tokenFile: token\ntls:\n  keyRef: env:PG_TEST_OPERATOR_KEY\n",
    )
    .unwrap();
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://localhost:{}", address.port());
        let before = seen.lock().unwrap().len();
        let output = cli_with(
            &dir,
            &[
                (
                    "PERMGUARD_CONFIG",
                    conf.join("cli-config.yml").to_str().unwrap(),
                ),
                ("PG_TEST_OPERATOR_KEY", &pki.client_key_pem),
            ],
            &[
                "--tls-ca-file",
                pki.authority.to_str().unwrap(),
                "--tls-cert-file",
                pki.client_certificate.to_str().unwrap(),
                "zones",
                "list",
                "--control-endpoint",
                &endpoint,
            ],
        );
        assert!(output.status.success(), "{scheme}: {output:?}");
        let printed = String::from_utf8_lossy(&output.stdout).into_owned()
            + String::from_utf8_lossy(&output.stderr).as_ref();
        assert!(!printed.contains("PRIVATE KEY"), "{scheme}: {printed}");
        let received = seen.lock().unwrap()[before..].to_vec();
        assert!(
            !received.is_empty()
                && received
                    .iter()
                    .all(|value| value.as_deref() == Some(&format!("Bearer {TOKEN}"))),
            "{scheme}: {received:?}"
        );
    }
}

/// TC-1: an event read asked to verify, whose record no inclusion path accounts for, ran and did
/// not pass: exit 2 with `events_unverified`, over both transports alike.
#[test]
fn an_event_read_that_does_not_verify_exits_two_over_both_transports() {
    let dir = scratch("events-verify");
    let pki = pki(&dir);
    let address = serve(rest().merge(grpc()), &pki, Seen::default());
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://localhost:{}", address.port());
        let output = cli(
            &dir,
            &[
                "-o",
                "json",
                "--tls-ca-file",
                pki.authority.to_str().unwrap(),
                "events",
                "list",
                "--zone",
                "acme",
                "--ledger",
                "main-ledger",
                "--verify",
                "--control-endpoint",
                &endpoint,
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{scheme}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("events_unverified"), "{scheme}: {stderr}");
        assert!(!output.stdout.is_empty(), "{scheme}");
    }
}
