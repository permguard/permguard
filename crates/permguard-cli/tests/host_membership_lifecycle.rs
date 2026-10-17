// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The two-Host membership lifecycle through the public CLI, over both Host transports (WP-4.8).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use permguard_core::KeyManager as _;
use permguard_core::assurance::{AssuranceProfile, Control, EvidenceClass};
use permguard_core::authz::{Principal, Resource, Selector, operations};
use permguard_core::{Disclosure, Health, PeerSessionsReport, TlsSettings};
use permguard_host::api::sessions::PeerSessions;
use permguard_host::api::{Assurance, Composition, Effective, HostApi, Replay};
use permguard_host::authz::{Authorization, GrantStore, Issue};
use permguard_host::identity::{Identity, Suite, directories};
use permguard_host::keys::FileKeyProvider;
use permguard_host::keys::ring::{DATA_ATTEST, HOST_OPERATIONS, Policy, Ring};
use permguard_host::membership::appraisal::{
    Appraisal, Appraised, Policy as AppraisalPolicy, Verifier, Verifiers,
};
use permguard_host::membership::record::HostRef;
use permguard_host::membership::record::{Role, TaskType};
use permguard_host::membership::{Capabilities, Store};
use permguard_host::session::Context;
use permguard_host::session::peers::Peers;
use permguard_host::storage::volume::Volume;
use permguard_host::time::TimeGuard;
use permguard_transport::Surface;
use serde_json::Value;

const ADMIN: &str = "spiffe://acme/operators/root";
const SERVED: PeerSessionsReport = PeerSessionsReport {
    served: true,
    reason: None,
};

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-cli-members-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

struct Pki {
    directory: PathBuf,
    authority: rcgen::Certificate,
    authority_key: rcgen::KeyPair,
    authority_params: rcgen::CertificateParams,
}

impl Pki {
    fn new(directory: &Path) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("parameters");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let authority_key = rcgen::KeyPair::generate().expect("a key");
        let authority = params.self_signed(&authority_key).expect("self-signed");
        Self {
            directory: directory.to_path_buf(),
            authority,
            authority_key,
            authority_params: params,
        }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.directory.join(name);
        std::fs::File::create(&path)
            .and_then(|mut file| file.write_all(contents.as_bytes()))
            .expect("written");
        path
    }

    fn authority(&self) -> PathBuf {
        self.write("ca.pem", &self.authority.pem())
    }

    fn issue(&self, stem: &str, name: &str) -> (PathBuf, PathBuf) {
        let params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("parameters");
        let key = rcgen::KeyPair::generate().expect("a key");
        let issuer = rcgen::Issuer::from_params(&self.authority_params, &self.authority_key);
        let certificate = params.signed_by(&key, &issuer).expect("signed");
        (
            self.write(&format!("{stem}.pem"), &certificate.pem()),
            self.write(&format!("{stem}.key"), &key.serialize_pem()),
        )
    }
}

struct MutualTlsAdmin;

impl permguard_core::authz::Authenticator for MutualTlsAdmin {
    fn authenticate(
        &self,
        peer: Option<&permguard_core::PeerIdentity>,
        _bearer: Option<&str>,
    ) -> Result<permguard_core::authz::Actor, permguard_core::AccessDenial> {
        use permguard_core::authz::{Actor, ActorContext, Credential};
        Ok(match peer {
            Some(_) => Actor::Authenticated(ActorContext::new(
                Principal::new(ADMIN).expect("the administrator principal"),
                Credential::SanUri,
                None,
            )),
            None => Actor::Anonymous,
        })
    }
}

struct Echo;

impl permguard_host::membership::task::TaskHandler for Echo {
    fn handle(
        &self,
        _context: &permguard_host::membership::task::TaskContext,
        body: &[u8],
    ) -> Result<Vec<u8>, permguard_host::session::Refusal> {
        Ok(body.to_vec())
    }
}

struct GoldenVerifier;

impl Verifier for GoldenVerifier {
    fn appraise(
        &self,
        _member: &HostRef,
        _nonce: &[u8; 32],
        evidence: &[u8],
        now: u64,
    ) -> Result<Appraised, String> {
        if evidence != b"golden-attestation" {
            return Err("not the independent golden evidence".to_owned());
        }
        Ok(Appraised {
            controls: vec![Control::CustodyHsm],
            expires_at: now + 3600,
        })
    }
}

fn golden_appraisal() -> Appraisal {
    Appraisal::new(
        AppraisalPolicy::new(
            BTreeMap::from([
                (
                    Control::OperationsDualControl,
                    EvidenceClass::OperatorApproved,
                ),
                (Control::CustodyHsm, EvidenceClass::Attested),
            ]),
            Duration::from_secs(86_400),
        ),
        Verifiers::default().register("golden-verifier", Arc::new(GoldenVerifier)),
    )
}

#[derive(Clone)]
struct Endpoint {
    address: SocketAddr,
    host_id: String,
    fingerprint: String,
}

fn launch_host(
    root: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
    authority: PathBuf,
    role: Role,
) -> Endpoint {
    let (ready, started) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the Host runtime starts");
        runtime.block_on(async move {
            let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
            let identity = Arc::new(
                Identity::provision(
                    &volume,
                    Arc::new(FileKeyProvider::new(
                        directories(&volume).expect("identity directories").1,
                    )),
                    Suite::Ed25519Sha256V1,
                    permguard_host::authz::store::now(),
                    permguard_host::authz::store::now() * 1000,
                )
                .expect("provisioned"),
            );
            let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
            let (grants, _) = GrantStore::open(&volume).expect("the grant store opens");
            let audit = Arc::new(
                permguard_host::audit::Engine::open(
                    &volume,
                    permguard_host::audit::Stamp {
                        host_id: identity.host_id(),
                        boot_id: identity.boot_id(),
                        build: "test".to_owned(),
                        config_revision: permguard_host::audit::config_revision(std::iter::empty()),
                    },
                    Arc::clone(&time),
                    None,
                )
                .expect("the audit engine opens"),
            );
            let mutations = Arc::new(
                permguard_host::operations::mutation::Mutations::open(
                    &volume,
                    Arc::clone(&audit) as Arc<dyn permguard_host::operations::mutation::Projection>,
                    Arc::clone(&time),
                )
                .expect("the mutation journal opens"),
            );
            permguard_host::operations::grants::issue(
                &mutations,
                &grants,
                permguard_host::operations::journal::Initiator::System("test".to_owned()),
                Issue {
                    principal: Principal::new(ADMIN).expect("the administrator"),
                    operations: operations::ALL.iter().map(|op| (*op).to_owned()).collect(),
                    selector: Selector::under(Resource::host()),
                    resource_types: vec!["*".to_owned()],
                    constraints: Default::default(),
                    issued_by: "test".to_owned(),
                    expires_at: None,
                },
                permguard_host::authz::store::now(),
            )
            .expect("the administrator is issued");
            // The stream reads (WP-5.7b), on the Data Plane's resources; the list is on `host`,
            // which the administrator's grant above already covers.
            permguard_host::operations::grants::issue(
                &mutations,
                &grants,
                permguard_host::operations::journal::Initiator::System("test".to_owned()),
                Issue {
                    principal: Principal::new(ADMIN).expect("the administrator"),
                    operations: vec![operations::STREAMS_READ.to_owned()],
                    selector: Selector::under(Resource::parse("plane/data").expect("a resource")),
                    resource_types: vec!["*".to_owned()],
                    constraints: Default::default(),
                    issued_by: "test".to_owned(),
                    expires_at: None,
                },
                permguard_host::authz::store::now(),
            )
            .expect("the stream reader is issued");
            let (replay, _) = Replay::open(&volume, permguard_host::authz::store::now())
                .expect("the replay opens");
            let open_ring = |id: &'static str| {
                let ring = Arc::new(
                    Ring::open(
                        &volume,
                        id,
                        Suite::Ed25519Sha256V1,
                        Policy {
                            publish_ahead: Duration::from_secs(600),
                            rotate_every: Duration::from_secs(3600),
                            retain: Duration::from_secs(7200),
                        },
                        Arc::clone(&time),
                    )
                    .expect("the ring opens")
                    .with_binder(identity.clone()),
                );
                ring.maintain().expect("the first key");
                ring
            };
            let rings = vec![open_ring(HOST_OPERATIONS), open_ring(DATA_ATTEST)];
            audit.seal_with(Arc::clone(&rings[0])
                as Arc<dyn permguard_host::audit::checkpoint::CheckpointSigner>);
            let keys = Arc::new(permguard_host::keys::registry::Registry::new(
                Some(Arc::clone(&identity)),
                rings,
            ));
            let members = Store::open(&volume).expect("the membership store opens");
            let capabilities = Capabilities::default().declare(TaskType::DecisionsShip, role);
            let tasks = Arc::new(permguard_host::membership::task::Tasks {
                handlers: permguard_host::membership::task::TaskHandlers::default()
                    .register(TaskType::DecisionsShip, 1, Arc::new(Echo))
                    .expect("the task handler registers"),
                ..permguard_host::membership::task::Tasks::default()
            });
            let peers = Arc::new(Peers::open(&volume, &[]).expect("the peers open"));
            peers.with_source(
                Arc::clone(&members) as Arc<dyn permguard_host::session::peers::PinSource>
            );
            let context = Context {
                identity: Arc::clone(&identity),
                peers,
                time: Arc::clone(&time),
                declared_assurance: AssuranceProfile::Production,
                audit: None,
                metrics: permguard_core::Metrics::none(),
                service: Some(Arc::new(
                    permguard_host::membership::service::Coordinating {
                        store: Arc::clone(&members),
                        mutations: Arc::clone(&mutations),
                        identity: Arc::clone(&identity),
                        keys: Arc::clone(&keys),
                        capabilities: capabilities.clone(),
                        time: Arc::clone(&time),
                        tasks: Arc::clone(&tasks),
                    },
                )),
            };
            let settings = TlsSettings::new(&certificate, &key).with_client_ca(&authority);
            let connector = permguard_server::host_api::peer::member_client(Some(&settings))
                .expect("the peer client builds")
                .map(|tls| {
                    Arc::new(permguard_server::host_api::peer::PeerConnector::new(
                        context.clone(),
                        tls,
                    )) as Arc<dyn permguard_host::membership::member::Connector>
                });
            let api = Arc::new(
                HostApi::new(Composition {
                    authorization: Arc::new(Authorization::new(Arc::clone(&grants), &[])),
                    store: Some(grants),
                    replay,
                    keys,
                    health: Health::new(),
                    assurance: Assurance::of(
                        &permguard_core::assurance::Assurance::new(
                            AssuranceProfile::Production,
                            [],
                        )
                        .report(&[]),
                    ),
                    effective: Effective {
                        revision: 0,
                        settings: Vec::new(),
                    },
                    trail: "test".to_owned(),
                    mutations: Some(mutations),
                    identity: Some(Arc::clone(&identity)),
                    time,
                    peer_sessions: PeerSessions {
                        report: SERVED,
                        context: Some(context),
                    },
                    listeners: Vec::new(),
                    audit: Some(audit),
                    memberships: Some(Arc::new(permguard_host::api::members::MembershipService {
                        store: members,
                        capabilities,
                        connector,
                        appraisal: golden_appraisal(),
                        live: Arc::clone(&tasks.live),
                        streams: None,
                        shipping: None,
                    })),
                })
                .with_streams(Arc::new(FixedStreams)),
            );
            let surface = Surface::listener(
                "host-api",
                "127.0.0.1:0",
                permguard_server::host_api::routes(api, Disclosure::Full),
            )
            .tls(Some(&settings))
            .authenticator(Some(Arc::new(MutualTlsAdmin)))
            .streaming([permguard_server::host_api::peer::channel_path()])
            .start()
            .await
            .expect("the Host listener binds");
            ready
                .send(Endpoint {
                    address: surface.address(),
                    host_id: identity.host_id_text(),
                    fingerprint: identity.first_fingerprint().to_owned(),
                })
                .expect("the test waits");
            std::future::pending::<()>().await;
            drop(surface);
            drop(volume);
        });
    });
    started.recv().expect("the Host listener starts")
}

struct OperatorTls {
    authority: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
}

fn cli(workdir: &Path, endpoint: &str, tls: &OperatorTls, args: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(std::env::temp_dir())
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .args([
            "-o",
            "json",
            "-w",
            workdir.to_str().expect("a UTF-8 workdir"),
            "--host-endpoint",
            endpoint,
            "--tls-ca-file",
            tls.authority.to_str().expect("a UTF-8 path"),
            "--tls-cert-file",
            tls.certificate.to_str().expect("a UTF-8 path"),
            "--tls-key-file",
            tls.key.to_str().expect("a UTF-8 path"),
        ])
        .args(args)
        .output()
        .expect("the CLI runs")
}

fn call(workdir: &Path, endpoint: &str, tls: &OperatorTls, args: &[String]) -> Value {
    let output = cli(workdir, endpoint, tls, args);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the CLI answers JSON")
}

fn call_local(workdir: &Path, args: &[String]) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    let output = command
        .current_dir(workdir)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .args(["-o", "json", "-w"])
        .arg(workdir)
        .args(args)
        .output()
        .expect("the local CLI runs");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the local CLI answers JSON")
}

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn revision(value: &Value) -> String {
    value["receipt"]["revision"]
        .as_u64()
        .expect("a receipt revision")
        .to_string()
}

fn lifecycle(scheme: &str) {
    let root = scratch(scheme);
    let pki = Pki::new(&root);
    let authority = pki.authority();
    let (operator_certificate, operator_key) = pki.issue("operator", "operator");
    let tls = OperatorTls {
        authority: authority.clone(),
        certificate: operator_certificate,
        key: operator_key,
    };
    let (coordinator_certificate, coordinator_key) = pki.issue("coordinator", "127.0.0.1");
    let (member_certificate, member_key) = pki.issue("member", "127.0.0.1");
    let coordinator = launch_host(
        root.join("coordinator"),
        coordinator_certificate,
        coordinator_key,
        authority.clone(),
        Role::Coordinator,
    );
    let member = launch_host(
        root.join("member"),
        member_certificate,
        member_key,
        authority,
        Role::Member,
    );
    let coordinator_endpoint = format!("{scheme}://127.0.0.1:{}", coordinator.address.port());
    let member_endpoint = format!("{scheme}://127.0.0.1:{}", member.address.port());
    let coordinator_peer = format!("https://127.0.0.1:{}", coordinator.address.port());

    // The public document alone is not the answer: the member Host initiates a fresh
    // connection-bound proof. Its administrative request rides each scheme in this fixture,
    // while the peer channel is always canonical HTTPS. Completing it sends no enrollment Task
    // frame and therefore creates no pending membership.
    let proved = call(
        &root,
        &member_endpoint,
        &tls,
        &words(&[
            "host",
            "identity",
            "verify",
            &coordinator_peer,
            "--fingerprint",
            &coordinator.fingerprint,
        ]),
    );
    assert_eq!(proved["host_id"], coordinator.host_id);
    assert_eq!(proved["fingerprint"], coordinator.fingerprint);
    assert_eq!(proved["verified"], true);
    let untouched = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&["host", "members", "pending"]),
    );
    assert_eq!(untouched["members"], serde_json::json!([]));

    let tasks = root.join("tasks.json");
    std::fs::write(
        &tasks,
        include_bytes!("../../../contracts/vectors/host-cli-tasks.json"),
    )
    .expect("tasks write");
    let narrow = root.join("narrow.json");
    std::fs::write(
        &narrow,
        include_bytes!("../../../contracts/vectors/host-cli-narrow.json"),
    )
    .expect("narrowing writes");
    let assurance_result = root.join("assurance-result.json");
    std::fs::write(
        &assurance_result,
        include_bytes!("../../../contracts/vectors/host-cli-assurance-result.json"),
    )
    .expect("assurance result writes");

    let invited = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&[
            "host",
            "members",
            "invite",
            "create",
            "--selector",
            "plane/data/*",
            "--tasks",
            "tasks.json",
            "--expect-fingerprint",
            &member.fingerprint,
            "--min-assurance",
            "production",
        ]),
    );
    assert_eq!(invited["version"], 1);
    assert_eq!(invited["coordinator"]["host_id"], coordinator.host_id);
    let token = invited["token"].as_str().expect("the one-time token");
    let listed = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&["host", "members", "invite", "list"]),
    );
    assert!(
        !listed.to_string().contains(token),
        "the token is printed once"
    );

    let handoff = root.join("invitation.json");
    std::fs::write(
        &handoff,
        serde_json::to_vec_pretty(&invited).expect("handoff serializes"),
    )
    .expect("handoff writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&handoff, std::fs::Permissions::from_mode(0o600))
            .expect("the handoff is private");
    }
    let peer_address = invited["coordinator"]["address"]
        .as_str()
        .expect("a coordinator address");
    if scheme == "grpcs" {
        let pinned = call_local(
            &root,
            &words(&[
                "host",
                "identity",
                "pin",
                "add",
                peer_address,
                "--host-id",
                &coordinator.host_id,
                "--fingerprint",
                &coordinator.fingerprint,
            ]),
        );
        assert_eq!(pinned["pins"][0]["host_id"], coordinator.host_id);
    }
    let mut join = words(&[
        "--token-file",
        "invitation.json",
        "host",
        "members",
        "join",
        peer_address,
    ]);
    if scheme == "https" {
        join.extend([
            "--pin-fingerprint".to_owned(),
            coordinator.fingerprint.clone(),
        ]);
    }
    let joined = call(&root, &member_endpoint, &tls, &join);
    assert_eq!(
        (joined["status"].as_str(), joined["role"].as_str()),
        (Some("pending"), Some("member"))
    );
    assert!(
        !joined.to_string().contains(token),
        "join never repeats the token"
    );
    let id = joined["membership_id"].as_str().expect("a membership id");
    let pending = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&["host", "members", "pending"]),
    );
    assert_eq!(pending["members"][0]["membership_id"], id);
    let pending_revision = pending["members"][0]["revision"]
        .as_u64()
        .expect("a revision")
        .to_string();
    let approved = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&[
            "host",
            "members",
            "approve",
            id,
            "--expected-revision",
            &pending_revision,
            "--narrow",
            "narrow.json",
            "--assurance-result",
            "assurance-result.json",
        ]),
    );
    assert_eq!(approved["status"], "active");

    let scheduled = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&["host", "members", "verify", id]),
    );
    assert_eq!(scheduled["status"], "scheduled");
    assert!(
        scheduled["receipt"]["operation_id"]
            .as_str()
            .is_some_and(|operation_id| !operation_id.is_empty()),
        "member verification carries its replay receipt: {scheduled}"
    );
    let proved = call(
        &root,
        &member_endpoint,
        &tls,
        &words(&["host", "members", "verify", id]),
    );
    assert_eq!(proved["status"], "proved");
    assert!(
        proved["receipt"]["operation_id"]
            .as_str()
            .is_some_and(|operation_id| !operation_id.is_empty()),
        "the member-side proof carries its replay receipt: {proved}"
    );
    assert_eq!(proved["member"]["status"], "active");

    let suspended = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&[
            "host",
            "members",
            "suspend",
            id,
            "--expected-revision",
            &revision(&approved),
            "--reason",
            "maintenance",
        ]),
    );
    assert_eq!(suspended["status"], "suspended");
    let resumed = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&[
            "host",
            "members",
            "resume",
            id,
            "--expected-revision",
            &revision(&suspended),
            "--reason",
            "restored",
        ]),
    );
    assert_eq!(resumed["status"], "active");
    let fenced = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&[
            "host",
            "members",
            "fence",
            id,
            "--expected-revision",
            &revision(&resumed),
            "--reason",
            "rotate peer sessions",
        ]),
    );
    assert_eq!(fenced["status"], "active");

    let plan = root.join(format!("{scheme}-revoke.json"));
    let planned = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&[
            "host",
            "members",
            "revoke",
            "plan",
            id,
            "--reason",
            "decommissioned",
            "--expected-revision",
            &revision(&fenced),
            "--out",
            plan.file_name()
                .and_then(|name| name.to_str())
                .expect("a UTF-8 plan name"),
        ]),
    );
    assert!(planned["receipt"].is_string());
    let revoked = call(
        &root,
        &coordinator_endpoint,
        &tls,
        &words(&[
            "host",
            "members",
            "revoke",
            "run",
            id,
            "--confirm-file",
            plan.file_name()
                .and_then(|name| name.to_str())
                .expect("a UTF-8 plan name"),
        ]),
    );
    assert_eq!(revoked["status"], "revoked");
    let final_proof = call(
        &root,
        &member_endpoint,
        &tls,
        &words(&["host", "members", "verify", id]),
    );
    assert_eq!(final_proof["member"]["status"], "revoked");
}

#[test]
fn the_cli_drives_a_two_host_membership_lifecycle_over_rest() {
    lifecycle("https");
}

#[test]
fn the_cli_drives_a_two_host_membership_lifecycle_over_grpc() {
    lifecycle("grpcs");
}

/// One decision stream on `plane/data/zone/z1/ledger/l1`, its prefix through 4 deleted
/// (WP-5.7b).
struct FixedStreams;

const RUN: &str = "0123456789abcdef0123456789abcdef";

fn fixed_anchor() -> permguard_host::api::streams::AnchorView {
    permguard_host::api::streams::AnchorView {
        role: "producer".to_owned(),
        producer: RUN.to_owned(),
        run: RUN.to_owned(),
        through: 4,
        low_watermark: 5,
        terminal_head: format!("sha256:{}", "a".repeat(64)),
        covering: 2,
        anchor: "oQEC".to_owned(),
    }
}

impl permguard_host::api::streams::StreamReads for FixedStreams {
    fn list(&self) -> Result<Vec<permguard_host::api::streams::StreamView>, String> {
        Ok(vec![permguard_host::api::streams::StreamView {
            plane: "data".to_owned(),
            stream_type: "decisions".to_owned(),
            version: 1,
            role: "producer".to_owned(),
            retention: "evidence".to_owned(),
            ring: "data.attest".to_owned(),
            task: Some("decisions.ship".to_owned()),
            resources: vec![permguard_host::api::streams::ResourceState {
                resource: "plane/data/zone/z1/ledger/l1".to_owned(),
                state: "open".to_owned(),
            }],
        }])
    }
    fn frontier(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<permguard_host::api::streams::Frontier>, String> {
        Ok(((plane, stream_type) == ("data", "decisions")).then(|| {
            permguard_host::api::streams::Frontier {
                resource: resource.to_owned(),
                producer: vec![permguard_host::api::streams::ProducerRun {
                    run: RUN.to_owned(),
                    ended: false,
                    last_seq: 8,
                    sealed: 8,
                    acknowledged: Some(6),
                    low_watermark: 5,
                }],
                consumer: Vec::new(),
            }
        }))
    }
    fn records(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<(&[u8; 16], &[u8; 16])>,
        _: u64,
        _: usize,
    ) -> Result<Option<permguard_host::api::streams::RecordPage>, String> {
        Ok(None)
    }
    fn signers(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<permguard_host::api::streams::RunSigners>>, String> {
        Ok(Some(vec![permguard_host::api::streams::RunSigners {
            role: "producer".to_owned(),
            producer: RUN.to_owned(),
            run: RUN.to_owned(),
            spans: vec![permguard_host::api::streams::SpanView {
                from_seq: 1,
                kid: "kid-1".to_owned(),
                jwk: "{}".to_owned(),
            }],
        }]))
    }
    fn subscriptions(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<permguard_host::api::streams::SubscriptionView>>, String> {
        Ok(Some(vec![permguard_host::api::streams::SubscriptionView {
            membership: "0198f2aa-0000-7000-8000-000000000001".to_owned(),
            task: "decisions".to_owned(),
            required: true,
            state: "stopped".to_owned(),
            reason: Some("gone".to_owned()),
            acked: vec![permguard_host::api::streams::RunAck {
                run: RUN.to_owned(),
                acked: 6,
            }],
        }]))
    }
    fn gaps(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<permguard_host::api::streams::GapEntry>>, String> {
        Ok(Some(vec![permguard_host::api::streams::GapEntry {
            role: "producer".to_owned(),
            producer: RUN.to_owned(),
            run: RUN.to_owned(),
            low_watermark: 5,
        }]))
    }
    fn anchors(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<permguard_host::api::streams::AnchorView>>, String> {
        Ok(Some(vec![fixed_anchor()]))
    }
}

/// WP-5.7b: `host streams` reads the Host's streams over both transports and prints the same
/// answer; a stream the Host does not serve is refused with its code.
#[test]
fn the_stream_commands_answer_the_same_over_both_transports() {
    let root = scratch("streams");
    let pki = Pki::new(&root);
    let authority = pki.authority();
    let (operator_certificate, operator_key) = pki.issue("operator", "operator");
    let tls = OperatorTls {
        authority: authority.clone(),
        certificate: operator_certificate,
        key: operator_key,
    };
    let (certificate, key) = pki.issue("host", "127.0.0.1");
    let host = launch_host(
        root.join("host"),
        certificate,
        key,
        authority,
        Role::Coordinator,
    );
    let resource = "plane/data/zone/z1/ledger/l1";
    let mut answers: Vec<Vec<Value>> = Vec::new();
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://127.0.0.1:{}", host.address.port());
        let mut seen = vec![call(
            &root,
            &endpoint,
            &tls,
            &words(&["host", "streams", "list"]),
        )];
        for what in [
            "frontier",
            "runs",
            "signers",
            "subscriptions",
            "gaps",
            "anchors",
        ] {
            seen.push(call(
                &root,
                &endpoint,
                &tls,
                &words(&[
                    "host",
                    "streams",
                    what,
                    "data",
                    "decisions",
                    "--resource",
                    resource,
                ]),
            ));
        }
        let unknown = cli(
            &root,
            &endpoint,
            &tls,
            &words(&[
                "host",
                "streams",
                "frontier",
                "data",
                "nothing",
                "--resource",
                resource,
            ]),
        );
        // Refused with its code on stderr, nothing on stdout, the usage exit status.
        assert_eq!(unknown.status.code(), Some(64), "{scheme}");
        assert!(unknown.stdout.is_empty(), "{scheme}");
        let refusal: Value = serde_json::from_slice(&unknown.stderr).expect("a JSON refusal");
        assert_eq!(
            (refusal["class"].as_str(), refusal["code"].as_str()),
            (Some("not_found"), Some("stream_unknown")),
            "{scheme}"
        );
        answers.push(seen);
    }
    assert_eq!(answers[0], answers[1], "the same answer over REST and gRPC");
    let rest = &answers[0];
    assert_eq!(rest[0]["streams"][0]["retention"], "evidence");
    assert_eq!(rest[1]["producer"][0]["acknowledged"], 6);
    assert_eq!(
        rest[1]["resource"], resource,
        "the resource the Host decoded"
    );
    assert_eq!(
        rest[2]["runs"][0]["role"], "producer",
        "runs from the frontier"
    );
    assert_eq!(rest[2]["runs"][0]["oldest_retained"], 5);
    assert_eq!(rest[3]["runs"][0]["spans"][0]["kid"], "kid-1");
    assert_eq!(rest[4]["subscriptions"][0]["reason"], "gone");
    assert_eq!(rest[5]["gaps"][0]["low_watermark"], 5);
    assert_eq!(rest[6]["anchors"][0]["anchor"], "oQEC");
}
