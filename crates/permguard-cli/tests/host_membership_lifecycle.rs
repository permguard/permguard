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
            // The operator's object sweep (TC-4), on the Control Plane's resources.
            permguard_host::operations::grants::issue(
                &mutations,
                &grants,
                permguard_host::operations::journal::Initiator::System("test".to_owned()),
                Issue {
                    principal: Principal::new(ADMIN).expect("the administrator"),
                    operations: vec![operations::GC_MANAGE.to_owned()],
                    selector: Selector::under(
                        Resource::parse("plane/control").expect("a resource"),
                    ),
                    resource_types: vec!["*".to_owned()],
                    constraints: Default::default(),
                    issued_by: "test".to_owned(),
                    expires_at: None,
                },
                permguard_host::authz::store::now(),
            )
            .expect("the sweeper is issued");
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
                        settings: vec![permguard_host::api::Setting {
                            key: "PERMGUARD_LOG_LEVEL".to_owned(),
                            value: Some("info".to_owned()),
                            masked: false,
                            origin: "environment".to_owned(),
                            class: "startup".to_owned(),
                        }],
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
                        importing: None,
                    })),
                })
                .with_streams(Arc::new(FixedStreams))
                // The application-consistent backups (TC-3).
                .with_backups(
                    Arc::new(
                        permguard_host::operations::backup::Backups::open(&volume)
                            .expect("the backups open"),
                    ),
                    None,
                    None,
                ),
            );
            // The Control Plane's object sweep, answering what it was asked (TC-4).
            api.gc_jobs()
                .provide(
                    permguard_host::gc::OBJECTS,
                    "control",
                    Arc::new(Sweep) as Arc<dyn permguard_host::gc::GcJob>,
                )
                .expect("the sweep is provided");
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
    // The member takes the signed manifest at once, rather than at its next pass (TD-3).
    let synced = call(
        &root,
        &member_endpoint,
        &tls,
        &words(&["host", "members", "sync", id]),
    );
    assert_eq!(
        (
            synced["status"].as_str(),
            synced["role"].as_str(),
            synced["epoch"].as_u64(),
            synced["membership_id"].as_str()
        ),
        (Some("active"), Some("member"), Some(1), Some(id)),
        "{scheme}: {synced}"
    );

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
        plane: &str,
        stream_type: &str,
        _: &str,
    ) -> Result<Option<Vec<permguard_host::api::streams::AnchorView>>, String> {
        Ok(((plane, stream_type) == ("data", "decisions")).then(|| vec![fixed_anchor()]))
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

/// The JSON file a command wrote.
fn written(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("the file is written")).expect("JSON")
}

/// TC-2: the `host keys`, `host audit`, `host config`, `host status` and `host plans` commands
/// against an in-process Host, over REST and over gRPC: each answers what the Host holds, the
/// two-step revocation runs from the plan file it wrote, the bundle and the export walk their
/// pages into new owner-only files, and a refusal carries its code on both transports.
#[test]
fn the_host_operations_commands_answer_over_both_transports() {
    let root = scratch("operations");
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
    let mut configs = Vec::new();
    let mut refusals = Vec::new();
    let mut first_records = Vec::new();
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://127.0.0.1:{}", host.address.port());
        let call = |args: &[&str]| call(&root, &endpoint, &tls, &words(args));
        let file = |name: &str| root.join(format!("{scheme}-{name}"));

        let status = call(&["host", "status"]);
        assert!(status["state"].is_string(), "{scheme}: {status}");
        assert_eq!(status["assurance"]["profile"], "production", "{scheme}");

        let rings = call(&["host", "keys", "list"]);
        let names: Vec<&str> = rings["rings"]
            .as_array()
            .expect("rings")
            .iter()
            .filter_map(|ring| ring["ring"].as_str())
            .collect();
        assert!(names.contains(&"host.operations"), "{scheme}: {names:?}");
        let ring = call(&["host", "keys", "show", "data.attest"]);
        let epoch = ring["epoch"].as_u64().expect("an epoch");
        let before: Vec<String> = ring["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .filter_map(|key| key["kid"].as_str().map(str::to_owned))
            .collect();
        assert!(!before.is_empty(), "{scheme}");

        let rotated = call(&[
            "host",
            "keys",
            "rotate",
            "data.attest",
            "--expected-epoch",
            &epoch.to_string(),
        ]);
        let new_kid = rotated["kid"].as_str().expect("the new kid").to_owned();
        assert!(
            rotated["receipt"]["operation_id"].is_string(),
            "{scheme}: {rotated}"
        );
        let retired = before
            .iter()
            .find(|kid| **kid != new_kid)
            .expect("a key other than the new one")
            .clone();

        // A two-step revocation: the plan written once to a new file, run from it.
        let plan_file = file("revoke.json");
        let planned = call(&[
            "host",
            "keys",
            "revoke",
            "plan",
            "data.attest",
            &retired,
            "--reason",
            "compromise",
            "--out",
            plan_file.to_str().expect("UTF-8"),
        ]);
        assert_eq!(written(&plan_file), planned, "{scheme}");
        let again = cli(
            &root,
            &endpoint,
            &tls,
            &words(&[
                "host",
                "keys",
                "revoke",
                "plan",
                "data.attest",
                &retired,
                "--reason",
                "compromise",
                "--out",
                plan_file.to_str().expect("UTF-8"),
            ]),
        );
        assert_eq!(
            again.status.code(),
            Some(64),
            "{scheme}: a plan file is never overwritten"
        );
        let refusal: Value = serde_json::from_slice(&again.stderr).expect("a JSON refusal");
        assert!(
            refusal["message"]
                .as_str()
                .is_some_and(|text| text.contains("--out")),
            "{scheme}: {refusal}"
        );
        assert_eq!(
            written(&plan_file),
            planned,
            "{scheme}: the first plan kept"
        );
        let revoked = call(&[
            "host",
            "keys",
            "revoke",
            "run",
            "data.attest",
            "--confirm-file",
            plan_file.to_str().expect("UTF-8"),
        ]);
        assert_eq!(revoked["kid"], retired.as_str(), "{scheme}");

        // The verification bundle, every page, in the shape an import reads.
        let bundle_file = file("bundle.json");
        let bundled = call(&[
            "host",
            "keys",
            "bundle",
            "export",
            "--resource",
            "host",
            "--out",
            bundle_file.to_str().expect("UTF-8"),
        ]);
        let bundle = written(&bundle_file);
        assert_eq!(bundle["resource"], "host", "{scheme}");
        assert!(bundle["manifest"].as_str().is_some_and(|m| !m.is_empty()));
        assert_eq!(
            bundled["items"].as_u64(),
            Some(bundle["items"].as_array().expect("items").len() as u64),
            "{scheme}"
        );
        assert_eq!(
            bundled["bundle_digest"], bundle["bundle_digest"],
            "{scheme}"
        );

        // The security trail holds the rotation and the revocation.
        let page = call(&[
            "host",
            "audit",
            "query",
            "--class",
            "security",
            "--resource",
            "host",
            "--limit",
            "1000",
        ]);
        let actions: Vec<&str> = page["records"]
            .as_array()
            .expect("records")
            .iter()
            .filter_map(|record| record["action"].as_str())
            .collect();
        assert!(
            actions.contains(&"host.keys.rotated"),
            "{scheme}: {actions:?}"
        );
        // The time bounds reach the Host: nothing after the far future, nothing before 2001.
        for (bound, instant) in [
            ("--from", "2099-01-01T00:00:00Z"),
            ("--to", "2001-01-01T00:00:00Z"),
        ] {
            let none = call(&[
                "host",
                "audit",
                "query",
                "--class",
                "security",
                "--resource",
                "host",
                bound,
                instant,
            ]);
            assert_eq!(
                none["records"].as_array().map(Vec::len),
                Some(0),
                "{scheme} {bound}: {none}"
            );
        }
        // The trail's first record, the same bytes whichever transport carried it.
        let first = call(&[
            "host",
            "audit",
            "query",
            "--class",
            "security",
            "--resource",
            "host",
            "--limit",
            "1",
        ]);
        first_records.push(first["records"][0].clone());
        assert!(first["next_cursor"].is_string(), "{scheme}: {first}");
        let checkpoints = call(&[
            "host",
            "audit",
            "checkpoints",
            "--class",
            "security",
            "--resource",
            "host",
        ]);
        assert_eq!(checkpoints["class"], "security", "{scheme}");
        let export_file = file("audit.json");
        let exported = call(&[
            "host",
            "audit",
            "export",
            "--class",
            "security",
            "--resource",
            "host",
            "--out",
            export_file.to_str().expect("UTF-8"),
        ]);
        let export = written(&export_file);
        let frontier = export["frontier"].as_u64().expect("a frontier");
        assert_eq!(exported["frontier"].as_u64(), Some(frontier), "{scheme}");
        let records: usize = export["pages"]
            .as_array()
            .expect("pages")
            .iter()
            .map(|page| page["records"].as_array().map_or(0, Vec::len))
            .sum();
        assert_eq!(
            exported["records"].as_u64(),
            Some(records as u64),
            "{scheme}"
        );
        assert!(records > 0, "{scheme}");

        configs.push((
            call(&["host", "config", "show", "--effective"]),
            call(&["host", "config", "revisions"]),
        ));

        // The revocation's plan is listed, consumed; its planner cannot approve it.
        let plans = call(&["host", "plans", "list"]);
        let plan_id = planned["plan_id"].as_str().expect("a plan id");
        let listed = plans["plans"]
            .as_array()
            .expect("plans")
            .iter()
            .find(|plan| plan["plan_id"] == plan_id)
            .unwrap_or_else(|| panic!("{scheme}: the plan is listed: {plans}"));
        assert_eq!(listed["status"], "consumed", "{scheme}");
        let approve = cli(
            &root,
            &endpoint,
            &tls,
            &words(&["host", "plans", "approve", plan_id]),
        );
        assert!(!approve.status.success(), "{scheme}");
        let refusal: Value = serde_json::from_slice(&approve.stderr).expect("a JSON refusal");
        refusals.push((refusal["class"].clone(), refusal["code"].clone()));
    }
    assert_eq!(
        configs[0], configs[1],
        "the same configuration over REST and gRPC"
    );
    assert_eq!(
        configs[0].0["settings"][0]["key"], "PERMGUARD_LOG_LEVEL",
        "the settings carried"
    );
    assert_eq!(
        first_records[0], first_records[1],
        "the same first record over REST and gRPC"
    );
    assert!(
        first_records[0]["record"]
            .as_str()
            .is_some_and(|record| !record.is_empty())
    );
    // Every file a command wrote is its owner's alone.
    #[cfg(unix)]
    for scheme in ["https", "grpcs"] {
        use std::os::unix::fs::PermissionsExt as _;
        for name in ["revoke.json", "bundle.json", "audit.json"] {
            let mode = std::fs::metadata(root.join(format!("{scheme}-{name}")))
                .expect("written")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{scheme}-{name}");
        }
    }
    assert_eq!(
        refusals[0], refusals[1],
        "the same refusal over REST and gRPC"
    );
}

/// Every file below `from`, copied to `to`: what a storage driver's snapshot holds.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("the copy");
    for entry in std::fs::read_dir(from).expect("lists").flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copied");
        }
    }
}

/// TC-3: `host backup` over REST and over gRPC: the prepare writes the token to a new owner-only
/// file and never prints it, the list shows the backup, the finalize records the driver's
/// snapshot from the token file and an abort ends another; then, offline, `backup verify` checks
/// the snapshot taken inside the barrier against the printed manifest, the exported bundle and the
/// identity pin, and labels a changed one crash-consistent, exit 2.
#[test]
fn the_backup_commands_drive_a_snapshot_over_both_transports() {
    let root = scratch("backup");
    let pki = Pki::new(&root);
    let authority = pki.authority();
    let (operator_certificate, operator_key) = pki.issue("operator", "operator");
    let tls = OperatorTls {
        authority: authority.clone(),
        certificate: operator_certificate,
        key: operator_key,
    };
    let (certificate, key) = pki.issue("host", "127.0.0.1");
    let host_root = root.join("host");
    let host = launch_host(
        host_root.clone(),
        certificate,
        key,
        authority,
        Role::Coordinator,
    );
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://127.0.0.1:{}", host.address.port());
        let call = |args: &[&str]| call(&root, &endpoint, &tls, &words(args));
        let file = |name: &str| root.join(format!("{scheme}-{name}"));
        let token_file = file("backup.token");
        let output = cli(
            &root,
            &endpoint,
            &tls,
            &words(&[
                "host",
                "backup",
                "prepare",
                "--token-out",
                token_file.to_str().expect("UTF-8"),
            ]),
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let token = std::fs::read_to_string(&token_file).expect("the token");
        assert!(token.len() > 20, "{scheme}");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(token.trim())
                && !String::from_utf8_lossy(&output.stderr).contains(token.trim()),
            "{scheme}: the token is never printed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&token_file)
                .expect("written")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{scheme}");
        }
        let prepared: Value = serde_json::from_slice(&output.stdout).expect("JSON");
        let listed = call(&["host", "backup", "list"]);
        let state = |listed: &Value| {
            listed["backups"]
                .as_array()
                .expect("backups")
                .iter()
                .find(|backup| backup["operation_id"] == prepared["operation_id"])
                .map(|backup| backup["state"].clone())
        };
        assert_eq!(state(&listed), Some(Value::from("prepared")), "{scheme}");

        // The storage driver's snapshot, inside the barrier.
        let snapshot = file("snapshot");
        copy_tree(&host_root, &snapshot);
        let snapshot_id = format!("copy:{scheme}");
        let finalized = call(&[
            "host",
            "backup",
            "finalize",
            "--backup-token-file",
            token_file.to_str().expect("UTF-8"),
            "--snapshot-id",
            &snapshot_id,
        ]);
        assert_eq!(finalized["state"], "finalized", "{scheme}");
        assert_eq!(finalized["snapshot_id"], snapshot_id.as_str(), "{scheme}");
        assert_eq!(
            state(&call(&["host", "backup", "list"])),
            Some(Value::from("finalized")),
            "{scheme}"
        );

        // Another backup, aborted.
        let second_token = file("second.token");
        call(&[
            "host",
            "backup",
            "prepare",
            "--token-out",
            second_token.to_str().expect("UTF-8"),
        ]);
        let aborted = call(&[
            "host",
            "backup",
            "abort",
            "--backup-token-file",
            second_token.to_str().expect("UTF-8"),
        ]);
        assert_eq!(aborted["state"], "aborted", "{scheme}");

        // Offline: the snapshot against its manifest, under the exported bundle and the pin.
        let bundle = file("bundle.json");
        call(&[
            "host",
            "keys",
            "bundle",
            "export",
            "--resource",
            "host",
            "--out",
            bundle.to_str().expect("UTF-8"),
        ]);
        let manifest = file("manifest.txt");
        std::fs::write(
            &manifest,
            prepared["manifest"].as_str().expect("a manifest"),
        )
        .expect("written");
        let verify_with = |volume: &Path, pin: &str| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
            for (name, _) in std::env::vars_os() {
                if name.to_string_lossy().starts_with("PERMGUARD_") {
                    command.env_remove(name);
                }
            }
            command
                .current_dir(&root)
                .env("PERMGUARD_CONFIG", root.join("cli-config.yml"))
                .args(["-o", "json", "-w"])
                .arg(&root)
                .args(["backup", "verify", "--volume"])
                .arg(volume)
                .arg("--manifest")
                .arg(&manifest)
                .arg("--bundle")
                .arg(&bundle)
                .args(["--pin", pin])
                .output()
                .expect("the local CLI runs")
        };
        let verify = |volume: &Path| verify_with(volume, &host.fingerprint);
        // Another pin: refused, never labelled, exit 2.
        let pinned = verify_with(&snapshot, "sha256:0000");
        assert_eq!(pinned.status.code(), Some(2), "{scheme}");
        let refusal: Value = serde_json::from_slice(&pinned.stderr).expect("a JSON refusal");
        assert_eq!(refusal["code"], "backup_unverified", "{scheme}");
        let verified = verify(&snapshot);
        assert!(
            verified.status.success(),
            "{scheme}: {}",
            String::from_utf8_lossy(&verified.stderr)
        );
        let verdict: Value = serde_json::from_slice(&verified.stdout).expect("JSON");
        assert_eq!(verdict["consistency"], "application_consistent", "{scheme}");
        assert_eq!(
            verdict["operation_id"], prepared["operation_id"],
            "{scheme}"
        );
        // A file of the snapshot changed: only crash-consistent, exit 2.
        std::fs::write(snapshot.join("host/VOLUME_ID.changed"), b"x").expect("written");
        let identity = snapshot.join("host/identity/BOOT");
        let mut bytes = std::fs::read(&identity).expect("a BOOT");
        bytes.push(0);
        std::fs::write(&identity, bytes).expect("changed");
        let changed = verify(&snapshot);
        assert_eq!(changed.status.code(), Some(2), "{scheme}");
        let verdict: Value = serde_json::from_slice(&changed.stdout).expect("JSON");
        assert_eq!(verdict["consistency"], "crash_consistent", "{scheme}");
    }
}

/// The runs the fake sweep was asked for: a plan never is one.
static SWEEPS_RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A sweep that removes nothing and says what it keeps and where it would stop; its runs counted.
struct Sweep;

impl permguard_host::gc::GcJob for Sweep {
    fn plan(
        &self,
        scope: &Resource,
    ) -> Result<permguard_host::gc::Report, permguard_host::gc::GcError> {
        Ok(sweep_report(scope, "grace"))
    }

    fn run(
        &self,
        scope: &Resource,
        _plan_id: &str,
    ) -> Result<permguard_host::gc::Report, permguard_host::gc::GcError> {
        SWEEPS_RUN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(sweep_report(scope, "bound"))
    }
}

fn sweep_report(scope: &Resource, kept: &str) -> permguard_host::gc::Report {
    permguard_host::gc::Report {
        entries: vec![permguard_host::gc::Entry {
            resource: format!("{scope}"),
            candidates: 3,
            candidate_bytes: 30,
            removed: 0,
            removed_bytes: 0,
            kept: vec![permguard_host::gc::Kept {
                reason: kept.to_owned(),
                count: 3,
            }],
        }],
        resumes_at: Some(format!("{scope}/ledger/l9")),
        skipped: vec![format!("{scope}/ledger/l2: unreadable")],
        omitted: 7,
    }
}

/// TC-4: `gc objects plan` changes nothing and writes its plan to a new owner-only file; `run`
/// presents its receipt once and prints what was removed, what was kept and why, and the receipt;
/// the run is audited even when it removes nothing; alike over REST and gRPC.
#[test]
fn the_object_sweep_is_planned_and_run_over_both_transports() {
    let root = scratch("gc");
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
    let mut runs = Vec::new();
    let mut plans: Vec<Value> = Vec::new();
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://127.0.0.1:{}", host.address.port());
        let call = |args: &[&str]| call(&root, &endpoint, &tls, &words(args));
        // The whole Plane and one ledger: the scope each names.
        for (args, scope) in [
            (vec![], "plane/control"),
            (
                vec!["--zone", "z1", "--ledger", "l1"],
                "plane/control/zone/z1/ledger/l1",
            ),
        ] {
            let file = root.join(format!("{scheme}-{}-gc.plan", args.len()));
            let mut all = vec!["gc", "objects", "plan"];
            all.extend(args.iter().copied());
            all.extend(["--out", file.to_str().expect("UTF-8")]);
            assert_eq!(call(&all)["resource"], scope, "{scheme}");
        }
        // An id that is not one component, and a plan of another job, are refused.
        let refused = cli(
            &root,
            &endpoint,
            &tls,
            &words(&[
                "gc",
                "objects",
                "plan",
                "--zone",
                "z1/ledger/x",
                "--out",
                root.join(format!("{scheme}-bad.plan"))
                    .to_str()
                    .expect("UTF-8"),
            ]),
        );
        assert_eq!(refused.status.code(), Some(64), "{scheme}");
        assert!(!root.join(format!("{scheme}-bad.plan")).exists());
        let other = root.join(format!("{scheme}-mirrors.plan"));
        std::fs::write(
            &other,
            serde_json::json!({
                "job": "mirrors", "resource": "plane/data", "plan_id": "p", "plan_digest": "d",
                "expires": "2099-01-01T00:00:00Z", "receipt": "AA", "approvals_required": 0,
                "report": {"entries": [], "resumes_at": null, "skipped": [], "omitted": 0}
            })
            .to_string(),
        )
        .expect("written");
        let refused = cli(
            &root,
            &endpoint,
            &tls,
            &words(&[
                "gc",
                "objects",
                "run",
                "--confirm-file",
                other.to_str().expect("UTF-8"),
            ]),
        );
        assert_eq!(refused.status.code(), Some(64), "{scheme}");
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("plans the `mirrors` job"),
            "{scheme}: refused before the Host is asked"
        );
        let plan_file = root.join(format!("{scheme}-gc.plan"));
        let planned = call(&[
            "gc",
            "objects",
            "plan",
            "--zone",
            "z1",
            "--out",
            plan_file.to_str().expect("UTF-8"),
        ]);
        let before = SWEEPS_RUN.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(planned["resource"], "plane/control/zone/z1", "{scheme}");
        assert_eq!(planned["approvals_required"], 0, "{scheme}");
        assert!(
            planned["expires"]
                .as_str()
                .and_then(permguard_core::time::from_rfc3339)
                .is_some(),
            "{scheme}: {planned}"
        );
        let report = &planned["report"];
        assert_eq!(
            report["entries"][0]["kept"][0]["reason"], "grace",
            "{scheme}"
        );
        assert_eq!(
            (
                report["entries"][0]["candidates"].as_u64(),
                report["entries"][0]["candidate_bytes"].as_u64(),
                report["omitted"].as_u64()
            ),
            (Some(3), Some(30), Some(7)),
            "{scheme}"
        );
        assert_eq!(
            report["resumes_at"], "plane/control/zone/z1/ledger/l9",
            "{scheme}"
        );
        assert_eq!(
            report["skipped"][0],
            "plane/control/zone/z1/ledger/l2: unreadable"
        );
        let mut plan = planned.clone();
        for minted in ["receipt", "plan_id", "plan_digest", "expires"] {
            plan[minted] = Value::Null;
        }
        plans.push(plan);
        assert_eq!(written(&plan_file), planned, "{scheme}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&plan_file)
                .expect("written")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{scheme}");
        }
        let ran = call(&[
            "gc",
            "objects",
            "run",
            "--confirm-file",
            plan_file.to_str().expect("UTF-8"),
        ]);
        assert_eq!(ran["plan_id"], planned["plan_id"], "{scheme}");
        assert_eq!(ran["report"]["entries"][0]["removed"], 0, "{scheme}");
        assert_eq!(ran["report"]["entries"][0]["kept"][0]["reason"], "bound");
        assert_eq!(
            SWEEPS_RUN.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "{scheme}: the plan ran nothing, the run ran once"
        );
        assert!(
            ran["receipt"]["operation_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "{scheme}: {ran}"
        );
        assert!(
            ran["receipt"]["audit"]["trail"]
                .as_str()
                .is_some_and(|trail| !trail.is_empty()),
            "{scheme}: {ran}"
        );
        let again = cli(
            &root,
            &endpoint,
            &tls,
            &words(&[
                "gc",
                "objects",
                "run",
                "--confirm-file",
                plan_file.to_str().expect("UTF-8"),
            ]),
        );
        assert!(!again.status.success(), "{scheme}: a receipt runs once");
        let refusal: Value = serde_json::from_slice(&again.stderr).expect("a JSON refusal");
        assert_eq!(refusal["code"], "plan_expired", "{scheme}");
        let mut answer = ran.clone();
        answer["receipt"] = Value::Null;
        answer["plan_id"] = Value::Null;
        runs.push(answer);
    }
    assert_eq!(runs[0], runs[1], "the same run over REST and gRPC");
    assert_eq!(plans[0], plans[1], "the same plan over REST and gRPC");
    // Audited, though nothing was removed.
    let endpoint = format!("https://127.0.0.1:{}", host.address.port());
    let page = call(
        &root,
        &endpoint,
        &tls,
        &words(&[
            "host",
            "audit",
            "query",
            "--class",
            "security",
            "--resource",
            "host",
            "--limit",
            "1000",
        ]),
    );
    let ran = page["records"]
        .as_array()
        .expect("records")
        .iter()
        .filter(|record| record["action"] == "host.gc.ran")
        .count();
    assert!(
        ran >= 2,
        "a run is audited even when it removes nothing: {page}"
    );
}

/// TC-5: `evidence anchors <zone> <ledger>` reads the retained prefix anchors of the ledger's
/// decision and event streams through the Host listener, alike over REST and gRPC, says which
/// stream the Host does not keep, and refuses an id that is not one.
#[test]
fn the_evidence_anchors_answer_over_both_transports() {
    let root = scratch("anchors");
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
    let mut answers = Vec::new();
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://127.0.0.1:{}", host.address.port());
        let anchors = call(
            &root,
            &endpoint,
            &tls,
            &words(&["evidence", "anchors", "z1", "l1"]),
        );
        assert_eq!(
            anchors["resource"], "plane/data/zone/z1/ledger/l1",
            "{scheme}"
        );
        let decisions = &anchors["streams"][0];
        assert_eq!(decisions["stream_type"], "decisions", "{scheme}");
        assert_eq!(
            (&decisions["served"], &decisions["held"]),
            (&Value::Bool(true), &Value::Bool(true)),
            "{scheme}"
        );
        assert_eq!(
            decisions["anchors"]["anchors"][0]["anchor"], "oQEC",
            "{scheme}"
        );
        // A stream type the Host does not serve is said so, without anchors.
        let events = &anchors["streams"][1];
        assert_eq!(events["stream_type"], "events", "{scheme}");
        assert_eq!(
            (&events["served"], &events["held"]),
            (&Value::Bool(false), &Value::Bool(false)),
            "{scheme}"
        );
        assert!(events.get("anchors").is_none(), "{scheme}");
        // A ledger the Host's streams do not list: served, not held.
        let elsewhere = call(
            &root,
            &endpoint,
            &tls,
            &words(&["evidence", "anchors", "z1", "l404"]),
        );
        assert_eq!(elsewhere["streams"][0]["served"], true, "{scheme}");
        assert_eq!(elsewhere["streams"][0]["held"], false, "{scheme}");
        let refused = cli(
            &root,
            &endpoint,
            &tls,
            &words(&["evidence", "anchors", "z1/ledger", "l1"]),
        );
        assert_eq!(refused.status.code(), Some(64), "{scheme}");
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("are ids"),
            "{scheme}: refused before the Host is asked"
        );
        answers.push(anchors);
    }
    assert_eq!(
        answers[0], answers[1],
        "the same anchors over REST and gRPC"
    );
}

/// `2-command-line-commands.md` (grants, host identity): an operator issues a grant, lists it,
/// revokes it in two steps from a private plan file and rotates the Host identity, over REST and
/// over gRPC; and bootstraps the recovery administrator of a volume offline.
#[test]
fn the_grant_and_identity_commands_answer_over_both_transports() {
    let root = scratch("grants-identity");
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
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://127.0.0.1:{}", host.address.port());
        let call = |args: &[&str]| call(&root, &endpoint, &tls, &words(args));
        let principal = format!("spiffe://acme/{scheme}-billing");

        let issued = call(&[
            "host",
            "grants",
            "issue",
            "--principal",
            &principal,
            "--operations",
            "catalog.read,policy.push",
            "--selector",
            "plane/control/*",
        ]);
        let grant_id = issued["grant"]["grant_id"]
            .as_str()
            .expect("a grant id")
            .to_owned();
        assert_eq!(issued["grant"]["status"], "active", "{scheme}: {issued}");
        assert_eq!(issued["grant"]["resource_types"], serde_json::json!(["*"]));
        assert!(issued["receipt"]["operation_id"].is_string(), "{scheme}");
        let listed = call(&["host", "grants", "list", "--principal", &principal]);
        assert_eq!(
            listed["grants"]
                .as_array()
                .expect("grants")
                .iter()
                .map(|grant| (grant["grant_id"].as_str(), grant["status"].as_str()))
                .collect::<Vec<_>>(),
            vec![(Some(grant_id.as_str()), Some("active"))],
            "{scheme}: {listed}"
        );

        // A two-step revocation from a private plan file; the grant is then revoked, terminally.
        let plan_file = root.join(format!("{scheme}-grant-revoke.json"));
        let planned = call(&[
            "host",
            "grants",
            "revoke",
            "plan",
            &grant_id,
            "--expected-revision",
            &listed["revision"].as_u64().expect("a revision").to_string(),
            "--out",
            plan_file.to_str().expect("UTF-8"),
        ]);
        assert_eq!(written(&plan_file), planned, "{scheme}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&plan_file)
                .expect("written")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "{scheme}: the plan is the owner's alone"
            );
        }
        call(&[
            "host",
            "grants",
            "revoke",
            "run",
            &grant_id,
            "--confirm-file",
            plan_file.to_str().expect("UTF-8"),
        ]);
        let after = call(&["host", "grants", "list", "--principal", &principal]);
        assert_eq!(after["grants"][0]["status"], "revoked", "{scheme}: {after}");
        assert!(after["revision"].as_u64() > listed["revision"].as_u64());

        // The identity rotates to its next epoch online; a rotation from a stale epoch is refused.
        let shown = call(&["host", "identity", "show"]);
        let epoch = shown["epoch"].as_u64().expect("an epoch");
        let rotated = call(&[
            "host",
            "identity",
            "rotate",
            "--expected-epoch",
            &epoch.to_string(),
        ]);
        assert!(rotated["succession"].is_string(), "{scheme}: {rotated}");
        let again = call(&["host", "identity", "show"]);
        assert_eq!(
            again["epoch"].as_u64(),
            Some(epoch + 1),
            "{scheme}: {again}"
        );
        assert_eq!(again["host_id"], shown["host_id"], "the same Host");
        assert_eq!(
            again["successions"].as_array().map(Vec::len),
            Some(usize::try_from(epoch).expect("small")),
            "{scheme}: a succession per rotation"
        );
        let stale = cli(
            &root,
            &endpoint,
            &tls,
            &words(&[
                "host",
                "identity",
                "rotate",
                "--expected-epoch",
                &epoch.to_string(),
            ]),
        );
        assert!(
            !stale.status.success(),
            "{scheme}: a stale epoch is refused"
        );
        let refusal: Value = serde_json::from_slice(&stale.stderr).expect("a JSON refusal");
        assert_eq!(
            (refusal["class"].as_str(), refusal["code"].as_str()),
            (
                Some("conflict"),
                Some(permguard_core::codes::host::REVISION_MISMATCH)
            ),
            "{scheme}: refused for its epoch, not for anything else: {refusal}"
        );
    }

    // The recovery administrator of a volume, offline: committed once, replayed exactly, and
    // another fingerprint refused.
    let volume = root.join("offline-volume");
    std::fs::create_dir_all(&volume).expect("created");
    // A Server Host volume the server has started on once, and released.
    drop(Volume::claim(&volume, AssuranceProfile::Development).expect("claimed"));
    let fingerprint = format!("sha256:{}", "ab".repeat(32));
    let bootstrap = |fingerprint: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("PERMGUARD_") {
                command.env_remove(name);
            }
        }
        command
            .current_dir(&root)
            .env("PERMGUARD_CONFIG", root.join("cli-config.yml"))
            .args(["-o", "json", "host", "grants", "bootstrap", "--volume"])
            .arg(&volume)
            .args(["--fingerprint", fingerprint])
            .output()
            .expect("the local CLI runs")
    };
    let answered = |output: &Output| -> Value {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("JSON")
    };
    let first = answered(&bootstrap(&fingerprint));
    assert_eq!(first["fingerprint"], fingerprint.as_str());
    assert_eq!(
        first["principal"],
        format!("cert:{fingerprint}").as_str(),
        "{first}"
    );
    assert_eq!(first["already_there"], false, "{first}");
    let replayed = answered(&bootstrap(&fingerprint));
    assert_eq!(replayed["already_there"], true, "{replayed}");
    let other = bootstrap(&format!("sha256:{}", "cd".repeat(32)));
    assert_eq!(other.status.code(), Some(64));
    let refusal: Value = serde_json::from_slice(&other.stderr).expect("a JSON refusal");
    assert!(
        refusal["message"]
            .as_str()
            .is_some_and(|text| text.contains("another recovery administrator")),
        "{refusal}"
    );
}
