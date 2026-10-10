// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Peer Host sessions between two in-process Hosts over loopback mutual TLS (WP-2.3): the
//! PeerChannel each Host listener serves, the initiator's one-connection channel, and the H-11
//! cases, a connection changed between phases and a relayed channel, refused.

#![allow(clippy::expect_used)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::{Disclosure, Health, PeerSessionsReport, PinnedPeer, TlsSettings, codes};
use permguard_host::api::sessions::PeerSessions;
use permguard_host::api::{Assurance, Composition, Effective, HostApi, Replay};
use permguard_host::authz::{Authorization, GrantStore};
use permguard_host::identity::{Identity, Suite, directories};
use permguard_host::keys::FileKeyProvider;
use permguard_host::session::peers::Peers;
use permguard_host::session::record::Operation;
use permguard_host::session::{Context, Frame, Initiator, Request};
use permguard_host::storage::volume::Volume;
use permguard_host::time::TimeGuard;
use permguard_server::host_api::peer::{Connection, PeerError, initiate};
use permguard_transport::{Surface, load_certificates, load_key};

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-peer-session-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// A certificate authority both Hosts' listeners trust for their clients, and the certificates it
/// signed.
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

    /// A client configuration presenting `stem`'s certificate.
    fn client(&self, stem: &str) -> rustls::ClientConfig {
        let (certificate, key) = self.issue(stem, stem);
        let mut roots = rustls::RootCertStore::empty();
        for root in load_certificates(&self.authority()).expect("the authority") {
            roots.add(root).expect("a root");
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                load_certificates(&certificate).expect("the certificate"),
                load_key(&key).expect("the key"),
            )
            .expect("a client configuration")
    }
}

/// One Host: its volume, identity and time, and the listener serving its Host API.
struct Host {
    volume: Volume,
    identity: Arc<Identity>,
    time: Arc<TimeGuard>,
}

fn host(root: &Path) -> Host {
    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let identity = Identity::provision(
        &volume,
        Arc::new(FileKeyProvider::new(
            directories(&volume).expect("the identity directory").1,
        )),
        Suite::Ed25519Sha256V1,
        permguard_host::authz::store::now(),
        permguard_host::authz::store::now() * 1000,
    )
    .expect("provisioned");
    // A reset provisions the next identity in the same `keys/`.
    let keys = directories(&volume)
        .expect("the identity directory")
        .1
        .path()
        .to_path_buf();
    let identity = identity.with_provisioner(Arc::new(move |_| {
        Ok(
            Arc::new(FileKeyProvider::new(permguard_host::storage::Dir::open(
                &keys,
            )?)) as Arc<dyn permguard_host::keys::KeyProvider>,
        )
    }));
    Host {
        volume,
        identity: Arc::new(identity),
        time: Arc::new(TimeGuard::system(Duration::from_secs(30))),
    }
}

fn pin(identity: &Identity) -> PinnedPeer {
    format!(
        "{} {}",
        identity.host_id_text(),
        identity.first_fingerprint()
    )
    .parse()
    .expect("a pin")
}

impl Host {
    /// This Host's session context, pinning `peers`.
    fn context(&self, peers: &[&Identity]) -> Context {
        let pins: Vec<PinnedPeer> = peers.iter().map(|identity| pin(identity)).collect();
        Context {
            identity: Arc::clone(&self.identity),
            peers: Arc::new(Peers::open(&self.volume, &pins).expect("the peers")),
            time: Arc::clone(&self.time),
            declared_assurance: AssuranceProfile::Development,
            audit: None,
            metrics: permguard_core::Metrics::none(),
            service: None,
        }
    }

    /// Serves this Host's API on a loopback mutual-TLS listener, peer sessions as `report` says.
    async fn listen(&self, pki: &Pki, peers: &[&Identity], report: PeerSessionsReport) -> Surface {
        let (store, _) = GrantStore::open(&self.volume).expect("the grant store opens");
        let (replay, _) =
            Replay::open(&self.volume, permguard_host::authz::store::now()).expect("the replay");
        let api = Arc::new(HostApi::new(Composition {
            authorization: Arc::new(Authorization::new(Arc::clone(&store), &[])),
            store: Some(store),
            replay,
            keys: Arc::new(permguard_host::keys::registry::Registry::default()),
            health: Health::new(),
            assurance: Assurance::of(
                &permguard_core::assurance::Assurance::new(AssuranceProfile::Development, [])
                    .report(&[]),
            ),
            effective: Effective {
                revision: 0,
                settings: Vec::new(),
            },
            trail: "test".to_owned(),
            mutations: None,
            identity: Some(Arc::clone(&self.identity)),
            time: Arc::clone(&self.time),
            peer_sessions: PeerSessions {
                report,
                context: Some(self.context(peers)),
            },
            memberships: None,
        }));
        let (certificate, key) = pki.issue("server", "localhost");
        let settings = TlsSettings::new(&certificate, &key).with_client_ca(pki.authority());
        Surface::listener(
            "host-api",
            "127.0.0.1:0",
            permguard_server::host_api::routes(api, Disclosure::Full),
        )
        .tls(Some(&settings))
        .streaming([permguard_server::host_api::peer::channel_path()])
        .start()
        .await
        .expect("the listener binds")
    }
}

const SERVED: PeerSessionsReport = PeerSessionsReport {
    served: true,
    reason: None,
};

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("a name")
}

fn request(peer: &Identity) -> Request {
    Request {
        peer: peer.host_id(),
        operation: Operation::Task,
        membership_id: None,
        task: None,
        request_digest: None,
        pin: None,
    }
}

async fn open(address: SocketAddr, pki: &Pki, stem: &str) -> Connection {
    Connection::open(address, localhost(), &pki.client(stem))
        .await
        .expect("the channel opens")
}

/// The frames the responder answers to `frames`, until it has answered them all.
async fn exchange(connection: &mut Connection, frames: Vec<Frame>, answers: usize) -> Vec<Frame> {
    for frame in frames {
        connection.send(frame).await.expect("sent");
    }
    let mut received = Vec::new();
    while received.len() < answers {
        match tokio::time::timeout(Duration::from_secs(10), connection.receive())
            .await
            .expect("an answer in time")
            .expect("readable")
        {
            Some(frame) => received.push(frame),
            None => break,
        }
    }
    received
}

#[tokio::test]
async fn two_hosts_establish_a_session_over_loopback_mutual_tls_both_ways() {
    let root = scratch("both-ways");
    let pki = Pki::new(&root);
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let a_listener = a.listen(&pki, &[&b.identity], SERVED).await;
    let b_listener = b.listen(&pki, &[&a.identity], SERVED).await;

    let established = initiate(
        open(b_listener.address(), &pki, "host-a").await,
        a.context(&[&b.identity]),
        request(&b.identity),
    )
    .await
    .expect("A's session with B");
    assert_eq!(established.session.peer, b.identity.host_id());
    assert_eq!(established.session.peer_epoch, 1);
    // B recorded A's epoch once A's proof verified.
    let seen = b
        .context(&[&a.identity])
        .peers
        .seen(&a.identity.host_id())
        .expect("readable")
        .expect("A is seen by B");
    assert_eq!(seen.epoch, 1);

    // The session stays on its channel: a task message is answered there, `not_served_yet`.
    let mut connection = established.connection;
    let answered = exchange(&mut connection, vec![Frame::Task(b"t".to_vec())], 1).await;
    assert_eq!(
        answered,
        vec![Frame::Refusal {
            code: codes::host::NOT_SERVED_YET.to_owned()
        }]
    );

    initiate(
        open(a_listener.address(), &pki, "host-b").await,
        b.context(&[&a.identity]),
        request(&a.identity),
    )
    .await
    .expect("B's session with A");

    drop(connection);
    a_listener
        .stop(Duration::from_secs(5))
        .await
        .expect("stops");
    b_listener
        .stop(Duration::from_secs(5))
        .await
        .expect("stops");
}

/// H-11: a phase moved to another connection fails the session. The responder's state, its
/// nonce and the exporter it signs, belong to one channel on one connection: the proof alone on
/// a fresh connection is out of order there, and after that connection's own `hello` it signs
/// another challenge and another exporter. The relay case below is the one where the exporter
/// alone differs; the initiator's connector never reconnects (`peer::tests`).
#[tokio::test]
async fn a_connection_changed_between_phases_fails_the_session() {
    let root = scratch("connection-change");
    let pki = Pki::new(&root);
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let listener = b.listen(&pki, &[&a.identity], SERVED).await;

    let mut first = open(listener.address(), &pki, "host-a").await;
    let mut initiator = Initiator::new(
        a.context(&[&b.identity]),
        first.exporter(),
        request(&b.identity),
    );
    let opening = initiator.start().expect("started");
    let answers = exchange(&mut first, opening.clone(), 2).await;
    let mut proof = Vec::new();
    for frame in answers {
        proof.extend(initiator.receive(frame).expect("answered"));
    }
    assert!(matches!(proof.as_slice(), [Frame::Proof(_)]));

    // The proof alone, on a new connection: out of order there.
    let mut second = open(listener.address(), &pki, "host-a").await;
    assert_ne!(second.exporter(), first.exporter());
    let refused = exchange(&mut second, proof.clone(), 1).await;
    assert_eq!(
        refused,
        vec![Frame::Refusal {
            code: codes::host::SESSION_REFUSED.to_owned()
        }]
    );

    // The same opening again on a third connection, then the first connection's proof: it
    // signs the first connection's exporter and challenge, and is refused.
    let mut third = open(listener.address(), &pki, "host-a").await;
    let challenged = exchange(&mut third, opening, 2).await;
    assert!(matches!(
        challenged.as_slice(),
        [Frame::Identity(_), Frame::Challenge(_)]
    ));
    let refused = exchange(&mut third, proof, 1).await;
    assert_eq!(
        refused,
        vec![Frame::Refusal {
            code: codes::host::SESSION_REFUSED.to_owned()
        }]
    );
    assert!(
        b.context(&[&a.identity])
            .peers
            .seen(&a.identity.host_id())
            .expect("readable")
            .is_none(),
        "no session was established"
    );
    drop((first, second, third));
    listener.stop(Duration::from_secs(5)).await.expect("stops");
}

/// A relay between two connections forwards every frame: the initiator signs the exporter of its
/// own connection, the responder the exporter of the relay's, and the proof is refused. No frame
/// can carry an exporter, so none can be forwarded in its place.
#[tokio::test]
async fn a_relayed_channel_is_refused() {
    let root = scratch("relay");
    let pki = Pki::new(&root);
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let listener = b.listen(&pki, &[&a.identity], SERVED).await;

    let mine = open(listener.address(), &pki, "host-a").await;
    let mut relayed = open(listener.address(), &pki, "relay").await;
    let mut initiator = Initiator::new(
        a.context(&[&b.identity]),
        mine.exporter(),
        request(&b.identity),
    );
    let answers = exchange(&mut relayed, initiator.start().expect("started"), 2).await;
    let mut proof = Vec::new();
    for frame in answers {
        proof.extend(initiator.receive(frame).expect("answered"));
    }
    let refused = exchange(&mut relayed, proof, 1).await;
    assert_eq!(
        refused,
        vec![Frame::Refusal {
            code: codes::host::SESSION_REFUSED.to_owned()
        }]
    );
    drop((mine, relayed));
    listener.stop(Duration::from_secs(5)).await.expect("stops");
}

/// A deployment behind a TLS-terminating proxy states `admin.peer_sessions: disabled`: the
/// channel is refused with the unserveable code before any frame is read.
#[tokio::test]
async fn a_listener_that_serves_no_peer_sessions_refuses_the_channel() {
    let root = scratch("disabled");
    let pki = Pki::new(&root);
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let listener = b
        .listen(
            &pki,
            &[&a.identity],
            PeerSessionsReport {
                served: false,
                reason: Some(PeerSessionsReport::DISABLED),
            },
        )
        .await;
    let refused =
        match Connection::open(listener.address(), localhost(), &pki.client("host-a")).await {
            Err(PeerError::Transport(detail)) => detail,
            Ok(mut connection) => match connection.receive().await {
                Err(PeerError::Transport(detail)) => detail,
                other => panic!("the channel was served: {other:?}"),
            },
            Err(other) => panic!("{other}"),
        };
    assert!(
        refused.contains(codes::host::PEER_SESSIONS_UNSERVEABLE)
            || refused.contains("serves no peer sessions"),
        "{refused}"
    );
    listener.stop(Duration::from_secs(5)).await.expect("stops");
}

/// The channel is long-lived: the listener's cumulative body limit (1 MiB by default) does not
/// end it, each frame being bounded on its own.
#[tokio::test]
async fn an_established_channel_carries_more_than_the_body_limit_frame_by_frame() {
    let root = scratch("long-lived");
    let pki = Pki::new(&root);
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let listener = b.listen(&pki, &[&a.identity], SERVED).await;
    let mut connection = initiate(
        open(listener.address(), &pki, "host-a").await,
        a.context(&[&b.identity]),
        request(&b.identity),
    )
    .await
    .expect("established")
    .connection;
    for _ in 0..4 {
        let answered = exchange(&mut connection, vec![Frame::Task(vec![7; 400 * 1024])], 1).await;
        assert_eq!(
            answered,
            vec![Frame::Refusal {
                code: codes::host::NOT_SERVED_YET.to_owned()
            }]
        );
    }
    drop(connection);
    listener.stop(Duration::from_secs(5)).await.expect("stops");
}

/// One side of a membership (WP-4.1): a Host whose facade composes its memberships, its rings,
/// a mutation journal and an administrator, served on a listener whose certificate names
/// `127.0.0.1`.
struct Side {
    host: Host,
    api: Arc<HostApi>,
    listener: Surface,
}

const ADMIN: &str = "spiffe://acme/operators/root";

fn admin() -> permguard_core::authz::Actor {
    permguard_core::authz::Actor::Authenticated(permguard_core::authz::ActorContext::new(
        permguard_core::authz::Principal::new(ADMIN).expect("a principal"),
        permguard_core::authz::Credential::SanUri,
        None,
    ))
}

async fn side(
    root: &Path,
    pki: &Pki,
    stem: &str,
    ring: &'static str,
    capabilities: permguard_host::membership::Capabilities,
) -> Side {
    use permguard_core::authz::{Principal, Resource, Selector, operations};

    let host = host(root);
    let (store, _) = GrantStore::open(&host.volume).expect("the grant store opens");
    let mutations = Arc::new(
        permguard_host::operations::mutation::Mutations::open_offline(&host.volume, "test")
            .expect("the mutation journal opens"),
    );
    permguard_host::operations::grants::issue(
        &mutations,
        &store,
        permguard_host::operations::journal::Initiator::System("test".to_owned()),
        permguard_host::authz::Issue {
            principal: Principal::new(ADMIN).expect("a principal"),
            operations: operations::ALL
                .iter()
                .map(|operation| (*operation).to_owned())
                .collect(),
            selector: Selector::under(Resource::host()),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            issued_by: "test".to_owned(),
            expires_at: None,
        },
        permguard_host::authz::store::now(),
    )
    .expect("the administrator is issued");
    let (replay, _) =
        Replay::open(&host.volume, permguard_host::authz::store::now()).expect("the replay");
    let ring = Arc::new(
        permguard_host::keys::ring::Ring::open(
            &host.volume,
            ring,
            Suite::Ed25519Sha256V1,
            permguard_host::keys::ring::Policy {
                publish_ahead: Duration::from_secs(600),
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(7200),
            },
            Arc::clone(&host.time),
        )
        .expect("the ring opens")
        .with_binder(host.identity.clone()),
    );
    permguard_core::KeyManager::maintain(ring.as_ref()).expect("the ring is maintained");
    let keys = Arc::new(permguard_host::keys::registry::Registry::new(
        Some(Arc::clone(&host.identity)),
        vec![ring],
    ));
    let members = permguard_host::membership::Store::open(&host.volume).expect("the memberships");
    let peers = Arc::new(Peers::open(&host.volume, &[]).expect("the peers"));
    peers.with_source(Arc::clone(&members) as Arc<dyn permguard_host::session::peers::PinSource>);
    let context = Context {
        identity: Arc::clone(&host.identity),
        peers,
        time: Arc::clone(&host.time),
        declared_assurance: AssuranceProfile::Production,
        audit: None,
        metrics: permguard_core::Metrics::none(),
        service: Some(Arc::new(
            permguard_host::membership::service::Coordinating {
                store: Arc::clone(&members),
                mutations: Arc::clone(&mutations),
                identity: Arc::clone(&host.identity),
                keys: Arc::clone(&keys),
                capabilities: capabilities.clone(),
                time: Arc::clone(&host.time),
            },
        )),
    };
    // The listener's own certificate is the member's client identity, its client CA the
    // anchors a coordinator is verified against.
    let (certificate, key) = pki.issue(stem, "127.0.0.1");
    let settings = TlsSettings::new(&certificate, &key).with_client_ca(pki.authority());
    let connector = permguard_server::host_api::peer::member_client(Some(&settings))
        .expect("the peer client")
        .map(|tls| {
            Arc::new(permguard_server::host_api::peer::PeerConnector::new(
                context.clone(),
                tls,
            )) as Arc<dyn permguard_host::membership::member::Connector>
        });
    assert!(connector.is_some(), "a client CA makes a peer client");
    let api = Arc::new(HostApi::new(Composition {
        authorization: Arc::new(Authorization::new(Arc::clone(&store), &[])),
        store: Some(store),
        replay,
        keys,
        health: Health::new(),
        assurance: Assurance::of(
            &permguard_core::assurance::Assurance::new(AssuranceProfile::Production, [])
                .report(&[]),
        ),
        effective: Effective {
            revision: 0,
            settings: Vec::new(),
        },
        trail: "test".to_owned(),
        mutations: Some(mutations),
        identity: Some(Arc::clone(&host.identity)),
        time: Arc::clone(&host.time),
        peer_sessions: PeerSessions {
            report: SERVED,
            context: Some(context),
        },
        memberships: Some(Arc::new(permguard_host::api::members::MembershipService {
            store: members,
            capabilities,
            connector,
        })),
    }));
    let listener = Surface::listener(
        "host-api",
        "127.0.0.1:0",
        permguard_server::host_api::routes(Arc::clone(&api), Disclosure::Full),
    )
    .tls(Some(&settings))
    .streaming([permguard_server::host_api::peer::channel_path()])
    .start()
    .await
    .expect("the listener binds");
    Side {
        host,
        api,
        listener,
    }
}

fn decisions() -> permguard_host::api::members::TaskView {
    permguard_host::api::members::TaskView {
        task_id: "decisions".to_owned(),
        task_type: "decisions.ship".to_owned(),
        provider_role: None,
        consumer_role: None,
        selector: "plane/data/*".to_owned(),
        resource_types: vec!["decision".to_owned()],
        required: true,
        limits: permguard_host::api::members::LimitsView {
            max_body_bytes: 1 << 20,
            max_concurrency: 4,
            max_rate_per_minute: 600,
            max_batch_records: 1000,
            retention_seconds: 86_400,
        },
        assurance_requirements: Vec::new(),
    }
}

fn join_of(
    coordinator: &Side,
    invited: &permguard_host::api::members::InviteCreated,
    request_id: &str,
) -> permguard_host::api::members::JoinMembership {
    permguard_host::api::members::JoinMembership {
        request_id: request_id.to_owned(),
        coordinator: permguard_host::api::members::CoordinatorView {
            address: format!(
                "https://127.0.0.1:{}",
                coordinator.listener.address().port()
            ),
            host_id: coordinator.host.identity.host_id_text(),
            fingerprint: coordinator.host.identity.first_fingerprint().to_owned(),
        },
        invite_id: invited.invite_id.clone(),
        token: invited.token.clone(),
        requested: permguard_host::api::members::NarrowView {
            selector: "plane/data/*".to_owned(),
            tasks: vec![decisions()],
        },
    }
}

fn code(refusal: &permguard_host::api::Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

/// Two Hosts over loopback mutual TLS (WP-4.1): the member joins on a proven session whose
/// exporter binds its token proof, the coordinator approves, suspends and revokes, and every
/// manifest reaches the member on a sync, verified against the coordinator it pinned at join.
#[tokio::test]
async fn a_member_joins_a_coordinator_over_mutual_tls_and_follows_its_manifests() {
    use permguard_host::api::members::{
        ApproveMember, ChangeMember, CreateInvite, PlanMemberRevoke, RunMemberRevoke,
        SyncMembership,
    };
    use permguard_host::membership::Capabilities;
    use permguard_host::membership::record::{Role, TaskType};

    let root = scratch("membership");
    let pki = Pki::new(&root);
    let coordinator = side(
        &root.join("coordinator"),
        &pki,
        "coordinator",
        "host.operations",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Coordinator),
    )
    .await;
    let member = side(
        &root.join("member"),
        &pki,
        "member",
        "data.attest",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    )
    .await;

    let invited = coordinator
        .api
        .create_invite(
            &admin(),
            CreateInvite {
                request_id: "invite".to_owned(),
                selector: "plane/data/*".to_owned(),
                tasks: vec![decisions()],
                expires: None,
                expected_fingerprint: Some(member.host.identity.first_fingerprint().to_owned()),
                min_assurance: Some("production".to_owned()),
                max_uses: 1,
            },
        )
        .await
        .expect("invited");
    let joined = member
        .api
        .join_membership(&admin(), join_of(&coordinator, &invited, "join"))
        .await
        .expect("joined");
    assert_eq!(
        (joined.status.as_str(), joined.role.as_str()),
        ("pending", "member")
    );
    let id = joined.membership_id.clone();
    let pending = coordinator.api.member(&admin(), &id).expect("enrolled");
    assert_eq!(
        (pending.status.as_str(), pending.role.as_str()),
        ("pending", "coordinator")
    );
    assert_eq!(pending.member.host_id, member.host.identity.host_id_text());

    // A retried join answers what it recorded; the spent token enrols nobody else.
    let again = member
        .api
        .join_membership(&admin(), join_of(&coordinator, &invited, "join-again"))
        .await
        .expect("answered locally");
    assert_eq!(again.membership_id, id);
    let stranger = side(
        &root.join("stranger"),
        &pki,
        "stranger",
        "data.attest",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    )
    .await;
    let refused = stranger
        .api
        .join_membership(&admin(), join_of(&coordinator, &invited, "steal"))
        .await
        .expect_err("the token was used, and named another Host");
    assert_eq!(code(&refused), codes::host::ENROLLMENT_REFUSED);

    // Pending on the member until the coordinator decides.
    let synced = member
        .api
        .sync_membership(
            &admin(),
            &id,
            SyncMembership {
                request_id: "s0".to_owned(),
            },
        )
        .await
        .expect("synced");
    assert_eq!((synced.status.as_str(), synced.epoch), ("pending", 0));

    let approved = coordinator
        .api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "approve".to_owned(),
                expected_revision: pending.revision,
                narrow: None,
                lease_policy: None,
            },
        )
        .await
        .expect("approved");
    let synced = member
        .api
        .sync_membership(
            &admin(),
            &id,
            SyncMembership {
                request_id: "s1".to_owned(),
            },
        )
        .await
        .expect("synced");
    assert_eq!((synced.status.as_str(), synced.epoch), ("active", 1));
    assert_eq!(synced.manifest.as_deref(), Some(approved.manifest.as_str()));

    let suspended = coordinator
        .api
        .suspend_member(
            &admin(),
            &id,
            ChangeMember {
                request_id: "suspend".to_owned(),
                expected_revision: approved.receipt.revision,
                reason: Some("maintenance".to_owned()),
            },
        )
        .await
        .expect("suspended");
    let planned = coordinator
        .api
        .plan_member_revoke(
            &admin(),
            &id,
            PlanMemberRevoke {
                request_id: "plan".to_owned(),
                reason: "decommissioned".to_owned(),
                expected_revision: Some(suspended.receipt.revision),
            },
        )
        .await
        .expect("planned");
    coordinator
        .api
        .run_member_revoke(
            &admin(),
            &id,
            RunMemberRevoke {
                request_id: "run".to_owned(),
                plan_id: planned.plan_id,
                plan_digest: planned.plan_digest,
            },
        )
        .await
        .expect("revoked");
    // Both successors in one sync, each the exact successor of the last.
    let synced = member
        .api
        .sync_membership(
            &admin(),
            &id,
            SyncMembership {
                request_id: "s2".to_owned(),
            },
        )
        .await
        .expect("synced");
    assert_eq!((synced.status.as_str(), synced.epoch), ("revoked", 3));

    for side in [coordinator, member, stranger] {
        side.listener
            .stop(Duration::from_secs(5))
            .await
            .expect("stops");
    }
}

/// A normal identity reset on the member (WP-4.1): the coordinator, reached over mutual TLS,
/// revokes the membership and its revoked manifest is the member's receipt; nothing is orphaned.
#[tokio::test]
async fn a_members_normal_reset_is_acknowledged_by_its_coordinator() {
    use permguard_host::api::members::{ApproveMember, CreateInvite};
    use permguard_host::api::reset::{PlanIdentityReset, RunIdentityReset};
    use permguard_host::membership::Capabilities;
    use permguard_host::membership::record::{Role, TaskType};

    let root = scratch("member-reset");
    let pki = Pki::new(&root);
    let coordinator = side(
        &root.join("coordinator"),
        &pki,
        "coordinator",
        "host.operations",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Coordinator),
    )
    .await;
    let member = side(
        &root.join("member"),
        &pki,
        "member",
        "data.attest",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    )
    .await;
    let invited = coordinator
        .api
        .create_invite(
            &admin(),
            CreateInvite {
                request_id: "invite".to_owned(),
                selector: "plane/data/*".to_owned(),
                tasks: vec![decisions()],
                expires: None,
                expected_fingerprint: None,
                min_assurance: None,
                max_uses: 1,
            },
        )
        .await
        .expect("invited");
    let joined = member
        .api
        .join_membership(&admin(), join_of(&coordinator, &invited, "join"))
        .await
        .expect("joined");
    let id = joined.membership_id;
    let revision = coordinator
        .api
        .member(&admin(), &id)
        .expect("read")
        .revision;
    coordinator
        .api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "approve".to_owned(),
                expected_revision: revision,
                narrow: None,
                lease_policy: None,
            },
        )
        .await
        .expect("approved");

    let old = member.host.identity.host_id_text();
    let planned = member
        .api
        .plan_identity_reset(
            &admin(),
            PlanIdentityReset {
                request_id: "plan".to_owned(),
                mode: "normal".to_owned(),
                reason: "a drill".to_owned(),
            },
        )
        .await
        .expect("planned");
    assert_eq!(planned.memberships.len(), 1);
    assert_eq!(planned.memberships[0].step, "revoke_remote");
    let done = member
        .api
        .run_identity_reset(
            &admin(),
            RunIdentityReset {
                request_id: "run".to_owned(),
                plan_id: planned.plan_id,
                plan_digest: planned.plan_digest,
            },
        )
        .await
        .expect("reset");
    assert!(done.orphaned.is_empty(), "the coordinator acknowledged");
    assert_eq!(done.ended.len(), 1);
    assert_eq!(
        (done.ended[0].role.as_str(), done.ended[0].status.as_str()),
        ("member", "revoked")
    );
    assert!(done.ended[0].manifest.is_some(), "the receipt is kept");
    assert_eq!(done.old_host_id, old);
    assert_ne!(done.host_id, old);
    assert_eq!(
        coordinator.api.member(&admin(), &id).expect("read").status,
        "revoked"
    );
    // The member's rings retired with its identity: their public records kept.
    assert!(
        root.join(format!("member/host/keys/retired/{old}/data.attest/public"))
            .is_dir()
    );

    for side in [coordinator, member] {
        side.listener
            .stop(Duration::from_secs(5))
            .await
            .expect("stops");
    }
}
