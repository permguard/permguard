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

    /// `stem`'s certificate for `name` under `serial`, written over any earlier one; already
    /// expired when `expired` (WP-2.11).
    fn issue_serial(&self, stem: &str, name: &str, serial: u64, expired: bool) {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("parameters");
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        }
        let key = rcgen::KeyPair::generate().expect("a key");
        let issuer = rcgen::Issuer::from_params(&self.authority_params, &self.authority_key);
        let certificate = params.signed_by(&key, &issuer).expect("signed");
        self.write(&format!("{stem}.pem"), &certificate.pem());
        self.write(&format!("{stem}.key"), &key.serialize_pem());
    }

    /// A revocation list taking `serials` back, written as `stem`.
    fn revoke(&self, stem: &str, serials: &[u64]) -> PathBuf {
        let params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2099, 1, 1),
            crl_number: rcgen::SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|serial| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(*serial),
                    revocation_time: rcgen::date_time_ymd(2020, 6, 1),
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let issuer = rcgen::Issuer::from_params(&self.authority_params, &self.authority_key);
        let list = params.signed_by(&issuer).expect("the list is signed");
        self.write(stem, &list.pem().expect("PEM"))
    }

    /// A revocation list whose `nextUpdate` has passed, written as `stem`.
    fn revoke_expired(&self, stem: &str) -> PathBuf {
        let params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2021, 1, 1),
            crl_number: rcgen::SerialNumber::from(2_u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let issuer = rcgen::Issuer::from_params(&self.authority_params, &self.authority_key);
        let list = params.signed_by(&issuer).expect("the list is signed");
        self.write(stem, &list.pem().expect("PEM"))
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

/// The Host of `root`: its identity provisioned on the first open, opened again on a restart.
fn host(root: &Path) -> Host {
    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let provider: Arc<dyn permguard_host::keys::KeyProvider> = Arc::new(FileKeyProvider::new(
        directories(&volume).expect("the identity directory").1,
    ));
    let identity = if permguard_host::identity::is_provisioned(&volume).expect("read") {
        Identity::open(&volume, provider).expect("opened")
    } else {
        Identity::provision(
            &volume,
            provider,
            Suite::Ed25519Sha256V1,
            permguard_host::authz::store::now(),
            permguard_host::authz::store::now() * 1000,
        )
        .expect("provisioned")
    };
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
            listeners: Vec::new(),
            audit: None,
            memberships: None,
        }));
        pki.issue_serial("server", "localhost", SERVER_SERIAL, false);
        let settings = TlsSettings::new(
            pki.directory.join("server.pem"),
            pki.directory.join("server.key"),
        )
        .with_client_ca(pki.authority());
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

/// The serial of every test listener's own certificate, so a list can name it.
const SERVER_SERIAL: u64 = 7001;

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
        // A task session names its one membership and task (WP-4.3).
        membership_id: Some("m-1".to_owned()),
        task: Some("decisions".to_owned()),
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
    // A frame past the body limit reaches the session; this listener serves no task session, so
    // its lease request is refused (WP-4.3). The task messages of an open session, frame after
    // frame past the body limit, are in
    // `a_member_opens_a_task_session_over_mutual_tls_and_the_coordinator_lists_it`.
    let answered = exchange(&mut connection, vec![Frame::Task(vec![7; 400 * 1024])], 1).await;
    assert_eq!(
        answered,
        vec![Frame::Refusal {
            code: codes::host::NOT_SERVED_YET.to_owned()
        }]
    );
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
    members: Arc<permguard_host::membership::Store>,
    mutations: Arc<permguard_host::operations::mutation::Mutations>,
    keys: Arc<permguard_host::keys::registry::Registry>,
    connector: Option<Arc<dyn permguard_host::membership::member::Connector>>,
    tasks: Arc<permguard_host::membership::task::Tasks>,
    /// The decision log's producer on the Host's stream engine, when the side runs one (WP-5.8).
    producer: Option<Arc<DecisionProducer>>,
}

/// The decision log's producer, as the server registers it.
type DecisionProducer = permguard_stream::engine::Producer<permguard_decisions::stream::Codec>;

/// A task handler that answers each body with `echo:` before it.
struct Echo;

impl permguard_host::membership::task::TaskHandler for Echo {
    fn handle(
        &self,
        _context: &permguard_host::membership::task::TaskContext,
        body: &[u8],
    ) -> Result<Vec<u8>, permguard_host::session::Refusal> {
        Ok([b"echo:".as_slice(), body].concat())
    }
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
    side_with(root, pki, stem, ring, capabilities, None, false).await
}

/// A side running the Host's stream engine as the server composes it: the decision log's
/// producer, signed under `ring`, shipped by the member side, and its consumer behind the
/// `decisions.ship` ingest (WP-5.8).
async fn streaming_side(
    root: &Path,
    pki: &Pki,
    stem: &str,
    ring: &'static str,
    capabilities: permguard_host::membership::Capabilities,
) -> Side {
    side_with(root, pki, stem, ring, capabilities, None, true).await
}

/// A side whose listener, and peer client, check `crl` (WP-2.11).
async fn side_with(
    root: &Path,
    pki: &Pki,
    stem: &str,
    ring: &'static str,
    capabilities: permguard_host::membership::Capabilities,
    crl: Option<PathBuf>,
    streaming: bool,
) -> Side {
    use permguard_core::authz::{Principal, Resource, Selector, operations};

    let host = host(root);
    let (store, _) = GrantStore::open(&host.volume).expect("the grant store opens");
    // One audit engine for the mutations and the checkpoints, as the server composes it.
    let audit = Arc::new(
        permguard_host::audit::Engine::open(
            &host.volume,
            permguard_host::audit::Stamp {
                host_id: host.identity.host_id(),
                boot_id: host.identity.boot_id(),
                build: "test".to_owned(),
                config_revision: permguard_host::audit::config_revision(std::iter::empty()),
            },
            Arc::clone(&host.time),
            None,
        )
        .expect("the audit engine opens"),
    );
    let mutations = Arc::new(
        permguard_host::operations::mutation::Mutations::open(
            &host.volume,
            Arc::clone(&audit) as Arc<dyn permguard_host::operations::mutation::Projection>,
            Arc::clone(&host.time),
        )
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
    let open_ring = |id: &'static str| {
        let ring = Arc::new(
            permguard_host::keys::ring::Ring::open(
                &host.volume,
                id,
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
        ring
    };
    let signing = open_ring(ring);
    let mut rings = vec![Arc::clone(&signing)];
    // `host.operations` signs the plan receipts of either side (WP-3.9) and seals the trails.
    if ring != permguard_host::keys::ring::HOST_OPERATIONS {
        rings.push(open_ring(permguard_host::keys::ring::HOST_OPERATIONS));
    }
    let operations = rings
        .iter()
        .find(|held| held.id() == permguard_host::keys::ring::HOST_OPERATIONS)
        .cloned()
        .expect("the operations ring");
    // The decision log on the Host's stream engine, as the server registers it (WP-5.8).
    let engine = streaming.then(|| {
        let engine = permguard_stream::engine::Streams::open(
            &host.volume,
            &host.identity,
            Arc::clone(&operations),
            Arc::clone(&host.time),
        )
        .expect("the stream engine opens");
        let producer = engine
            .register_producer(
                permguard_decisions::stream::descriptor(),
                permguard_decisions::stream::Codec,
            )
            .expect("the producer");
        // The member seals under its `data.attest`; a coordinator produces nothing here.
        let producer = if signing.id() == permguard_host::composition::DATA_ATTEST.as_str() {
            producer
                .with_signer(Arc::clone(&signing))
                .expect("its signer")
        } else {
            producer
        };
        let consumer = engine
            .register_consumer(
                permguard_decisions::stream::descriptor(),
                permguard_decisions::stream::Codec,
            )
            .expect("the consumer");
        (Arc::new(producer), Arc::new(consumer))
    });
    if let Some(operations) = rings
        .iter()
        .find(|held| held.id() == permguard_host::keys::ring::HOST_OPERATIONS)
    {
        audit
            .seal_with(Arc::clone(operations)
                as Arc<dyn permguard_host::audit::checkpoint::CheckpointSigner>);
    }
    let keys = Arc::new(permguard_host::keys::registry::Registry::new(
        Some(Arc::clone(&host.identity)),
        rings,
    ));
    let members = permguard_host::membership::Store::open(&host.volume).expect("the memberships");
    let ship: Arc<dyn permguard_host::membership::task::TaskHandler> = match &engine {
        Some((_, consumer)) => Arc::new(permguard_stream::engine::ingest::Ingest {
            consumer: Arc::clone(consumer),
            pins: Arc::clone(&members) as Arc<dyn permguard_stream::engine::ingest::StreamPins>,
        }),
        None => Arc::new(Echo),
    };
    let tasks = Arc::new(permguard_host::membership::task::Tasks {
        handlers: permguard_host::membership::task::TaskHandlers::default()
            .register(
                permguard_host::membership::record::TaskType::DecisionsShip,
                1,
                ship,
            )
            .expect("one handler"),
        // A quiet watch heartbeats soon, so a test sees one.
        watch_heartbeat: Duration::from_millis(300),
        ..permguard_host::membership::task::Tasks::default()
    });
    let served = engine.as_ref().map(|(producer, _)| {
        Arc::new(
            permguard_stream::engine::Served::default()
                .with(permguard_decisions::stream::STREAM, Arc::clone(producer)),
        )
    });
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
                tasks: Arc::clone(&tasks),
            },
        )),
    };
    // The listener's own certificate is the member's client identity, its client CA the
    // anchors a coordinator is verified against.
    let (certificate, key) = pki.issue(stem, "127.0.0.1");
    let mut settings = TlsSettings::new(&certificate, &key).with_client_ca(pki.authority());
    if let Some(crl) = crl {
        settings = settings.with_crl(crl);
    }
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
        keys: Arc::clone(&keys),
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
        mutations: Some(Arc::clone(&mutations)),
        identity: Some(Arc::clone(&host.identity)),
        time: Arc::clone(&host.time),
        peer_sessions: PeerSessions {
            report: SERVED,
            context: Some(context),
        },
        listeners: Vec::new(),
        audit: Some(Arc::clone(&audit)),
        memberships: Some(Arc::new(permguard_host::api::members::MembershipService {
            store: Arc::clone(&members),
            capabilities,
            connector: connector.clone(),
            appraisal: permguard_host::membership::appraisal::Appraisal::default(),
            live: Arc::clone(&tasks.live),
            streams: served
                .clone()
                .map(|served| served as Arc<dyn permguard_host::composition::StreamCutovers>),
            shipping: served
                .clone()
                .map(|served| served as Arc<dyn permguard_host::composition::StreamShipping>),
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
        members,
        mutations,
        keys,
        connector,
        tasks,
        producer: engine.map(|(producer, _)| producer),
    }
}

fn decisions() -> permguard_host::api::members::TaskView {
    permguard_host::api::members::TaskView {
        version: None,
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
                assurance: None,
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
                receipt: planned.receipt,
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
                assurance: None,
            },
        )
        .await
        .expect("approved");

    member
        .api
        .sync_membership(
            &admin(),
            &id,
            permguard_host::api::members::SyncMembership {
                request_id: "sync".to_owned(),
            },
        )
        .await
        .expect("synced");
    // A session the member holds open across the reset (WP-4.9).
    let membership_id = only_membership(&coordinator);
    let mut live = acting(&member)
        .open(&membership_id)
        .await
        .expect("a lease before the reset");
    assert_eq!(
        live.send("before", b"x".to_vec()).await.expect("answered"),
        b"echo:x"
    );

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
                receipt: planned.receipt,
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
    // Recorded on both sides (WP-4.9): the coordinator's revocation, the member's reset.
    assert!(security_actions(&coordinator).contains(&"host.membership.revoked".to_owned()));
    assert!(security_actions(&member).contains(&"host.identity.reset".to_owned()));
    // The session open across the reset ends at its next frame: the membership is revoked.
    assert!(
        live.send("after", b"x".to_vec()).await.is_err(),
        "a live session outlived the revocation"
    );
    drop(live);
    let mut waited = 0;
    while !coordinator.tasks.live.of(&membership_id).is_empty() {
        assert!(waited < 100, "the coordinator kept the old session");
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += 1;
    }
    // The old membership is usable nowhere: the coordinator holds its revocation and takes no
    // task session for it (WP-4.9).
    assert!(
        acting(&member).open_task_now(&membership_id).await.is_err(),
        "no task session on a revoked membership"
    );
    assert!(coordinator.tasks.live.of(&membership_id).is_empty());

    // Restarted, the member serves its new identity and carries nothing of the old one over.
    let Side {
        host,
        api,
        listener,
        members,
        mutations,
        keys,
        connector,
        tasks,
        producer,
    } = member;
    listener.stop(Duration::from_secs(5)).await.expect("stops");
    // Everything of the old process goes, the volume's lock with it.
    drop((
        host, api, members, mutations, keys, connector, tasks, producer,
    ));
    let member = side(
        &root.join("member"),
        &pki,
        "member",
        "data.attest",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    )
    .await;
    assert_eq!(member.host.identity.host_id_text(), done.host_id);
    assert_eq!(member.host.identity.first_fingerprint(), done.fingerprint);
    let held = member.api.members(&admin(), None).expect("listed").members;
    assert_eq!(held.len(), 1, "the old membership, kept as evidence");
    assert_eq!(
        (held[0].membership_id.as_str(), held[0].status.as_str()),
        (id.as_str(), "revoked")
    );
    assert_eq!(held[0].member.host_id, old, "it names the old identity");
    assert!(
        member.tasks.live.of(&membership_id).is_empty() && held[0].last_session_at.is_none(),
        "no session under it"
    );
    // The used invitation does not admit the new identity; a new one enrolls it from zero, pending.
    let replayed = member
        .api
        .join_membership(&admin(), join_of(&coordinator, &invited, "join-again"))
        .await
        .expect_err("an invitation is used once");
    assert_eq!(
        code(&replayed),
        codes::host::ENROLLMENT_REFUSED,
        "{replayed:?}"
    );
    let again = coordinator
        .api
        .create_invite(
            &admin(),
            CreateInvite {
                request_id: "invite-again".to_owned(),
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
    let rejoined = member
        .api
        .join_membership(&admin(), join_of(&coordinator, &again, "rejoin"))
        .await
        .expect("joined");
    assert_ne!(rejoined.membership_id, id);
    let enrolled = coordinator
        .api
        .member(&admin(), &rejoined.membership_id)
        .expect("read");
    assert_eq!(enrolled.status, "pending");
    assert_eq!(enrolled.member.host_id, done.host_id);
    assert!(enrolled.manifest.is_none(), "no authority before approval");

    for side in [coordinator, member] {
        side.listener
            .stop(Duration::from_secs(5))
            .await
            .expect("stops");
    }
}

/// The actions of `side`'s security trail on the Host, as its volume holds them.
fn security_actions(side: &Side) -> Vec<String> {
    use permguard_host::audit::{Class, Engine, HOST, Stamp, query::Query};
    let engine = Engine::open(
        &side.host.volume,
        Stamp {
            host_id: side.host.identity.host_id(),
            boot_id: side.host.identity.boot_id(),
            build: "test".to_owned(),
            config_revision: permguard_host::audit::config_revision(std::iter::empty()),
        },
        Arc::clone(&side.host.time),
        None,
    )
    .expect("the audit engine opens");
    engine
        .read(
            Class::Security,
            HOST,
            &Query {
                limit: Some(permguard_host::audit::query::MAX_LIMIT),
                ..Query::default()
            },
        )
        .expect("read")
        .records
        .into_iter()
        .map(|record| record.action)
        .collect()
}

/// The one membership `side` holds.
fn only_membership(side: &Side) -> [u8; 16] {
    let held = side.members.memberships();
    assert_eq!(held.len(), 1, "one membership");
    held[0].0
}

/// The member side of `side`, acting with its own store, identity, rings and peer client.
struct Acting<'a> {
    side: &'a Side,
    capabilities: permguard_host::membership::Capabilities,
}

fn acting(side: &Side) -> Acting<'_> {
    use permguard_host::membership::Capabilities;
    use permguard_host::membership::record::{Role, TaskType};
    Acting {
        side,
        capabilities: Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    }
}

impl Acting<'_> {
    async fn open_task_now(
        &self,
        membership_id: &[u8; 16],
    ) -> Result<(), permguard_host::membership::MembershipError> {
        self.open(membership_id).await.map(drop)
    }

    async fn open(
        &self,
        membership_id: &[u8; 16],
    ) -> Result<
        permguard_host::membership::member::MemberTask,
        permguard_host::membership::MembershipError,
    > {
        let member = permguard_host::membership::member::Member {
            store: &self.side.members,
            mutations: &self.side.mutations,
            identity: &self.side.host.identity,
            rings: self.side.keys.rings(),
            capabilities: &self.capabilities,
            connector: self.side.connector.as_deref().expect("a peer client"),
            declared_assurance: AssuranceProfile::Production,
            time: &self.side.host.time,
            streams: None,
            shipping: None,
        };
        member
            .open_task(
                permguard_host::operations::journal::Initiator::System("test".to_owned()),
                membership_id,
                "decisions",
                "plane/data/zone/z1",
                Vec::new(),
            )
            .await
    }
}

/// A coordinator and a member joined, approved and synced over mutual TLS: the membership id.
async fn approved_pair(coordinator: &Side, member: &Side) -> String {
    use permguard_host::api::members::{ApproveMember, CreateInvite, SyncMembership};

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
    let id = member
        .api
        .join_membership(&admin(), join_of(coordinator, &invited, "join"))
        .await
        .expect("joined")
        .membership_id;
    let pending = coordinator.api.member(&admin(), &id).expect("enrolled");
    coordinator
        .api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "approve".to_owned(),
                expected_revision: pending.revision,
                narrow: None,
                lease_policy: None,
                assurance: None,
            },
        )
        .await
        .expect("approved");
    member
        .api
        .sync_membership(
            &admin(),
            &id,
            SyncMembership {
                request_id: "sync".to_owned(),
            },
        )
        .await
        .expect("synced");
    id
}

/// WP-4.9: while a reset is under way, the member opens no task session and the coordinator
/// accepts none, each with its own refusal; lifted, both serve again.
#[tokio::test]
async fn a_reset_under_way_neither_opens_nor_accepts_a_task_session() {
    use permguard_host::membership::record::{Role, TaskType};
    use permguard_host::membership::{Capabilities, MembershipError};

    let root = scratch("reset-fence");
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
    approved_pair(&coordinator, &member).await;
    let membership_id = only_membership(&coordinator);
    let acting = acting(&member);
    acting
        .open_task_now(&membership_id)
        .await
        .expect("a lease before any reset");

    coordinator.members.fence();
    match acting.open_task_now(&membership_id).await {
        // The member is told the code; the coordinator's reason stays in its own log.
        Err(MembershipError::Remote { code, reason }) => {
            assert_eq!(code, codes::common::UNAVAILABLE, "{reason}");
        }
        other => panic!("the coordinator under a reset accepted a session: {other:?}"),
    }
    assert!(coordinator.tasks.live.of(&membership_id).is_empty());
    coordinator.members.unfence();
    acting
        .open_task_now(&membership_id)
        .await
        .expect("a lease once the coordinator's fence is lifted");

    member.members.fence();
    match acting.open_task_now(&membership_id).await {
        Err(MembershipError::Invalid(reason)) => {
            assert!(reason.contains("identity reset"), "{reason}");
        }
        other => panic!("the member under a reset opened a session: {other:?}"),
    }
    member.members.unfence();
    acting
        .open_task_now(&membership_id)
        .await
        .expect("a lease once the member's fence is lifted");

    for side in [coordinator, member] {
        side.listener
            .stop(Duration::from_secs(5))
            .await
            .expect("stops");
    }
}

/// WP-4.9: a coordinator nobody reaches refuses a normal reset, the fence lifted and the identity
/// unchanged; an emergency reset orphans the membership and names that coordinator, which still
/// holds it active until it is revoked out of band.
#[tokio::test]
async fn an_unreachable_coordinator_refuses_a_normal_reset_and_is_named_by_an_emergency_one() {
    use permguard_host::api::reset::{PlanIdentityReset, RunIdentityReset};
    use permguard_host::membership::Capabilities;
    use permguard_host::membership::record::{Role, TaskType};

    let root = scratch("reset-orphan");
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
    let id = approved_pair(&coordinator, &member).await;
    let address = format!(
        "https://127.0.0.1:{}",
        coordinator.listener.address().port()
    );
    coordinator
        .listener
        .stop(Duration::from_secs(5))
        .await
        .expect("stops");

    let plan = |request_id: &str, mode: &str| PlanIdentityReset {
        request_id: request_id.to_owned(),
        mode: mode.to_owned(),
        reason: "a drill".to_owned(),
    };
    let planned = member
        .api
        .plan_identity_reset(&admin(), plan("plan-1", "normal"))
        .await
        .expect("planned");
    let refused = member
        .api
        .run_identity_reset(
            &admin(),
            RunIdentityReset {
                request_id: "run-1".to_owned(),
                receipt: planned.receipt,
            },
        )
        .await
        .expect_err("the coordinator is unreachable");
    assert_eq!(
        code(&refused),
        codes::host::IDENTITY_RESET_INCOMPLETE,
        "{refused:?}"
    );
    assert!(!member.host.identity.is_retired(), "the identity unchanged");
    assert!(!member.members.is_fenced(), "the fence lifted");

    let planned = member
        .api
        .plan_identity_reset(&admin(), plan("plan-2", "emergency"))
        .await
        .expect("planned");
    let done = member
        .api
        .run_identity_reset(
            &admin(),
            RunIdentityReset {
                request_id: "run-2".to_owned(),
                receipt: planned.receipt,
            },
        )
        .await
        .expect("reset");
    assert!(done.ended.is_empty(), "nothing acknowledged");
    assert_eq!(done.orphaned.len(), 1);
    assert_eq!(done.orphaned[0].membership_id, id);
    assert_eq!(
        done.orphaned[0].coordinator.host_id,
        coordinator.host.identity.host_id_text()
    );
    assert_eq!(done.orphaned[0].address.as_deref(), Some(address.as_str()));
    assert_eq!(
        member.api.member(&admin(), &id).expect("read").status,
        "orphaned"
    );
    // The coordinator never heard of it: revoked out of band, by the operator the report names.
    assert_eq!(
        coordinator.api.member(&admin(), &id).expect("read").status,
        "active"
    );
    member
        .listener
        .stop(Duration::from_secs(5))
        .await
        .expect("stops");
}

/// WP-4.3: over mutual TLS the member opens a task session to its coordinator, verifies the lease
/// bound to that connection, exchanges a message; the coordinator lists the session with the
/// member's boot id and drops it with the connection.
#[tokio::test]
async fn a_member_opens_a_task_session_over_mutual_tls_and_the_coordinator_lists_it() {
    use permguard_host::api::members::{ApproveMember, CreateInvite, SyncMembership};
    use permguard_host::membership::Capabilities;
    use permguard_host::membership::member::Member;
    use permguard_host::membership::record::{Role, TaskType};

    let root = scratch("task-session");
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
                min_assurance: None,
                max_uses: 1,
            },
        )
        .await
        .expect("invited");
    let id = member
        .api
        .join_membership(&admin(), join_of(&coordinator, &invited, "join"))
        .await
        .expect("joined")
        .membership_id;
    let pending = coordinator.api.member(&admin(), &id).expect("enrolled");
    coordinator
        .api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "approve".to_owned(),
                expected_revision: pending.revision,
                narrow: None,
                lease_policy: None,
                assurance: None,
            },
        )
        .await
        .expect("approved");
    member
        .api
        .sync_membership(
            &admin(),
            &id,
            SyncMembership {
                request_id: "sync".to_owned(),
            },
        )
        .await
        .expect("synced");

    let capabilities = Capabilities::default().declare(TaskType::DecisionsShip, Role::Member);
    let acting = Member {
        store: &member.members,
        mutations: &member.mutations,
        identity: &member.host.identity,
        rings: member.keys.rings(),
        capabilities: &capabilities,
        connector: member.connector.as_deref().expect("a peer client"),
        declared_assurance: AssuranceProfile::Production,
        time: &member.host.time,
        streams: None,
        shipping: None,
    };
    let membership_id = coordinator
        .members
        .memberships()
        .into_iter()
        .map(|(id, _)| id)
        .next()
        .expect("one membership");
    let mut task = acting
        .open_task(
            permguard_host::operations::journal::Initiator::System("test".to_owned()),
            &membership_id,
            "decisions",
            "plane/data/zone/z1",
            Vec::new(),
        )
        .await
        .expect("a lease over mutual TLS");
    assert_eq!(task.lease.member_boot_id, member.host.identity.boot_id());
    assert_eq!(
        task.lease.coordinator_boot_id,
        coordinator.host.identity.boot_id()
    );
    assert_eq!(
        task.send("r-1", b"over tls".to_vec())
            .await
            .expect("answered"),
        b"echo:over tls"
    );
    // Frame after frame on the one connection, together past the listener's body limit.
    for round in 0..4 {
        let body = vec![7_u8; 400 * 1024];
        let answer = task
            .send(&format!("big-{round}"), body.clone())
            .await
            .expect("answered");
        assert_eq!(answer.len(), body.len() + 5);
    }
    let listed = coordinator
        .api
        .member_sessions(&admin(), &id)
        .expect("listed")
        .sessions;
    assert_eq!(listed.len(), 1);
    let hex: String = member
        .host
        .identity
        .boot_id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(listed[0].member_boot_id, hex);
    assert_eq!(listed[0].task_id, "decisions");
    // The connection closed, the coordinator drops the session.
    drop(task);
    let mut waited = 0;
    while !coordinator.tasks.live.of(&membership_id).is_empty() {
        assert!(
            waited < 100,
            "the session was not dropped with its connection"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += 1;
    }

    // A watch on its own session (WP-4.4): a hint the coordinator publishes is pushed to the
    // member over the same connection, and a quiet watch heartbeats.
    let mut watching = acting
        .open_task(
            permguard_host::operations::journal::Initiator::System("test".to_owned()),
            &membership_id,
            "decisions",
            "plane/data/zone/z1",
            Vec::new(),
        )
        .await
        .expect("a second lease");
    watching
        .watch(vec![("l1".to_owned(), 1)])
        .await
        .expect("watching");
    let hint = permguard_host::membership::record::WatchHint {
        key: "l1".to_owned(),
        head: "head-2".to_owned(),
        counter: 2,
    };
    coordinator.tasks.hub.publish(
        TaskType::DecisionsShip,
        &permguard_core::authz::Resource::parse("plane/data/zone/z1").expect("a resource"),
        &hint,
    );
    let event = watching.next_event().await.expect("pushed");
    assert_eq!(event.hints, vec![hint]);
    let quiet = watching.next_event().await.expect("a heartbeat");
    assert!(quiet.hints.is_empty());
    // The session belongs to its watch: a message on it is refused over the wire too.
    match watching.send("r-late", b"late".to_vec()).await {
        Err(permguard_host::membership::MembershipError::Remote { code, .. }) => {
            assert_eq!(code, permguard_core::codes::common::INVALID_ARGUMENT);
        }
        other => panic!("refused, not {other:?}"),
    }
    let _ = (&coordinator.listener, &member.listener);
}

/// WP-2.11: the member's peer client checks the coordinator against the listener's revocation
/// list, read again for every connection: a list naming the coordinator's certificate refuses
/// the next connection of the same client, with no restart.
#[tokio::test]
async fn a_member_refuses_a_coordinator_whose_certificate_its_list_revokes() {
    let root = scratch("revoked-coordinator");
    let pki = Pki::new(&root);
    let coordinator = host(&root.join("coordinator"));
    let member = host(&root.join("member"));
    let listener = coordinator.listen(&pki, &[&member.identity], SERVED).await;
    pki.issue_serial("member", "member", 8001, false);
    let crl = pki.revoke("member.crl", &[]);
    let settings = TlsSettings::new(
        pki.directory.join("member.pem"),
        pki.directory.join("member.key"),
    )
    .with_client_ca(pki.authority())
    .with_crl(&crl);
    let client = permguard_server::host_api::peer::member_client(Some(&settings))
        .expect("the peer client builds")
        .expect("a client CA makes one");
    let config = client.config().expect("the material reads");
    // The pinned algorithm policy, as every listener's.
    let suites: Vec<String> = config
        .crypto_provider()
        .cipher_suites
        .iter()
        .map(|suite| format!("{:?}", suite.suite()))
        .collect();
    let pinned: Vec<String> = permguard_transport::CIPHER_SUITES
        .iter()
        .map(|suite| format!("{:?}", suite.suite()))
        .collect();
    assert_eq!(suites, pinned);
    Connection::open(listener.address(), localhost(), &config)
        .await
        .map(drop)
        .unwrap_or_else(|error| panic!("nothing is revoked yet: {error:?}"));

    pki.revoke("member.crl", &[SERVER_SERIAL]);
    let config = client.config().expect("the material reads again");
    match Connection::open(listener.address(), localhost(), &config).await {
        Err(PeerError::Transport(detail)) => {
            assert!(detail.contains("Revoked"), "{detail}");
        }
        Err(other) => panic!("refused for another reason: {other:?}"),
        Ok(_) => panic!("a coordinator its list revokes was trusted"),
    }
    // A list past its `nextUpdate` refuses rather than vouches, as the listener's does.
    pki.revoke_expired("member.crl");
    let config = client.config().expect("the material reads again");
    match Connection::open(listener.address(), localhost(), &config).await {
        Err(PeerError::Transport(detail)) => {
            assert!(detail.contains("revocation list expired"), "{detail}");
        }
        Err(other) => panic!("refused for another reason: {other:?}"),
        Ok(_) => panic!("an expired list vouched for the coordinator"),
    }
    let _ = &listener;
}

/// WP-2.11 Part 2 step 3: an enrolled member whose certificate is then revoked, or expired,
/// cannot establish a task session; its certificate valid again, it can. The coordinator's
/// listener refuses at the handshake, and the member's client takes the certificate on disk at
/// every connection.
#[tokio::test]
async fn an_expired_or_revoked_member_cannot_open_a_task_session() {
    use permguard_host::api::members::{ApproveMember, CreateInvite, SyncMembership};
    use permguard_host::membership::member::Member;
    use permguard_host::membership::record::{Role, TaskType};
    use permguard_host::membership::{Capabilities, MembershipError};

    const REVOKED: u64 = 9001;
    let root = scratch("revoked-member");
    let pki = Pki::new(&root);
    let crl = pki.revoke("coordinator.crl", &[REVOKED]);
    let coordinator = side_with(
        &root.join("coordinator"),
        &pki,
        "coordinator",
        "host.operations",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Coordinator),
        Some(crl),
        false,
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
                min_assurance: None,
                max_uses: 1,
            },
        )
        .await
        .expect("invited");
    let id = member
        .api
        .join_membership(&admin(), join_of(&coordinator, &invited, "join"))
        .await
        .expect("joined")
        .membership_id;
    let pending = coordinator.api.member(&admin(), &id).expect("enrolled");
    coordinator
        .api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "approve".to_owned(),
                expected_revision: pending.revision,
                narrow: None,
                lease_policy: None,
                assurance: None,
            },
        )
        .await
        .expect("approved");
    member
        .api
        .sync_membership(
            &admin(),
            &id,
            SyncMembership {
                request_id: "sync".to_owned(),
            },
        )
        .await
        .expect("synced");
    let capabilities = Capabilities::default().declare(TaskType::DecisionsShip, Role::Member);
    let acting = Member {
        store: &member.members,
        mutations: &member.mutations,
        identity: &member.host.identity,
        rings: member.keys.rings(),
        capabilities: &capabilities,
        connector: member.connector.as_deref().expect("a peer client"),
        declared_assurance: AssuranceProfile::Production,
        time: &member.host.time,
        streams: None,
        shipping: None,
    };
    let membership_id = coordinator
        .members
        .memberships()
        .into_iter()
        .map(|(id, _)| id)
        .next()
        .expect("one membership");
    let open = || {
        acting.open_task(
            permguard_host::operations::journal::Initiator::System("test".to_owned()),
            &membership_id,
            "decisions",
            "plane/data/zone/z1",
            Vec::new(),
        )
    };
    drop(open().await.expect("a lease under a valid certificate"));
    let wait_closed = || async {
        let mut waited = 0;
        while !coordinator.tasks.live.of(&membership_id).is_empty() {
            assert!(waited < 100, "the session was not dropped");
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 1;
        }
    };
    wait_closed().await;

    for (case, serial, expired) in [("revoked", REVOKED, false), ("expired", 9002, true)] {
        pki.issue_serial("member", "127.0.0.1", serial, expired);
        match open().await {
            Err(MembershipError::Remote { code, reason }) => {
                // The coordinator's handshake, never this Host's own material.
                assert_eq!(code, codes::common::UNAVAILABLE, "{case}: {reason}");
                assert!(
                    reason.contains("Certificate") || reason.contains("certificate"),
                    "{case}: {reason}"
                );
            }
            Err(other) => panic!("{case}: refused for another reason: {other}"),
            Ok(_) => panic!("{case}: a task session was established"),
        }
        assert!(
            coordinator.tasks.live.of(&membership_id).is_empty(),
            "{case}: the coordinator holds no session"
        );
    }
    // Material this Host cannot read is its own fault: another code, before any connection.
    std::fs::write(pki.directory.join("member.key"), "not a key").expect("written");
    match open().await {
        Err(MembershipError::Remote { code, .. }) => {
            assert_eq!(code, codes::host::PEER_CLIENT_UNCONFIGURED);
        }
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("a task session without a usable key"),
    }
    pki.issue_serial("member", "127.0.0.1", 9003, false);
    drop(open().await.expect("valid again, a lease"));
    let _ = (&coordinator.listener, &member.listener);
}

/// One decision record of the log, the marker of its stream: what the producer appends.
fn decision_record(seq: u64) -> serde_json::Value {
    serde_json::json!({
        "v": 1,
        "kind": "marker",
        "stream": { "id": "plane", "instance": "drain-f28" },
        "seq": seq,
        "prev": format!("sha256:{}", "0".repeat(64)),
        "at": "2026-10-15T10:00:00Z",
        "pdp": { "version": "0.1.0", "engines": { "cedar": "4.4.0" } },
        "commitments": { "alg": "HMAC-SHA256", "key_version": "v1" },
        "sampling": { "permits": "1.0" }
    })
}

/// Whether `side`'s Host is `degraded: evidence`.
fn evidence_degraded(side: &Side) -> bool {
    side.api
        .status(&admin())
        .expect("the status")
        .degraded
        .iter()
        .any(|degraded| degraded.capability == "evidence")
}

/// WP-5.8, F-28: a drain with 1 000 records the coordinator has not acknowledged ships them all
/// while it answers, and is complete; while it does not, the drain is incomplete, the stream is
/// marked `unshipped`, nothing past the acknowledgement is truncated and the Host stays
/// `degraded: evidence`; a restart on the same volume resumes in Load and, the coordinator back,
/// ships every record, clears the mark and reports the stream `shipped` to the coordinator. The
/// coordinator stops answering through the fence an identity reset takes (WP-4.9), which refuses
/// every task session with `unavailable` as an unreachable Host would leave the drain.
#[tokio::test]
async fn a_drain_ships_every_record_or_leaves_a_marked_recoverable_volume() {
    use permguard_core::Drained;
    use permguard_host::membership::Capabilities;
    use permguard_host::membership::record::{Role, TaskType};

    let root = scratch("drain-f28");
    let pki = Pki::new(&root);
    let coordinator = streaming_side(
        &root.join("coordinator"),
        &pki,
        "coordinator",
        "host.operations",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Coordinator),
    )
    .await;
    let member = streaming_side(
        &root.join("member"),
        &pki,
        "member",
        "data.attest",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    )
    .await;
    let id = approved_pair(&coordinator, &member).await;
    let membership_id = only_membership(&coordinator);
    let epoch = member.api.member(&admin(), &id).expect("read").epoch;
    let resource = permguard_core::authz::Resource::ledger("data", "zone-a", "ledger-1");
    let producer = member.producer.clone().expect("a producer");
    let run = producer
        .open_run(
            &resource,
            Some(permguard_stream::engine::Fence {
                membership_id,
                task_id: "decisions".to_owned(),
                epoch,
            }),
        )
        .expect("the run opens")
        .run_id;
    let append = |producer: &DecisionProducer, from: u64| {
        for seq in from..from + 1_000 {
            producer
                .append(&resource, &decision_record(seq))
                .expect("appended");
        }
    };
    let budget = || std::time::Instant::now() + Duration::from_secs(60);

    // Before any pass the stream owes nobody it knows of; kept subscriptions make it owed.
    append(&producer, 1);
    assert!(!member.api.shipping_behind().expect("read"));
    member
        .api
        .register_subscriptions()
        .expect("the subscriptions are kept");
    assert!(member.api.shipping_behind().expect("read"));

    // A deadline already passed ships nothing and is never complete: no pass judged anything.
    assert!(matches!(
        permguard_server::shipping::drain(&member.api, std::time::Instant::now())
            .await
            .expect("drained"),
        Drained::Incomplete(_)
    ));

    // The coordinator answers: every record is shipped, and the drain is complete.
    assert_eq!(
        permguard_server::shipping::drain(&member.api, budget())
            .await
            .expect("drained"),
        Drained::Complete
    );
    assert_eq!(
        producer.truncate_safe(&resource, &run).expect("safe"),
        Some(1_000)
    );
    assert!(!evidence_degraded(&member));

    // It does not: the drain is incomplete, the stream marked, nothing past 1 000 truncated.
    append(&producer, 1_001);
    coordinator.members.fence();
    let drained = permguard_server::shipping::drain(
        &member.api,
        std::time::Instant::now() + Duration::from_secs(2),
    )
    .await
    .expect("drained");
    assert!(matches!(drained, Drained::Incomplete(_)), "{drained:?}");
    let marked = permguard_host::composition::Unshipped {
        stream: permguard_decisions::stream::STREAM.to_owned(),
        resource: resource.to_string(),
        tail: 2_000,
        truncate_safe: 1_000,
    };
    assert_eq!(
        member.api.settle_unshipped().expect("settled"),
        vec![marked.clone()]
    );
    assert_eq!(
        producer.truncate_safe(&resource, &run).expect("safe"),
        Some(1_000)
    );
    assert!(evidence_degraded(&member));

    // Restarted on the same volume: the mark is the volume's, and the Load pass, the coordinator
    // still silent, leaves it and the degradation.
    let Side {
        host,
        api,
        listener,
        members,
        mutations,
        keys,
        connector,
        tasks,
        producer: _,
    } = member;
    drop(producer);
    listener.stop(Duration::from_secs(5)).await.expect("stops");
    drop((host, api, members, mutations, keys, connector, tasks));
    let member = streaming_side(
        &root.join("member"),
        &pki,
        "member",
        "data.attest",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    )
    .await;
    permguard_server::shipping::resume(&member.api, Duration::from_secs(2)).await;
    assert_eq!(
        member.api.settle_unshipped().expect("settled"),
        vec![marked]
    );
    assert!(evidence_degraded(&member));

    // The coordinator back: the next pass ships every record, the mark goes, the Host is no
    // longer degraded, and the coordinator holds the member's report that the stream is shipped.
    coordinator.members.unfence();
    permguard_server::shipping::resume(&member.api, Duration::from_secs(30)).await;
    assert!(member.api.settle_unshipped().expect("settled").is_empty());
    assert!(!evidence_degraded(&member));
    let producer = member.producer.clone().expect("a producer");
    assert_eq!(
        producer.truncate_safe(&resource, &run).expect("safe"),
        Some(2_000)
    );
    let reported = coordinator
        .api
        .member(&admin(), &id)
        .expect("read")
        .task_progress
        .into_iter()
        .find(|task| task.task_id == "decisions")
        .and_then(|task| task.member_reported)
        .expect("a report");
    assert_eq!(reported.resources.len(), 1);
    assert_eq!(reported.resources[0].resource, resource.to_string());
    assert_eq!(reported.resources[0].state, "shipped");
    assert_eq!(reported.resources[0].frontier.as_deref(), Some("2000"));

    for side in [coordinator, member] {
        side.listener
            .stop(Duration::from_secs(5))
            .await
            .expect("stops");
    }
}

/// WP-5.8: a Host that ships no stream drains complete at once, whatever its deadline.
#[tokio::test]
async fn a_host_shipping_no_stream_drains_complete() {
    use permguard_host::membership::Capabilities;
    use permguard_host::membership::record::{Role, TaskType};

    let root = scratch("drain-no-stream");
    let pki = Pki::new(&root);
    let alone = side(
        &root.join("alone"),
        &pki,
        "alone",
        "data.attest",
        Capabilities::default().declare(TaskType::DecisionsShip, Role::Member),
    )
    .await;
    assert_eq!(
        permguard_server::shipping::drain(&alone.api, std::time::Instant::now())
            .await
            .expect("drained"),
        permguard_core::Drained::Complete
    );
    alone
        .listener
        .stop(Duration::from_secs(5))
        .await
        .expect("stops");
}
