// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The peer channel (WP-2.3): `permguard.host.v1.IdentityService/PeerChannel`, one bidirectional
//! stream per peer session, on one TLS 1.3 connection.
//!
//! The responder's half is the stream the Host listener serves: the frames the peer sends go to
//! a [`Responder`] and its answers go back, until the session is refused or the peer closes.
//! The initiator's half is [`Connection`]: one TCP connection and one TLS handshake, handed to
//! the gRPC client by a connector that answers once and never again, so a channel can never be
//! moved to another connection by a pool or a reconnect (H-11). Each side takes its RFC 9266
//! exporter from its own connection; none ever travels in a frame.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tonic::Streaming;
use tonic::codegen::BoxStream;
use tonic::transport::Endpoint;

use permguard_core::{ChannelBinding, codes};
use permguard_host::identity::Verified;
use permguard_host::membership::member::{
    Connector, Exchange, Exchanged, Target, TaskChannel, TaskOpen, TaskOpened,
};
use permguard_host::session::record::Operation;
use permguard_host::session::{
    Context, Frame, Initiator, NONCE_LIFETIME, Refusal, Request, Responder, Session,
};

use super::v1;
use super::v1::identity_service_client::IdentityServiceClient;
use super::v1::peer_frame::Frame as Wire;

/// How long the handshake may take, every frame of it, before the channel is given up.
pub const HANDSHAKE: Duration = NONCE_LIFETIME;
/// How long an established session may stay silent before the channel is closed: nothing uses
/// a session yet (WP-11 brings memberships and their leases), and a stream nobody speaks on is
/// a stream held for nothing.
pub const IDLE: Duration = Duration::from_secs(15 * 60);
/// The largest message the PeerChannel decodes: a frame and its protobuf envelope.
pub const MAX_MESSAGE_BYTES: usize = permguard_host::session::record::MAX_FRAME_BYTES + 1024;

/// The HTTP/2 path of the PeerChannel, which the listener exempts from its cumulative body
/// limit.
pub fn channel_path() -> String {
    format!(
        "/{}/PeerChannel",
        permguard_core::domains::grpc::HOST_IDENTITY_SERVICE
    )
}
/// How many frames wait to be sent on one channel.
const QUEUE: usize = 8;

/// A frame as the session reads it; `None` for a frame that carries nothing.
pub(crate) fn frame_of(frame: v1::PeerFrame) -> Option<Frame> {
    Some(match frame.frame? {
        Wire::Identity(bytes) => Frame::Identity(bytes),
        Wire::Hello(bytes) => Frame::Hello(bytes),
        Wire::Challenge(bytes) => Frame::Challenge(bytes),
        Wire::Proof(bytes) => Frame::Proof(bytes),
        Wire::Task(bytes) => Frame::Task(bytes),
        Wire::Refusal(refusal) => Frame::Refusal { code: refusal.code },
    })
}

/// A frame as the wire carries it.
pub(crate) fn wire_of(frame: Frame) -> v1::PeerFrame {
    v1::PeerFrame {
        frame: Some(match frame {
            Frame::Identity(bytes) => Wire::Identity(bytes),
            Frame::Hello(bytes) => Wire::Hello(bytes),
            Frame::Challenge(bytes) => Wire::Challenge(bytes),
            Frame::Proof(bytes) => Wire::Proof(bytes),
            Frame::Task(bytes) => Wire::Task(bytes),
            Frame::Refusal { code } => Wire::Refusal(v1::PeerRefusal { code }),
        }),
    }
}

/// What a channel's receiver yields, as a stream: the response body of the served half, the
/// request body of the initiator's.
struct Receiving<T>(mpsc::Receiver<T>);

impl<T> futures_core::Stream for Receiving<T> {
    type Item = T;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<T>> {
        self.0.poll_recv(context)
    }
}

/// The frames a stream of `receiver` yields, as a response body.
fn stream_of(
    receiver: mpsc::Receiver<Result<v1::PeerFrame, tonic::Status>>,
) -> BoxStream<v1::PeerFrame> {
    Box::pin(Receiving(receiver))
}

/// Serves one PeerChannel stream with `responder`: the handshake bounded by [`HANDSHAKE`], the
/// established session kept until the peer closes. Any refusal is sent as its code, then the
/// stream ends.
pub(crate) fn respond(
    mut responder: Responder,
    mut inbound: Streaming<v1::PeerFrame>,
) -> BoxStream<v1::PeerFrame> {
    let (sender, receiver) = mpsc::channel(QUEUE);
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + HANDSHAKE;
        loop {
            let next = if responder.session().is_some() {
                match tokio::time::timeout(IDLE, inbound.message()).await {
                    Ok(next) => next,
                    Err(_) => {
                        tracing::info!(
                            event.name = "host.session_idle",
                            component = "host",
                            "a peer session stayed silent past its idle bound; the channel is closed"
                        );
                        return;
                    }
                }
            } else {
                match tokio::time::timeout_at(deadline, inbound.message()).await {
                    Ok(next) => next,
                    Err(_) => {
                        let refusal = responder.abort("the handshake took too long");
                        let _ = sender.send(Ok(refused(&refusal))).await;
                        return;
                    }
                }
            };
            let frame = match next {
                Ok(Some(frame)) => frame,
                // The peer closed, or the connection went: nothing more to answer.
                Ok(None) | Err(_) => {
                    if responder.session().is_none() {
                        responder.abort("the channel closed before the session was established");
                    }
                    return;
                }
            };
            let Some(frame) = frame_of(frame) else {
                let refusal = responder.abort("a frame carrying nothing");
                let _ = sender.send(Ok(refused(&refusal))).await;
                return;
            };
            match responder.receive(frame) {
                Ok(frames) => {
                    for frame in frames {
                        if sender.send(Ok(wire_of(frame))).await.is_err() {
                            return;
                        }
                    }
                }
                Err(refusal) => {
                    let _ = sender.send(Ok(refused(&refusal))).await;
                    return;
                }
            }
        }
    });
    stream_of(receiver)
}

fn refused(refusal: &Refusal) -> v1::PeerFrame {
    wire_of(Frame::Refusal {
        code: refusal.code.to_owned(),
    })
}

/// Why an initiated session did not establish.
#[derive(Debug)]
pub enum PeerError {
    /// The session protocol refused: this side, or the peer.
    Refused(Refusal),
    /// The connection or the stream failed.
    Transport(String),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "the peer session was refused: {refusal}"),
            Self::Transport(detail) => write!(f, "the peer channel failed: {detail}"),
        }
    }
}

impl std::error::Error for PeerError {}

fn transport(error: impl std::fmt::Display) -> PeerError {
    PeerError::Transport(error.to_string())
}

/// The initiator's channel: one connection, one stream, the exporter of that connection.
pub struct Connection {
    binding: ChannelBinding,
    outbound: mpsc::Sender<v1::PeerFrame>,
    inbound: Streaming<v1::PeerFrame>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Connection {
    /// Connects to the Host listener at `address`, verified as `server_name` under `tls` (a
    /// client certificate in it, mutual TLS being what the listener asks), and opens the
    /// PeerChannel stream. Refused unless the connection is TLS 1.3.
    pub async fn open(
        address: SocketAddr,
        server_name: ServerName<'static>,
        tls: &rustls::ClientConfig,
    ) -> Result<Self, PeerError> {
        let mut tls = tls.clone();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpStream::connect(address).await.map_err(transport)?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(server_name.clone(), tcp)
            .await
            .map_err(transport)?;
        let binding =
            permguard_transport::channel_binding(&**stream.get_ref().1).ok_or_else(|| {
                PeerError::Refused(Refusal {
                    code: codes::host::PEER_SESSIONS_UNSERVEABLE,
                    reason: "the connection is not TLS 1.3: it exports no channel binding"
                        .to_owned(),
                })
            })?;
        // Handed over once: a second call, a reconnect or a pool growing, finds nothing, so the
        // channel lives and dies with this connection.
        let connector = once(TokioIo::new(stream));
        let authority = match &server_name {
            ServerName::DnsName(name) => name.as_ref().to_owned(),
            _ => address.to_string(),
        };
        let channel = Endpoint::from_shared(format!("http://{authority}"))
            .map_err(transport)?
            .connect_with_connector(connector)
            .await
            .map_err(transport)?;
        let (outbound, receiver) = mpsc::channel(QUEUE);
        let inbound = IdentityServiceClient::new(channel)
            .peer_channel(Receiving(receiver))
            .await
            .map_err(transport)?
            .into_inner();
        Ok(Self {
            binding,
            outbound,
            inbound,
        })
    }

    /// The exporter of this connection.
    pub fn exporter(&self) -> [u8; 32] {
        *self.binding.exporter()
    }

    /// Sends one frame.
    pub async fn send(&self, frame: Frame) -> Result<(), PeerError> {
        self.outbound
            .send(wire_of(frame))
            .await
            .map_err(|_| transport("the stream is closed"))
    }

    /// The next frame, `None` once the peer closed; a frame carrying nothing is an error.
    pub async fn receive(&mut self) -> Result<Option<Frame>, PeerError> {
        match self.inbound.message().await.map_err(transport)? {
            Some(frame) => frame_of(frame)
                .map(Some)
                .ok_or_else(|| transport("a frame carrying nothing")),
            None => Ok(None),
        }
    }
}

/// A connector that hands `connection` over once and refuses every later call: a reconnect, or
/// a pool growing, finds nothing, so a channel lives and dies with the one connection whose
/// exporter its session signs (H-11).
fn once<T: Send + 'static>(
    connection: T,
) -> impl tower::Service<
    tonic::codegen::http::Uri,
    Response = T,
    Error = std::io::Error,
    Future = impl std::future::Future<Output = Result<T, std::io::Error>> + Send,
> + Clone
+ Send
+ 'static {
    let held = Arc::new(Mutex::new(Some(connection)));
    tower::service_fn(move |_: tonic::codegen::http::Uri| {
        let held = Arc::clone(&held);
        async move {
            held.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .ok_or_else(|| std::io::Error::other("the peer channel never reconnects"))
        }
    })
}

/// A session this Host initiated, the peer as its pin verified it, and the connection it runs on.
#[derive(Debug)]
pub struct Established {
    pub session: Session,
    pub peer: Verified,
    pub connection: Connection,
}

/// Runs the initiator's handshake over `connection`, bounded by [`HANDSHAKE`].
pub async fn initiate(
    mut connection: Connection,
    context: Context,
    request: Request,
) -> Result<Established, PeerError> {
    let mut initiator = Initiator::new(context, connection.exporter(), request);
    for frame in initiator.start().map_err(PeerError::Refused)? {
        connection.send(frame).await?;
    }
    let deadline = tokio::time::Instant::now() + HANDSHAKE;
    while initiator.session().is_none() {
        let frame = match tokio::time::timeout_at(deadline, connection.receive()).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => {
                return Err(PeerError::Refused(initiator.abort(
                    "the responder closed the channel before the session was established",
                )));
            }
            Ok(Err(error)) => {
                initiator.abort(error.to_string());
                return Err(error);
            }
            Err(_) => {
                return Err(PeerError::Refused(
                    initiator.abort("the handshake took too long"),
                ));
            }
        };
        match initiator.receive(frame) {
            Ok(frames) => {
                for frame in frames {
                    connection.send(frame).await?;
                }
            }
            Err(refusal) => {
                let _ = connection
                    .send(Frame::Refusal {
                        code: refusal.code.to_owned(),
                    })
                    .await;
                return Err(PeerError::Refused(refusal));
            }
        }
    }
    let session = initiator
        .session()
        .cloned()
        .ok_or_else(|| transport("no session"))?;
    let peer = initiator
        .peer()
        .cloned()
        .ok_or_else(|| transport("no verified peer"))?;
    Ok(Established {
        session,
        peer,
        connection,
    })
}

/// The client configuration a member reaches its coordinators with (WP-4.1, owner decision of
/// 2026-10-09): the Host listener's own certificate and key as its client identity, the
/// listener's `client_ca` as the anchors a coordinator's certificate is verified against, and
/// TLS 1.3 only, since the session signs the connection's exporter. `None` without a client CA:
/// a join is then `peer_client_unconfigured`.
pub fn member_client(
    settings: Option<&permguard_core::TlsSettings>,
) -> anyhow::Result<Option<Arc<rustls::ClientConfig>>> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let Some(client_ca) = settings.client_ca() else {
        return Ok(None);
    };
    let mut roots = rustls::RootCertStore::empty();
    for certificate in permguard_transport::load_certificates(client_ca)? {
        roots.add(certificate).map_err(|error| {
            anyhow::anyhow!(
                "adding {} to the peer anchors: {error}",
                client_ca.display()
            )
        })?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| anyhow::anyhow!("the TLS versions of the peer client: {error}"))?
    .with_root_certificates(roots)
    .with_client_auth_cert(
        permguard_transport::load_certificates(settings.certificate())?,
        permguard_transport::load_key(settings.key())?,
    )
    .map_err(|error| anyhow::anyhow!("the client identity of the peer client: {error}"))?;
    Ok(Some(Arc::new(config)))
}

/// How a member reaches its coordinators (WP-4.1): one connection, one session and one request
/// per exchange, the request's digest signed by the session's transcript and its token proof, if
/// any, bound to the connection's exporter.
pub struct PeerConnector {
    context: Context,
    tls: Arc<rustls::ClientConfig>,
}

impl PeerConnector {
    /// A connector initiating with `context` over `tls`.
    pub fn new(context: Context, tls: Arc<rustls::ClientConfig>) -> Self {
        Self { context, tls }
    }

    async fn exchange_once(
        &self,
        target: Target,
        exchange: Exchange,
    ) -> Result<Exchanged, Refusal> {
        // A configured pin wins over the fingerprint an operator types: a join naming another
        // one is refused before the invitation is spent.
        if exchange.operation == Operation::Enroll
            && let Some(pinned) = self
                .context
                .peers
                .pinned_for(&target.host_id, Some(Operation::Membership))
            && pinned != target.fingerprint
        {
            return Err(Refusal {
                code: codes::common::INVALID_ARGUMENT,
                reason: "a pin already names this coordinator by another fingerprint".to_owned(),
            });
        }
        // Resolution, TCP, TLS and the stream bounded together: an address that drops packets
        // never holds a request.
        let connection = tokio::time::timeout(HANDSHAKE, async {
            let (address, name) = endpoint(&target.address).await?;
            Connection::open(address, name, &self.tls)
                .await
                .map_err(refusal_of)
        })
        .await
        .map_err(|_| unreachable_peer("the coordinator could not be reached in time"))??;
        let bytes = (exchange.build)(&connection.exporter())?;
        let request = Request {
            peer: target.host_id,
            operation: exchange.operation,
            membership_id: exchange
                .membership_id
                .as_ref()
                .map(permguard_host::identity::record::uuid_text),
            task: None,
            request_digest: Some(permguard_host::membership::record::request_digest(&bytes)),
            // Only a join brings its own pin: every other exchange reaches the coordinator by
            // the pin its membership holds, gated by the membership's status.
            pin: (exchange.operation == Operation::Enroll)
                .then(|| (target.host_id, target.fingerprint.clone())),
        };
        let Established {
            peer,
            mut connection,
            ..
        } = initiate(connection, self.context.clone(), request)
            .await
            .map_err(refusal_of)?;
        connection
            .send(Frame::Task(bytes))
            .await
            .map_err(refusal_of)?;
        match tokio::time::timeout(HANDSHAKE, connection.receive()).await {
            Ok(Ok(Some(Frame::Task(answer)))) => Ok(Exchanged { peer, answer }),
            Ok(Ok(Some(Frame::Refusal { code }))) => Err(Refusal {
                // A registered code is kept, so the operator reads why; anything else is not
                // repeated.
                code: codes::all()
                    .into_iter()
                    .map(|(_, registered)| registered)
                    .find(|registered| *registered == code)
                    .unwrap_or(codes::host::SESSION_REFUSED),
                reason: "the coordinator refused the request".to_owned(),
            }),
            Ok(Ok(_)) => Err(unreachable_peer("the coordinator answered no request")),
            Ok(Err(error)) => Err(refusal_of(error)),
            Err(_) => Err(unreachable_peer("the coordinator did not answer in time")),
        }
    }
}

/// The refusal a coordinator answered, its code kept when registered.
fn answered(code: &str, reason: &str) -> Refusal {
    Refusal {
        code: codes::all()
            .into_iter()
            .map(|(_, registered)| registered)
            .find(|registered| *registered == code)
            .unwrap_or(codes::host::SESSION_REFUSED),
        reason: reason.to_owned(),
    }
}

/// The connection of an open task session: one message, one answer, each bounded.
struct PeerTask {
    connection: Connection,
}

impl TaskChannel for PeerTask {
    fn exchange(
        &mut self,
        message: Vec<u8>,
    ) -> permguard_core::BoxFuture<'_, Result<Vec<u8>, Refusal>> {
        Box::pin(async move {
            self.connection
                .send(Frame::Task(message))
                .await
                .map_err(refusal_of)?;
            match tokio::time::timeout(HANDSHAKE, self.connection.receive()).await {
                Ok(Ok(Some(Frame::Task(answer)))) => Ok(answer),
                Ok(Ok(Some(Frame::Refusal { code }))) => {
                    Err(answered(&code, "the coordinator refused the message"))
                }
                Ok(Ok(_)) => Err(unreachable_peer("the coordinator closed the task session")),
                Ok(Err(error)) => Err(refusal_of(error)),
                Err(_) => Err(unreachable_peer("the coordinator did not answer in time")),
            }
        })
    }
}

impl PeerConnector {
    async fn open_task_once(&self, target: Target, open: TaskOpen) -> Result<TaskOpened, Refusal> {
        let connection = tokio::time::timeout(HANDSHAKE, async {
            let (address, name) = endpoint(&target.address).await?;
            Connection::open(address, name, &self.tls)
                .await
                .map_err(refusal_of)
        })
        .await
        .map_err(|_| unreachable_peer("the coordinator could not be reached in time"))??;
        // A task session reaches the coordinator by the pin its membership holds, and names the
        // one membership and the one task it serves.
        let request = Request {
            peer: target.host_id,
            operation: Operation::Task,
            membership_id: Some(permguard_host::identity::record::uuid_text(
                &open.membership_id,
            )),
            task: Some(open.task_id),
            request_digest: None,
            pin: None,
        };
        let Established {
            peer,
            mut connection,
            ..
        } = initiate(connection, self.context.clone(), request)
            .await
            .map_err(refusal_of)?;
        let exporter = connection.exporter();
        connection
            .send(Frame::Task(open.request))
            .await
            .map_err(refusal_of)?;
        match tokio::time::timeout(HANDSHAKE, connection.receive()).await {
            Ok(Ok(Some(Frame::Task(answer)))) => Ok(TaskOpened {
                peer,
                exporter,
                answer,
                channel: Box::new(PeerTask { connection }),
            }),
            Ok(Ok(Some(Frame::Refusal { code }))) => {
                Err(answered(&code, "the coordinator refused the lease"))
            }
            Ok(Ok(_)) => Err(unreachable_peer("the coordinator answered no lease")),
            Ok(Err(error)) => Err(refusal_of(error)),
            Err(_) => Err(unreachable_peer("the coordinator did not answer in time")),
        }
    }
}

impl Connector for PeerConnector {
    fn open_task(
        &self,
        target: Target,
        open: TaskOpen,
    ) -> permguard_core::BoxFuture<'_, Result<TaskOpened, Refusal>> {
        Box::pin(async move {
            tokio::time::timeout(3 * HANDSHAKE, self.open_task_once(target, open))
                .await
                .map_err(|_| unreachable_peer("the coordinator did not answer in time"))?
        })
    }

    fn exchange(
        &self,
        target: Target,
        exchange: Exchange,
    ) -> permguard_core::BoxFuture<'_, Result<Exchanged, Refusal>> {
        // The connection, the handshake and the answer each have their bound; the whole exchange
        // has one too, so no step a peer slows holds a request past it.
        Box::pin(async move {
            tokio::time::timeout(3 * HANDSHAKE, self.exchange_once(target, exchange))
                .await
                .map_err(|_| unreachable_peer("the coordinator did not answer in time"))?
        })
    }
}

fn unreachable_peer(reason: impl Into<String>) -> Refusal {
    Refusal {
        code: codes::common::UNAVAILABLE,
        reason: reason.into(),
    }
}

fn refusal_of(error: PeerError) -> Refusal {
    match error {
        PeerError::Refused(refusal) => refusal,
        PeerError::Transport(detail) => unreachable_peer(detail),
    }
}

/// The socket address and server name of `https://<host>:<port>`.
async fn endpoint(address: &str) -> Result<(SocketAddr, ServerName<'static>), Refusal> {
    let invalid = || Refusal {
        code: codes::common::INVALID_ARGUMENT,
        reason: format!("`{address}` is not `https://<host>:<port>`"),
    };
    let uri: tonic::codegen::http::Uri = address.parse().map_err(|_| invalid())?;
    if uri.scheme_str() != Some("https")
        || uri.query().is_some()
        || uri.path() != "/" && !uri.path().is_empty()
    {
        return Err(invalid());
    }
    let host = uri.host().ok_or_else(invalid)?;
    let port = uri.port_u16().ok_or_else(invalid)?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let name = ServerName::try_from(host.clone()).map_err(|_| invalid())?;
    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| unreachable_peer(format!("resolving `{address}`: {error}")))?
        .next()
        .ok_or_else(|| unreachable_peer(format!("`{address}` resolves to nothing")))?;
    Ok((resolved, name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use tower::{Service as _, ServiceExt as _};

    use super::*;

    #[tokio::test]
    async fn the_connector_hands_its_connection_over_once_and_never_reconnects() {
        let uri = tonic::codegen::http::Uri::from_static("http://peer.invalid");
        let mut connector = once("the connection");
        let first = connector
            .ready()
            .await
            .expect("ready")
            .call(uri.clone())
            .await;
        assert_eq!(first.expect("the first call"), "the connection");
        let again = connector
            .ready()
            .await
            .expect("ready")
            .call(uri.clone())
            .await
            .expect_err("a second call finds nothing");
        assert!(again.to_string().contains("never reconnects"), "{again}");
        // A clone, as a pool would hold, shares the one connection already taken.
        let cloned = connector.clone().oneshot(uri).await;
        assert!(cloned.is_err());
    }

    #[tokio::test]
    async fn a_coordinator_address_is_https_with_a_host_and_a_port() {
        let (address, name) = endpoint("https://127.0.0.1:7443")
            .await
            .expect("an address");
        assert_eq!(address.port(), 7443);
        assert_eq!(name, ServerName::try_from("127.0.0.1").expect("a name"));
        let (address, _) = endpoint("https://[::1]:7443")
            .await
            .expect("an IPv6 address");
        assert!(address.is_ipv6());
        for refused in [
            "http://127.0.0.1:7443",
            "https://127.0.0.1",
            "https://127.0.0.1:7443/path",
            "https://127.0.0.1:7443/?query",
            "127.0.0.1:7443",
            "",
        ] {
            assert_eq!(
                endpoint(refused).await.expect_err(refused).code,
                codes::common::INVALID_ARGUMENT,
                "{refused}"
            );
        }
    }

    #[test]
    fn the_channel_path_names_the_identity_service_method() {
        assert_eq!(
            channel_path(),
            format!(
                "/{}/PeerChannel",
                permguard_core::domains::grpc::HOST_IDENTITY_SERVICE
            )
        );
        const { assert!(MAX_MESSAGE_BYTES > permguard_host::session::record::MAX_FRAME_BYTES) };
    }
}
