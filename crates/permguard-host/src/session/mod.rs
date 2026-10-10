// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Peer Host sessions (WP-2.3): `hello`, `challenge` and the two proofs over the transcript
//! `permguard.host.session.v1`, on one framed channel bound to one TLS connection.
//!
//! ```text
//! initiator A                                              responder B
//! │── identity_A, hello {version, A, epoch_A, assurance, nonce_A, operation, …} ─▶│
//! │◀─ identity_B, challenge {B, epoch_B, assurance, nonce_B, expires} ────────────│
//! │── proof_A = COSE_Sign1(transcript, signer initiator) ─────────────────────────▶│
//! │◀─ proof_B = COSE_Sign1(transcript, signer responder) ─────────────────────────│
//! │                      one authenticated Host session                           │
//! ```
//!
//! | Rule                                         | Where                                                                  |
//! | -------------------------------------------- | ---------------------------------------------------------------------- |
//! | a peer is pinned, its epoch never goes back  | [`peers::Peers::accept`], before `hello` is read                       |
//! | nonces are 128 random bits                   | the OS CSPRNG; [`record`] refuses another length                       |
//! | the responder nonce is single-use, 60 s      | one challenge per channel, consumed by the first proof, timed monotonic |
//! | relay resistance                             | the transcript signs the connection's RFC 9266 exporter, never one read from a message |
//! | reflection and unknown-key-share resistance  | the transcript names both Hosts and the signer's role; each side builds the bytes it expects and compares |
//! | one exchange per connection                  | a channel carries one session; a second `hello` ends it                |
//!
//! The state machines here know nothing of the transport: they take frames and answer frames.
//! The server's `PeerChannel` drives a [`Responder`] per stream; an initiating Host drives an
//! [`Initiator`]. Any refusal ends the channel.

pub mod peers;
pub mod record;

use std::sync::Arc;
use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::audit::{AuditEvent, AuditOutcome, Fact, Subject};
use permguard_core::codes;
use permguard_core::domains::protected;
use permguard_core::metrics::{Metric, Metrics, labels};
use permguard_objects::cose::Sign1;

use crate::audit::Engine;
use crate::identity::record::{subject, uuid_text};
use crate::identity::{Identity, Verified};
use crate::time::TimeGuard;

use crate::membership::record::request_digest as membership_request_digest;
use peers::Peers;
use record::{
    Challenge, EXPORTER_BYTES, Hello, NONCE_BYTES, Operation, Presentation, Role, Transcript,
    VERSION, challenge_digest, hello_digest,
};

/// How long a responder nonce stays valid.
pub const NONCE_LIFETIME: Duration = Duration::from_secs(60);
/// The audit action of an established session.
pub const AUDIT_ESTABLISHED: &str = "host.session.established";
/// The audit action of a refused session.
pub const AUDIT_REFUSED: &str = "host.session.refused";
/// Peer sessions, established or refused (WP-2.3).
pub const SESSIONS: Metric = Metric::counter(
    "permguard_host_peer_sessions_total",
    "Peer Host sessions, both roles: established (`ok`) or refused, a refusal by its stable code.",
);
/// The longest refusal reason a record carries.
const REASON_BYTES: usize = 512;

/// One message on the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The sender's published identity, before anything else it sends.
    Identity(Vec<u8>),
    Hello(Vec<u8>),
    Challenge(Vec<u8>),
    /// A COSE_Sign1 over the transcript.
    Proof(Vec<u8>),
    /// A task message, inside an established session (WP-11).
    Task(Vec<u8>),
    /// The other side refused: a stable code, nothing more.
    Refusal {
        code: String,
    },
}

impl Frame {
    fn name(&self) -> &'static str {
        match self {
            Self::Identity(_) => "identity",
            Self::Hello(_) => "hello",
            Self::Challenge(_) => "challenge",
            Self::Proof(_) => "proof",
            Self::Task(_) => "task",
            Self::Refusal { .. } => "refusal",
        }
    }
}

/// Why a session ended before or instead of being established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// What the peer is told.
    pub code: &'static str,
    /// What the audit record and the log say; never sent.
    pub reason: String,
}

impl Refusal {
    fn session(reason: impl Into<String>) -> Self {
        Self {
            code: codes::host::SESSION_REFUSED,
            reason: reason.into(),
        }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            code: codes::common::UNAVAILABLE,
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for Refusal {}

/// What a side knew of its peer when a session was refused: recorded with the refusal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Known {
    pub peer: Option<[u8; 16]>,
    pub epoch: Option<u64>,
    pub operation: Option<Operation>,
}

/// An established session, from one side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// This side's role.
    pub role: Role,
    pub peer: [u8; 16],
    pub peer_epoch: u64,
    /// What the peer declared: for compatibility and audit only, never authority.
    pub peer_declared_assurance: AssuranceProfile,
    pub operation: Operation,
    pub membership_id: Option<String>,
    pub task: Option<String>,
    /// The digest of the one request the session serves (`enroll`, `membership`).
    pub request_digest: Option<permguard_objects::digest::Digest>,
}

/// What serves the one request of an `enroll` or `membership` session (WP-4.1): the
/// memberships, composed by the server.
pub trait Service: Send + Sync {
    /// Answers `request`, whose digest the session's transcript signed; `peer` is the verified
    /// identity of the initiator, `presentation` the bytes it was verified from and `exporter`
    /// the connection's RFC 9266 exporter.
    fn serve(
        &self,
        session: &Session,
        peer: &Verified,
        presentation: &[u8],
        exporter: &[u8; EXPORTER_BYTES],
        request: &[u8],
    ) -> Result<Vec<u8>, Refusal>;
}

/// What both sides need: this Host's identity, its pinned peers, its time and its audit.
#[derive(Clone)]
pub struct Context {
    pub identity: Arc<Identity>,
    pub peers: Arc<Peers>,
    pub time: Arc<TimeGuard>,
    /// What this Host declares in its `hello` or `challenge`.
    pub declared_assurance: AssuranceProfile,
    /// Where established and refused sessions are recorded; without one nothing is.
    pub audit: Option<Arc<Engine>>,
    /// Where [`SESSIONS`] is counted.
    pub metrics: Metrics,
    /// What serves an established session's request; without one, every request answers
    /// `not_served_yet`.
    pub service: Option<Arc<dyn Service>>,
}

impl Context {
    fn presentation(&self) -> Result<Vec<u8>, Refusal> {
        Presentation {
            document: self.identity.document(),
            successions: self.identity.successions(),
            first_public_key: self.identity.first_public_key().to_vec(),
        }
        .encode()
        .map_err(|error| Refusal::unavailable(error.to_string()))
    }

    /// Verifies a peer's presentation: an enrolling member from its own chain, any other peer
    /// from its pin (configured, a membership's, or `extra`, a join's).
    fn accept(
        &self,
        bytes: &[u8],
        operation: Option<Operation>,
        extra: Option<&([u8; 16], String)>,
    ) -> Result<Verified, Refusal> {
        let presentation =
            Presentation::decode(bytes).map_err(|error| Refusal::session(error.to_string()))?;
        let verified = match (operation, extra) {
            // Only a responder accepts an enrolling peer from its own chain; an initiator always
            // names the Host it means to reach, by pin.
            (Some(Operation::Enroll), None) => self.peers.accept_enrolling(&presentation),
            _ => self.peers.accept(&presentation, extra, operation),
        }
        .map_err(|error| match error {
            peers::PeerRefusal::Storage(_) => Refusal::unavailable(error.to_string()),
            _ => Refusal::session(error.to_string()),
        })?;
        if verified.host_id == self.identity.host_id() {
            return Err(Refusal::session(
                "the peer presents this Host's own identity",
            ));
        }
        Ok(verified)
    }

    fn prove(&self, transcript: &Transcript) -> Result<Vec<u8>, Refusal> {
        let bytes = transcript
            .encode()
            .map_err(|error| Refusal::unavailable(error.to_string()))?;
        self.identity
            .sign(protected::HOST_PROOF, bytes)
            .map_err(|error| Refusal::unavailable(error.to_string()))
    }

    /// Records the session and moves the peer's seen epoch: a session the trail cannot record
    /// is not established.
    fn establish(&self, peer: &Verified, session: &Session) -> Result<(), Refusal> {
        // An enrollment's peer is pinned by nothing yet: its chain moves no seen epoch, or any
        // client could claim a Host's id and stand in the way of its real sessions. The epoch is
        // seen from its first session under the membership's pin.
        if session.operation != Operation::Enroll {
            self.peers
                .advance(peer, self.time.now_secs())
                .map_err(|error| match error {
                    peers::PeerRefusal::Storage(_) => Refusal::unavailable(error.to_string()),
                    _ => Refusal::session(error.to_string()),
                })?;
        }
        if let Some(audit) = &self.audit {
            let peer_subject = subject(&session.peer);
            let target = uuid_text(&session.peer);
            let facts = [
                ("role", Fact::Text(session.role.as_str())),
                ("epoch", Fact::Uint(session.peer_epoch)),
                ("operation", Fact::Text(session.operation.as_str())),
                (
                    "declared_assurance",
                    Fact::Text(session.peer_declared_assurance.as_str()),
                ),
            ];
            audit
                .append(
                    &AuditEvent::new(AUDIT_ESTABLISHED, Subject::System(&peer_subject))
                        .on(&target)
                        .with_outcome(AuditOutcome::Ok)
                        .with_facts(&facts),
                    None,
                )
                .map_err(|error| Refusal::unavailable(error.to_string()))?;
        }
        self.metrics.count(&SESSIONS, &[(labels::OUTCOME, "ok")]);
        Ok(())
    }

    /// Records a refusal, with what was known of the peer, and counts it; a trail that cannot
    /// record it is logged, the session being refused anyway. Also what the listener calls for a
    /// channel it refuses before any frame is read.
    pub fn refused(&self, role: Role, known: &Known, refusal: &Refusal) {
        self.metrics.count(
            &SESSIONS,
            &[(labels::OUTCOME, "refused"), (labels::REASON, refusal.code)],
        );
        // Bounded in the log as in the trail: a reason can quote what a peer sent.
        let mut end = refusal.reason.len().min(REASON_BYTES);
        while !refusal.reason.is_char_boundary(end) {
            end -= 1;
        }
        let reason = &refusal.reason[..end];
        tracing::warn!(
            event.name = "host.session_refused",
            component = "host",
            role = role.as_str(),
            peer = known.peer.as_ref().map(uuid_text).unwrap_or_default(),
            code = refusal.code,
            reason = %reason,
            "a peer session was refused"
        );
        let Some(audit) = &self.audit else {
            return;
        };
        let peer_subject = known.peer.as_ref().map(subject);
        let target = known.peer.as_ref().map(uuid_text);
        let mut facts = vec![
            ("role", Fact::Text(role.as_str())),
            ("code", Fact::Text(refusal.code)),
            ("reason", Fact::Text(reason)),
        ];
        if let Some(epoch) = known.epoch {
            facts.push(("epoch", Fact::Uint(epoch)));
        }
        if let Some(operation) = known.operation {
            facts.push(("operation", Fact::Text(operation.as_str())));
        }
        let mut event = AuditEvent::new(
            AUDIT_REFUSED,
            peer_subject
                .as_deref()
                .map_or(Subject::Anonymous, Subject::System),
        )
        .with_outcome(AuditOutcome::Refused)
        .with_facts(&facts);
        if let Some(target) = &target {
            event = event.on(target);
        }
        if let Err(error) = audit.append(&event, None) {
            tracing::error!(
                event.name = "host.session_refusal_unrecorded",
                component = "host",
                error = %error,
                "a refused peer session could not be recorded"
            );
        }
    }
}

/// The proof `bytes` verified as `peer`'s over exactly `expected`: signed by the key of the
/// epoch `peer` presented, as a proof, over the transcript this side built. A proof over any
/// other bytes, a replayed, relayed, reflected or misaddressed one, is refused.
pub fn verify_proof(peer: &Verified, bytes: &[u8], expected: &[u8]) -> Result<(), Refusal> {
    if bytes.len() > record::MAX_FRAME_BYTES {
        return Err(Refusal::session("a proof beyond the frame bound"));
    }
    let envelope = Sign1::decode(bytes).map_err(|error| Refusal::session(error.to_string()))?;
    let header = envelope
        .header()
        .map_err(|error| Refusal::session(error.to_string()))?;
    if header.kid != peer.epoch.to_string().into_bytes() {
        return Err(Refusal::session(
            "the proof is signed at another epoch than the one presented",
        ));
    }
    let payload = envelope
        .verify(peer.suite, &peer.public_key, protected::HOST_PROOF)
        .map_err(|error| Refusal::session(format!("the proof: {error}")))?;
    if payload != expected {
        return Err(Refusal::session(
            "the proof signs another transcript than this session's",
        ));
    }
    Ok(())
}

fn nonce() -> Result<[u8; NONCE_BYTES], Refusal> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; NONCE_BYTES];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Refusal::unavailable("the OS random source refused"))?;
    Ok(bytes)
}

/// A frame this side did not expect now.
fn unexpected(frame: &Frame) -> Refusal {
    Refusal::session(format!("a {} frame out of order", frame.name()))
}

/// The other side refused.
fn refused_by_peer(code: &str) -> Refusal {
    // A registered code is quoted; anything else a peer sends is not repeated.
    let quoted = codes::all()
        .into_iter()
        .map(|(_, registered)| registered)
        .find(|registered| *registered == code)
        .unwrap_or("an unregistered code");
    Refusal {
        code: codes::host::SESSION_REFUSED,
        reason: format!("the peer refused the session: `{quoted}`"),
    }
}

/// A frame beyond [`record::MAX_FRAME_BYTES`]: refused before anything reads it.
fn oversized(frame: &Frame) -> bool {
    match frame {
        Frame::Identity(bytes)
        | Frame::Hello(bytes)
        | Frame::Challenge(bytes)
        | Frame::Proof(bytes)
        | Frame::Task(bytes) => bytes.len() > record::MAX_FRAME_BYTES,
        Frame::Refusal { code } => code.len() > record::MAX_NAME_BYTES,
    }
}

/// The challenge a responder issued, waiting for its single proof.
struct Issued {
    peer: Verified,
    /// The presentation `peer` was verified from.
    presentation: Vec<u8>,
    hello: Hello,
    hello_digest: permguard_objects::digest::Digest,
    challenge: Challenge,
    challenge_digest: permguard_objects::digest::Digest,
    /// Monotonic, from the time guard's origin.
    issued: Duration,
}

/// An established session, the initiator and the presentation it was verified from.
struct Proven {
    session: Session,
    peer: Verified,
    presentation: Vec<u8>,
}

enum Responding {
    Identity,
    /// The initiator's presentation, verified once its `hello` names the operation.
    Hello(Vec<u8>),
    Proof(Box<Issued>),
    Established(Box<Proven>),
    /// The session's one request was answered.
    Served(Session),
    Closed,
}

/// The responder's side of one channel.
pub struct Responder {
    context: Context,
    exporter: [u8; EXPORTER_BYTES],
    state: Responding,
    known: Known,
}

impl Responder {
    /// A responder on a connection whose RFC 9266 exporter is `exporter`.
    pub fn new(context: Context, exporter: [u8; EXPORTER_BYTES]) -> Self {
        Self {
            context,
            exporter,
            state: Responding::Identity,
            known: Known::default(),
        }
    }

    /// The session, once established.
    pub fn session(&self) -> Option<&Session> {
        match &self.state {
            Responding::Established(proven) => Some(&proven.session),
            Responding::Served(session) => Some(session),
            _ => None,
        }
    }

    /// Ends the channel for a reason the transport found before the session was established:
    /// a frame it could not read, a handshake that took too long. Recorded like any refusal.
    pub fn abort(&mut self, reason: impl Into<String>) -> Refusal {
        let refusal = Refusal::session(reason);
        self.state = Responding::Closed;
        self.context.refused(Role::Responder, &self.known, &refusal);
        refusal
    }

    /// Takes one frame and answers the frames to send. A refusal ends the channel: it is
    /// recorded here, and the caller sends its code and closes.
    pub fn receive(&mut self, frame: Frame) -> Result<Vec<Frame>, Refusal> {
        let state = std::mem::replace(&mut self.state, Responding::Closed);
        match self.step(state, frame) {
            Ok((state, frames)) => {
                self.state = state;
                Ok(frames)
            }
            Err(refusal) => {
                self.context.refused(Role::Responder, &self.known, &refusal);
                Err(refusal)
            }
        }
    }

    fn step(
        &mut self,
        state: Responding,
        frame: Frame,
    ) -> Result<(Responding, Vec<Frame>), Refusal> {
        if oversized(&frame) {
            return Err(Refusal::session("a frame beyond the frame bound"));
        }
        match (state, frame) {
            (_, Frame::Refusal { code }) => Err(refused_by_peer(&code)),
            (Responding::Identity, Frame::Identity(bytes)) => {
                Ok((Responding::Hello(bytes), Vec::new()))
            }
            (Responding::Hello(presentation), Frame::Hello(bytes)) => {
                let hello = Hello::decode(&bytes).map_err(|error| Refusal::session(error.0))?;
                self.known.operation = Some(hello.operation);
                let peer = self
                    .context
                    .accept(&presentation, Some(hello.operation), None)?;
                self.known.peer = Some(peer.host_id);
                self.known.epoch = Some(peer.epoch);
                let serves_a_request =
                    matches!(hello.operation, Operation::Enroll | Operation::Membership);
                if serves_a_request != hello.request_digest.is_some() {
                    return Err(Refusal::session(
                        "an enroll or membership hello names its request's digest, and only those",
                    ));
                }
                let scoped = match hello.operation {
                    // An enrollment names no membership yet, and no task.
                    Operation::Enroll => hello.membership_id.is_none() && hello.task.is_none(),
                    // A membership session names the one membership it reads, and no task.
                    Operation::Membership => hello.membership_id.is_some() && hello.task.is_none(),
                    Operation::Task => true,
                };
                if !scoped {
                    return Err(Refusal::session(
                        "the hello names a membership or a task its operation does not take",
                    ));
                }
                if hello.host != peer.host_id || hello.epoch != peer.epoch {
                    return Err(Refusal::session(
                        "the hello names another Host or epoch than the identity presented",
                    ));
                }
                // A new session is a lease of sorts: none is granted while the clock is in
                // anomaly (WP-2.12).
                let now = self
                    .context
                    .time
                    .lease_now()
                    .map_err(|anomaly| Refusal::unavailable(anomaly.to_string()))?;
                let challenge = Challenge {
                    host: self.context.identity.host_id(),
                    epoch: self.context.identity.epoch(),
                    declared_assurance: self.context.declared_assurance,
                    nonce: nonce()?,
                    expires: u64::try_from(now).unwrap_or(0) + NONCE_LIFETIME.as_secs(),
                };
                let challenge_bytes = challenge
                    .encode()
                    .map_err(|error| Refusal::unavailable(error.0))?;
                let frames = vec![
                    Frame::Identity(self.context.presentation()?),
                    Frame::Challenge(challenge_bytes.clone()),
                ];
                Ok((
                    Responding::Proof(Box::new(Issued {
                        peer,
                        presentation,
                        hello,
                        hello_digest: hello_digest(&bytes),
                        challenge,
                        challenge_digest: challenge_digest(&challenge_bytes),
                        issued: self.context.time.elapsed(),
                    })),
                    frames,
                ))
            }
            // The challenge is consumed here whatever the proof turns out to be.
            (Responding::Proof(issued), Frame::Proof(bytes)) => {
                let Issued {
                    peer,
                    presentation,
                    hello,
                    hello_digest,
                    challenge,
                    challenge_digest,
                    issued,
                } = *issued;
                if self.context.time.elapsed().saturating_sub(issued) > NONCE_LIFETIME
                    || self.context.time.now_secs() > challenge.expires
                {
                    return Err(Refusal::session(
                        "the proof arrived after the challenge expired",
                    ));
                }
                let mut transcript = Transcript {
                    initiator_host: peer.host_id,
                    responder_host: challenge.host,
                    initiator_epoch: peer.epoch,
                    responder_epoch: challenge.epoch,
                    nonce_a: hello.nonce,
                    nonce_b: challenge.nonce,
                    membership_id: hello.membership_id.clone(),
                    task: hello.task.clone(),
                    operation: hello.operation,
                    expires_at: challenge.expires,
                    tls_exporter: self.exporter,
                    hello_digest,
                    challenge_digest,
                    signer: Role::Initiator,
                    request_digest: hello.request_digest.clone(),
                };
                let expected = transcript
                    .encode()
                    .map_err(|error| Refusal::unavailable(error.0))?;
                verify_proof(&peer, &bytes, &expected)?;
                transcript.signer = Role::Responder;
                let proof = self.context.prove(&transcript)?;
                let session = Session {
                    role: Role::Responder,
                    peer: peer.host_id,
                    peer_epoch: peer.epoch,
                    peer_declared_assurance: hello.declared_assurance,
                    operation: hello.operation,
                    membership_id: hello.membership_id,
                    task: hello.task,
                    request_digest: hello.request_digest,
                };
                self.context.establish(&peer, &session)?;
                Ok((
                    Responding::Established(Box::new(Proven {
                        session,
                        peer,
                        presentation,
                    })),
                    vec![Frame::Proof(proof)],
                ))
            }
            // The one request of an `enroll` or `membership` session: its bytes are the ones the
            // transcript signed the digest of (WP-4.1).
            (Responding::Established(proven), Frame::Task(bytes))
                if proven.session.request_digest.is_some() =>
            {
                let Proven {
                    session,
                    peer,
                    presentation,
                } = *proven;
                if session.request_digest.as_ref() != Some(&membership_request_digest(&bytes)) {
                    return Err(Refusal::session(
                        "the request is not the one the transcript signed",
                    ));
                }
                let Some(service) = self.context.service.clone() else {
                    return Ok((
                        Responding::Served(session),
                        vec![Frame::Refusal {
                            code: codes::host::NOT_SERVED_YET.to_owned(),
                        }],
                    ));
                };
                let answer =
                    service.serve(&session, &peer, &presentation, &self.exporter, &bytes)?;
                Ok((Responding::Served(session), vec![Frame::Task(answer)]))
            }
            // Task sessions are served by the task transport (WP-4.3, WP-4.4): answered, the
            // session kept.
            (Responding::Established(proven), Frame::Task(_)) => Ok((
                Responding::Established(proven),
                vec![Frame::Refusal {
                    code: codes::host::NOT_SERVED_YET.to_owned(),
                }],
            )),
            (Responding::Served(_), Frame::Task(_)) => Err(Refusal::session(
                "a second request on a session that serves one",
            )),
            (Responding::Established(..) | Responding::Served(_), frame @ Frame::Hello(_)) => {
                Err(Refusal::session(format!(
                    "a {} on an established session: one exchange per connection",
                    frame.name()
                )))
            }
            (_, frame) => Err(unexpected(&frame)),
        }
    }
}

/// What an initiator asks a session for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The Host the initiator means to reach: a pinned one.
    pub peer: [u8; 16],
    pub operation: Operation,
    pub membership_id: Option<String>,
    pub task: Option<String>,
    /// The digest of the request the session will carry (`enroll`, `membership`).
    pub request_digest: Option<permguard_objects::digest::Digest>,
    /// The pin a join brings for the coordinator it names, before any membership pins it:
    /// `(host_id, first fingerprint)`.
    pub pin: Option<([u8; 16], String)>,
}

enum Initiating {
    Start,
    Identity {
        hello: Hello,
        hello_digest: permguard_objects::digest::Digest,
    },
    Challenge {
        peer: Verified,
        hello: Hello,
        hello_digest: permguard_objects::digest::Digest,
    },
    Proof {
        peer: Verified,
        expected: Vec<u8>,
        session: Session,
    },
    Established(Session, Verified),
    Closed,
}

/// The initiator's side of one channel.
pub struct Initiator {
    context: Context,
    exporter: [u8; EXPORTER_BYTES],
    request: Request,
    state: Initiating,
    known: Known,
}

impl Initiator {
    /// An initiator on a connection whose RFC 9266 exporter is `exporter`.
    pub fn new(context: Context, exporter: [u8; EXPORTER_BYTES], request: Request) -> Self {
        Self {
            context,
            exporter,
            known: Known {
                peer: Some(request.peer),
                epoch: None,
                operation: Some(request.operation),
            },
            request,
            state: Initiating::Start,
        }
    }

    /// The session, once established.
    pub fn session(&self) -> Option<&Session> {
        match &self.state {
            Initiating::Established(session, _) => Some(session),
            _ => None,
        }
    }

    /// The responder's identity, verified from its pin, once the session is established.
    pub fn peer(&self) -> Option<&Verified> {
        match &self.state {
            Initiating::Established(_, peer) => Some(peer),
            _ => None,
        }
    }

    /// The opening frames: this Host's identity and its `hello`.
    pub fn start(&mut self) -> Result<Vec<Frame>, Refusal> {
        if !matches!(self.state, Initiating::Start) {
            return Err(Refusal::session("the session was already started"));
        }
        let joining = self
            .request
            .pin
            .as_ref()
            .is_some_and(|(host_id, _)| *host_id == self.request.peer);
        if !joining
            && !self
                .context
                .peers
                .is_pinned(&self.request.peer, Some(self.request.operation))
        {
            let refusal = Refusal::session("no pin names the Host asked for");
            self.context.refused(Role::Initiator, &self.known, &refusal);
            self.state = Initiating::Closed;
            return Err(refusal);
        }
        let opening = (|| {
            let hello = Hello {
                version: VERSION,
                host: self.context.identity.host_id(),
                epoch: self.context.identity.epoch(),
                declared_assurance: self.context.declared_assurance,
                nonce: nonce()?,
                operation: self.request.operation,
                membership_id: self.request.membership_id.clone(),
                task: self.request.task.clone(),
                request_digest: self.request.request_digest.clone(),
            };
            let bytes = hello
                .encode()
                .map_err(|error| Refusal::unavailable(error.0))?;
            Ok((hello, bytes))
        })();
        let (hello, bytes) = match opening {
            Ok(opening) => opening,
            Err(refusal) => {
                self.context.refused(Role::Initiator, &self.known, &refusal);
                self.state = Initiating::Closed;
                return Err(refusal);
            }
        };
        let identity = self.context.presentation()?;
        self.state = Initiating::Identity {
            hello_digest: hello_digest(&bytes),
            hello,
        };
        Ok(vec![Frame::Identity(identity), Frame::Hello(bytes)])
    }

    /// Ends the channel for a reason the transport found before the session was established.
    /// Recorded like any refusal.
    pub fn abort(&mut self, reason: impl Into<String>) -> Refusal {
        let refusal = Refusal::session(reason);
        self.state = Initiating::Closed;
        self.context.refused(Role::Initiator, &self.known, &refusal);
        refusal
    }

    /// Takes one frame and answers the frames to send; a refusal ends the channel.
    pub fn receive(&mut self, frame: Frame) -> Result<Vec<Frame>, Refusal> {
        let state = std::mem::replace(&mut self.state, Initiating::Closed);
        match self.step(state, frame) {
            Ok((state, frames)) => {
                self.state = state;
                Ok(frames)
            }
            Err(refusal) => {
                self.context.refused(Role::Initiator, &self.known, &refusal);
                Err(refusal)
            }
        }
    }

    fn step(
        &mut self,
        state: Initiating,
        frame: Frame,
    ) -> Result<(Initiating, Vec<Frame>), Refusal> {
        if oversized(&frame) {
            return Err(Refusal::session("a frame beyond the frame bound"));
        }
        match (state, frame) {
            (_, Frame::Refusal { code }) => Err(refused_by_peer(&code)),
            (
                Initiating::Identity {
                    hello,
                    hello_digest,
                },
                Frame::Identity(bytes),
            ) => {
                let peer = self.context.accept(
                    &bytes,
                    // The responder is always verified by its pin: an enrollment is the
                    // initiator's, never the responder's.
                    Some(self.request.operation).filter(|op| *op != Operation::Enroll),
                    self.request.pin.as_ref(),
                )?;
                self.known.epoch = Some(peer.epoch);
                if peer.host_id != self.request.peer {
                    return Err(Refusal::session(
                        "the responder is another Host than the one asked for",
                    ));
                }
                Ok((
                    Initiating::Challenge {
                        peer,
                        hello,
                        hello_digest,
                    },
                    Vec::new(),
                ))
            }
            (
                Initiating::Challenge {
                    peer,
                    hello,
                    hello_digest,
                },
                Frame::Challenge(bytes),
            ) => {
                let challenge =
                    Challenge::decode(&bytes).map_err(|error| Refusal::session(error.0))?;
                if challenge.host != peer.host_id || challenge.epoch != peer.epoch {
                    return Err(Refusal::session(
                        "the challenge names another Host or epoch than the identity presented",
                    ));
                }
                let mut transcript = Transcript {
                    initiator_host: hello.host,
                    responder_host: challenge.host,
                    initiator_epoch: hello.epoch,
                    responder_epoch: challenge.epoch,
                    nonce_a: hello.nonce,
                    nonce_b: challenge.nonce,
                    membership_id: hello.membership_id.clone(),
                    task: hello.task.clone(),
                    operation: hello.operation,
                    expires_at: challenge.expires,
                    tls_exporter: self.exporter,
                    hello_digest,
                    challenge_digest: challenge_digest(&bytes),
                    signer: Role::Initiator,
                    request_digest: hello.request_digest.clone(),
                };
                let proof = self.context.prove(&transcript)?;
                transcript.signer = Role::Responder;
                let expected = transcript
                    .encode()
                    .map_err(|error| Refusal::unavailable(error.0))?;
                let session = Session {
                    role: Role::Initiator,
                    peer: peer.host_id,
                    peer_epoch: peer.epoch,
                    peer_declared_assurance: challenge.declared_assurance,
                    operation: hello.operation,
                    membership_id: hello.membership_id,
                    task: hello.task,
                    request_digest: hello.request_digest,
                };
                Ok((
                    Initiating::Proof {
                        peer,
                        expected,
                        session,
                    },
                    vec![Frame::Proof(proof)],
                ))
            }
            (
                Initiating::Proof {
                    peer,
                    expected,
                    session,
                },
                Frame::Proof(bytes),
            ) => {
                verify_proof(&peer, &bytes, &expected)?;
                self.context.establish(&peer, &session)?;
                Ok((Initiating::Established(session, peer), Vec::new()))
            }
            (_, frame) => Err(unexpected(&frame)),
        }
    }
}

#[cfg(test)]
mod tests;
