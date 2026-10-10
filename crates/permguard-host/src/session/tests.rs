// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use permguard_core::PinnedPeer;
use permguard_core::time::ManualClock;

use super::*;
use crate::identity::{Suite, directories};
use crate::keys::FileKeyProvider;
use crate::operations::mutation::Applying;
use crate::storage::volume::Volume;
use crate::time::ManualMonotonic;

const NOW: i64 = 1_800_000_000;
const EXPORTER: [u8; EXPORTER_BYTES] = [7; EXPORTER_BYTES];

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-session-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// One Host: its volume, its identity and the clocks its time guard reads.
struct Host {
    volume: Volume,
    identity: Arc<Identity>,
}

fn host(root: &Path) -> Host {
    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let (_, keys) = directories(&volume).expect("the directories");
    let identity = Identity::provision(
        &volume,
        Arc::new(FileKeyProvider::new(keys)),
        Suite::Ed25519Sha256V1,
        NOW as u64,
        NOW as u64 * 1000,
    )
    .expect("provisioned");
    Host {
        volume,
        identity: Arc::new(identity),
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

struct Clocks {
    wall: Arc<ManualClock>,
    monotonic: Arc<ManualMonotonic>,
    time: Arc<TimeGuard>,
}

fn clocks() -> Clocks {
    let wall = Arc::new(ManualClock::at(NOW));
    let monotonic = Arc::new(ManualMonotonic::default());
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        monotonic.clone(),
        Duration::from_secs(5),
    ));
    Clocks {
        wall,
        monotonic,
        time,
    }
}

/// `host`'s context, pinning `pinned`; its seen epochs kept in its own `peers/` beside the
/// volume.
fn context(host: &Host, pinned: &[&Identity], time: &Arc<TimeGuard>) -> Context {
    let pins: Vec<PinnedPeer> = pinned.iter().map(|identity| pin(identity)).collect();
    Context {
        identity: Arc::clone(&host.identity),
        peers: Arc::new(Peers::open(&host.volume, &pins).expect("the peers")),
        time: Arc::clone(time),
        declared_assurance: AssuranceProfile::Development,
        audit: None,
        metrics: permguard_core::Metrics::none(),
        service: None,
    }
}

struct Pair {
    a: Host,
    b: Host,
    clocks: Clocks,
}

fn pair(tag: &str) -> Pair {
    let root = scratch(tag);
    Pair {
        a: host(&root.join("a")),
        b: host(&root.join("b")),
        clocks: clocks(),
    }
}

impl Pair {
    fn initiator(&self) -> Initiator {
        self.initiator_on(EXPORTER)
    }

    fn initiator_on(&self, exporter: [u8; EXPORTER_BYTES]) -> Initiator {
        Initiator::new(
            context(&self.a, &[&self.b.identity], &self.clocks.time),
            exporter,
            Request {
                peer: self.b.identity.host_id(),
                operation: Operation::Task,
                // A task session names its one membership and task (WP-4.3).
                membership_id: Some("m-1".to_owned()),
                task: Some("decisions".to_owned()),
                request_digest: None,
                pin: None,
            },
        )
    }

    fn responder(&self) -> Responder {
        self.responder_on(EXPORTER)
    }

    fn responder_on(&self, exporter: [u8; EXPORTER_BYTES]) -> Responder {
        Responder::new(
            context(&self.b, &[&self.a.identity], &self.clocks.time),
            exporter,
        )
    }
}

/// Every frame the initiator sends, in order, with the responder's answers fed back.
fn run(initiator: &mut Initiator, responder: &mut Responder) -> Result<Vec<Frame>, Refusal> {
    let mut sent = Vec::new();
    let mut outbound = initiator.start()?;
    while !outbound.is_empty() {
        let mut inbound = Vec::new();
        for frame in outbound {
            sent.push(frame.clone());
            inbound.extend(responder.receive(frame)?);
        }
        outbound = Vec::new();
        for frame in inbound {
            outbound.extend(initiator.receive(frame)?);
        }
    }
    Ok(sent)
}

fn proof_of(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .find_map(|frame| match frame {
            Frame::Proof(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("a proof was sent")
}

#[test]
fn a_session_is_established_on_both_sides_and_the_peer_epoch_is_seen() {
    let pair = pair("established");
    let (mut initiator, mut responder) = (pair.initiator(), pair.responder());
    run(&mut initiator, &mut responder).expect("established");
    let (a, b) = (
        initiator.session().expect("the initiator's session"),
        responder.session().expect("the responder's session"),
    );
    assert_eq!(a.role, Role::Initiator);
    assert_eq!(b.role, Role::Responder);
    assert_eq!(a.peer, pair.b.identity.host_id());
    assert_eq!(b.peer, pair.a.identity.host_id());
    assert_eq!((a.peer_epoch, b.peer_epoch), (1, 1));
    assert_eq!(b.operation, Operation::Task);
    assert_eq!(b.peer_declared_assurance, AssuranceProfile::Development);
    let seen = responder
        .context
        .peers
        .seen(&pair.a.identity.host_id())
        .expect("readable")
        .expect("the initiator's epoch is seen");
    assert_eq!(
        (seen.epoch, seen.fingerprint.as_str()),
        (1, pair.a.identity.fingerprint().as_str())
    );
    assert!(
        initiator
            .context
            .peers
            .seen(&pair.b.identity.host_id())
            .expect("readable")
            .is_some()
    );
}

#[test]
fn a_replayed_proof_fails_against_a_fresh_challenge() {
    let pair = pair("replay");
    let (mut initiator, mut responder) = (pair.initiator(), pair.responder());
    let sent = run(&mut initiator, &mut responder).expect("established");
    // The attacker replays everything the initiator sent, on a new channel: the responder
    // issues another nonce, and the recorded proof signs the old one.
    let mut replayed = pair.responder();
    let mut refused = None;
    for frame in sent {
        if let Err(refusal) = replayed.receive(frame) {
            refused = Some(refusal);
            break;
        }
    }
    let refused = refused.expect("the replay is refused");
    assert_eq!(refused.code, codes::host::SESSION_REFUSED);
    assert!(refused.reason.contains("another transcript"), "{refused}");
    assert!(replayed.session().is_none());
}

#[test]
fn a_relayed_session_fails_because_each_connection_has_its_exporter() {
    let pair = pair("relay");
    // The relay terminates the initiator's TLS and opens its own to the responder: the two
    // connections export different values.
    let mut initiator = pair.initiator_on([1; EXPORTER_BYTES]);
    let mut responder = pair.responder_on([2; EXPORTER_BYTES]);
    let refused = run(&mut initiator, &mut responder).expect_err("the relay is refused");
    assert_eq!(refused.code, codes::host::SESSION_REFUSED);
    assert!(refused.reason.contains("another transcript"), "{refused}");
    assert!(responder.session().is_none() && initiator.session().is_none());
}

#[test]
fn a_reflected_proof_is_refused_by_the_side_that_signed_it() {
    // B answers with a proof over the initiator's transcript: B's own key, the right session,
    // the initiator's role. Only the signed role tells it from B's real proof.
    let pair = pair("reflection");
    let (mut initiator, _responder, inbound) = challenged(&pair);
    let mut proof_a = None;
    for frame in inbound {
        for reply in initiator.receive(frame).expect("answered") {
            if let Frame::Proof(bytes) = reply {
                proof_a = Some(bytes);
            }
        }
    }
    let proof_a = Sign1::decode(&proof_a.expect("the initiator's proof")).expect("decoded");
    let transcript = Transcript::decode(proof_a.payload_unverified()).expect("a transcript");
    assert_eq!(transcript.signer, Role::Initiator);
    let reflected = context(&pair.b, &[&pair.a.identity], &pair.clocks.time)
        .prove(&transcript)
        .expect("B signs the initiator's transcript");
    let refused = initiator
        .receive(Frame::Proof(reflected))
        .expect_err("a reflected proof is refused");
    assert_eq!(refused.code, codes::host::SESSION_REFUSED);
    assert!(refused.reason.contains("another transcript"), "{refused}");
    assert!(initiator.session().is_none());
}

#[test]
fn a_proof_for_the_same_transcript_with_the_other_role_is_refused() {
    // The roles are signed: the transcript the responder signs differs from the initiator's
    // in `signer` alone, and neither verifies as the other.
    let pair = pair("roles");
    let transcript = Transcript {
        initiator_host: pair.a.identity.host_id(),
        responder_host: pair.b.identity.host_id(),
        initiator_epoch: 1,
        responder_epoch: 1,
        nonce_a: [1; NONCE_BYTES],
        nonce_b: [2; NONCE_BYTES],
        membership_id: None,
        task: None,
        operation: Operation::Task,
        expires_at: NOW as u64 + 60,
        tls_exporter: EXPORTER,
        hello_digest: hello_digest(b"h"),
        challenge_digest: challenge_digest(b"c"),
        signer: Role::Initiator,
        request_digest: None,
    };
    let context = context(&pair.a, &[&pair.b.identity], &pair.clocks.time);
    let proof = context.prove(&transcript).expect("signed");
    let verified = crate::identity::verify_published(
        &pair.a.identity.document(),
        &pair.a.identity.successions(),
        pair.a.identity.first_public_key(),
    )
    .expect("verified");
    verify_proof(&verified, &proof, &transcript.encode().expect("encoded")).expect("verifies");
    let responder_side = Transcript {
        signer: Role::Responder,
        ..transcript
    };
    assert!(
        verify_proof(
            &verified,
            &proof,
            &responder_side.encode().expect("encoded")
        )
        .is_err()
    );
}

#[test]
fn an_unknown_key_share_fails_when_the_challenge_names_the_attacker() {
    // C is pinned by A and by B. A means to reach C; C passes A's opening on to B and B's
    // challenge back, rewritten to name C: A's proof then names C as responder, and B, which
    // builds the transcript naming itself, refuses it.
    let root = scratch("uks");
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let c = host(&root.join("c"));
    let clocks = clocks();
    let mut initiator = Initiator::new(
        context(&a, &[&b.identity, &c.identity], &clocks.time),
        EXPORTER,
        Request {
            peer: c.identity.host_id(),
            operation: Operation::Task,
            // A task session names its one membership and task (WP-4.3).
            membership_id: Some("m-1".to_owned()),
            task: Some("decisions".to_owned()),
            request_digest: None,
            pin: None,
        },
    );
    let mut responder = Responder::new(context(&b, &[&a.identity], &clocks.time), EXPORTER);
    let c_context = context(&c, &[&a.identity], &clocks.time);
    let mut to_initiator = Vec::new();
    for frame in initiator.start().expect("started") {
        to_initiator.extend(responder.receive(frame).expect("B answers"));
    }
    let mut proof = None;
    for frame in to_initiator {
        let frame = match frame {
            Frame::Identity(_) => Frame::Identity(c_context.presentation().expect("C's identity")),
            Frame::Challenge(bytes) => {
                let mut challenge = Challenge::decode(&bytes).expect("decoded");
                challenge.host = c.identity.host_id();
                Frame::Challenge(challenge.encode().expect("encoded"))
            }
            other => other,
        };
        for reply in initiator.receive(frame).expect("A answers") {
            if let Frame::Proof(bytes) = reply {
                proof = Some(bytes);
            }
        }
    }
    let refused = responder
        .receive(Frame::Proof(proof.expect("A proved to C")))
        .expect_err("B refuses a proof made for C");
    assert_eq!(refused.code, codes::host::SESSION_REFUSED);
    assert!(responder.session().is_none());
}

#[test]
fn the_initiator_refuses_a_responder_other_than_the_one_it_asked_for() {
    let root = scratch("other-responder");
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let c = host(&root.join("c"));
    let clocks = clocks();
    // A asks for C, and B answers.
    let mut initiator = Initiator::new(
        context(&a, &[&b.identity, &c.identity], &clocks.time),
        EXPORTER,
        Request {
            peer: c.identity.host_id(),
            operation: Operation::Task,
            // A task session names its one membership and task (WP-4.3).
            membership_id: Some("m-1".to_owned()),
            task: Some("decisions".to_owned()),
            request_digest: None,
            pin: None,
        },
    );
    let mut responder = Responder::new(context(&b, &[&a.identity], &clocks.time), EXPORTER);
    let refused = run(&mut initiator, &mut responder).expect_err("refused");
    assert!(refused.reason.contains("another Host"), "{refused}");
}

#[test]
fn an_unpinned_peer_is_refused_unless_it_enrolls() {
    let root = scratch("unpinned");
    let a = host(&root.join("a"));
    let b = host(&root.join("b"));
    let c = host(&root.join("c"));
    let clocks = clocks();
    let mut initiator = Initiator::new(
        context(&a, &[&b.identity], &clocks.time),
        EXPORTER,
        Request {
            peer: b.identity.host_id(),
            operation: Operation::Task,
            // A task session names its one membership and task (WP-4.3).
            membership_id: Some("m-1".to_owned()),
            task: Some("decisions".to_owned()),
            request_digest: None,
            pin: None,
        },
    );
    // B pins C, not A.
    let mut responder = Responder::new(context(&b, &[&c.identity], &clocks.time), EXPORTER);
    let opening = initiator.start().expect("started");
    // The identity is held until the hello names the operation: only an enrollment is taken
    // from an unpinned Host (WP-4.1); any other is refused before its chain is walked.
    responder
        .receive(opening[0].clone())
        .expect("held until the hello");
    let refused = responder
        .receive(opening[1].clone())
        .expect_err("an unpinned identity is refused");
    assert_eq!(refused.code, codes::host::SESSION_REFUSED);
    assert!(refused.reason.contains("no pin"), "{refused}");
    // And an initiator asked for a Host it does not pin sends nothing.
    let mut unpinned = Initiator::new(
        context(&a, &[&b.identity], &clocks.time),
        EXPORTER,
        Request {
            peer: c.identity.host_id(),
            operation: Operation::Task,
            // A task session names its one membership and task (WP-4.3).
            membership_id: Some("m-1".to_owned()),
            task: Some("decisions".to_owned()),
            request_digest: None,
            pin: None,
        },
    );
    assert!(unpinned.start().is_err());
}

#[test]
fn a_proof_after_sixty_seconds_is_refused_and_the_nonce_is_spent() {
    let pair = pair("expiry");
    let mut initiator = pair.initiator();
    let mut responder = pair.responder();
    let mut inbound = Vec::new();
    for frame in initiator.start().expect("started") {
        inbound.extend(responder.receive(frame).expect("answered"));
    }
    let mut proof = Vec::new();
    for frame in inbound {
        proof.extend(initiator.receive(frame).expect("answered"));
    }
    pair.clocks.monotonic.advance(Duration::from_secs(61));
    pair.clocks.wall.jump(61);
    let refused = responder
        .receive(proof[0].clone())
        .expect_err("an expired challenge is refused");
    assert!(refused.reason.contains("expired"), "{refused}");
    // The channel is closed: the same proof again is out of order, never a second try.
    let again = responder.receive(proof[0].clone()).expect_err("closed");
    assert!(again.reason.contains("out of order"), "{again}");
}

#[test]
fn a_proof_within_sixty_seconds_is_accepted() {
    let pair = pair("in-time");
    let mut initiator = pair.initiator();
    let mut responder = pair.responder();
    let mut inbound = Vec::new();
    for frame in initiator.start().expect("started") {
        inbound.extend(responder.receive(frame).expect("answered"));
    }
    let mut proof = Vec::new();
    for frame in inbound {
        proof.extend(initiator.receive(frame).expect("answered"));
    }
    pair.clocks.monotonic.advance(Duration::from_secs(59));
    pair.clocks.wall.jump(59);
    responder
        .receive(proof[0].clone())
        .expect("a proof inside the window is accepted");
    assert!(responder.session().is_some());
}

#[test]
fn no_challenge_is_issued_while_the_clock_is_in_anomaly() {
    let pair = pair("anomaly");
    let mut initiator = pair.initiator();
    let mut responder = pair.responder();
    pair.clocks.wall.jump(-3600);
    let opening = initiator.start().expect("started");
    responder.receive(opening[0].clone()).expect("the identity");
    let refused = responder
        .receive(opening[1].clone())
        .expect_err("no challenge in anomaly");
    assert_eq!(refused.code, codes::common::UNAVAILABLE);
}

#[test]
fn a_hello_naming_another_epoch_than_the_identity_is_refused() {
    let pair = pair("epoch-mismatch");
    let mut initiator = pair.initiator();
    let mut responder = pair.responder();
    let opening = initiator.start().expect("started");
    responder.receive(opening[0].clone()).expect("the identity");
    let Frame::Hello(bytes) = &opening[1] else {
        panic!("a hello")
    };
    let mut hello = Hello::decode(bytes).expect("decoded");
    hello.epoch = 2;
    let refused = responder
        .receive(Frame::Hello(hello.encode().expect("encoded")))
        .expect_err("refused");
    assert!(
        refused.reason.contains("another Host or epoch"),
        "{refused}"
    );
}

#[test]
fn an_established_channel_carries_one_exchange_and_a_host_serving_no_tasks_refuses_a_lease() {
    let pair = pair("one-exchange");
    // A Host serving no task sessions refuses the lease request, and the session ends (WP-4.3).
    let (mut initiator, mut responder) = (pair.initiator(), pair.responder());
    run(&mut initiator, &mut responder).expect("established");
    let refused = responder
        .receive(Frame::Task(b"anything".to_vec()))
        .expect_err("no task sessions");
    assert_eq!(refused.code, codes::host::NOT_SERVED_YET);
    assert!(responder.session().is_none());
    // One exchange per connection: a second hello on an established session is refused.
    let (mut initiator, mut responder) = (pair.initiator(), pair.responder());
    let sent = run(&mut initiator, &mut responder).expect("established");
    let hello = sent
        .iter()
        .find(|frame| matches!(frame, Frame::Hello(_)))
        .expect("a hello")
        .clone();
    let refused = responder.receive(hello).expect_err("a second exchange");
    assert!(refused.reason.contains("one exchange"), "{refused}");
    assert!(responder.session().is_none());
}

#[test]
fn frames_out_of_order_and_a_peer_refusal_end_the_channel() {
    let pair = pair("order");
    let mut initiator = pair.initiator();
    let opening = initiator.start().expect("started");
    let mut responder = pair.responder();
    // A hello before the identity.
    let refused = responder
        .receive(opening[1].clone())
        .expect_err("out of order");
    assert!(refused.reason.contains("out of order"), "{refused}");
    // A proof before any challenge.
    let mut responder = pair.responder();
    responder.receive(opening[0].clone()).expect("the identity");
    assert!(responder.receive(Frame::Proof(vec![0x80])).is_err());
    // The peer's refusal ends the initiator's side.
    let refused = initiator
        .receive(Frame::Refusal {
            code: codes::host::SESSION_REFUSED.to_owned(),
        })
        .expect_err("ended");
    assert!(refused.reason.contains("the peer refused"), "{refused}");
    assert!(initiator.start().is_err(), "a channel starts once");
}

#[test]
fn a_rotated_peer_is_accepted_through_its_succession_and_its_old_epoch_is_rollback() {
    let pair = pair("rotated");
    let old = Context::presentation(&context(&pair.a, &[&pair.b.identity], &pair.clocks.time))
        .expect("A at epoch 1");
    pair.a
        .identity
        .rotate(&Applying::for_tests(1), Some(1), NOW as u64 + 1)
        .expect("rotated");
    let (mut initiator, mut responder) = (pair.initiator(), pair.responder());
    run(&mut initiator, &mut responder).expect("established at epoch 2");
    assert_eq!(responder.session().expect("a session").peer_epoch, 2);
    // A presentation of epoch 1 now is rollback: refused once the hello names the operation.
    let mut responder = pair.responder();
    responder
        .receive(Frame::Identity(old))
        .expect("held until the hello");
    let hello = record::Hello {
        version: record::VERSION,
        host: pair.a.identity.host_id(),
        epoch: 1,
        declared_assurance: AssuranceProfile::Development,
        nonce: [7; record::NONCE_BYTES],
        operation: Operation::Task,
        // A task session names its one membership and task (WP-4.3).
        membership_id: Some("m-1".to_owned()),
        task: Some("decisions".to_owned()),
        request_digest: None,
    }
    .encode()
    .expect("encodes");
    let refused = responder
        .receive(Frame::Hello(hello))
        .expect_err("rollback");
    assert!(refused.reason.contains("rollback"), "{refused}");
}

#[test]
fn the_proof_signs_the_connections_exporter_and_never_one_read_from_a_frame() {
    // Nothing a peer sends carries an exporter: every frame the initiator sends is checked for
    // the bytes of its own, and the transcript's comes from the side's connection alone.
    let pair = pair("no-forwarded-exporter");
    let (mut initiator, mut responder) = (pair.initiator(), pair.responder());
    let sent = run(&mut initiator, &mut responder).expect("established");
    for frame in &sent {
        if let Frame::Identity(bytes) | Frame::Hello(bytes) = frame {
            assert!(
                !bytes
                    .windows(EXPORTER_BYTES)
                    .any(|window| window == EXPORTER),
                "a {} frame carries the exporter",
                frame.name()
            );
        }
    }
    let proof = Sign1::decode(&proof_of(&sent)).expect("a COSE_Sign1");
    let transcript = Transcript::decode(proof.payload_unverified()).expect("a transcript");
    assert_eq!(transcript.tls_exporter, EXPORTER);
    assert_eq!(transcript.signer, Role::Initiator);
}

#[test]
fn every_established_and_refused_session_is_recorded_in_the_security_trail() {
    use crate::audit::{Class, Engine, HOST, Stamp, trail};

    let pair = pair("audited");
    let engine = Arc::new(
        Engine::open(
            &pair.b.volume,
            Stamp {
                host_id: pair.b.identity.host_id(),
                boot_id: pair.b.identity.boot_id(),
                build: "test".to_owned(),
                config_revision: permguard_objects::digest::Digest::compute(b"settings"),
            },
            Arc::clone(&pair.clocks.time),
            None,
        )
        .expect("the engine opens"),
    );
    let counted = Arc::new(Counted::default());
    let audited = |exporter| {
        let mut context = context(&pair.b, &[&pair.a.identity], &pair.clocks.time);
        context.audit = Some(Arc::clone(&engine));
        context.metrics = permguard_core::Metrics::new(
            Arc::clone(&counted) as Arc<dyn permguard_core::metrics::Recorder>
        );
        Responder::new(context, exporter)
    };
    let mut responder = audited(EXPORTER);
    run(&mut pair.initiator(), &mut responder).expect("established");
    let mut relayed = audited([9; EXPORTER_BYTES]);
    run(&mut pair.initiator(), &mut relayed).expect_err("refused");

    let dir = engine.trail_dir(Class::Security, HOST).expect("the trail");
    let records: Vec<_> = trail::days(&dir)
        .expect("listed")
        .iter()
        .flat_map(|day| trail::read_day(&dir, day).expect("read"))
        .filter(|record| record.action.starts_with("host.session."))
        .collect();
    let actions: Vec<&str> = records
        .iter()
        .map(|record| record.action.as_str())
        .collect();
    assert_eq!(actions, vec![AUDIT_ESTABLISHED, AUDIT_REFUSED]);
    let peer = pair.a.identity.host_id_text();
    assert!(
        records
            .iter()
            .all(|record| record.target.as_deref() == Some(peer.as_str())),
        "{records:?}"
    );
    assert_eq!(
        (records[0].outcome.as_str(), records[1].outcome.as_str()),
        ("ok", "refused")
    );
    assert!(records[0].facts.contains_key("declared_assurance"));
    assert!(records[1].facts.contains_key("reason"));
    // The refusal names what was known of the peer by then: its epoch and the operation asked.
    assert!(
        records[1].facts.contains_key("epoch") && records[1].facts.contains_key("operation"),
        "{:?}",
        records[1].facts
    );
    assert_eq!(
        *counted.0.lock().expect("the counts"),
        vec![
            vec![("outcome".to_owned(), "ok".to_owned())],
            vec![
                ("outcome".to_owned(), "refused".to_owned()),
                ("reason".to_owned(), codes::host::SESSION_REFUSED.to_owned())
            ],
        ],
        "each session counted once, by outcome"
    );
}

/// The labels of every [`SESSIONS`] recording, in order.
#[derive(Debug, Default)]
struct Counted(std::sync::Mutex<Vec<Vec<(String, String)>>>);

impl permguard_core::metrics::Recorder for Counted {
    fn record(
        &self,
        metric: &permguard_core::Metric,
        labels: &[permguard_core::Label<'_>],
        _value: f64,
    ) {
        if metric.name() == SESSIONS.name() {
            self.0.lock().expect("the counts").push(
                labels
                    .iter()
                    .map(|(name, value)| (name.as_str().to_owned(), (*value).to_owned()))
                    .collect(),
            );
        }
    }

    fn snapshot(&self) -> Vec<permguard_core::Sample> {
        Vec::new()
    }
}

/// The opening and the initiator's proof, delivered up to the responder's challenge.
fn challenged(pair: &Pair) -> (Initiator, Responder, Vec<Frame>) {
    let mut initiator = pair.initiator();
    let mut responder = pair.responder();
    let mut inbound = Vec::new();
    for frame in initiator.start().expect("started") {
        inbound.extend(responder.receive(frame).expect("answered"));
    }
    (initiator, responder, inbound)
}

#[test]
fn the_nonce_expires_by_monotonic_time_and_by_the_wall_clock_alike() {
    // Only the monotonic clock moves: the challenge is older than 60 seconds.
    let monotonic = pair("expiry-monotonic");
    let (mut initiator, mut responder, inbound) = challenged(&monotonic);
    let mut proof = Vec::new();
    for frame in inbound {
        proof.extend(initiator.receive(frame).expect("answered"));
    }
    monotonic.clocks.monotonic.advance(Duration::from_secs(61));
    let refused = responder.receive(proof[0].clone()).expect_err("expired");
    assert!(refused.reason.contains("expired"), "{refused}");

    // Only the wall clock moves forward: past the challenge's `expires`.
    let pair = pair("expiry-wall");
    let (mut initiator, mut responder, inbound) = challenged(&pair);
    let mut proof = Vec::new();
    for frame in inbound {
        proof.extend(initiator.receive(frame).expect("answered"));
    }
    pair.clocks.wall.jump(61);
    let refused = responder.receive(proof[0].clone()).expect_err("expired");
    assert!(refused.reason.contains("expired"), "{refused}");
}

#[test]
fn a_challenge_naming_another_host_or_epoch_than_the_identity_presented_is_refused() {
    let pair = pair("challenge-mismatch");
    for rewrite in [
        |challenge: &mut Challenge| challenge.epoch = 2,
        |challenge: &mut Challenge| challenge.host[15] ^= 1,
    ] {
        let (mut initiator, _responder, inbound) = challenged(&pair);
        let mut refused = None;
        for frame in inbound {
            let frame = match frame {
                Frame::Challenge(bytes) => {
                    let mut challenge = Challenge::decode(&bytes).expect("decoded");
                    rewrite(&mut challenge);
                    Frame::Challenge(challenge.encode().expect("encoded"))
                }
                other => other,
            };
            if let Err(refusal) = initiator.receive(frame) {
                refused = Some(refusal);
            }
        }
        let refused = refused.expect("refused");
        assert!(
            refused.reason.contains("another Host or epoch"),
            "{refused}"
        );
    }
}

#[test]
fn a_proof_whose_kid_names_another_epoch_than_the_one_presented_is_refused() {
    // Signed by the right key over the right transcript, the envelope claiming epoch 2.
    let pair = pair("kid");
    let (mut initiator, mut responder, inbound) = challenged(&pair);
    let mut proof = Vec::new();
    for frame in inbound {
        proof.extend(initiator.receive(frame).expect("answered"));
    }
    let Frame::Proof(bytes) = &proof[0] else {
        panic!("a proof")
    };
    let honest = Sign1::decode(bytes).expect("decoded");
    let (_, keys) = directories(&pair.a.volume).expect("the keys");
    let provider = FileKeyProvider::new(keys);
    let relabelled = Sign1::sign_with(
        Suite::Ed25519Sha256V1,
        protected::HOST_PROOF,
        b"2",
        honest.payload_unverified().to_vec(),
        |to_sign| {
            crate::keys::KeyProvider::sign(&provider, "1", Suite::Ed25519Sha256V1, to_sign)
                .map_err(|error| error.to_string())
        },
    )
    .expect("signed")
    .encode()
    .expect("encoded");
    let refused = responder
        .receive(Frame::Proof(relabelled))
        .expect_err("another epoch's kid");
    assert!(refused.reason.contains("another epoch"), "{refused}");
}

#[test]
fn a_frame_beyond_its_bound_is_refused_and_a_peers_text_is_never_repeated() {
    let pair = pair("bounds");
    let mut responder = pair.responder();
    let refused = responder
        .receive(Frame::Identity(vec![0; record::MAX_FRAME_BYTES + 1]))
        .expect_err("beyond the bound");
    assert!(refused.reason.contains("frame bound"), "{refused}");

    let mut initiator = pair.initiator();
    initiator.start().expect("started");
    let refused = initiator
        .receive(Frame::Refusal {
            code: "<script>".to_owned(),
        })
        .expect_err("ended");
    assert!(!refused.reason.contains("<script>"), "{refused}");
    assert!(refused.reason.contains("an unregistered code"), "{refused}");

    let mut initiator = pair.initiator();
    initiator.start().expect("started");
    let refused = initiator
        .receive(Frame::Refusal {
            code: codes::host::SESSION_REFUSED.to_owned(),
        })
        .expect_err("ended");
    assert!(
        refused.reason.contains(codes::host::SESSION_REFUSED),
        "a registered code is quoted: {refused}"
    );
}

/// A's initiator for `operation`, carrying `digest` and naming `membership_id`, pinning B by the
/// join's own pin.
fn scoped(
    pair: &Pair,
    operation: Operation,
    membership_id: Option<&str>,
    digest: Option<permguard_objects::digest::Digest>,
) -> Initiator {
    Initiator::new(
        context(&pair.a, &[], &pair.clocks.time),
        EXPORTER,
        Request {
            peer: pair.b.identity.host_id(),
            operation,
            membership_id: membership_id.map(str::to_owned),
            task: None,
            request_digest: digest,
            pin: Some((
                pair.b.identity.host_id(),
                pair.b.identity.first_fingerprint().to_owned(),
            )),
        },
    )
}

#[test]
fn an_enrollment_moves_no_seen_epoch_of_the_host_it_claims() {
    let pair = pair("enroll-seen");
    let digest = membership_request_digest(b"request");
    let mut initiator = scoped(&pair, Operation::Enroll, None, Some(digest));
    // B pins nobody: A enrolls from its own chain.
    let mut responder = Responder::new(context(&pair.b, &[], &pair.clocks.time), EXPORTER);
    run(&mut initiator, &mut responder).expect("established");
    assert!(responder.session().is_some());
    assert!(
        responder
            .context
            .peers
            .seen(&pair.a.identity.host_id())
            .expect("readable")
            .is_none(),
        "an enrollment's chain pins nothing and moves no seen epoch"
    );
}

#[test]
fn a_hello_naming_what_its_operation_does_not_take_is_refused() {
    let pair = pair("hello-scope");
    let digest = || Some(membership_request_digest(b"request"));
    for (operation, membership_id, digest) in [
        // An enrollment names no membership yet.
        (Operation::Enroll, Some("m-1"), digest()),
        // An enrollment names its request's digest.
        (Operation::Enroll, None, None),
        // A membership session names the membership it reads.
        (Operation::Membership, None, digest()),
        // A task session carries no request digest.
        (Operation::Task, None, digest()),
    ] {
        let mut initiator = scoped(&pair, operation, membership_id, digest.clone());
        let mut responder = pair.responder();
        let refused = run(&mut initiator, &mut responder).expect_err("refused at the hello");
        assert_eq!(
            refused.code,
            codes::host::SESSION_REFUSED,
            "{operation:?} {membership_id:?}"
        );
        assert!(responder.session().is_none());
    }
}

/// WP-4.3: a task session names the one membership and the one task it serves; without either
/// the hello is refused, with both the session is established.
#[test]
fn a_task_hello_names_one_membership_and_one_task() {
    let pair = pair("task-scope");
    let task_hello = |membership_id: Option<&str>, task: Option<&str>| {
        Initiator::new(
            context(&pair.a, &[], &pair.clocks.time),
            EXPORTER,
            Request {
                peer: pair.b.identity.host_id(),
                operation: Operation::Task,
                membership_id: membership_id.map(str::to_owned),
                task: task.map(str::to_owned),
                request_digest: None,
                pin: Some((
                    pair.b.identity.host_id(),
                    pair.b.identity.first_fingerprint().to_owned(),
                )),
            },
        )
    };
    for (membership_id, task) in [(None, Some("decisions")), (Some("m-1"), None), (None, None)] {
        let mut initiator = task_hello(membership_id, task);
        let mut responder = pair.responder();
        let refused = run(&mut initiator, &mut responder).expect_err("refused at the hello");
        assert_eq!(
            refused.code,
            codes::host::SESSION_REFUSED,
            "{membership_id:?} {task:?}"
        );
        assert!(responder.session().is_none());
    }
    let mut initiator = task_hello(Some("m-1"), Some("decisions"));
    let mut responder = pair.responder();
    run(&mut initiator, &mut responder).expect("established");
    let session = responder.session().expect("a session");
    assert_eq!(session.task.as_deref(), Some("decisions"));
}

#[test]
fn a_session_serves_one_request_and_none_before_it_is_established() {
    let pair = pair("one-request");
    let bytes = b"the request".to_vec();
    let digest = membership_request_digest(&bytes);
    let mut initiator = scoped(&pair, Operation::Membership, Some("m-1"), Some(digest));
    let mut responder = pair.responder();
    // Before the proof, a request is refused.
    let opening = initiator.start().expect("started");
    for frame in opening {
        responder.receive(frame).expect("the handshake goes on");
    }
    let mut early = pair.responder();
    assert!(early.receive(Frame::Task(bytes.clone())).is_err());
    // Established, the one request is answered (no service here: `not_served_yet`).
    let mut initiator = scoped(
        &pair,
        Operation::Membership,
        Some("m-1"),
        Some(membership_request_digest(&bytes)),
    );
    let mut responder = pair.responder();
    run(&mut initiator, &mut responder).expect("established");
    let answer = responder
        .receive(Frame::Task(bytes.clone()))
        .expect("answered");
    assert!(matches!(
        answer.as_slice(),
        [Frame::Refusal { code }] if code == codes::host::NOT_SERVED_YET
    ));
    // A second request on the same session is refused.
    assert!(responder.receive(Frame::Task(bytes)).is_err());
}
