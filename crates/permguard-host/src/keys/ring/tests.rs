// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Condvar;

use permguard_core::KeyManager as _;
use permguard_core::assurance::AssuranceProfile;
use permguard_core::keys::{PublicSet as _, Sign as _};
use permguard_core::time::ManualClock;

use super::*;
use crate::identity::Identity;
use crate::operations::mutation::Applying;
use crate::time::ManualMonotonic;
use permguard_objects::crypto::suite::SigningKey;

const NOW: i64 = 1_800_000_000;
const AHEAD: u64 = 600;
const ROTATE: u64 = 3_600;
const RETAIN: u64 = 7_200;

fn policy() -> Policy {
    Policy {
        publish_ahead: Duration::from_secs(AHEAD),
        rotate_every: Duration::from_secs(ROTATE),
        retain: Duration::from_secs(RETAIN),
    }
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-ring-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

struct Fixture {
    volume: Volume,
    clock: Arc<ManualClock>,
    time: Arc<TimeGuard>,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let volume = Volume::claim(&scratch(tag), AssuranceProfile::Development).expect("claimed");
        let clock = Arc::new(ManualClock::at(NOW));
        let time = Arc::new(TimeGuard::new(
            clock.clone(),
            Arc::new(ManualMonotonic::default()),
            Duration::from_secs(30),
        ));
        Self {
            volume,
            clock,
            time,
        }
    }

    fn ring(&self) -> Ring {
        Ring::open(
            &self.volume,
            DATA_ATTEST,
            Suite::Ed25519Sha256V1,
            policy(),
            self.time.clone(),
        )
        .expect("opens")
    }

    fn advance(&self, seconds: u64) {
        self.clock.jump(i64::try_from(seconds).expect("small"));
    }

    fn dir(&self) -> Dir {
        directory(&self.volume, DATA_ATTEST).expect("the ring directory")
    }

    fn kinds(&self) -> Vec<(Kind, u64)> {
        journal_entries(&self.dir())
            .expect("the journal reads")
            .into_iter()
            .map(|entry| (entry.kind, entry.epoch))
            .collect()
    }
}

fn verifies(keys: &[Jwk], signature: &Signature, payload: &[u8]) -> bool {
    keys.iter()
        .find(|key| key.kid == signature.key_id().as_str())
        .is_some_and(|key| {
            let public = B64.decode(&key.x).expect("base64url");
            Suite::Ed25519Sha256V1
                .verify(&public, payload, signature.bytes())
                .is_ok()
        })
}

fn thumbprint_part(kid: &str) -> String {
    thumbprint::split_kid(kid).expect("a ring kid").1.to_owned()
}

#[test]
fn the_first_key_signs_at_once_named_by_its_ring_and_thumbprint() {
    let fixture = Fixture::new("first");
    let ring = fixture.ring();
    assert!(matches!(ring.statement(), Err(RingError::NotReady(_))));
    assert!(ring.public_keys().is_err(), "never an empty set");

    let report = ring.maintain().expect("maintained");
    assert_eq!((report.published, report.activated), (1, 1));
    let statement = ring.statement().expect("a statement");
    assert_eq!(statement.epoch, 1);
    assert_eq!(statement.keys.len(), 1);
    let kid = statement.keys[0].kid.clone();
    let thumbprint = thumbprint_part(&kid);
    assert!(kid.starts_with("data.attest:"));
    assert_eq!(
        thumbprint::jwk_thumbprint_of(&statement.keys[0]).as_deref(),
        Some(thumbprint.as_str())
    );
    assert_eq!(
        statement.key_set_digest,
        thumbprint::key_set_digest(DATA_ATTEST, 1, Suite::Ed25519Sha256V1, &[&thumbprint])
            .expect("a digest")
    );

    let signature = ring.sign(b"payload").expect("signs");
    assert_eq!(signature.key_id().as_str(), kid);
    assert_eq!(signature.algorithm(), "EdDSA");
    assert!(verifies(&statement.keys, &signature, b"payload"));

    let dir = fixture.dir();
    assert!(dir.exists(VIEW).expect("listed"));
    assert!(
        dir.subdir(PUBLIC, false)
            .expect("public")
            .exists(&format!("{thumbprint}.jwk"))
            .expect("listed")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let private = dir.path().join(PRIVATE).join(format!("{thumbprint}.key"));
        let mode = std::fs::metadata(private)
            .expect("held")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "owner only");
    }
    assert_eq!(
        fixture.kinds(),
        vec![(Kind::Prepublished, 1), (Kind::Activated, 1)]
    );
    assert_eq!(
        ring.maintain().expect("again"),
        Maintenance::default(),
        "idempotent"
    );
}

#[test]
fn a_rotation_prepublishes_hands_over_destroys_and_archives_with_the_epoch_rising() {
    let fixture = Fixture::new("rotation");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    let first = ring.active_key_id().expect("active").to_string();
    let old_signature = ring.sign(b"old").expect("signs");

    // `publish_ahead` before the turn ends, the successor is published, not signing.
    fixture.advance(ROTATE - AHEAD);
    let report = ring.maintain().expect("successor");
    assert_eq!(report.published, 1);
    let statement = ring.statement().expect("statement");
    assert_eq!(statement.epoch, 2);
    assert_eq!(statement.keys.len(), 2);
    assert_eq!(ring.active_key_id().expect("active").to_string(), first);
    let second = statement
        .keys
        .iter()
        .map(|key| key.kid.clone())
        .find(|kid| *kid != first)
        .expect("the successor");

    // Not before its window has passed.
    fixture.advance(AHEAD - 1);
    assert_eq!(ring.maintain().expect("early"), Maintenance::default());
    fixture.advance(1);
    let report = ring.maintain().expect("hand-over");
    assert_eq!((report.retired, report.activated), (1, 1));
    assert_eq!(ring.active_key_id().expect("active").to_string(), second);
    let statement = ring.statement().expect("statement");
    assert_eq!(statement.epoch, 2, "the published set did not change");
    assert!(
        verifies(&statement.keys, &old_signature, b"old"),
        "retired-public still verifies"
    );
    let slots = FileKeyProvider::new(fixture.dir().subdir(PRIVATE, false).expect("private"))
        .slots()
        .expect("listed");
    assert_eq!(
        slots,
        vec![thumbprint_part(&second)],
        "the old private half is gone"
    );

    // After `retain`, the retired key leaves the set and stays in `public/`.
    fixture.advance(RETAIN);
    let report = ring.maintain().expect("archive");
    assert_eq!(report.archived, 1);
    let statement = ring.statement().expect("statement");
    assert!(statement.keys.iter().all(|key| key.kid != first));
    assert!(statement.epoch >= 3);
    assert!(
        fixture
            .dir()
            .subdir(PUBLIC, false)
            .expect("public")
            .exists(&format!("{}.jwk", thumbprint_part(&first)))
            .expect("listed")
    );
    let view = ring.view().expect("view");
    assert_eq!(
        view.keys
            .iter()
            .find(|key| key.kid == first)
            .map(|key| key.state),
        Some(State::Archived)
    );
    let kinds: Vec<Kind> = fixture.kinds().into_iter().map(|(kind, _)| kind).collect();
    assert_eq!(
        kinds[..7],
        [
            Kind::Prepublished,
            Kind::Activated,
            Kind::Prepublished,
            Kind::Retired,
            Kind::Activated,
            Kind::Destroyed,
            Kind::Prepublished,
        ],
        "{kinds:?}"
    );
    assert!(kinds.contains(&Kind::Archived));
}

#[test]
fn ring_cbor_is_rebuilt_from_the_journal() {
    let fixture = Fixture::new("rebuild");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    fixture.advance(ROTATE);
    ring.maintain().expect("successor");
    let dir = fixture.dir();
    let before = read_view(&dir, VIEW, format::VIEW)
        .expect("read")
        .expect("held");
    drop(ring);
    crate::storage::tombstone::delete(&dir, VIEW).expect("removed");
    assert!(!dir.exists(VIEW).expect("listed"));

    let reopened = fixture.ring();
    let after = read_view(&dir, VIEW, format::VIEW)
        .expect("read")
        .expect("rebuilt");
    assert_eq!(after, before);
    assert_eq!(
        View::decode(&after).expect("decodes"),
        reopened.view().expect("view")
    );
}

/// A provider whose signing waits for a gate, and which notes the order of what it did.
struct Gated {
    inner: FileKeyProvider,
    events: Mutex<Vec<&'static str>>,
    gate: (Mutex<bool>, Condvar),
}

impl Gated {
    fn note(&self, event: &'static str) {
        self.events.lock().expect("lock").push(event);
    }

    fn open(&self) {
        *self.gate.0.lock().expect("lock") = true;
        self.gate.1.notify_all();
    }
}

impl KeyProvider for Gated {
    fn name(&self) -> &'static str {
        "gated"
    }
    fn custody(&self) -> super::super::Custody {
        self.inner.custody()
    }
    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, ProviderError> {
        self.inner.generate(slot, suite)
    }
    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), ProviderError> {
        self.inner.generate_addressed(suite)
    }
    fn slots(&self) -> Result<Vec<String>, ProviderError> {
        self.inner.slots()
    }
    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, ProviderError> {
        self.inner.public(slot, suite)
    }
    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, ProviderError> {
        self.note("sign-start");
        let mut open = self.gate.0.lock().expect("lock");
        while !*open {
            open = self.gate.1.wait(open).expect("wait");
        }
        drop(open);
        let signed = self.inner.sign(slot, suite, message);
        self.note("sign-end");
        signed
    }
    fn destroy(&self, slot: &str) -> Result<(), ProviderError> {
        self.note("destroy");
        self.inner.destroy(slot)
    }
}

#[test]
fn the_private_half_is_destroyed_only_after_the_signings_in_flight() {
    let fixture = Fixture::new("in-flight");
    let dir = fixture.dir();
    let gated = Arc::new(Gated {
        inner: FileKeyProvider::new(dir.subdir(PRIVATE, true).expect("private")),
        events: Mutex::new(Vec::new()),
        gate: (Mutex::new(true), Condvar::new()),
    });
    let ring = Arc::new(
        Ring::open_with(
            directory(&fixture.volume, DATA_ATTEST).expect("dir"),
            dir.subdir(PUBLIC, true).expect("public"),
            gated.clone(),
            DATA_ATTEST,
            Suite::Ed25519Sha256V1,
            policy(),
            fixture.time.clone(),
        )
        .expect("opens"),
    );
    ring.maintain().expect("first");
    fixture.advance(ROTATE - AHEAD);
    ring.maintain().expect("successor");
    fixture.advance(AHEAD);
    gated.events.lock().expect("lock").clear();
    *gated.gate.0.lock().expect("lock") = false;

    let signing = {
        let ring = ring.clone();
        std::thread::spawn(move || ring.sign(b"in flight").expect("signs"))
    };
    while gated.events.lock().expect("lock").is_empty() {
        std::thread::yield_now();
    }
    let maintaining = {
        let ring = ring.clone();
        std::thread::spawn(move || ring.maintain().expect("hand-over"))
    };
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        *gated.events.lock().expect("lock"),
        vec!["sign-start"],
        "nothing destroyed while a signing is in flight"
    );
    gated.open();
    let signature = signing.join().expect("the signing ends");
    maintaining.join().expect("the hand-over ends");
    assert_eq!(
        *gated.events.lock().expect("lock"),
        vec!["sign-start", "sign-end", "destroy"]
    );
    assert!(
        verifies(
            &ring.public_keys().expect("published"),
            &signature,
            b"in flight"
        ),
        "the signature made in flight verifies under the retired key"
    );
}

/// A provider whose destroy fails while armed: a crash between a retirement and its destruction.
struct Undestroyable {
    inner: FileKeyProvider,
    armed: std::sync::atomic::AtomicBool,
}

impl KeyProvider for Undestroyable {
    fn name(&self) -> &'static str {
        "undestroyable"
    }
    fn custody(&self) -> super::super::Custody {
        self.inner.custody()
    }
    fn generate(&self, slot: &str, suite: Suite) -> Result<PublicKey, ProviderError> {
        self.inner.generate(slot, suite)
    }
    fn generate_addressed(&self, suite: Suite) -> Result<(String, PublicKey), ProviderError> {
        self.inner.generate_addressed(suite)
    }
    fn slots(&self) -> Result<Vec<String>, ProviderError> {
        self.inner.slots()
    }
    fn public(&self, slot: &str, suite: Suite) -> Result<PublicKey, ProviderError> {
        self.inner.public(slot, suite)
    }
    fn sign(&self, slot: &str, suite: Suite, message: &[u8]) -> Result<Vec<u8>, ProviderError> {
        self.inner.sign(slot, suite, message)
    }
    fn destroy(&self, slot: &str) -> Result<(), ProviderError> {
        if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ProviderError::Malformed("the device is gone".to_owned()));
        }
        self.inner.destroy(slot)
    }
}

#[test]
fn what_a_crash_left_is_completed_and_journaled_by_the_next_maintenance() {
    let fixture = Fixture::new("crash");
    let dir = fixture.dir();
    let private = || FileKeyProvider::new(dir.subdir(PRIVATE, true).expect("private"));
    let first = {
        let ring = Ring::open_with(
            fixture.dir(),
            dir.subdir(PUBLIC, true).expect("public"),
            Arc::new(Undestroyable {
                inner: private(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }),
            DATA_ATTEST,
            Suite::Ed25519Sha256V1,
            policy(),
            fixture.time.clone(),
        )
        .expect("opens");
        ring.maintain().expect("first");
        let first = ring.active_key_id().expect("active").to_string();
        fixture.advance(ROTATE);
        ring.maintain().expect("successor");
        fixture.advance(AHEAD);
        assert!(ring.maintain().is_err(), "the destruction failed");
        first
    };
    // A key generated and never journaled, as a crash before its entry leaves it.
    let (orphan, _) = private()
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("generated");
    let kinds = fixture.kinds();
    assert_eq!(kinds.last().map(|(kind, _)| *kind), Some(Kind::Activated));

    let ring = fixture.ring();
    ring.maintain().expect("completed");
    let entries = journal_entries(&dir).expect("journal");
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == Kind::Destroyed && entry.kid == first)
    );
    let slots = private().slots().expect("listed");
    assert!(!slots.contains(&thumbprint_part(&first)));
    assert!(!slots.contains(&orphan), "the orphan is destroyed");
    assert_eq!(slots.len(), 1, "only the active key's private half");
}

#[test]
fn a_ring_whose_active_key_lost_its_private_half_refuses_to_open() {
    let fixture = Fixture::new("lost");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    let slot = thumbprint_part(&ring.active_key_id().expect("active").to_string());
    drop(ring);
    std::fs::remove_file(
        fixture
            .dir()
            .path()
            .join(PRIVATE)
            .join(format!("{slot}.key")),
    )
    .expect("removed");
    let refused = Ring::open(
        &fixture.volume,
        DATA_ATTEST,
        Suite::Ed25519Sha256V1,
        policy(),
        fixture.time.clone(),
    )
    .expect_err("a lost key");
    assert!(matches!(refused, RingError::Corrupt(_)), "{refused}");
    assert!(fixture.dir().path().join(JOURNAL).exists());
}

#[test]
fn a_ring_refuses_another_suite_and_a_ring_with_no_keys_of_its_own() {
    let fixture = Fixture::new("suite");
    fixture.ring().maintain().expect("first");
    let refused = Ring::open(
        &fixture.volume,
        DATA_ATTEST,
        Suite::P256Sha256V1,
        policy(),
        fixture.time.clone(),
    )
    .expect_err("another suite");
    assert!(matches!(refused, RingError::Refused(_)), "{refused}");
    for ring in [HOST_IDENTITY, "realm.tokens"] {
        assert!(
            Ring::open(
                &fixture.volume,
                ring,
                Suite::Ed25519Sha256V1,
                policy(),
                fixture.time.clone(),
            )
            .is_err(),
            "{ring}"
        );
    }
}

#[test]
fn a_tampered_journal_refuses_to_open() {
    let fixture = Fixture::new("tampered");
    fixture.ring().maintain().expect("first");
    let dir = fixture.dir();
    let mut entries = journal_entries(&dir).expect("journal");
    entries[1].epoch = 5;
    let mut bytes = Vec::new();
    for entry in &entries {
        bytes.extend(entry.encode().expect("encodes"));
    }
    crate::storage::write::replace_bytes(&dir, JOURNAL, &bytes).expect("rewritten");
    let refused = Ring::open(
        &fixture.volume,
        DATA_ATTEST,
        Suite::Ed25519Sha256V1,
        policy(),
        fixture.time.clone(),
    )
    .expect_err("an epoch the history does not allow");
    assert!(matches!(refused, RingError::Corrupt(_)), "{refused}");
}

#[test]
fn rollback_and_equivocation_are_refused_and_only_a_bound_higher_epoch_is_accepted() {
    let held = (4, [1; 32]);
    assert_eq!(
        continuity(Some(held), 4, &[1; 32], false),
        Continuity::Retry
    );
    assert_eq!(
        continuity(Some(held), 4, &[2; 32], true),
        Continuity::Equivocation
    );
    assert_eq!(
        continuity(Some(held), 3, &[1; 32], true),
        Continuity::Rollback
    );
    assert_eq!(
        continuity(Some(held), 5, &[2; 32], true),
        Continuity::Accept
    );
    assert_eq!(
        continuity(Some(held), 5, &[2; 32], false),
        Continuity::Unbound
    );
    assert_eq!(continuity(None, 1, &[2; 32], true), Continuity::Accept);
    assert_eq!(continuity(None, 1, &[2; 32], false), Continuity::Unbound);
    for verdict in [
        Continuity::Equivocation,
        Continuity::Rollback,
        Continuity::Unbound,
    ] {
        assert!(!verdict.is_accepted());
    }
    assert!(Continuity::Accept.is_accepted() && Continuity::Retry.is_accepted());
}

fn identity(fixture: &Fixture) -> Arc<Identity> {
    let (_, keys) = crate::identity::directories(&fixture.volume).expect("dirs");
    Arc::new(
        Identity::provision(
            &fixture.volume,
            Arc::new(FileKeyProvider::new(keys)),
            Suite::Ed25519Sha256V1,
            u64::try_from(NOW).expect("positive"),
            u64::try_from(NOW).expect("positive") * 1000,
        )
        .expect("provisioned"),
    )
}

#[test]
fn every_epoch_is_bound_by_the_identity_and_the_binding_verifies_only_as_itself() {
    let fixture = Fixture::new("binding");
    let identity = identity(&fixture);
    let ring = fixture.ring().with_binder(identity.clone());
    ring.maintain().expect("first");
    let now = fixture.time.now_secs();
    let statement = ring.statement().expect("statement");
    let envelope = statement.binding.clone().expect("bound");
    let public = identity.public_key();
    let binding = verify_binding(
        &envelope,
        public.suite,
        &public.bytes,
        &identity.host_id(),
        DATA_ATTEST,
        now,
    )
    .expect("verifies");
    assert_eq!(binding.epoch, statement.epoch);
    assert_eq!(binding.key_set_digest, statement.key_set_digest);
    assert_eq!(
        binding.not_after - binding.not_before,
        BINDING_LIFETIME.as_secs()
    );
    for (name, refused) in [
        (
            "another ring",
            verify_binding(
                &envelope,
                public.suite,
                &public.bytes,
                &identity.host_id(),
                CONTROL_ATTEST,
                now,
            ),
        ),
        (
            "another Host",
            verify_binding(
                &envelope,
                public.suite,
                &public.bytes,
                &[9; 16],
                DATA_ATTEST,
                now,
            ),
        ),
        (
            "after its end",
            verify_binding(
                &envelope,
                public.suite,
                &public.bytes,
                &identity.host_id(),
                DATA_ATTEST,
                binding.not_after,
            ),
        ),
        (
            "another key",
            verify_binding(
                &envelope,
                public.suite,
                &[7; 32],
                &identity.host_id(),
                DATA_ATTEST,
                now,
            ),
        ),
    ] {
        assert!(refused.is_err(), "{name}");
    }

    // A new epoch is bound again; so is one whose binding is about to end.
    fixture.advance(ROTATE - AHEAD);
    ring.maintain().expect("successor");
    let next = ring.statement().expect("statement");
    assert_eq!(next.epoch, 2);
    let rebound = Binding::decode(
        Sign1::decode(&next.binding.expect("bound"))
            .expect("cose")
            .payload_unverified(),
    )
    .expect("payload");
    assert_eq!(rebound.epoch, 2);
    let bound = journal_entries(&fixture.dir())
        .expect("journal")
        .into_iter()
        .filter(|entry| entry.kind == Kind::Bound)
        .count();
    assert_eq!(bound, 2);
    assert_eq!(
        journal_entries(&fixture.dir())
            .expect("journal")
            .last()
            .map(|entry| entry.kid.clone()),
        Some(identity.kid().expect("a kid"))
    );
}

#[test]
fn an_operator_rotation_is_observed_by_its_operation_and_refused_while_one_waits() {
    let fixture = Fixture::new("operator-rotate");
    let ring = Arc::new(fixture.ring());
    ring.maintain().expect("first");
    let stale = ring
        .rotate(&Applying::for_tests(1), 7)
        .expect_err("a stale epoch");
    assert!(matches!(
        stale,
        RingError::Conflict {
            expected: 7,
            current: 1
        }
    ));
    let rotated = ring.rotate(&Applying::for_tests(2), 1).expect("rotated");
    assert_eq!(rotated.epoch, 2);
    assert!(matches!(
        ring.rotate(&Applying::for_tests(3), 2),
        Err(RingError::Pending(_))
    ));
    let rings = [ring.clone()];
    let observed = Rings(&rings)
        .observe(&OperationId::from_bytes([2; 16]), None)
        .expect("the journal shows it");
    assert_eq!(observed.revision, 2);
    assert_eq!(observed.target.as_deref(), Some("data.attest:epoch:2"));
    assert!(
        Rings(&rings)
            .observe(&OperationId::from_bytes([3; 16]), None)
            .is_none()
    );
    // It takes over once `publish_ahead` has passed, like any successor.
    fixture.advance(AHEAD);
    ring.maintain().expect("hand-over");
    assert_eq!(
        ring.active_key_id().expect("active").to_string(),
        rotated.kid
    );
}

#[test]
fn a_revoked_key_leaves_the_set_at_once_and_an_active_one_is_replaced() {
    let fixture = Fixture::new("revoke");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    let first = ring.active_key_id().expect("active").to_string();
    assert!(matches!(
        ring.revoke(&Applying::for_tests(1), &first, "", None, 1),
        Err(RingError::Refused(_))
    ));
    assert!(matches!(
        ring.revoke(
            &Applying::for_tests(1),
            "data.attest:nope",
            "compromise",
            None,
            1
        ),
        Err(RingError::UnknownKey(_))
    ));
    let revoked = ring
        .revoke(
            &Applying::for_tests(4),
            &first,
            "key-compromise",
            Some(1_799_999_000),
            1,
        )
        .expect("revoked");
    assert_eq!(revoked.epoch, 2);
    let statement = ring.statement().expect("statement");
    assert!(
        statement.keys.iter().all(|key| key.kid != first),
        "out at once"
    );
    let replacement = ring.active_key_id().expect("a new active key").to_string();
    assert_ne!(replacement, first);
    assert_eq!(statement.epoch, 3, "the replacement entered the set");
    let entry = journal_entries(&fixture.dir())
        .expect("journal")
        .into_iter()
        .find(|entry| entry.kind == Kind::Revoked)
        .expect("journaled");
    assert_eq!(entry.reason.as_deref(), Some("key-compromise"));
    assert_eq!(entry.compromised_at, Some(1_799_999_000));
    assert_eq!(entry.operation_id, Some([4; 16]));
    assert_eq!(
        ring.view()
            .expect("view")
            .keys
            .iter()
            .find(|key| key.kid == first)
            .map(|key| key.state),
        Some(State::Revoked)
    );
    assert!(matches!(
        ring.revoke(&Applying::for_tests(5), &first, "again", None, 3),
        Err(RingError::Revoked(_))
    ));
    let slots = FileKeyProvider::new(fixture.dir().subdir(PRIVATE, false).expect("private"))
        .slots()
        .expect("listed");
    assert_eq!(slots, vec![thumbprint_part(&replacement)]);
}

#[test]
fn a_key_that_stopped_signing_is_revoked_once_and_its_half_is_not_destroyed_twice() {
    let fixture = Fixture::new("revoke-retired");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    let first = ring.active_key_id().expect("active").to_string();
    fixture.advance(ROTATE);
    ring.maintain().expect("successor");
    fixture.advance(AHEAD);
    ring.maintain().expect("hand-over");
    // A retired-public key: in the set, its private half destroyed at the hand-over.
    let epoch = ring.epoch();
    let revoked = ring
        .revoke(&Applying::for_tests(6), &first, "compromise", None, epoch)
        .expect("revoked");
    assert_eq!(revoked.epoch, epoch + 1, "it left the published set");
    let destroyed = journal_entries(&fixture.dir())
        .expect("journal")
        .into_iter()
        .filter(|entry| entry.kind == Kind::Destroyed && entry.kid == first)
        .count();
    assert_eq!(destroyed, 1);

    // An archived key: out of the set already, so the epoch stays.
    let second = ring.active_key_id().expect("active").to_string();
    fixture.advance(ROTATE);
    ring.maintain().expect("successor");
    fixture.advance(AHEAD);
    ring.maintain().expect("hand-over");
    fixture.advance(RETAIN);
    ring.maintain().expect("archive");
    assert_eq!(
        ring.view()
            .expect("view")
            .keys
            .iter()
            .find(|key| key.kid == second)
            .map(|key| key.state),
        Some(State::Archived)
    );
    let epoch = ring.epoch();
    let revoked = ring
        .revoke(&Applying::for_tests(7), &second, "compromise", None, epoch)
        .expect("revoked");
    assert_eq!(revoked.epoch, epoch);
    assert!(ring.active_key_id().is_ok());
}

/// Appends `entry`, encoded, to the ring's journal: what a crash between two entries leaves.
fn append(dir: &Dir, entry: &Entry) {
    sequence::append(dir, JOURNAL, &entry.encode().expect("encodes")).expect("appended");
}

#[test]
fn a_ring_left_without_an_active_key_by_a_crash_has_one_at_the_next_maintenance() {
    // A revocation of the active key journaled, its successor not: no key signs.
    let fixture = Fixture::new("no-active");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    let first = ring.active_key_id().expect("active").to_string();
    drop(ring);
    let dir = fixture.dir();
    let last = journal_entries(&dir)
        .expect("journal")
        .pop()
        .expect("an entry");
    append(
        &dir,
        &Entry {
            seq: last.seq + 1,
            kind: Kind::Revoked,
            kid: first.clone(),
            epoch: last.epoch + 1,
            at: 1,
            operation_id: Some([3; 16]),
            reason: Some("compromise".to_owned()),
            jwk: None,
            compromised_at: None,
        },
    );
    let ring = fixture.ring();
    assert!(ring.active_key_id().is_err(), "no key signs");
    let report = ring.maintain().expect("restored");
    assert_eq!((report.published, report.activated), (1, 1));
    let active = ring.active_key_id().expect("a new active key").to_string();
    assert_ne!(active, first);
    assert!(ring.sign(b"again").is_ok());

    // The first key prepublished and never activated: it signs at once, whatever the window.
    let fixture = Fixture::new("no-active-first");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    drop(ring);
    let dir = fixture.dir();
    let entries = journal_entries(&dir).expect("journal");
    let mut bytes = Vec::new();
    bytes.extend(entries[0].encode().expect("encodes"));
    crate::storage::write::replace_bytes(&dir, JOURNAL, &bytes).expect("rewritten");
    let ring = fixture.ring();
    assert!(ring.active_key_id().is_err());
    ring.maintain().expect("restored");
    assert_eq!(
        ring.active_key_id().expect("active").to_string(),
        entries[0].kid
    );
}

#[test]
fn a_failed_journal_write_stops_the_ring_until_it_is_opened_again() {
    let fixture = Fixture::new("stopped");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    let journal = fixture.dir().path().join(JOURNAL);
    {
        let _failing =
            permguard_core::fault::inject(&journal, permguard_core::fault::Fault::WriteFails);
        assert!(ring.rotate(&Applying::for_tests(1), 1).is_err());
    }
    let refused = ring
        .rotate(&Applying::for_tests(2), 1)
        .expect_err("stopped");
    assert!(matches!(refused, RingError::NotReady(_)), "{refused}");
    drop(ring);
    let ring = fixture.ring();
    ring.rotate(&Applying::for_tests(2), 1)
        .expect("the next open reads the journal back");
}

#[test]
fn a_binding_is_issued_again_after_the_identity_rotates_or_the_file_changes() {
    let fixture = Fixture::new("rebind");
    let identity = identity(&fixture);
    let ring = fixture.ring().with_binder(identity.clone());
    ring.maintain().expect("first");
    let bound = |_: &Ring| {
        journal_entries(&fixture.dir())
            .expect("journal")
            .into_iter()
            .filter(|entry| entry.kind == Kind::Bound)
            .count()
    };
    assert_eq!(bound(&ring), 1);
    ring.maintain().expect("again");
    assert_eq!(bound(&ring), 1, "a current binding is kept");

    identity
        .rotate(
            &Applying::for_tests(9),
            Some(1),
            u64::try_from(NOW).expect("positive"),
        )
        .expect("the identity rotates");
    ring.maintain().expect("rebound");
    assert_eq!(
        bound(&ring),
        2,
        "the old identity key's binding is replaced"
    );
    let public = identity.public_key();
    verify_binding(
        &ring.statement().expect("statement").binding.expect("bound"),
        public.suite,
        &public.bytes,
        &identity.host_id(),
        DATA_ATTEST,
        fixture.time.now_secs(),
    )
    .expect("signed by the current identity key");

    // A binding file changed on the volume is not trusted at the next open.
    drop(ring);
    let held = read_view(&fixture.dir(), BINDING, format::VIEW)
        .expect("read")
        .expect("held");
    let mut tampered = held.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    replace_view(&fixture.dir(), BINDING, format::VIEW, &tampered).expect("tampered");
    let ring = fixture.ring().with_binder(identity.clone());
    ring.maintain().expect("rebound");
    assert_eq!(bound(&ring), 3);
}

#[test]
fn every_history_the_ring_does_not_allow_is_refused() {
    let fixture = Fixture::new("histories");
    let ring = fixture.ring();
    ring.maintain().expect("first");
    fixture.advance(ROTATE);
    ring.maintain().expect("successor");
    let good = journal_entries(&fixture.dir()).expect("journal");
    check_history(DATA_ATTEST, &good).expect("the ring's own history");
    let first = good[0].clone();
    let second = good[2].clone();
    let foreign = {
        let key = SigningKey::from_pkcs8(
            Suite::Ed25519Sha256V1,
            &SigningKey::generate_pkcs8(Suite::Ed25519Sha256V1).expect("generated"),
        )
        .expect("reads");
        thumbprint::jwk_thumbprint(Suite::Ed25519Sha256V1, key.public_key()).expect("thumbprint")
    };
    let cases: Vec<(&str, Vec<Entry>)> = vec![
        (
            "a second active key",
            vec![
                first.clone(),
                good[1].clone(),
                second.clone(),
                Entry {
                    seq: 4,
                    kind: Kind::Activated,
                    epoch: 2,
                    jwk: None,
                    ..second.clone()
                },
            ],
        ),
        ("another ring's prefix", {
            // The jwk names the same kid, so only the prefix is wrong.
            let kid = first.kid.replace("data.attest:", "control.attest:");
            let mut jwk: Jwk =
                serde_json::from_str(first.jwk.as_deref().expect("a jwk")).expect("json");
            jwk.kid = kid.clone();
            vec![
                Entry {
                    kid: kid.clone(),
                    jwk: Some(serde_json::to_string(&jwk).expect("json")),
                    ..first.clone()
                },
                Entry {
                    kid,
                    ..good[1].clone()
                },
            ]
        }),
        (
            "a thumbprint of other material",
            vec![Entry {
                kid: thumbprint::kid(DATA_ATTEST, &foreign),
                ..first.clone()
            }],
        ),
        (
            "a gap in seq",
            vec![
                first.clone(),
                Entry {
                    seq: 3,
                    ..good[1].clone()
                },
            ],
        ),
        (
            "destroyed while active",
            vec![
                first.clone(),
                good[1].clone(),
                Entry {
                    seq: 3,
                    kind: Kind::Destroyed,
                    ..good[1].clone()
                },
            ],
        ),
        (
            "bound by a key outside host.identity",
            vec![
                first.clone(),
                good[1].clone(),
                Entry {
                    seq: 3,
                    kind: Kind::Bound,
                    kid: second.kid.clone(),
                    ..good[1].clone()
                },
            ],
        ),
        (
            "an epoch that did not rise",
            vec![
                first.clone(),
                good[1].clone(),
                Entry {
                    epoch: 1,
                    ..second.clone()
                },
            ],
        ),
    ];
    for (name, entries) in cases {
        assert!(check_history(DATA_ATTEST, &entries).is_err(), "{name}");
    }
    // A suite change: a P-256 key prepublished into an Edwards ring.
    let p256 = SigningKey::from_pkcs8(
        Suite::P256Sha256V1,
        &SigningKey::generate_pkcs8(Suite::P256Sha256V1).expect("generated"),
    )
    .expect("reads");
    let public = PublicKey {
        suite: Suite::P256Sha256V1,
        bytes: p256.public_key().to_vec(),
    };
    let tp = thumbprint::jwk_thumbprint(Suite::P256Sha256V1, &public.bytes).expect("thumbprint");
    let kid = thumbprint::kid(DATA_ATTEST, &tp);
    let other_suite = Entry {
        kid: kid.clone(),
        jwk: Some(serde_json::to_string(&jwk_of(&kid, &public)).expect("json")),
        ..second.clone()
    };
    assert!(
        check_history(DATA_ATTEST, &[first, good[1].clone(), other_suite]).is_err(),
        "a suite change"
    );
}

/// Records whether the ring has an active key at every transition it records.
struct Watching {
    ring: std::sync::OnceLock<std::sync::Weak<Ring>>,
    seen: Mutex<Vec<(Kind, bool)>>,
}

impl Recorder for Watching {
    fn record(&self, _ring: &str, entry: &Entry) {
        let active = self
            .ring
            .get()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|ring| ring.active_key_id().is_ok());
        self.seen.lock().expect("lock").push((entry.kind, active));
    }
}

#[test]
fn no_transition_shows_the_ring_without_an_active_key() {
    let fixture = Fixture::new("atomic");
    let watching = Arc::new(Watching {
        ring: std::sync::OnceLock::new(),
        seen: Mutex::new(Vec::new()),
    });
    let ring = Arc::new(fixture.ring().with_recorder(watching.clone()));
    watching.ring.set(Arc::downgrade(&ring)).expect("set once");
    ring.maintain().expect("first");
    fixture.advance(ROTATE);
    ring.maintain().expect("successor");
    fixture.advance(AHEAD);
    ring.maintain().expect("hand-over");
    let active = ring.active_key_id().expect("active").to_string();
    let epoch = ring.epoch();
    ring.revoke(&Applying::for_tests(8), &active, "compromise", None, epoch)
        .expect("revoked");
    let seen = watching.seen.lock().expect("lock").clone();
    assert!(seen.iter().any(|(kind, _)| *kind == Kind::Retired));
    assert!(seen.iter().any(|(kind, _)| *kind == Kind::Revoked));
    assert!(
        seen.iter().all(|(_, active)| *active),
        "a transition showed no active key: {seen:?}"
    );
}
