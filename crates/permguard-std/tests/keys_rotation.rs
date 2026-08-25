#![cfg(feature = "keys")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The lifecycle a key goes through, driven by a clock the test controls.
//!
//! Rotation is the kind of thing that is only ever exercised in production, months after it was
//! written, by which point nobody remembers what it was supposed to do. A clock that can be moved
//! forward turns "we will find out in thirty days" into an assertion.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use permguard_core::{KeyManager, KeyState};
use permguard_std::keys::{Clock, DirectoryKeyManager, KeyPolicy, RingAlgorithm};

/// The instant every clock in one test reads, so the test can move it.
#[derive(Default)]
struct TestClock(AtomicU64);

impl TestClock {
    fn at(seconds: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(seconds)))
    }

    fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_secs(), Ordering::SeqCst);
    }
}

/// The clock a manager is given: a handle onto the instant above.
struct SharedClock(Arc<TestClock>);

impl Clock for SharedClock {
    fn now(&self) -> u64 {
        self.0.0.load(Ordering::SeqCst)
    }
}

/// A key ring location nothing else is using.
fn ring(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("permguard-keys-{name}"));
    let _ = fs::remove_dir_all(&path);

    path
}

/// An hour to publish ahead, a day of signing, a week of verifying afterwards.
///
/// Shorter than any real deployment would use, and in the same proportions, so the windows can be
/// stepped through without the arithmetic changing shape.
fn policy() -> KeyPolicy {
    KeyPolicy {
        publish_ahead: Duration::from_secs(3600),
        rotate_every: Duration::from_secs(86_400),
        retain: Duration::from_secs(7 * 86_400),
        // No separate public lifetime: a key is forgotten outright when it stops being retained, which
        // is the behaviour the rotation cases below step through. The archive phase has its own test.
        verify_retain: Duration::from_secs(7 * 86_400),
    }
}

fn manager(name: &str, clock: &Arc<TestClock>) -> (DirectoryKeyManager, PathBuf) {
    let directory = ring(name);
    let manager = DirectoryKeyManager::with_clock(
        &directory,
        policy(),
        Box::new(SharedClock(Arc::clone(clock))),
    );

    (manager, directory)
}

/// Returns the state of every key, newest first, as the published set reports them.
fn states(manager: &DirectoryKeyManager) -> Vec<(String, KeyState)> {
    let text =
        fs::read_to_string(manager.directory().join("ring.json")).expect("the ring is there");
    let ring: serde_json::Value = serde_json::from_str(&text).expect("the ring parses");

    ring["keys"]
        .as_array()
        .expect("keys is a list")
        .iter()
        .map(|entry| {
            let state = match entry["state"].as_str().expect("a state") {
                "published" => KeyState::Published,
                "active" => KeyState::Active,
                "retired" => KeyState::Retired,
                "archived" => KeyState::Archived,
                other => panic!("unknown state {other}"),
            };

            (entry["kid"].as_str().expect("a kid").to_owned(), state)
        })
        .collect()
}

#[test]
fn test_the_first_key_of_a_fresh_deployment_signs_immediately() {
    let clock = TestClock::at(1_000_000);
    let (manager, _) = manager("first", &clock);

    let report = manager.maintain().expect("the first pass succeeds");

    // Publishing ahead protects verifiers that already cached a key set. A deployment starting for
    // the first time has none, so waiting an hour to serve would be downtime bought for nobody.
    assert_eq!(report.published, 1);
    assert_eq!(report.activated, 1);
    assert_eq!(states(&manager).len(), 1);
    assert_eq!(states(&manager)[0].1, KeyState::Active);
    assert!(manager.active_key_id().is_ok());
}

#[test]
fn test_a_pass_that_changes_nothing_changes_nothing() {
    let clock = TestClock::at(1_000_000);
    let (manager, _) = manager("idempotent", &clock);

    manager.maintain().expect("the first pass succeeds");
    let before = states(&manager);

    // Called from startup and from a timer, so calling it twice in a row has to be safe.
    let report = manager.maintain().expect("the second pass succeeds");

    assert!(report.is_empty(), "a second pass did something: {report:?}");
    assert_eq!(states(&manager), before);
}

#[test]
fn test_a_successor_is_published_before_the_incumbent_is_due_to_stop() {
    let clock = TestClock::at(1_000_000);
    let (manager, _) = manager("successor", &clock);

    manager.maintain().expect("the first pass succeeds");
    let first = manager.active_key_id().expect("a key is signing");

    // Not yet: with a day of signing and an hour of publishing ahead, the successor appears at
    // twenty-three hours, not at twenty-four.
    clock.advance(Duration::from_secs(22 * 3600));
    assert!(manager.maintain().expect("a pass succeeds").is_empty());

    clock.advance(Duration::from_secs(2 * 3600));
    let report = manager.maintain().expect("a pass succeeds");

    assert_eq!(report.published, 1, "no successor was published");
    assert_eq!(
        report.activated, 0,
        "the successor started signing too early"
    );
    assert_eq!(
        manager.active_key_id().expect("a key is signing"),
        first,
        "the incumbent stopped signing before its time"
    );

    let published = states(&manager);
    assert_eq!(published.len(), 2);
    assert!(
        published
            .iter()
            .any(|(_, state)| *state == KeyState::Published)
    );
}

#[test]
fn test_the_handover_lands_on_the_rotation_period_not_after_it() {
    let clock = TestClock::at(1_000_000);
    let (manager, _) = manager("handover", &clock);

    manager.maintain().expect("the first pass succeeds");
    let first = manager.active_key_id().expect("a key is signing");

    // Publish the successor, then reach the end of the incumbent's day exactly.
    clock.advance(Duration::from_secs(23 * 3600));
    manager.maintain().expect("a pass succeeds");

    clock.advance(Duration::from_secs(3600));
    let report = manager.maintain().expect("a pass succeeds");

    assert_eq!(report.activated, 1);
    assert_eq!(report.retired, 1);

    let second = manager.active_key_id().expect("a key is signing");
    assert_ne!(second, first, "the same key is still signing");

    let published = states(&manager);
    assert_eq!(published.len(), 2, "the retired key left the key set");
    assert!(
        published
            .iter()
            .any(|(kid, state)| kid == first.as_str() && *state == KeyState::Retired),
        "the previous key is not published as retired, so yesterday's signatures stop verifying"
    );
}

#[test]
fn test_a_retired_key_stays_published_for_exactly_as_long_as_it_was_promised() {
    let clock = TestClock::at(1_000_000);
    let (manager, directory) = manager("retention", &clock);

    manager.maintain().expect("the first pass succeeds");
    let first = manager.active_key_id().expect("a key is signing");

    // Through one whole rotation, so the first key is retired.
    clock.advance(Duration::from_secs(24 * 3600));
    manager.maintain().expect("a pass succeeds");
    clock.advance(Duration::from_secs(3600));
    manager.maintain().expect("a pass succeeds");

    assert!(
        manager
            .public_keys()
            .expect("the set reads")
            .iter()
            .any(|key| key.kid == first.as_str())
    );

    // A day short of the week it was promised.
    clock.advance(Duration::from_secs(6 * 86_400));
    manager.maintain().expect("a pass succeeds");
    assert!(
        manager
            .public_keys()
            .expect("the set reads")
            .iter()
            .any(|key| key.kid == first.as_str()),
        "a key was dropped before the retention it was given, so good signatures now look forged"
    );

    clock.advance(Duration::from_secs(2 * 86_400));
    let report = manager.maintain().expect("a pass succeeds");

    assert!(report.forgotten >= 1);
    assert!(
        !manager
            .public_keys()
            .expect("the set reads")
            .iter()
            .any(|key| key.kid == first.as_str())
    );
    assert!(
        !directory.join(format!("{first}.pem")).exists(),
        "the key left the set but its private half is still on disk"
    );
}

#[test]
fn test_a_keys_private_half_goes_at_retain_while_its_public_half_verifies_until_the_trail_expires()
{
    // The audit-sealing lifecycle: a seal must keep verifying for as long as the trail it covers is
    // kept, which outlasts how long the key that made it should keep its private half on disk. So the
    // private half is deleted at `retain`, and the public half stays — Archived — until `verify_retain`.
    let clock = TestClock::at(1_000_000);
    let directory = ring("archive");
    let manager = DirectoryKeyManager::with_clock(
        &directory,
        KeyPolicy {
            publish_ahead: Duration::from_secs(3600),
            rotate_every: Duration::from_secs(86_400),
            retain: Duration::from_secs(7 * 86_400), // private half: a week after it retires
            verify_retain: Duration::from_secs(30 * 86_400), // public half: a month
        },
        Box::new(SharedClock(Arc::clone(&clock))),
    );

    // Bring the first key up and rotate once so it retires, exactly as the handover test does.
    manager.maintain().expect("the first pass succeeds");
    let first = manager.active_key_id().expect("a key is signing");
    clock.advance(Duration::from_secs(23 * 3600));
    manager.maintain().expect("a pass succeeds");
    clock.advance(Duration::from_secs(3600));
    manager.maintain().expect("a pass succeeds");
    assert!(
        directory.join(format!("{first}.pem")).exists(),
        "a just-retired key should still hold its private half"
    );

    // Past `retain`: the private half is deleted, the public half stays and is Archived.
    clock.advance(Duration::from_secs(8 * 86_400));
    let report = manager.maintain().expect("a pass succeeds");
    assert!(
        report.archived >= 1,
        "the retired key was not archived: {report:?}"
    );
    assert!(
        !directory.join(format!("{first}.pem")).exists(),
        "the private half outlived `retain`, which is the exposure this avoids"
    );
    assert!(
        manager
            .public_keys()
            .expect("the set reads")
            .iter()
            .any(|key| key.kid == first.as_str()),
        "an archived key must still verify — the seals it made are not yet past retention"
    );
    assert!(
        states(&manager)
            .iter()
            .any(|(kid, state)| kid == first.as_str() && *state == KeyState::Archived),
        "the key is not recorded as archived"
    );

    // Past `verify_retain`: nothing it signed is expected to verify any longer, so it goes entirely.
    clock.advance(Duration::from_secs(25 * 86_400));
    let report = manager.maintain().expect("a pass succeeds");
    assert!(
        report.forgotten >= 1,
        "the archived key was never forgotten: {report:?}"
    );
    assert!(
        !manager
            .public_keys()
            .expect("the set reads")
            .iter()
            .any(|key| key.kid == first.as_str()),
        "the key outlived the verification window it was promised"
    );
}

#[test]
fn test_a_process_that_was_stopped_for_a_week_catches_up_in_one_pass() {
    let clock = TestClock::at(1_000_000);
    let (manager, _) = manager("catch-up", &clock);

    manager.maintain().expect("the first pass succeeds");

    // Nothing ran for long enough that several rotations were missed. Coming back to a ring that
    // needs three more passes to become correct is not a state worth being able to reach.
    clock.advance(Duration::from_secs(5 * 86_400));
    manager.maintain().expect("a pass succeeds");

    let signing: Vec<_> = states(&manager)
        .into_iter()
        .filter(|(_, state)| *state == KeyState::Active)
        .collect();

    assert_eq!(signing.len(), 1, "exactly one key must ever be signing");
}

#[test]
fn test_a_signature_names_a_key_the_set_actually_publishes() {
    let clock = TestClock::at(1_000_000);
    let (manager, _) = manager("signing", &clock);

    manager.maintain().expect("the first pass succeeds");

    let signature = manager.sign(b"a payload").expect("it signs");
    let published = manager.public_keys().expect("the set reads");

    assert_eq!(signature.algorithm(), "EdDSA");
    // Ed25519 signatures are 64 bytes, always.
    assert_eq!(signature.bytes().len(), 64);
    assert!(
        published
            .iter()
            .any(|key| key.kid == signature.key_id().as_str()),
        "a signature names a key nobody can fetch"
    );
}

#[test]
fn test_a_key_ring_that_has_not_been_maintained_refuses_to_sign() {
    let clock = TestClock::at(1_000_000);
    let (manager, _) = manager("not-ready", &clock);

    // Refusing is the whole point: signing under a key no verifier has been given a chance to fetch
    // produces signatures that fail, and failures that look like forgery.
    let error = manager
        .sign(b"a payload")
        .expect_err("nothing is signing yet");

    assert!(
        error.is_retryable(),
        "a ring that is coming up is worth retrying"
    );
    assert!(format!("{error}").contains("no key"));
}

#[test]
fn test_the_published_set_never_opens_a_private_key() {
    let clock = TestClock::at(1_000_000);
    let (manager, directory) = manager("public-only", &clock);

    manager.maintain().expect("the first pass succeeds");
    let active = manager.active_key_id().expect("a key is signing");

    // Take the private half away entirely. Serving the key set must still work: what it publishes
    // comes from the ring, and the ring holds only public material.
    fs::remove_file(directory.join(format!("{active}.pem"))).expect("the key is removed");

    let published = manager.public_keys().expect("the set still reads");

    assert_eq!(published.len(), 1);
    assert_eq!(published[0].kty, "OKP");
    assert_eq!(published[0].crv.as_deref(), Some("Ed25519"));
    assert_eq!(published[0].usage, "sig");
}

#[test]
fn test_a_private_key_is_readable_only_by_the_user_running_the_process() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let clock = TestClock::at(1_000_000);
        let (manager, directory) = manager("permissions", &clock);

        manager.maintain().expect("the first pass succeeds");
        let active = manager.active_key_id().expect("a key is signing");

        let mode = fs::metadata(directory.join(format!("{active}.pem")))
            .expect("the key is there")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600, "the private key is readable by others");
    }
}

#[test]
fn test_two_deployments_never_produce_the_same_key() {
    let clock = TestClock::at(1_000_000);
    let (first, _) = manager("distinct-a", &clock);
    let (second, _) = manager("distinct-b", &clock);

    first.maintain().expect("a pass succeeds");
    second.maintain().expect("a pass succeeds");

    assert_ne!(
        first.active_key_id().expect("a key"),
        second.active_key_id().expect("a key"),
        "two rings produced the same key, which means the key is not random"
    );
}

/// A ring that signs with ES256 must produce signatures a verifier can check against the key set
/// it publishes — the point of offering the algorithm is hardware custody, and hardware is no use
/// if the published key does not match what signed.
#[test]
fn a_p256_ring_signs_and_publishes_a_matching_key() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let keys = DirectoryKeyManager::with_algorithm(
        ring("p256-ring"),
        KeyPolicy {
            publish_ahead: Duration::from_secs(0),
            ..policy()
        },
        RingAlgorithm::Es256,
    );
    keys.maintain().expect("the ring is created");

    let signature = keys.sign(b"payload to sign").expect("the ring signs");
    assert_eq!(signature.algorithm(), "ES256");

    let published = keys.public_keys().expect("the key set is published");
    let jwk = published
        .iter()
        .find(|jwk| jwk.kid == signature.key_id().as_str())
        .expect("the signing key is published");
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv.as_deref(), Some("P-256"));
    assert_eq!(jwk.alg, "ES256");

    // Rebuild the SEC1 point from the published coordinates and verify what the ring signed.
    let x = URL_SAFE_NO_PAD.decode(&jwk.x).expect("x decodes");
    let y = URL_SAFE_NO_PAD
        .decode(jwk.y.as_deref().expect("an EC key publishes y"))
        .expect("y decodes");
    let mut point = vec![0x04];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &point)
        .verify(b"payload to sign", signature.bytes())
        .expect("the published key verifies the signature it signed");
}

/// The default stays Edwards, and a ring file written before algorithms were a choice still loads.
#[test]
fn the_default_ring_is_edwards_and_older_rings_still_load() {
    let directory = ring("edwards-default");
    let keys = DirectoryKeyManager::new(
        directory.clone(),
        KeyPolicy {
            publish_ahead: Duration::from_secs(0),
            ..policy()
        },
    );
    keys.maintain().expect("the ring is created");
    assert_eq!(
        keys.sign(b"payload").expect("it signs").algorithm(),
        "EdDSA"
    );

    // Strip the algorithm the way a file from an earlier build looks.
    let ring_file = directory.join("ring.json");
    let text = fs::read_to_string(&ring_file).expect("the ring file reads");
    fs::write(&ring_file, text.replace(r#""algorithm":"EdDSA","#, ""))
        .expect("the ring file is rewritten");

    let reopened = DirectoryKeyManager::new(
        directory,
        KeyPolicy {
            publish_ahead: Duration::from_secs(0),
            ..policy()
        },
    );
    assert_eq!(
        reopened
            .sign(b"payload")
            .expect("it still signs")
            .algorithm(),
        "EdDSA"
    );
}

/// Changing the algorithm a realm signs with must migrate the ring, not break it.
///
/// The realm publishes the new algorithm the moment configuration changes; if the ring kept an
/// Edwards key signing, every exchange would fail on the mismatch between what is advertised and
/// what is produced. The old keys stay published so what they signed keeps verifying.
#[test]
fn changing_the_algorithm_activates_a_key_of_the_new_kind() {
    let directory = ring("algorithm-change");
    let policy = KeyPolicy {
        publish_ahead: Duration::from_secs(0),
        ..policy()
    };

    let edwards = DirectoryKeyManager::new(directory.clone(), policy);
    edwards.maintain().expect("the ring is created");
    let first = edwards.sign(b"payload").expect("it signs");
    assert_eq!(first.algorithm(), "EdDSA");

    // The same directory, now configured for ES256.
    let nist = DirectoryKeyManager::with_algorithm(directory, policy, RingAlgorithm::Es256);
    nist.maintain().expect("the ring migrates");

    let second = nist.sign(b"payload").expect("it signs with the new kind");
    assert_eq!(second.algorithm(), "ES256");
    assert_ne!(second.key_id().as_str(), first.key_id().as_str());

    // The Edwards key is still published, so tokens it signed still verify.
    let published = nist.public_keys().expect("the key set is published");
    assert!(
        published
            .iter()
            .any(|jwk| jwk.kid == first.key_id().as_str()),
        "the superseded key must stay published: {published:?}"
    );
    assert!(
        published
            .iter()
            .any(|jwk| jwk.kid == second.key_id().as_str())
    );
}
