// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::time::ManualClock;

use super::*;
use crate::keys::ring::{DATA_ATTEST, Policy};
use crate::storage::volume::Volume;
use crate::time::{ManualMonotonic, TimeGuard};

const START: i64 = 1_800_000_000;

/// A Host with its identity and two bound rings, on a clock the test moves.
struct Host {
    root: std::path::PathBuf,
    _volume: Volume,
    identity: Arc<Identity>,
    rings: Vec<Arc<Ring>>,
    wall: Arc<ManualClock>,
    monotonic: Arc<ManualMonotonic>,
}

impl Host {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-bundle-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let wall = Arc::new(ManualClock::at(START));
        let monotonic = Arc::new(ManualMonotonic::default());
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            monotonic.clone(),
            Duration::from_secs(30),
        ));
        let provider: Arc<dyn crate::keys::KeyProvider> =
            Arc::new(crate::keys::FileKeyProvider::new(
                identity::directories(&volume).expect("the identity").1,
            ));
        let identity = Arc::new(
            Identity::provision(
                &volume,
                provider,
                Suite::Ed25519Sha256V1,
                START as u64,
                START as u64 * 1000,
            )
            .expect("provisioned"),
        );
        let rings = [HOST_OPERATIONS, DATA_ATTEST]
            .into_iter()
            .map(|id| {
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
                ring.maintain_now().expect("the first key");
                ring
            })
            .collect();
        Self {
            root,
            _volume: volume,
            identity,
            rings,
            wall,
            monotonic,
        }
    }

    fn source(&self) -> Source<'_> {
        Source {
            identity: &self.identity,
            rings: &self.rings,
        }
    }

    fn operations(&self) -> &Ring {
        &self.rings[0]
    }

    /// Moves the clock past the active keys' turn and maintains: every ring prepublishes a
    /// successor, its epoch rising, and binds the new set.
    fn rotate(&self) {
        self.wall.jump(3_100);
        self.monotonic.advance(Duration::from_secs(3_100));
        for ring in &self.rings {
            ring.maintain_now().expect("maintained");
        }
    }

    /// The bundle at `frontier`, its manifest signed.
    fn bundle(&self, frontier: &Frontier) -> (Vec<u8>, Vec<Vec<u8>>) {
        let built = self.build(frontier);
        let manifest = sign(self.operations(), &built).expect("signed");
        (manifest, built.items)
    }

    fn build(&self, frontier: &Frontier) -> Built {
        self.source()
            .build("host", frontier, START as u64)
            .expect("built")
    }

    fn pin(&self) -> String {
        self.identity.first_fingerprint().to_owned()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_bundle_verifies_from_the_pinned_identity_and_a_rotation_does_not_move_its_frontier() {
    let host = Host::new("frontier");
    let frontier = host.source().frontier().expect("the frontier");
    assert_eq!(frontier.identity_epoch, 1);
    let names: Vec<&str> = frontier
        .rings
        .iter()
        .map(|ring| ring.ring.as_str())
        .collect();
    assert_eq!(names, vec![DATA_ATTEST, HOST_OPERATIONS], "sorted");
    let (manifest, items) = host.bundle(&frontier);
    let verified = verify(&manifest, &items, &host.pin(), "host").expect("verifies");
    assert_eq!(verified.manifest.issued_at, START as u64);
    assert_eq!(verified.manifest.resource, "host");
    assert_eq!(verified.manifest.items, items.len() as u64);
    let kinds = |items: &[Item]| {
        let mut counts = [0usize; 4];
        for item in items {
            counts[match item {
                Item::Identity { .. } => 0,
                Item::Key { .. } => 1,
                Item::Binding { .. } => 2,
                Item::Revocation { .. } => 3,
            }] += 1;
        }
        counts
    };
    assert_eq!(kinds(&verified.items), [1, 2, 2, 0]);

    // The rings rotate while a client pages: the same frontier rebuilds the same items.
    host.rotate();
    let again = host.build(&frontier);
    assert_eq!(again.items, items, "the items of the fixed frontier");
    let later = host.source().frontier().expect("a later frontier");
    assert!(later.rings.iter().all(|ring| ring.epoch == 2));
    let (manifest_later, items_later) = host.bundle(&later);
    let verified = verify(&manifest_later, &items_later, &host.pin(), "host").expect("verifies");
    assert_eq!(kinds(&verified.items), [1, 4, 4, 0]);
}

#[test]
fn an_item_outside_the_frontier_is_refused_before_anything_is_digested() {
    let host = Host::new("outside");
    let frontier = host.source().frontier().expect("the frontier");
    let (manifest, items) = host.bundle(&frontier);
    host.rotate();
    let later = host.build(&host.source().frontier().expect("later"));
    let newer = |wanted: fn(&Item) -> bool| {
        later
            .items
            .iter()
            .find(|bytes| !items.contains(bytes) && wanted(&Item::decode(bytes).expect("an item")))
            .expect("an item of the later frontier")
            .clone()
    };
    for (what, extra) in [
        ("a key", newer(|item| matches!(item, Item::Key { .. }))),
        (
            "a binding",
            newer(|item| matches!(item, Item::Binding { .. })),
        ),
        (
            "a revocation",
            Item::Revocation {
                ring: DATA_ATTEST.to_owned(),
                kid: format!("{DATA_ATTEST}:{}", "A".repeat(43)),
                epoch: 2,
                at: START as u64,
                reason: "compromised".to_owned(),
                compromised_at: None,
            }
            .encode()
            .expect("encoded"),
        ),
    ] {
        let mut presented = items.clone();
        presented.push(extra);
        let refused = verify(&manifest, &presented, &host.pin(), "host").expect_err(what);
        assert!(
            matches!(refused, BundleError::Outside(_)),
            "{what}: {refused}"
        );
    }
}

#[test]
fn a_bundle_is_refused_under_another_pin_with_an_item_changed_or_without_its_binding() {
    let host = Host::new("refusals");
    let frontier = host.source().frontier().expect("the frontier");
    let (manifest, items) = host.bundle(&frontier);

    let other = Host::new("refusals-other");
    let refused = verify(&manifest, &items, &other.pin(), "host").expect_err("another pin");
    assert!(matches!(refused, BundleError::Anchor(_)), "{refused}");

    // A revocation inside the frontier that the manifest does not count.
    let mut presented = items.clone();
    presented.push(
        Item::Revocation {
            ring: DATA_ATTEST.to_owned(),
            kid: format!("{DATA_ATTEST}:{}", "A".repeat(43)),
            epoch: 1,
            at: START as u64,
            reason: "compromised".to_owned(),
            compromised_at: None,
        }
        .encode()
        .expect("encoded"),
    );
    let refused = verify(&manifest, &presented, &host.pin(), "host").expect_err("an extra item");
    assert!(matches!(refused, BundleError::Digest(_)), "{refused}");

    // Without the binding of `host.operations` the manifest's signer is vouched for by nothing.
    let unbound: Vec<Vec<u8>> = items
        .iter()
        .filter(|bytes| {
            !matches!(Item::decode(bytes).expect("an item"), Item::Binding { ring, .. } if ring == HOST_OPERATIONS)
        })
        .cloned()
        .collect();
    let refused = verify(&manifest, &unbound, &host.pin(), "host").expect_err("unbound");
    assert!(matches!(refused, BundleError::Unbound(_)), "{refused}");

    // A manifest signed by another Host's operations key.
    let built = host.build(&frontier);
    let ring = other.operations();
    let kid = ring.active_key_id().expect("active");
    let forged = Sign1::sign_with(
        ring.suite(),
        protected::KEYS_BUNDLE,
        kid.as_str().as_bytes(),
        built.manifest.encode().expect("encoded"),
        |bytes| {
            ring.sign(bytes)
                .map(|signature| signature.bytes().to_vec())
                .map_err(|error| error.to_string())
        },
    )
    .and_then(|envelope| envelope.encode())
    .expect("signed elsewhere");
    let refused = verify(&forged, &items, &host.pin(), "host").expect_err("another signer");
    assert!(matches!(refused, BundleError::Signature(_)), "{refused}");
    // The other Host's operations ring cannot sign this Host's frontier at all.
    assert!(matches!(
        sign(other.operations(), &built),
        Err(BundleError::Unreproducible(_))
    ));

    // The resource is signed: a bundle for `host` is not one for a Plane.
    let refused =
        verify(&manifest, &items, &host.pin(), "plane/control").expect_err("another resource");
    assert!(matches!(refused, BundleError::Anchor(_)), "{refused}");
}

#[test]
fn a_frontier_the_host_cannot_rebuild_is_refused() {
    let host = Host::new("unreproducible");
    let frontier = host.source().frontier().expect("the frontier");
    let mut beyond = frontier.clone();
    beyond.rings[0].seq += 100;
    assert!(matches!(
        host.source().build("host", &beyond, 0),
        Err(BundleError::Unreproducible(_))
    ));
    let mut other_set = frontier.clone();
    other_set.rings[0].key_set_digest = [7; 32];
    assert!(matches!(
        host.source().build("host", &other_set, 0),
        Err(BundleError::Unreproducible(_))
    ));
    let mut rotated_identity = frontier.clone();
    rotated_identity.identity_epoch = 2;
    assert!(matches!(
        host.source().build("host", &rotated_identity, 0),
        Err(BundleError::Unreproducible(_))
    ));
}

#[test]
fn a_frontier_reads_back_and_refuses_what_no_host_writes() {
    let frontier = Frontier {
        identity_epoch: 3,
        rings: vec![
            RingFrontier {
                ring: DATA_ATTEST.to_owned(),
                epoch: 2,
                seq: 9,
                key_set_digest: [1; 32],
            },
            RingFrontier {
                ring: HOST_OPERATIONS.to_owned(),
                epoch: 1,
                seq: 4,
                key_set_digest: [2; 32],
            },
        ],
    };
    let bytes = frontier.encode().expect("encoded");
    assert_eq!(Frontier::decode(&bytes).expect("reads back"), frontier);
    let refused = |frontier: Frontier| {
        Frontier::decode(&frontier.encode().expect("encoded")).expect_err("refused")
    };
    let mut unsorted = frontier.clone();
    unsorted.rings.reverse();
    refused(unsorted);
    let mut identity_ring = frontier.clone();
    identity_ring.rings[0].ring = HOST_IDENTITY.to_owned();
    refused(identity_ring);
    let mut zero = frontier.clone();
    zero.rings[1].seq = 0;
    refused(zero);
}

#[test]
fn every_item_reads_back_and_refuses_a_foreign_member() {
    let items = [
        Item::Identity {
            document: vec![1],
            successions: vec![vec![2], vec![3]],
            first_public_key: vec![4; 32],
        },
        Item::Key {
            ring: DATA_ATTEST.to_owned(),
            kid: format!("{DATA_ATTEST}:t"),
            jwk: "{}".to_owned(),
            epoch: 1,
            state: State::Active,
        },
        Item::Binding {
            ring: DATA_ATTEST.to_owned(),
            epoch: 1,
            envelope: vec![5],
        },
        Item::Revocation {
            ring: DATA_ATTEST.to_owned(),
            kid: format!("{DATA_ATTEST}:t"),
            epoch: 2,
            at: 9,
            reason: "lost".to_owned(),
            compromised_at: Some(8),
        },
    ];
    for item in items {
        let bytes = item.encode().expect("encoded");
        assert_eq!(Item::decode(&bytes).expect("decoded"), item);
        let mut value = permguard_objects::cbor::decode_canonical(&bytes).expect("cbor");
        if let Value::Map(pairs) = &mut value {
            pairs.push((Value::Int(99), Value::Int(0)));
        }
        let foreign = permguard_objects::cbor::encode(&value).expect("encoded");
        assert!(Item::decode(&foreign).is_err(), "{item:?}");
    }
}

#[test]
fn every_binding_is_kept_by_its_journal_entry_and_counts_once_journaled() {
    let host = Host::new("kept");
    let ring = &host.rings[1];
    let at = |ring: &Ring| {
        let (_, seq, _) = ring.frontier().expect("read").expect("a key");
        ring.history(seq).expect("the history")
    };
    let first = ring.kept_bindings(&at(ring)).expect("kept");
    assert_eq!(first.len(), 1);
    // Past the renewal point the binding is issued again: a new entry, a new kept binding, and
    // the first one stays.
    host.wall.jump(24 * 86_400);
    host.monotonic.advance(Duration::from_secs(24 * 86_400));
    ring.maintain_now().expect("maintained");
    let now = ring.kept_bindings(&at(ring)).expect("kept");
    assert!(now.len() > first.len(), "{} kept", now.len());
    assert_eq!(now[0], first[0], "the first binding stays");

    // A binding file whose entry never reached the journal counts for nothing.
    let history = at(ring);
    let orphan = history.seq + 1;
    std::fs::copy(
        host.root.join(format!(
            "host/keys/data.attest/bindings/{}.cose",
            history.bound[0].0
        )),
        host.root
            .join(format!("host/keys/data.attest/bindings/{orphan}.cose")),
    )
    .expect("copied");
    assert_eq!(ring.kept_bindings(&history).expect("kept"), now);
}

/// WP-3.4: `keys export --directory` reads a ring's journal on the volume, every public key it
/// published with its epoch and digest, and no private half.
#[test]
fn a_ring_exports_offline_from_its_journal() {
    let host = Host::new("export");
    let directory = host.root.join("host/keys/data.attest");
    let exported: serde_json::Value =
        serde_json::from_str(&super::super::ring::export(&directory).expect("exported"))
            .expect("JSON");
    let statement = host.rings[1].statement().expect("a statement");
    assert_eq!(exported["ring"], DATA_ATTEST);
    assert_eq!(exported["epoch"], 1);
    assert_eq!(
        exported["digest"],
        statement
            .key_set_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(exported["keys"].as_array().expect("keys").len(), 1);
    assert!(!exported.to_string().contains("\"d\""), "no private member");

    host.rotate();
    let exported: serde_json::Value =
        serde_json::from_str(&super::super::ring::export(&directory).expect("exported"))
            .expect("JSON");
    assert_eq!(exported["epoch"], 2);
    assert_eq!(exported["keys"].as_array().expect("keys").len(), 2);
    assert!(super::super::ring::export(&host.root.join("host/keys")).is_err());
}

fn data_attest(frontier: &Frontier) -> &RingFrontier {
    frontier
        .rings
        .iter()
        .find(|ring| ring.ring == DATA_ATTEST)
        .expect("data.attest in the frontier")
}

/// WP-3.4 review: each refusal of the verifier, asserted by its own reason, so no other check
/// stands in for it.
#[test]
fn the_verifier_refuses_each_forgery_for_its_own_reason() {
    let host = Host::new("reasons");
    // Two keys in each set, so one can be presented as archived.
    host.rotate();
    let frontier = host.source().frontier().expect("the frontier");
    let (manifest, items) = host.bundle(&frontier);
    let reason = |items: &[Vec<u8>]| {
        verify(&manifest, items, &host.pin(), "host")
            .expect_err("refused")
            .to_string()
    };

    // An item twice.
    let mut twice = items.clone();
    twice.push(
        items
            .iter()
            .find(|bytes| matches!(Item::decode(bytes), Ok(Item::Binding { .. })))
            .expect("a binding")
            .clone(),
    );
    assert!(
        reason(&twice).contains("appears twice"),
        "{}",
        reason(&twice)
    );

    // A published key presented as archived: the set no longer digests to the frontier's.
    let changed: Vec<Vec<u8>> = items
        .iter()
        .map(|bytes| match Item::decode(bytes).expect("an item") {
            Item::Key {
                ring,
                kid,
                jwk,
                epoch,
                state: State::Active,
            } if ring == DATA_ATTEST => Item::Key {
                ring,
                kid,
                jwk,
                epoch,
                state: State::Archived,
            }
            .encode()
            .expect("encoded"),
            _ => bytes.clone(),
        })
        .collect();
    assert!(
        reason(&changed).contains("are not the frontier's set"),
        "{}",
        reason(&changed)
    );

    // A binding of the frontier epoch over another set, signed by the identity: equivocation.
    let fixed = data_attest(&frontier);
    let other = Binding {
        host_id: host.identity.host_id(),
        ring: DATA_ATTEST.to_owned(),
        epoch: fixed.epoch,
        key_set_digest: [7; 32],
        suite: Suite::Ed25519Sha256V1,
        not_before: START as u64,
        not_after: START as u64 + 1,
    };
    let envelope = host
        .identity
        .sign(
            protected::HOST_RING_BINDING,
            other.encode().expect("encoded"),
        )
        .expect("signed");
    let mut equivocating = items.clone();
    equivocating.push(
        Item::Binding {
            ring: DATA_ATTEST.to_owned(),
            epoch: fixed.epoch,
            envelope,
        }
        .encode()
        .expect("encoded"),
    );
    assert!(
        reason(&equivocating).contains("equivocation"),
        "{}",
        reason(&equivocating)
    );
}

/// WP-3.4 review: the manifest is signed by the `host.operations` key active at the frontier,
/// never by another key of its set.
#[test]
fn a_manifest_signed_by_a_key_not_active_at_the_frontier_is_refused() {
    let host = Host::new("signer");
    host.rotate();
    let frontier = host.source().frontier().expect("the frontier");
    let built = host.build(&frontier);
    let successor = built
        .items
        .iter()
        .find_map(|bytes| match Item::decode(bytes).expect("an item") {
            Item::Key {
                ring, kid, state, ..
            } if ring == HOST_OPERATIONS && state == State::Prepublished => Some(kid),
            _ => None,
        })
        .expect("a prepublished successor");
    let slot = thumbprint::split_kid(&successor)
        .expect("a kid")
        .1
        .to_owned();
    let private = crate::keys::FileKeyProvider::new(
        crate::storage::Dir::open(&host.root.join("host/keys/host.operations/private"))
            .expect("opens"),
    );
    let forged = Sign1::sign_with(
        Suite::Ed25519Sha256V1,
        protected::KEYS_BUNDLE,
        successor.as_bytes(),
        built.manifest.encode().expect("encoded"),
        |bytes| {
            crate::keys::KeyProvider::sign(&private, &slot, Suite::Ed25519Sha256V1, bytes)
                .map_err(|error| error.to_string())
        },
    )
    .and_then(|envelope| envelope.encode())
    .expect("signed by the successor");
    let refused = verify(&forged, &built.items, &host.pin(), "host").expect_err("not active");
    assert!(matches!(refused, BundleError::Signature(_)), "{refused}");
}

/// WP-3.4 review: a bundle fixed before the identity rotated, presented with the identity of
/// after, is outside its frontier.
#[test]
fn an_identity_of_another_epoch_than_the_frontiers_is_outside_it() {
    let host = Host::new("identity-epoch");
    let mut frontier = host.source().frontier().expect("the frontier");
    let (_, items) = host.bundle(&frontier);
    // A manifest naming identity epoch 2, signed by the Host, over the same items.
    frontier.identity_epoch = 2;
    let built = Built {
        manifest: Manifest {
            frontier: frontier.clone(),
            ..host
                .build(&host.source().frontier().expect("again"))
                .manifest
        },
        items: items.clone(),
        signer: host.build(&host.source().frontier().expect("again")).signer,
    };
    let manifest = sign(host.operations(), &built).expect("signed");
    let refused = verify(&manifest, &items, &host.pin(), "host").expect_err("another epoch");
    assert!(matches!(refused, BundleError::Outside(_)), "{refused}");
}

/// WP-3.4 review: a later page's frontier is the Host's manifest for that resource, rebuilt to
/// the same digest.
#[test]
fn a_reopened_frontier_is_checked_for_its_resource_and_its_items() {
    let host = Host::new("reopen");
    let frontier = host.source().frontier().expect("the frontier");
    let (manifest, items) = host.bundle(&frontier);
    let reopened = host.source().reopen(&manifest, "host").expect("reopened");
    assert_eq!(reopened.items, items);
    assert!(matches!(
        host.source().reopen(&manifest, "plane/control"),
        Err(BundleError::Malformed(_))
    ));
    // A kept binding lost from the volume: the frontier no longer rebuilds as it was signed.
    let bindings = host.root.join("host/keys/data.attest/bindings");
    for entry in std::fs::read_dir(&bindings).expect("listed") {
        std::fs::remove_file(entry.expect("an entry").path()).expect("removed");
    }
    assert!(matches!(
        host.source().reopen(&manifest, "host"),
        Err(BundleError::Unreproducible(_))
    ));
}

/// WP-3.4: a binding issued before bindings were kept is issued again, kept, at the next
/// maintenance.
#[test]
fn a_binding_that_was_never_kept_is_issued_again() {
    let host = Host::new("legacy");
    let ring = &host.rings[1];
    std::fs::remove_dir_all(host.root.join("host/keys/data.attest/bindings")).expect("removed");
    ring.maintain_now().expect("maintained");
    let (_, seq, _) = ring.frontier().expect("read").expect("a key");
    let kept = ring
        .kept_bindings(&ring.history(seq).expect("the history"))
        .expect("kept");
    assert_eq!(kept.len(), 1, "issued again and kept");
}

/// WP-3.4 review: the export keeps a key that left the published set out of `keys`.
#[test]
fn an_archived_key_is_retained_never_in_the_exported_jwks() {
    let host = Host::new("export-archived");
    host.rotate();
    let directory = host.root.join("host/keys/data.attest");
    // The successor takes over, then the predecessor's `retain` ends.
    for step in [700, 7_300] {
        host.wall.jump(step);
        host.monotonic.advance(Duration::from_secs(step as u64));
        host.rings[1].maintain_now().expect("maintained");
    }
    let exported: serde_json::Value =
        serde_json::from_str(&super::super::ring::export(&directory).expect("exported"))
            .expect("JSON");
    let retained = exported["retained"].as_array().expect("retained");
    assert!(
        retained.iter().any(|key| key["state"] == "archived"),
        "{exported}"
    );
    let published: Vec<&str> = exported["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .filter_map(|key| key["kid"].as_str())
        .collect();
    for key in retained {
        assert!(!published.contains(&key["jwk"]["kid"].as_str().unwrap_or_default()));
    }
}
