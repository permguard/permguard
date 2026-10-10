// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use permguard_core::assurance::AssuranceProfile;

use super::*;
use crate::identity::{Identity, Suite, directories};
use crate::keys::FileKeyProvider;
use crate::operations::mutation::Applying;

const NOW: u64 = 1_800_000_000;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-peers-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn open(root: &Path) -> (Volume, Identity) {
    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let (_, keys) = directories(&volume).expect("the directories");
    let provider = Arc::new(FileKeyProvider::new(keys));
    let identity = if crate::identity::is_provisioned(&volume).expect("readable") {
        Identity::open(&volume, provider).expect("opened")
    } else {
        Identity::provision(&volume, provider, Suite::Ed25519Sha256V1, NOW, NOW * 1000)
            .expect("provisioned")
    };
    (volume, identity)
}

fn presentation(identity: &Identity) -> Presentation {
    Presentation {
        document: identity.document(),
        successions: identity.successions(),
        first_public_key: identity.first_public_key().to_vec(),
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

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("created");
    for entry in std::fs::read_dir(from).expect("listed") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copied");
        }
    }
}

#[test]
fn a_pinned_peer_is_accepted_and_its_epoch_advances_only_upward() {
    let root = scratch("advance");
    let (_peer_volume, peer) = open(&root.join("peer"));
    let (volume, _) = open(&root.join("verifier"));
    let peers = Peers::open(&volume, &[pin(&peer)]).expect("opened");
    let verified = peers
        .accept(&presentation(&peer), None, None)
        .expect("accepted");
    assert_eq!(verified.host_id, peer.host_id());
    assert!(peers.seen(&peer.host_id()).expect("readable").is_none());
    peers.advance(&verified, NOW).expect("advanced");
    peer.rotate(&Applying::for_tests(1), Some(1), NOW + 1)
        .expect("rotated");
    let rotated = peers
        .accept(&presentation(&peer), None, None)
        .expect("epoch 2 through its succession");
    assert_eq!(rotated.epoch, 2);
    peers.advance(&rotated, NOW + 2).expect("advanced");
    let seen = peers
        .seen(&peer.host_id())
        .expect("readable")
        .expect("seen");
    assert_eq!(
        (seen.epoch, seen.fingerprint.as_str()),
        (2, rotated.fingerprint())
    );
    // Advancing to an epoch already seen changes nothing; advancing back is refused.
    peers.advance(&rotated, NOW + 3).expect("unchanged");
    assert_eq!(
        peers
            .seen(&peer.host_id())
            .expect("readable")
            .expect("seen")
            .at,
        NOW + 2
    );
    assert!(matches!(
        peers.advance(&verified, NOW + 4),
        Err(PeerRefusal::Rollback {
            seen: 2,
            presented: 1
        })
    ));
}

#[test]
fn a_lower_epoch_is_rollback_and_another_key_at_a_seen_epoch_is_equivocation() {
    let root = scratch("equivocation");
    let (peer_volume, peer) = open(&root.join("peer"));
    let at_one = presentation(&peer);
    drop(peer);
    drop(peer_volume);
    // Two copies of the same identity rotate apart: two keys for epoch 2.
    copy(&root.join("peer"), &root.join("fork"));
    let (_peer_volume, peer) = open(&root.join("peer"));
    peer.rotate(&Applying::for_tests(1), Some(1), NOW + 1)
        .expect("rotated");
    let (_fork_volume, fork) = open(&root.join("fork"));
    fork.rotate(&Applying::for_tests(2), Some(1), NOW + 1)
        .expect("rotated");
    assert_eq!(fork.host_id(), peer.host_id());
    assert_ne!(fork.fingerprint(), peer.fingerprint());

    let (volume, _) = open(&root.join("verifier"));
    let peers = Peers::open(&volume, &[pin(&peer)]).expect("opened");
    let verified = peers
        .accept(&presentation(&peer), None, None)
        .expect("accepted");
    peers.advance(&verified, NOW).expect("advanced");

    assert!(matches!(
        peers.accept(&at_one, None, None),
        Err(PeerRefusal::Rollback {
            seen: 2,
            presented: 1
        })
    ));
    assert!(matches!(
        peers.accept(&presentation(&fork), None, None),
        Err(PeerRefusal::Equivocation { epoch: 2 })
    ));
    // The fork moving on is still a fork: its epoch-2 key is not the one seen.
    fork.rotate(&Applying::for_tests(3), Some(2), NOW + 2)
        .expect("rotated");
    assert!(matches!(
        peers.accept(&presentation(&fork), None, None),
        Err(PeerRefusal::Equivocation { epoch: 2 })
    ));
}

#[test]
fn a_peer_no_pin_names_or_whose_first_key_is_another_is_refused() {
    let root = scratch("unpinned");
    let (_one_volume, one) = open(&root.join("one"));
    let (_other_volume, other) = open(&root.join("other"));
    let (volume, _) = open(&root.join("verifier"));
    let none = Peers::open(&volume, &[]).expect("opened");
    assert!(matches!(
        none.accept(&presentation(&one), None, None),
        Err(PeerRefusal::Unpinned)
    ));
    // The pin names `one`'s Host with `other`'s first key.
    let wrong: PinnedPeer = format!("{} {}", one.host_id_text(), other.first_fingerprint())
        .parse()
        .expect("a pin");
    let peers = Peers::open(&volume, &[wrong]).expect("opened");
    assert!(matches!(
        peers.accept(&presentation(&one), None, None),
        Err(PeerRefusal::Unpinned)
    ));
}

#[test]
fn a_presentation_that_does_not_verify_is_refused() {
    let root = scratch("forged");
    let (_peer_volume, peer) = open(&root.join("peer"));
    let (_other_volume, other) = open(&root.join("other"));
    let (volume, _) = open(&root.join("verifier"));
    let peers = Peers::open(&volume, &[pin(&peer)]).expect("opened");
    // Another Host's document over the pinned Host's first key.
    let forged = Presentation {
        document: other.document(),
        ..presentation(&peer)
    };
    assert!(matches!(
        peers.accept(&forged, None, None),
        Err(PeerRefusal::Identity(_) | PeerRefusal::Unpinned)
    ));
    // A succession record dropped from the chain.
    peer.rotate(&Applying::for_tests(1), Some(1), NOW + 1)
        .expect("rotated");
    let truncated = Presentation {
        successions: Vec::new(),
        ..presentation(&peer)
    };
    assert!(matches!(
        peers.accept(&truncated, None, None),
        Err(PeerRefusal::Identity(_))
    ));
    // Too many records to walk.
    let flooded = Presentation {
        successions: vec![peer.successions()[0].clone(); crate::identity::MAX_SUCCESSIONS + 1],
        ..presentation(&peer)
    };
    assert!(matches!(
        peers.accept(&flooded, None, None),
        Err(PeerRefusal::Identity(_))
    ));
}

#[test]
fn a_seen_file_naming_another_host_is_refused() {
    let root = scratch("seen-other");
    let (_peer_volume, peer) = open(&root.join("peer"));
    let (volume, _) = open(&root.join("verifier"));
    let peers = Peers::open(&volume, &[pin(&peer)]).expect("opened");
    let seen = Seen {
        host_id: [9; 16],
        epoch: 1,
        fingerprint: peer.fingerprint(),
        at: NOW,
    };
    write::replace_bytes(
        &volume
            .host()
            .subdir(DIRECTORY, false)
            .expect("the directory"),
        &file(&peer.host_id()),
        &seen.encode().expect("encoded"),
    )
    .expect("written");
    assert!(matches!(
        peers.accept(&presentation(&peer), None, None),
        Err(PeerRefusal::Storage(_))
    ));
}
