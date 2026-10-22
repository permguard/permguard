// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The pull cycle: negotiate once, verify the signed head first, fetch the
//! missing objects in batches, prove the closure whole — and only then let
//! the checkpoint advance. Split in two on purpose:
//!
//! - [`fetch_closure`] does everything up to the proof and **does not**
//!   advance the checkpoint;
//! - [`commit_checkpoint`] advances it.
//!
//! A mirror (the data plane) calls the two back to back. The workspace puts
//! its file materialization between them, so a failure writing sources can
//! never leave the checkpoint claiming more than the disk holds.

use std::collections::BTreeSet;

use permguard_notp::{ExpectedRef, FetchObjectsRequest, NegotiatePullRequest};
use permguard_objects::digest::Digest;
use permguard_objects::object::{self, Object};

use crate::checkpoint::{self, Checkpoint};
use crate::remote::Remote;
use crate::store::Store;
use crate::verify;

/// The identity a pull verifies statements against: the resolved GUIDs the
/// checkout recorded, and the ref being followed.
#[derive(Debug, Clone)]
pub struct TrackedRef {
    pub zone_id: String,
    pub ledger_id: String,
    pub r#ref: String,
}

/// What a completed fetch proved: the verified head, ready to be committed.
#[derive(Debug, Clone)]
pub struct VerifiedHead {
    pub head: Digest,
    pub counter: u64,
    /// The digest of the verified ref state.
    pub ref_digest: Digest,
    /// The Host the head statement names as its authority.
    pub authority_host_id: [u8; 16],
    /// The ref the statement signed.
    pub reference: String,
    /// How many objects actually crossed the wire.
    pub fetched: usize,
}

/// Negotiate, verify, fetch, prove — everything except the checkpoint.
///
/// Objects persist incrementally (immutable, reusable on retry); the caller
/// decides when the checkpoint moves by calling [`commit_checkpoint`].
pub fn fetch_closure(
    store: &dyn Store,
    objects_root: &str,
    checkpoint_path: &str,
    remote: &dyn Remote,
    tracked: &TrackedRef,
) -> Result<VerifiedHead, String> {
    let checkpoint = checkpoint::read(store, checkpoint_path)?;

    let have = match &checkpoint {
        Some(checkpoint) => vec![
            Digest::parse(&checkpoint.head).map_err(|_| "the checkpoint is corrupt".to_owned())?,
        ],
        None => Vec::new(),
    };
    // The state last verified, when the checkpoint names its digest.
    let held = match &checkpoint {
        Some(Checkpoint {
            counter,
            ref_digest: Some(digest),
            ..
        }) => Some(ExpectedRef {
            counter: *counter,
            digest: Digest::parse(digest).map_err(|_| "the checkpoint is corrupt".to_owned())?,
        }),
        _ => None,
    };
    let negotiated = remote.negotiate_pull(&NegotiatePullRequest {
        r#ref: tracked.r#ref.clone(),
        at: None,
        have,
        checkpoint: held,
    })?;

    // Provenance and freshness before anything else moves.
    let jwks = remote.keyring()?;
    let statement = verify::verify_statement(
        &jwks,
        &negotiated.statement,
        &tracked.zone_id,
        &tracked.ledger_id,
        &tracked.r#ref,
        checkpoint.as_ref(),
    )?;
    // The answer's state is the one the statement signs, or nothing moves.
    if negotiated.head != statement.digest
        || negotiated.counter != statement.counter
        || negotiated.ref_digest != statement.ref_digest
    {
        return Err("the negotiated ref state is not the one its statement signs".to_owned());
    }

    // Fetch in batches within the advertised limits.
    let mut fetched = 0usize;
    let missing: Vec<Digest> = negotiated
        .missing
        .iter()
        .filter(|digest| !crate::objects::has(store, objects_root, digest))
        .cloned()
        .collect();
    for chunk in missing.chunks(negotiated.max_batch_objects.max(1) as usize) {
        let answer = remote.fetch(&FetchObjectsRequest {
            digests: chunk.to_vec(),
            // The transport states what it accepts and undoes it.
            accept_compression: None,
            transfer_id: negotiated.transfer_id,
        })?;
        for bytes in answer.objects {
            let digest = crate::objects::put(store, objects_root, &bytes)?;
            if !chunk.contains(&digest) {
                return Err(format!("the server sent {digest}, which was not asked for"));
            }
            fetched += 1;
        }
    }

    // The whole closure must be present and hash-verified.
    let head = statement.digest.clone();
    walk_local(store, objects_root, &head)?;

    Ok(VerifiedHead {
        head,
        counter: statement.counter,
        ref_digest: statement.ref_digest,
        authority_host_id: statement.authority_host_id,
        reference: tracked.r#ref.clone(),
        fetched,
    })
}

/// Advances the checkpoint to a head [`fetch_closure`] proved.
pub fn commit_checkpoint(
    store: &dyn Store,
    checkpoint_path: &str,
    verified: &VerifiedHead,
) -> Result<(), String> {
    checkpoint::write(
        store,
        checkpoint_path,
        &Checkpoint {
            head: verified.head.to_string(),
            counter: verified.counter,
            ref_digest: Some(verified.ref_digest.to_string()),
            authority_host_id: Some(uuid_text(&verified.authority_host_id)),
            reference: Some(verified.reference.clone()),
        },
    )
}

/// 16 UUID bytes in their canonical text form: lowercase, hyphenated.
fn uuid_text(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Everything reachable from `start` in the local mirror; an absent object
/// is an error — the closure must be whole.
pub fn walk_local(
    store: &dyn Store,
    objects_root: &str,
    start: &Digest,
) -> Result<BTreeSet<Digest>, String> {
    walk_region_local(store, objects_root, start, &BTreeSet::new())
}

/// Everything reachable from `start` down to (excluding) `stop` — the delta
/// region a push declares.
pub fn walk_region_local(
    store: &dyn Store,
    objects_root: &str,
    start: &Digest,
    stop: &BTreeSet<Digest>,
) -> Result<BTreeSet<Digest>, String> {
    let mut region = BTreeSet::new();
    let mut queue = vec![start.clone()];
    while let Some(digest) = queue.pop() {
        if stop.contains(&digest) || region.contains(&digest) {
            continue;
        }
        let bytes = crate::objects::get(store, objects_root, &digest)?
            .ok_or_else(|| format!("the closure is incomplete: {digest} is missing"))?;
        let decoded = object::decode(&bytes).map_err(|error| format!("{digest}: {error}"))?;
        region.insert(digest);
        match decoded {
            Object::Commit(commit) => {
                queue.push(commit.tree);
                queue.push(commit.manifest);
                queue.extend(commit.predecessors);
            }
            Object::Tree(tree) => queue.extend(tree.entries.into_iter().map(|entry| entry.digest)),
            Object::Blob(_) => {}
        }
    }
    Ok(region)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// WP-6.6b: the checkpoint keeps the authority the verified statement names, as a canonical
    /// UUID, and the ref it signed — what a signed decision response cites.
    #[test]
    fn the_checkpoint_keeps_the_statements_authority_and_ref() {
        let root =
            std::env::temp_dir().join(format!("permguard-pull-checkpoint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = crate::store::FsStore::new(&root);
        let verified = VerifiedHead {
            head: Digest::compute(b"head"),
            counter: 7,
            ref_digest: Digest::compute(b"ref state"),
            authority_host_id: [
                0x01, 0x93, 0x70, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xa0, 0xa0,
            ],
            reference: "main".to_owned(),
            fetched: 0,
        };
        commit_checkpoint(&store, "refs/main", &verified).expect("written");
        let held = checkpoint::read(&store, "refs/main")
            .expect("reads")
            .expect("held");
        assert_eq!(
            held.authority_host_id.as_deref(),
            Some("01937000-0000-7000-8000-00000000a0a0")
        );
        assert_eq!(held.reference.as_deref(), Some("main"));
        assert_eq!(held.counter, 7);
        let _ = std::fs::remove_dir_all(&root);
    }
}
