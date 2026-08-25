// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reclaiming what this workspace's mirror no longer needs.
//!
//! # What accumulates, and why
//!
//! The mirror under `.permguard/objects` only ever grows. A pull that was
//! interrupted leaves the objects it had fetched with no checkpoint naming
//! them; a `refresh` that built a snapshot nobody applied leaves a tree and
//! its blobs; an edit that replaced a policy leaves the previous version once
//! the head has moved past it. None of that is wrong — it is what a
//! content-addressed store looks like — but nothing removes it either.
//!
//! # The rule
//!
//! ```text
//! keep = reachable from the tracked checkpoint  ∪  reachable from the staged snapshot
//! ```
//!
//! Everything else goes. There is no grace period here, and there does not
//! need to be one: a mutating command holds the workspace lock, so a fetch in
//! flight and a prune cannot be looking at the same mirror at the same time —
//! which is exactly the race the server has to use time to avoid.
//!
//! # What it refuses to do
//!
//! If either closure has a **hole** — an object that is referenced and not
//! present — the prune is refused rather than performed. A walk that cannot be
//! completed cannot tell "unreachable" from "unreachable *from here*", and the
//! difference is somebody's policy history. `permguard verify` is the command
//! that says what is missing.
//!
//! Nothing is lost by pruning either way: every object here is a verified copy
//! of something the remote holds, and the next pull fetches back whatever a
//! later checkout needs.

use std::collections::BTreeSet;

use permguard_control_client::Store;
use permguard_control_client::objects;
use permguard_objects::digest::Digest;
use permguard_objects::object::{self, Object};

use super::inventory::{self, OBJECTS_DIR};
use super::{Result, WorkspaceError, config, err};

/// One object a prune took, or would take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reclaimed {
    pub digest: Digest,
    /// `blob`, `tree`, `commit` — or `unreadable`, for bytes that no longer
    /// decode to the object their name claims.
    pub kind: &'static str,
    /// The stored bytes it occupied, compressed as they are at rest.
    pub bytes: u64,
}

/// What a prune did, or would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pruned {
    pub reclaimed: Vec<Reclaimed>,
    /// Objects kept because something reaches them.
    pub kept: usize,
    /// Whether anything was actually removed.
    pub applied: bool,
}

impl Pruned {
    /// The bytes this prune freed, or would free.
    pub fn bytes(&self) -> u64 {
        self.reclaimed.iter().map(|object| object.bytes).sum()
    }
}

/// Removes every object neither the tracked head nor the staged snapshot
/// reaches. With `apply` false, nothing is written and the answer is what
/// *would* go.
pub fn prune(store: &dyn Store, apply: bool) -> Result<Pruned> {
    let tracked = reachable(store, tracked_head(store)?)?;
    let staged = reachable(store, staged_root(store)?)?;

    let mut pruned = Pruned {
        applied: apply,
        ..Pruned::default()
    };
    for record in inventory::inventory(store).map_err(err)? {
        if tracked.contains(&record.digest) || staged.contains(&record.digest) {
            pruned.kept += 1;
            continue;
        }
        let bytes = if apply {
            objects::remove(store, OBJECTS_DIR, &record.digest).map_err(err)?
        } else {
            stored_bytes(store, &record.digest)
        };
        pruned.reclaimed.push(Reclaimed {
            digest: record.digest,
            kind: record.kind,
            bytes,
        });
    }

    Ok(pruned)
}

/// The stored size of one object, for a report that has to say what would be
/// freed. Zero when it cannot be read — the same object the walk called
/// unreadable.
fn stored_bytes(store: &dyn Store, digest: &Digest) -> u64 {
    let hex = digest.to_string();
    let hex = &hex["sha256:".len()..];
    let path = format!("{OBJECTS_DIR}/{}/{}", &hex[..2], &hex[2..]);

    store
        .read(&path)
        .ok()
        .flatten()
        .map(|bytes| bytes.len() as u64)
        .unwrap_or(0)
}

/// Everything reachable from `start`, refusing on a hole.
///
/// Strict where [`inventory`](super::inventory) is tolerant, and deliberately
/// so: a listing may show an incomplete picture, a deletion may not act on
/// one.
fn reachable(store: &dyn Store, start: Option<Digest>) -> Result<BTreeSet<Digest>> {
    let mut reached = BTreeSet::new();
    let mut queue: Vec<Digest> = start.into_iter().collect();

    while let Some(digest) = queue.pop() {
        if !reached.insert(digest.clone()) {
            continue;
        }
        let bytes = inventory::get(store, &digest)
            .map_err(err)?
            .ok_or_else(|| WorkspaceError {
                message: format!(
                    "the object {digest} is referenced and missing: run `permguard verify` \
                         before pruning"
                ),
            })?;
        match object::decode(&bytes).map_err(|error| err(format!("{digest}: {error}")))? {
            Object::Commit(commit) => {
                queue.push(commit.tree);
                queue.push(commit.manifest);
                queue.extend(commit.predecessors);
            }
            Object::Tree(tree) => {
                queue.extend(tree.entries.into_iter().map(|entry| entry.digest));
            }
            Object::Blob(_) => {}
        }
    }

    Ok(reached)
}

fn tracked_head(store: &dyn Store) -> Result<Option<Digest>> {
    let Some(r#ref) = config::read_head(store).map_err(err)? else {
        return Ok(None);
    };

    Ok(config::read_checkpoint(store, &r#ref)
        .map_err(err)?
        .and_then(|checkpoint| Digest::parse(&checkpoint.head).ok()))
}

fn staged_root(store: &dyn Store) -> Result<Option<Digest>> {
    Ok(store
        .read(".permguard/staging/tree")
        .map_err(err)?
        .and_then(|bytes| Digest::parse(String::from_utf8_lossy(&bytes).trim()).ok()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_control_client::FsStore;
    use permguard_objects::object::Blob;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-prune-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");

        dir
    }

    /// One blob in the mirror, the way a fetch puts it there.
    fn blob(store: &dyn Store, text: &str) -> Digest {
        let bytes = Blob {
            media_type: "application/vnd.permguard.policy.cedar".to_owned(),
            data: format!("permit (principal, action, resource); // {text}").into_bytes(),
        }
        .encode()
        .expect("the blob encodes");

        inventory::put(store, &bytes).expect("the blob is stored")
    }

    /// A commit over one blob, and the checkpoint that tracks it.
    fn track(store: &dyn Store, policy: &Digest) -> Digest {
        let tree = inventory::put(
            store,
            &object::Tree {
                entries: vec![permguard_objects::object::TreeEntry {
                    kind: permguard_objects::object::Kind::Blob,
                    digest: policy.clone(),
                    name: "policy.cedar".to_owned(),
                    annotations: std::collections::BTreeMap::new(),
                }],
            }
            .encode()
            .expect("the tree encodes"),
        )
        .expect("the tree is stored");
        let manifest = blob(store, "a manifest stand-in");
        let commit = inventory::put(
            store,
            &object::Commit {
                tree,
                manifest,
                predecessors: Vec::new(),
                author: "tests".to_owned(),
                author_at: 1_700_000_000,
                message: "tracked".to_owned(),
            }
            .encode()
            .expect("the commit encodes"),
        )
        .expect("the commit is stored");

        config::write_head(store, "main").expect("the head is written");
        config::write_checkpoint(
            store,
            "main",
            &permguard_control_client::checkpoint::Checkpoint {
                head: commit.to_string(),
                counter: 1,
            },
        )
        .expect("the checkpoint is written");

        commit
    }

    #[test]
    fn what_the_tracked_head_reaches_is_kept_and_the_rest_goes() {
        let store = FsStore::new(scratch("orphan"));
        let policy = blob(&store, "kept");
        let commit = track(&store, &policy);
        let orphan = blob(&store, "an interrupted pull left this");

        let pruned = prune(&store, true).expect("the prune runs");

        assert_eq!(pruned.reclaimed.len(), 1);
        assert_eq!(pruned.reclaimed[0].digest, orphan);
        assert!(pruned.bytes() > 0, "the bytes it freed are reported");
        assert!(!inventory::has(&store, &orphan));
        assert!(inventory::has(&store, &policy), "and nothing else moved");
        assert!(inventory::has(&store, &commit));
    }

    #[test]
    fn a_dry_run_removes_nothing_and_says_what_it_would_take() {
        let store = FsStore::new(scratch("dry"));
        track(&store, &blob(&store, "kept"));
        let orphan = blob(&store, "would go");

        let pruned = prune(&store, false).expect("the prune runs");

        assert!(!pruned.applied);
        assert_eq!(pruned.reclaimed.len(), 1);
        assert!(pruned.bytes() > 0, "a preview still weighs what it found");
        assert!(
            inventory::has(&store, &orphan),
            "and the object is exactly where it was"
        );
    }

    #[test]
    fn the_staged_snapshot_protects_what_it_reaches() {
        let store = FsStore::new(scratch("staged"));
        track(&store, &blob(&store, "kept"));
        // What `refresh` leaves behind: a tree nobody has applied yet.
        let staged_policy = blob(&store, "staged");
        let staged_tree = inventory::put(
            &store,
            &object::Tree {
                entries: vec![permguard_objects::object::TreeEntry {
                    kind: permguard_objects::object::Kind::Blob,
                    digest: staged_policy.clone(),
                    name: "policy.cedar".to_owned(),
                    annotations: std::collections::BTreeMap::new(),
                }],
            }
            .encode()
            .expect("the tree encodes"),
        )
        .expect("the tree is stored");
        store
            .write(
                ".permguard/staging/tree",
                staged_tree.to_string().as_bytes(),
            )
            .expect("the staging pointer is written");

        let pruned = prune(&store, true).expect("the prune runs");

        assert!(pruned.reclaimed.is_empty(), "{pruned:?}");
        assert!(inventory::has(&store, &staged_policy));
    }

    #[test]
    fn a_hole_in_the_closure_refuses_the_prune_rather_than_guessing() {
        let store = FsStore::new(scratch("hole"));
        let policy = blob(&store, "kept");
        track(&store, &policy);
        let orphan = blob(&store, "would have gone");
        // Something the head reaches is missing.
        objects::remove(&store, OBJECTS_DIR, &policy).expect("removed by hand");

        let refused = prune(&store, true).expect_err("an incomplete walk cannot decide");

        assert!(refused.message.contains("permguard verify"), "{refused:?}");
        assert!(
            inventory::has(&store, &orphan),
            "and nothing was removed on the way to finding out"
        );
    }

    #[test]
    fn a_workspace_that_tracks_nothing_keeps_only_what_is_staged() {
        let store = FsStore::new(scratch("untracked"));
        let loose = blob(&store, "no head, no staging");

        let pruned = prune(&store, true).expect("the prune runs");

        assert_eq!(pruned.reclaimed.len(), 1);
        assert!(!inventory::has(&store, &loose));
    }
}
