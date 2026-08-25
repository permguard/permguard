// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this workspace's mirror holds: the same content-addressed layout as
//! the server's, rooted at `.permguard/objects`, plus the inventory that
//! situates every object — tracked by the remote head, staged by the last
//! refresh, both, or orphaned.
//!
//! The primitives are [`permguard_control_client::objects`]; this module
//! is where the workspace's root is decided, once.

use permguard_objects::digest::Digest;

use permguard_control_client::Store;
use permguard_control_client::objects;

/// Where a workspace keeps its mirror — the primitives are told, every time.
pub const OBJECTS_DIR: &str = ".permguard/objects";

/// Stores one object; a no-op when the digest is already present.
pub fn put(store: &dyn Store, bytes: &[u8]) -> Result<Digest, String> {
    objects::put(store, OBJECTS_DIR, bytes)
}

/// Reads one object, decompressed and hash-verified on the way out.
pub fn get(store: &dyn Store, digest: &Digest) -> Result<Option<Vec<u8>>, String> {
    objects::get(store, OBJECTS_DIR, digest)
}

/// Whether an object is present.
pub fn has(store: &dyn Store, digest: &Digest) -> bool {
    objects::has(store, OBJECTS_DIR, digest)
}

/// One object of the local store, situated: what it is and who reaches it.
#[derive(Debug, Clone)]
pub struct InventoryRecord {
    pub digest: Digest,
    /// `blob`, `tree` or `commit`; `unreadable` when the bytes do not decode.
    pub kind: &'static str,
    /// Reachable from the tracked remote head (the checkpoint).
    pub tracked: bool,
    /// Reachable from the staged snapshot (the last `refresh`).
    pub staged: bool,
    /// What a person calls this object, when the walk that reached it knows:
    /// a blob's entry name in its tree (with the declared alias beside it), a
    /// tree's path, a commit's message, the manifest by its own name. A digest
    /// tells an operator nothing; the name is what they were looking for.
    pub label: Option<String>,
}

/// The store, situated: every object with its kind and who reaches it —
/// the tracked head, the staged snapshot, both, or nobody (an orphan a
/// future GC may take). Tolerant on purpose: a hole in a closure marks the
/// walk incomplete rather than failing the listing.
pub fn inventory(store: &dyn Store) -> Result<Vec<InventoryRecord>, String> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut labels: BTreeMap<Digest, String> = BTreeMap::new();
    let tracked = reachable_from(store, tracked_head(store)?, &mut labels);
    let staged = reachable_from(store, staged_root(store)?, &mut labels);

    let mut records = Vec::new();
    for digest in list(store)? {
        let kind = match get(store, &digest)? {
            Some(bytes) => match permguard_objects::object::decode(&bytes) {
                Ok(permguard_objects::object::Object::Blob(_)) => "blob",
                Ok(permguard_objects::object::Object::Tree(_)) => "tree",
                Ok(permguard_objects::object::Object::Commit(_)) => "commit",
                Err(_) => "unreadable",
            },
            None => continue,
        };
        records.push(InventoryRecord {
            tracked: tracked.contains(&digest),
            staged: staged.contains(&digest),
            label: labels.get(&digest).cloned(),
            digest,
            kind,
        });
    }
    return Ok(records);

    /// Everything reachable from `start`, skipping holes: this is a listing,
    /// not a verification — `verify` is where holes are errors.
    ///
    /// Names are gathered on the way: a tree already says what its entries are
    /// called, and a walk that read the tree and threw the names away would
    /// leave the listing speaking only in digests.
    fn reachable_from(
        store: &dyn Store,
        start: Option<Digest>,
        labels: &mut BTreeMap<Digest, String>,
    ) -> BTreeSet<Digest> {
        use permguard_objects::object::{self, Object};
        use permguard_objects::policy_id::ANNOTATION_POLICY_ALIAS;
        let mut reached = BTreeSet::new();
        let mut queue: Vec<(Digest, String)> = start
            .into_iter()
            .map(|digest| (digest, String::new()))
            .collect();
        while let Some((digest, path)) = queue.pop() {
            if reached.contains(&digest) {
                continue;
            }
            let Ok(Some(bytes)) = get(store, &digest) else {
                continue;
            };
            reached.insert(digest.clone());
            match object::decode(&bytes) {
                Ok(Object::Commit(commit)) => {
                    // A commit's name is what its author called the change.
                    let subject = commit.message.lines().next().unwrap_or_default();
                    if !subject.is_empty() {
                        labels.entry(digest).or_insert_with(|| subject.to_owned());
                    }
                    queue.push((commit.tree, String::new()));
                    queue.push((commit.manifest, "manifest".to_owned()));
                    queue.extend(
                        commit
                            .predecessors
                            .into_iter()
                            .map(|predecessor| (predecessor, String::new())),
                    );
                }
                Ok(Object::Tree(tree)) => {
                    if !path.is_empty() {
                        labels.entry(digest).or_insert_with(|| format!("{path}/"));
                    }
                    for entry in tree.entries {
                        let entry_path = if path.is_empty() {
                            entry.name.clone()
                        } else {
                            format!("{path}/{}", entry.name)
                        };
                        let named = match entry.annotations.get(ANNOTATION_POLICY_ALIAS) {
                            Some(alias) => format!("{entry_path} ({alias})"),
                            None => entry_path.clone(),
                        };
                        labels.entry(entry.digest.clone()).or_insert(named);
                        queue.push((entry.digest, entry_path));
                    }
                }
                _ => {
                    if !path.is_empty() {
                        labels.entry(digest).or_insert(path);
                    }
                }
            }
        }
        reached
    }

    fn tracked_head(store: &dyn Store) -> Result<Option<Digest>, String> {
        let Some(r#ref) = crate::engine::workspace::config::read_head(store)? else {
            return Ok(None);
        };
        Ok(
            crate::engine::workspace::config::read_checkpoint(store, &r#ref)?
                .and_then(|checkpoint| Digest::parse(&checkpoint.head).ok()),
        )
    }

    fn staged_root(store: &dyn Store) -> Result<Option<Digest>, String> {
        Ok(store
            .read(".permguard/staging/tree")?
            .and_then(|bytes| Digest::parse(String::from_utf8_lossy(&bytes).trim()).ok()))
    }
}

/// Lists every stored digest.
pub fn list(store: &dyn Store) -> Result<Vec<Digest>, String> {
    objects::list(store, OBJECTS_DIR)
}
