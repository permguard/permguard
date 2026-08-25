// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Turning a mirror on disk into something that can answer a decision.
//!
//! # The walk
//!
//! ```text
//! refs/main  ──►  (head, counter)          what was last verified
//!       │
//!       ▼
//!   commit    ──►  manifest + root tree    what this ledger declares, and holds
//!       │
//!       ▼
//!   load gate ──►  language + engine ranges must be satisfied, or REFUSE
//!       │
//!       ▼
//!   partitions ──► policy blobs (+ the schema, when declared)
//!       │
//!       ▼
//!   compile   ──►  one Evaluator per partition, kept in memory
//! ```
//!
//! Every object is read through the same content-addressed store the CLI uses:
//! zlib at rest, digest verified on the way out. A corrupt object cannot be
//! evaluated — it cannot even be read.
//!
//! # The load gate is not advisory
//!
//! Before a single policy is compiled, the manifest's runtimes are checked
//! against what this binary carries: the language version, and the engine
//! version, two independent constraints. A ledger this engine is outside the
//! range of is **unavailable** — never evaluated best-effort, because an engine
//! interpreting the same policies differently is a silent authorization
//! bypass. The refusal is what [`super::block`] then remembers, so the plane
//! does not spend every round rediscovering it.
//!
//! # And neither is the schema
//!
//! A partition that declares `schema: true` must carry one, and every policy
//! in it must type-check against it. That check happens here, once, at load —
//! not per request, and not never (which is what the old Go implementation
//! did).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use permguard_control_client::objects;
use permguard_control_client::store::{FsStore, Store};
use permguard_languages::registry;
use permguard_languages::{Evaluator, StoredPolicy};
use permguard_objects::digest::Digest;
use permguard_objects::manifest::{self, Manifest};
use permguard_objects::object::{self, Kind, Object};
use permguard_objects::policy_id::{
    ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID, POLICY_FAMILY_PREFIX,
};

/// Why a ledger cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The mirror holds no history yet: nothing has been applied to this
    /// ledger, so there is nothing to decide with.
    Empty,
    /// This engine is outside what the manifest allows, or the schema is not
    /// satisfied. Sticky on purpose — see [`super::block`].
    Incompatible(String),
    /// The mirror is there and unreadable: a missing object, a corrupt one, a
    /// manifest that does not decode.
    Damaged(String),
    /// The request named a profile or a partition the manifest does not
    /// declare.
    Unknown(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the ledger has no history yet"),
            Self::Incompatible(detail) | Self::Damaged(detail) | Self::Unknown(detail) => {
                write!(f, "{detail}")
            }
        }
    }
}

/// What one ledger is, at one commit: what it declares, and what it holds.
#[derive(Debug)]
pub struct Head {
    /// The commit this was read at — the cache key, and what a decision cites.
    pub commit: String,
    /// The counter of the verified head statement.
    pub counter: u64,
    pub manifest: Manifest,
}

impl Head {
    /// The partitions a profile is built from, or a refusal naming what is
    /// missing.
    pub fn partitions_of(&self, profile: &str) -> Result<Vec<String>, Refusal> {
        let declared = self.manifest.profiles.get(profile).ok_or_else(|| {
            let known: Vec<&str> = self.manifest.profiles.keys().map(String::as_str).collect();
            Refusal::Unknown(format!(
                "this ledger declares no profile `{profile}` (it declares: {})",
                known.join(", ")
            ))
        })?;

        Ok(declared.partitions.clone())
    }
}

/// One compiled partition, ready to decide and cheap to share.
pub struct Partition {
    pub name: String,
    /// The language that answers here, for the report and the metric label.
    pub language: String,
    /// How many policies were compiled.
    pub policies: usize,
    /// Roughly how much memory it holds, for the cache's bounds.
    pub footprint: usize,
    evaluator: Box<dyn Evaluator>,
}

impl std::fmt::Debug for Partition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Partition")
            .field("name", &self.name)
            .field("language", &self.language)
            .field("policies", &self.policies)
            .field("footprint", &self.footprint)
            .finish_non_exhaustive()
    }
}

impl Partition {
    /// The compiled program this partition answers with.
    pub fn evaluator(&self) -> &dyn Evaluator {
        self.evaluator.as_ref()
    }

    /// A partition built by hand, for a test that is about something else —
    /// the cache's bounds, say, which do not care what compiled them.
    #[cfg(test)]
    pub fn for_test(name: &str, footprint: usize, evaluator: Box<dyn Evaluator>) -> Self {
        Self {
            name: name.to_owned(),
            language: "test".to_owned(),
            policies: 0,
            footprint,
            evaluator,
        }
    }
}

/// Reads the head of a mirror: what was last verified, and what it declares.
///
/// Cheap by design — a checkpoint, a commit and a manifest — because it runs
/// on every request: it is what makes a ledger synchronized a second ago
/// visible now, without trusting a cache to notice.
pub fn head(mirror: &Path) -> Result<Head, Refusal> {
    let store = FsStore::new(mirror);
    let checkpoint = permguard_control_client::checkpoint::read(&store, "refs/main")
        .map_err(Refusal::Damaged)?
        .ok_or(Refusal::Empty)?;
    let digest = Digest::parse(&checkpoint.head).map_err(|error| {
        Refusal::Damaged(format!("the checkpoint head is not a digest: {error}"))
    })?;

    let Object::Commit(commit) = read_object(&store, &digest)? else {
        return Err(Refusal::Damaged(format!(
            "{digest} is not a commit, and a ref must name one"
        )));
    };
    let Object::Blob(blob) = read_object(&store, &commit.manifest)? else {
        return Err(Refusal::Damaged(format!(
            "the manifest {} is not a blob",
            commit.manifest
        )));
    };
    let manifest = Manifest::decode(&blob.data)
        .map_err(|error| Refusal::Damaged(format!("the manifest does not decode: {error}")))?;

    // The gate, before anything is compiled or answered.
    manifest::check_load_gate(&manifest, &registry::provided_runtimes()).map_err(|error| {
        Refusal::Incompatible(format!(
            "this engine cannot serve this ledger: {}",
            error.detail
        ))
    })?;

    Ok(Head {
        commit: checkpoint.head,
        counter: checkpoint.counter,
        manifest,
    })
}

/// Compiles one partition of a ledger at a commit.
///
/// The expensive half, and the one the cache exists for: every policy parsed,
/// the engine's program built, the schema enforced.
pub fn compile(mirror: &Path, head: &Head, partition: &str) -> Result<Arc<Partition>, Refusal> {
    let declared = head.manifest.partitions.get(partition).ok_or_else(|| {
        Refusal::Unknown(format!("this ledger declares no partition `{partition}`"))
    })?;
    let runtime = head.manifest.runtimes.get(&declared.runtime).ok_or_else(|| {
        Refusal::Damaged(format!(
            "the partition `{partition}` names the runtime `{}`, which the manifest does not declare",
            declared.runtime
        ))
    })?;
    let language_name = runtime.language.name.clone();
    let engine = registry::evaluating(&language_name).ok_or_else(|| {
        Refusal::Incompatible(format!(
            "this build carries no engine for the language `{language_name}`"
        ))
    })?;

    let store = FsStore::new(mirror);
    let commit_digest = Digest::parse(&head.commit)
        .map_err(|error| Refusal::Damaged(format!("the head is not a digest: {error}")))?;
    let Object::Commit(commit) = read_object(&store, &commit_digest)? else {
        return Err(Refusal::Damaged("the head is not a commit".to_owned()));
    };
    let Object::Tree(root) = read_object(&store, &commit.tree)? else {
        return Err(Refusal::Damaged(
            "the commit's tree is not a tree".to_owned(),
        ));
    };
    let subtree = root
        .entries
        .iter()
        .find(|entry| entry.name == partition && entry.kind == Kind::Tree)
        .ok_or_else(|| {
            Refusal::Damaged(format!(
                "the partition `{partition}` is declared but absent from the commit"
            ))
        })?;

    let mut collected = Collected::default();
    collect(&store, &subtree.digest, &mut collected)?;

    if declared.schema && collected.schema.is_none() {
        return Err(Refusal::Incompatible(format!(
            "the partition `{partition}` declares a schema and the commit carries none"
        )));
    }
    if !declared.schema && collected.schema.is_some() {
        return Err(Refusal::Incompatible(format!(
            "the partition `{partition}` carries a schema it does not declare"
        )));
    }

    let footprint = collected.footprint();
    let policies = collected.policies.len();
    let evaluator = engine
        .compile(&collected.policies, collected.schema.as_deref())
        .map_err(Refusal::Incompatible)?;

    Ok(Arc::new(Partition {
        name: partition.to_owned(),
        language: language_name,
        policies,
        footprint,
        evaluator,
    }))
}

/// What a partition's subtree holds.
#[derive(Default)]
struct Collected {
    policies: Vec<StoredPolicy>,
    schema: Option<Vec<u8>>,
}

impl Collected {
    fn footprint(&self) -> usize {
        self.policies
            .iter()
            .map(|policy| policy.source.len())
            .sum::<usize>()
            + self.schema.as_ref().map_or(0, Vec::len)
    }
}

/// Walks a partition subtree, gathering the policies and the schema.
///
/// Nested directories are nested subtrees — a partition an author organised in
/// folders is one partition — so the walk recurses and the identity of a
/// policy is the annotation the commit carries, never the path.
fn collect(store: &dyn Store, digest: &Digest, into: &mut Collected) -> Result<(), Refusal> {
    let Object::Tree(tree) = read_object(store, digest)? else {
        return Err(Refusal::Damaged(format!("{digest} is not a tree")));
    };

    for entry in &tree.entries {
        match entry.kind {
            Kind::Tree => collect(store, &entry.digest, into)?,
            Kind::Blob => {
                let Object::Blob(blob) = read_object(store, &entry.digest)? else {
                    return Err(Refusal::Damaged(format!("{} is not a blob", entry.digest)));
                };
                if blob.media_type.starts_with(POLICY_FAMILY_PREFIX) {
                    let id = entry
                        .annotations
                        .get(ANNOTATION_POLICY_ID)
                        .cloned()
                        .ok_or_else(|| {
                            Refusal::Damaged(format!(
                                "the policy `{}` carries no identity",
                                entry.name
                            ))
                        })?;
                    into.policies.push(StoredPolicy {
                        id,
                        alias: entry.annotations.get(ANNOTATION_POLICY_ALIAS).cloned(),
                        source: blob.data,
                    });
                } else if into.schema.replace(blob.data).is_some() {
                    // At most one schema per partition — the same ambiguity
                    // rule the CLI enforces when it builds.
                    return Err(Refusal::Incompatible(
                        "the partition carries more than one schema".to_owned(),
                    ));
                }
            }
            Kind::Commit => {
                return Err(Refusal::Damaged(
                    "a partition cannot hold a commit".to_owned(),
                ));
            }
        }
    }

    Ok(())
}

fn read_object(store: &dyn Store, digest: &Digest) -> Result<Object, Refusal> {
    let bytes = objects::get(store, "objects", digest)
        .map_err(Refusal::Damaged)?
        .ok_or_else(|| Refusal::Damaged(format!("the object {digest} is missing")))?;

    object::decode(&bytes)
        .map_err(|error| Refusal::Damaged(format!("{digest} does not decode: {error}")))
}

/// Everything a profile names, compiled — the shape a decision is answered
/// from.
pub type Compiled = BTreeMap<String, Arc<Partition>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_reads_as_a_sentence() {
        assert_eq!(Refusal::Empty.to_string(), "the ledger has no history yet");
        assert_eq!(
            Refusal::Incompatible("engine 9 is not allowed".to_owned()).to_string(),
            "engine 9 is not allowed"
        );
    }

    #[test]
    fn a_mirror_that_is_not_there_has_no_head() {
        let refused =
            head(std::path::Path::new("/nonexistent/mirror")).expect_err("nothing to read");

        assert_eq!(refused, Refusal::Empty, "no checkpoint is an empty ledger");
    }
}
