// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a partition of a ledger holds, and the one walk that reads it.
//!
//! A partition is a subtree of a commit: policy blobs, at most one schema blob, and directories an
//! author organised them into. Reading it is not arithmetic — a nested folder is a nested subtree,
//! the media type says whether a blob is a policy, a policy carries its identity as an annotation,
//! and a partition that declares a schema must have exactly one — and every one of those rules is a
//! way for two readers to disagree.
//!
//! There were two readers. The data plane's dropped a nested directory nowhere, and the CLI's
//! dropped it on the floor; then the CLI's regained the recursion and lost the two schema checks
//! instead. So there is one, here, beside the [`StoredPolicy`] it produces: the plane that serves a
//! ledger and `permguard test` that decides one offline read a partition the same way or they are
//! not testing the same thing.
//!
//! The object store differs — one reads a filesystem, the other an in-memory snapshot — so it
//! arrives as [`Objects`], which is the only thing a walk needs of it.

use std::collections::BTreeMap;

use permguard_objects::object::{Kind, Object};
use permguard_objects::policy_id::{
    ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID, POLICY_FAMILY_PREFIX,
};

use crate::evaluate::StoredPolicy;

/// Where the objects of a commit are read from.
pub trait Objects {
    /// The canonical bytes of one object, by digest.
    fn get(&self, digest: &str) -> Result<Vec<u8>, String>;
}

/// Why a partition could not be read.
///
/// The distinction a plane reports differently and a workspace reports the same way: a ledger whose
/// objects do not hold together, against a ledger that holds together and says something this
/// engine will not serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Collecting {
    /// The objects do not decode, or an entry is not what it claims.
    Damaged(String),
    /// The objects are sound and the partition is not one this build may serve.
    Incompatible(String),
}

impl std::fmt::Display for Collecting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Collecting::Damaged(why) | Collecting::Incompatible(why) => write!(f, "{why}"),
        }
    }
}

/// What a partition's subtree holds.
#[derive(Debug, Default, Clone)]
pub struct Collected {
    pub policies: Vec<StoredPolicy>,
    pub schema: Option<Vec<u8>>,
}

impl Collected {
    /// Roughly how much memory it holds, for a cache's bounds.
    pub fn footprint(&self) -> usize {
        self.policies
            .iter()
            .map(|policy| policy.source.len())
            .sum::<usize>()
            + self.schema.as_ref().map_or(0, Vec::len)
    }
}

/// Reads one partition's subtree, and checks it against what the manifest declared.
///
/// `declares_schema` is the manifest's `schema:` for this partition. A partition that declares one
/// and carries none cannot validate anything it promised to; one that carries a schema it did not
/// declare is a ledger whose manifest and contents disagree. Both refuse — a plane that served
/// either would be answering against a model nobody agreed to.
pub fn collect(
    objects: &dyn Objects,
    root: &str,
    partition: &str,
    declares_schema: bool,
) -> Result<Collected, Collecting> {
    let mut collected = Collected::default();
    walk(objects, root, partition, &mut collected)?;

    if declares_schema && collected.schema.is_none() {
        return Err(Collecting::Incompatible(format!(
            "the partition `{partition}` declares a schema and the commit carries none"
        )));
    }
    if !declares_schema && collected.schema.is_some() {
        return Err(Collecting::Incompatible(format!(
            "the partition `{partition}` carries a schema it does not declare"
        )));
    }

    Ok(collected)
}

fn walk(
    objects: &dyn Objects,
    digest: &str,
    partition: &str,
    into: &mut Collected,
) -> Result<(), Collecting> {
    let Object::Tree(tree) = decode(objects, digest)? else {
        return Err(Collecting::Damaged(format!("{digest} is not a tree")));
    };

    for entry in &tree.entries {
        let digest = entry.digest.to_string();
        match entry.kind {
            // A partition an author organised in folders is one partition.
            Kind::Tree => walk(objects, &digest, partition, into)?,
            Kind::Blob => {
                let Object::Blob(blob) = decode(objects, &digest)? else {
                    return Err(Collecting::Damaged(format!("{digest} is not a blob")));
                };
                if blob.media_type.starts_with(POLICY_FAMILY_PREFIX) {
                    into.policies
                        .push(policy(&entry.annotations, entry, blob.data)?);
                } else if into.schema.replace(blob.data).is_some() {
                    return Err(Collecting::Incompatible(format!(
                        "the partition `{partition}` carries more than one schema"
                    )));
                }
            }
            Kind::Commit => {
                return Err(Collecting::Damaged(format!(
                    "the partition `{partition}` holds a commit, which no partition may"
                )));
            }
        }
    }

    Ok(())
}

fn policy(
    annotations: &BTreeMap<String, String>,
    entry: &permguard_objects::object::TreeEntry,
    source: Vec<u8>,
) -> Result<StoredPolicy, Collecting> {
    let id = annotations.get(ANNOTATION_POLICY_ID).ok_or_else(|| {
        Collecting::Damaged(format!("the policy `{}` carries no identity", entry.name))
    })?;

    Ok(StoredPolicy {
        id: id.clone(),
        alias: annotations.get(ANNOTATION_POLICY_ALIAS).cloned(),
        source,
    })
}

fn decode(objects: &dyn Objects, digest: &str) -> Result<Object, Collecting> {
    let bytes = objects.get(digest).map_err(Collecting::Damaged)?;

    permguard_objects::object::decode(&bytes)
        .map_err(|error| Collecting::Damaged(format!("{digest} does not decode: {error}")))
}
