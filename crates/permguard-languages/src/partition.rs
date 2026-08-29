// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a partition of a ledger holds, and the one walk that reads it.
//!
//! A partition is a subtree of a commit: policy blobs, the typed artifacts its runtime declares,
//! and directories an author organised them into. Reading it is not arithmetic — a nested folder
//! is a nested subtree, the media type says what a blob is, a policy carries its identity as an
//! annotation, and a partition that declares an artifact must carry as many of it as the registry
//! allows — and every one of those rules is a way for two readers to disagree.
//!
//! There were two readers. The data plane's dropped a nested directory nowhere, and the CLI's
//! dropped it on the floor; then the CLI's regained the recursion and lost the two schema checks
//! instead. So there is one, here, beside the [`StoredPolicy`] it produces: the plane that serves a
//! ledger and `permguard test` that decides one offline read a partition the same way or they are
//! not testing the same thing.
//!
//! # One walk, two ways of declaring contents
//!
//! A partition says what it holds in one of two ways, and the walk reads both without knowing
//! which runtime it is looking at:
//!
//! - the legacy `schema: true|false`, which names its runtime's one registered schema artifact;
//! - `artifacts:`, a list of registered type names, which is how a runtime with several fixed
//!   artifacts — a required action schema, an optional event schema, macros, provider declarations
//!   and the programs they name — states its contents.
//!
//! Both end in the same place: every non-policy blob is resolved to a registered artifact type by
//! its media type, and the registry says how many of it are allowed. Nothing here knows what
//! Cedar or Dogwood call things.
//!
//! The object store differs — one reads a filesystem, the other an in-memory snapshot — so it
//! arrives as [`Objects`], which is the only thing a walk needs of it.

use std::collections::BTreeMap;

use permguard_objects::manifest::Partition;
use permguard_objects::object::{Kind, Object};
use permguard_objects::policy_id::{
    ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID, POLICY_FAMILY_PREFIX,
};

use crate::artifact::{ArtifactBlob, ArtifactType, Artifacts, Cardinality};
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
    /// Everything that is not a policy, by registered artifact type.
    pub artifacts: Artifacts,
}

impl Collected {
    /// Roughly how much memory it holds, for a cache's bounds.
    pub fn footprint(&self) -> usize {
        self.policies
            .iter()
            .map(|policy| policy.source.len())
            .sum::<usize>()
            + self.artifacts.footprint()
    }
}

/// Reads one partition's subtree, and checks it against what the manifest declared.
///
/// `declared` is the manifest's own entry for this partition, passed whole rather than as the one
/// flag a caller thought mattered: what a partition is allowed to hold is the manifest's statement
/// plus the registry's rules about the types it names, and a caller that reduced that to a boolean
/// on the way in would be deciding, at the call site, which of those rules still applied.
///
/// A partition that declares an artifact and carries none cannot compile what it promised to; one
/// that carries an artifact it did not declare is a ledger whose manifest and contents disagree.
/// Both refuse — a plane that served either would be answering against a model nobody agreed to.
pub fn collect(
    objects: &dyn Objects,
    root: &str,
    partition: &str,
    declared: &Partition,
) -> Result<Collected, Collecting> {
    let Some(language) = crate::lookup::language(&declared.runtime) else {
        return Err(Collecting::Incompatible(format!(
            "the partition `{partition}` names the runtime `{}`, which this build does not carry",
            declared.runtime
        )));
    };
    let contracts = contracts_of(language, declared, partition)?;

    let mut collected = Collected::default();
    walk(objects, root, partition, language, &mut collected)?;

    for (artifact, required) in &contracts {
        let found = collected.artifacts.count(artifact.name());
        if *required && found == 0 {
            return Err(Collecting::Incompatible(format!(
                "the partition `{partition}` declares `{}` and the commit carries none",
                artifact.name()
            )));
        }
        if found > 1 && !matches!(artifact.cardinality(), Cardinality::Many) {
            return Err(Collecting::Incompatible(format!(
                "the partition `{partition}` carries {found} of `{}`, which admits at most one",
                artifact.name()
            )));
        }
    }
    for held in collected.artifacts.types() {
        if !contracts
            .iter()
            .any(|(artifact, _)| artifact.name() == held)
        {
            return Err(Collecting::Incompatible(format!(
                "the partition `{partition}` carries `{held}`, which it does not declare"
            )));
        }
    }

    Ok(collected)
}

/// What the partition declared, resolved to registered artifact types.
///
/// The legacy `schema: true` and a list of `artifacts:` are two spellings of one answer, so they
/// are turned into one here and nowhere else. A partition that says both is refused by the
/// manifest's own validation before it reaches this.
fn contracts_of(
    language: &'static dyn crate::role::Language,
    declared: &Partition,
    partition: &str,
) -> Result<Vec<(&'static dyn ArtifactType, bool)>, Collecting> {
    let owned = language.artifacts();

    if declared.artifacts.is_empty() {
        // The legacy contract: the runtime's one registered schema, required exactly when the
        // manifest's flag says so. A runtime that registers no schema and a partition that
        // declares one is a partition nothing can satisfy.
        let schema = owned
            .iter()
            .copied()
            .find(|held| held.media_type() == language.schema_media_type().unwrap_or_default());
        return match (declared.schema, schema) {
            // `schema: false` declares *nothing*, not "a schema that happens to be optional". A
            // commit carrying one for a partition that declares none is a ledger whose manifest
            // and contents disagree, and treating the contract as present-but-optional would serve
            // it in silence.
            (false, _) => Ok(Vec::new()),
            (true, Some(schema)) => Ok(vec![(schema, true)]),
            (true, None) => Err(Collecting::Incompatible(format!(
                "the partition `{partition}` declares a schema and `{}` registers none",
                language.name()
            ))),
        };
    }

    let mut contracts = Vec::with_capacity(declared.artifacts.len());
    for contract in &declared.artifacts {
        let Some(artifact) = owned
            .iter()
            .copied()
            .find(|held| held.name() == contract.r#type)
        else {
            return Err(Collecting::Incompatible(format!(
                "the partition `{partition}` declares `{}`, which `{}` does not own",
                contract.r#type,
                language.name()
            )));
        };
        // A manifest may require an otherwise optional artifact; it may not excuse a required one.
        contracts.push((
            artifact,
            contract.required || artifact.required_by_default(),
        ));
    }

    Ok(contracts)
}

fn walk(
    objects: &dyn Objects,
    digest: &str,
    partition: &str,
    language: &'static dyn crate::role::Language,
    into: &mut Collected,
) -> Result<(), Collecting> {
    let Object::Tree(tree) = decode(objects, digest)? else {
        return Err(Collecting::Damaged(format!("{digest} is not a tree")));
    };

    for entry in &tree.entries {
        let digest = entry.digest.to_string();
        match entry.kind {
            // A partition an author organised in folders is one partition.
            Kind::Tree => walk(objects, &digest, partition, language, into)?,
            Kind::Blob => {
                let Object::Blob(blob) = decode(objects, &digest)? else {
                    return Err(Collecting::Damaged(format!("{digest} is not a blob")));
                };
                if blob.media_type.starts_with(POLICY_FAMILY_PREFIX) {
                    into.policies
                        .push(policy(&entry.annotations, entry, blob.data)?);
                    continue;
                }
                // Everything else is resolved by media type against the types this runtime owns.
                // A blob whose media type belongs to another runtime is not "some schema": it is
                // content this partition cannot compile, and guessing would be how a Cedar schema
                // ends up loaded as a Dogwood one.
                let Some(artifact) = language
                    .artifacts()
                    .iter()
                    .copied()
                    .find(|held| held.media_type() == blob.media_type)
                else {
                    return Err(Collecting::Incompatible(format!(
                        "the partition `{partition}` holds `{}` under `{}`, which `{}` does not \
                         own",
                        entry.name,
                        blob.media_type,
                        language.name()
                    )));
                };
                into.artifacts.insert(
                    artifact,
                    ArtifactBlob {
                        name: entry.name.clone(),
                        media_type: blob.media_type,
                        data: blob.data,
                    },
                );
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
