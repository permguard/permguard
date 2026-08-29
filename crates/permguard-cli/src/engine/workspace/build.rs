// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The snapshot builder — `refresh` and everything above it.
//!
//! Reads the partition directories, extracts **each policy as its own
//! object** (files are presentation, policies are content), resolves every
//! identity through the cascade, and builds the trees. Duplicates are
//! ambiguity and reject, naming every path involved.

use std::collections::BTreeMap;

use permguard_objects::digest::Digest;
use permguard_objects::manifest::Manifest;
use permguard_objects::object::{Blob, Kind, Tree, TreeEntry};
use permguard_objects::policy_id;
use permguard_objects::policy_id::{
    ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND,
};

use super::{PolicyRecord, Result, err};
use crate::engine::workspace::inventory;
use crate::engine::workspace::sync;
use permguard_control_client::Store;

/// A built snapshot: the trees are stored, the closure is known.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The root tree digest.
    pub root: Digest,
    /// The manifest blob digest.
    pub manifest: Digest,
    /// Every object of the snapshot, digest → bytes.
    pub objects: BTreeMap<Digest, Vec<u8>>,
    /// Every policy, for plans and reports.
    pub policies: Vec<PolicyRecord>,
}

/// Builds the snapshot of the working tree.
pub(crate) fn build_snapshot(store: &dyn Store, manifest: &Manifest) -> Result<Snapshot> {
    let ignores = read_ignores(store)?;

    // The previous snapshot's hooks, for the identity cascade: entry path →
    // id, and alias → id across the whole snapshot.
    let (previous_by_path, previous_by_alias) = sync::previous_identity_maps(store)?;

    let mut snapshot_objects: BTreeMap<Digest, Vec<u8>> = BTreeMap::new();
    let mut policies: Vec<PolicyRecord> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    let mut ids_seen: BTreeMap<String, String> = BTreeMap::new(); // id → source file
    let mut aliases_seen: BTreeMap<String, String> = BTreeMap::new();
    let mut root_entries: Vec<TreeEntry> = Vec::new();

    for (partition_name, partition) in &manifest.partitions {
        let runtime = manifest.runtimes.get(&partition.runtime).ok_or_else(|| {
            err(format!(
                "partition `{partition_name}` names an undeclared runtime"
            ))
        })?;
        let plugin = permguard_languages::language(&runtime.language.name).ok_or_else(|| {
            err(format!(
                "no built-in plugin for `{}`",
                runtime.language.name
            ))
        })?;
        let authoring = plugin.authoring().ok_or_else(|| {
            err(format!(
                "this build carries `{}` but not its authoring half: it cannot read sources",
                runtime.language.name
            ))
        })?;
        // What this partition declares, resolved to registered artifact types. The legacy
        // `schema: true` and a list of `artifacts:` are two spellings of one answer, and the
        // registry is what turns them into one — so the walker never has to know that Cedar calls
        // its schema `.cedarschema` or that Dogwood has four of them.
        let declared = declared_artifacts(plugin, partition, partition_name)?;

        let mut context = PartitionContext {
            store,
            plugin,
            authoring,
            declared: declared.clone(),
            partition: partition_name.clone(),
            ignores: &ignores,
            previous_by_path: &previous_by_path,
            previous_by_alias: &previous_by_alias,
            snapshot_objects: &mut snapshot_objects,
            policies: &mut policies,
            ids_seen: &mut ids_seen,
            aliases_seen: &mut aliases_seen,
            artifact_files: BTreeMap::new(),
            policy_sources: Vec::new(),
            artifacts: BTreeMap::new(),
            problems: &mut problems,
        };
        let digest = build_directory(&mut context, partition_name, partition_name, 1)?;
        // Cardinality and requirement, from the registry rather than from a rule written here: an
        // author cannot redefine either, and a walker that decided them would be a second opinion
        // about what a partition holds.
        for (artifact, required) in &declared {
            let held = context
                .artifact_files
                .get(artifact.name())
                .map(Vec::len)
                .unwrap_or_default();
            if *required && held == 0 {
                return Err(err(format!(
                    "the partition `{partition_name}` declares `{}` and the sources hold none",
                    artifact.name()
                )));
            }
            if held > 1
                && !matches!(
                    artifact.cardinality(),
                    permguard_languages::artifact::Cardinality::Many
                )
            {
                let files = context
                    .artifact_files
                    .get(artifact.name())
                    .map(|held| held.join(", "))
                    .unwrap_or_default();

                return Err(err(format!(
                    "the partition `{partition_name}` holds {held} of `{}` ({files}): at most one",
                    artifact.name()
                )));
            }
        }
        // The set-level semantic check the server runs at commit acceptance
        // and the data plane runs at load — the same code, run first where the
        // error costs least: a policy that does not satisfy its partition's
        // schema fails `validate`, not a plane serving the ledger.
        let named: Vec<(&str, &[u8])> = context
            .policy_sources
            .iter()
            .map(|(file, bytes)| (file.as_str(), bytes.as_slice()))
            .collect();
        // The set-level check gets the whole bundle, not just "the schema": a Dogwood partition
        // lowers its policies against an action schema *and* an event schema *and* its macros, and
        // a check handed one of the four would be checking something the plane will not serve.
        let artifacts = std::mem::take(&mut context.artifacts);
        if let Err(error) = plugin.validate_bundle(partition_name, &named, &artifacts, partition) {
            problems.push(error);
        }
        root_entries.push(TreeEntry {
            kind: Kind::Tree,
            digest,
            name: partition_name.clone(),
            annotations: BTreeMap::new(),
        });
    }

    // Everything wrong, in one report: the author fixes the list, not one
    // line of it per run.
    if !problems.is_empty() {
        let count = problems.len();
        let listed: String = problems
            .iter()
            .map(|problem| format!("  - {problem}"))
            .collect::<Vec<_>>()
            .join("\n");

        return Err(err(format!(
            "the workspace does not validate:\n{listed}\n{count} problem(s)"
        )));
    }

    // The manifest blob, at the well-known root entry.
    let manifest_blob = Blob {
        media_type: permguard_objects::manifest::MEDIA_TYPE.to_owned(),
        data: manifest.encode(),
    };
    let manifest_bytes = manifest_blob
        .encode()
        .map_err(|error| err(error.to_string()))?;
    let manifest_digest = inventory::put(store, &manifest_bytes).map_err(err)?;
    snapshot_objects.insert(manifest_digest.clone(), manifest_bytes);
    root_entries.push(TreeEntry {
        kind: Kind::Blob,
        digest: manifest_digest.clone(),
        name: "manifest".to_owned(),
        annotations: BTreeMap::new(),
    });

    root_entries.sort_by(|a, b| a.name.cmp(&b.name));
    let root = Tree {
        entries: root_entries,
    };
    let root_bytes = root.encode().map_err(|error| err(error.to_string()))?;
    let root_digest = inventory::put(store, &root_bytes).map_err(err)?;
    snapshot_objects.insert(root_digest.clone(), root_bytes);

    store
        .write(
            ".permguard/staging/tree",
            root_digest.to_string().as_bytes(),
        )
        .map_err(err)?;

    Ok(Snapshot {
        root: root_digest,
        manifest: manifest_digest,
        objects: snapshot_objects,
        policies,
    })
}

/// Everything one partition's recursion carries.
struct PartitionContext<'a> {
    store: &'a dyn Store,
    plugin: &'static dyn permguard_languages::Language,
    /// The authoring half — reading files and splitting them into policies.
    /// A build that carries a language without it cannot author in that
    /// language, and says so where the language is looked up.
    authoring: &'static dyn permguard_languages::Authoring,
    /// What this partition declared, resolved to registered artifact types.
    declared: Vec<(
        &'static dyn permguard_languages::artifact::ArtifactType,
        bool,
    )>,
    /// The partition being walked, for an error that has to name it.
    partition: String,
    ignores: &'a [String],
    previous_by_path: &'a BTreeMap<String, String>,
    previous_by_alias: &'a BTreeMap<String, String>,
    snapshot_objects: &'a mut BTreeMap<Digest, Vec<u8>>,
    policies: &'a mut Vec<PolicyRecord>,
    ids_seen: &'a mut BTreeMap<String, String>,
    aliases_seen: &'a mut BTreeMap<String, String>,
    /// The files of each registered artifact type, for the cardinality check after the walk.
    artifact_files: BTreeMap<&'static str, Vec<String>>,
    /// Every policy's `(source file, verbatim bytes)`, for the set-level semantic check.
    policy_sources: Vec<(String, Vec<u8>)>,
    /// The bundle the set-level check is run against.
    artifacts: BTreeMap<String, Vec<u8>>,
    /// Everything wrong so far, named by its file.
    ///
    /// Collected rather than thrown: a validation that stops at the first
    /// broken file makes the author fix one problem per run — a compiler
    /// habit nobody misses. A file that fails is skipped and the walk goes
    /// on, so one report names them all; the build still fails at the end.
    problems: &'a mut Vec<String>,
}

/// What a partition declared, resolved to registered artifact types.
///
/// The legacy `schema: true` and a list of `artifacts:` are two spellings of one answer, and this
/// is the one place they become one. The registry decides role, cardinality and requirement; the
/// manifest may require an otherwise optional artifact, and may not excuse a required one.
fn declared_artifacts(
    plugin: &'static dyn permguard_languages::Language,
    partition: &permguard_objects::manifest::Partition,
    partition_name: &str,
) -> Result<
    Vec<(
        &'static dyn permguard_languages::artifact::ArtifactType,
        bool,
    )>,
> {
    let owned = plugin.artifacts();

    if partition.artifacts.is_empty() {
        // The legacy contract: this runtime's one registered schema, required exactly when the
        // manifest's flag says so.
        let schema = owned
            .iter()
            .copied()
            .find(|held| held.media_type() == plugin.schema_media_type().unwrap_or_default());

        return match (partition.schema, schema) {
            // `schema: false` declares *nothing*, not "a schema that happens to be optional".
            // The difference is the whole point of the flag: a schema sitting in a partition that
            // declares none must be refused, and treating the contract as present-but-optional
            // would accept it in silence.
            (false, _) => Ok(Vec::new()),
            (true, Some(schema)) => Ok(vec![(schema, true)]),
            (true, None) => Err(err(format!(
                "partition `{partition_name}` declares schema: true, but `{}` has no schema",
                plugin.name()
            ))),
        };
    }

    let mut declared = Vec::with_capacity(partition.artifacts.len());
    for contract in &partition.artifacts {
        let Some(artifact) = owned
            .iter()
            .copied()
            .find(|held| held.name() == contract.r#type)
        else {
            return Err(err(format!(
                "the partition `{partition_name}` declares `{}`, which `{}` does not own",
                contract.r#type,
                plugin.name()
            )));
        };
        declared.push((
            artifact,
            contract.required || artifact.required_by_default(),
        ));
    }

    Ok(declared)
}

/// Builds one directory into one tree, recursing into subdirectories —
/// folder structure round-trips: directory names become subtree entry
/// names, validated by the entry grammar.
fn build_directory(
    context: &mut PartitionContext<'_>,
    logical_path: &str,
    fs_path: &str,
    depth: usize,
) -> Result<Digest> {
    if depth > permguard_objects::limits::MAX_TREE_DEPTH {
        return Err(err(format!("{fs_path}: deeper than the model allows")));
    }
    let mut entries: BTreeMap<String, TreeEntry> = BTreeMap::new();

    for (name, is_dir) in context.store.list(fs_path).map_err(err)? {
        let child_fs = format!("{fs_path}/{name}");
        let child_logical = format!("{logical_path}/{name}");
        if context
            .ignores
            .iter()
            .any(|prefix| child_fs.starts_with(prefix.as_str()))
        {
            continue;
        }
        if is_dir {
            let digest = build_directory(context, &child_logical, &child_fs, depth + 1)?;
            insert_entry(
                &mut entries,
                TreeEntry {
                    kind: Kind::Tree,
                    digest,
                    name,
                    annotations: BTreeMap::new(),
                },
                &child_fs,
            )?;
            continue;
        }
        let Some(extension) = name.rsplit('.').next() else {
            continue;
        };
        // Which registered artifact this file is, asked of the registry and of nothing else. A
        // canonical file name wins over a shared extension, which is what lets `macros.dw` and
        // `policy.dw` live in one directory without this walker knowing that Dogwood exists.
        let owned = context.plugin.artifacts();
        let classified = permguard_languages::artifact::classify(owned, &name).copied();
        let is_policy_file = context.authoring.file_extensions().contains(&extension)
            && classified.is_none_or(|held| {
                held.role() == permguard_languages::artifact::ArtifactRole::Policy
            });
        // An artifact sitting in a partition that declares none is refused, not walked past.
        // Skipping it is the worst of the three outcomes: the author sees the file, believes their
        // inputs are validated, and nothing validates anything.
        let artifact = match classified {
            Some(held)
                if !context
                    .declared
                    .iter()
                    .any(|(declared, _)| declared.name() == held.name()) =>
            {
                return Err(err(format!(
                    "`{child_fs}` is a `{}` and the partition `{}` does not declare one: add it \
                     under `artifacts:` in the manifest, or remove the file",
                    held.name(),
                    context.partition
                )));
            }
            Some(held) if held.role() != permguard_languages::artifact::ArtifactRole::Policy => {
                Some(held)
            }
            _ => None,
        };
        if !is_policy_file && artifact.is_none() {
            continue;
        }
        let source = context
            .store
            .read(&child_fs)
            .map_err(err)?
            .ok_or_else(|| err(format!("{child_fs} vanished mid-read")))?;

        if let Some(artifact) = artifact {
            if let Err(error) = artifact.validate(&source) {
                context.problems.push(format!("{child_fs}: {error}"));
                continue;
            }
            context
                .artifact_files
                .entry(artifact.name())
                .or_default()
                .push(child_fs.clone());
            context
                .artifacts
                .insert(artifact.name().to_owned(), source.clone());
            let blob = Blob {
                media_type: artifact.media_type().to_owned(),
                data: source,
            };
            let bytes = blob.encode().map_err(|error| err(error.to_string()))?;
            let digest = inventory::put(context.store, &bytes).map_err(err)?;
            context.snapshot_objects.insert(digest.clone(), bytes);
            insert_entry(
                &mut entries,
                TreeEntry {
                    kind: Kind::Blob,
                    digest,
                    name,
                    annotations: BTreeMap::new(),
                },
                &child_fs,
            )?;
            continue;
        }

        let extracted = match context.authoring.extract(&source) {
            Ok(extracted) => extracted,
            Err(error) => {
                context.problems.push(format!("{child_fs}: {error}"));
                continue;
            }
        };
        for (position, policy) in extracted.into_iter().enumerate() {
            // Named uniquely even within one file — a file may hold several
            // policies, and the set-level check names each one on its own.
            context.policy_sources.push((
                if position == 0 {
                    child_fs.clone()
                } else {
                    format!("{child_fs}#{position}")
                },
                policy.bytes.clone(),
            ));
            let blob = Blob {
                media_type: context.plugin.policy_media_type().to_owned(),
                data: policy.bytes.clone(),
            };
            let bytes = blob.encode().map_err(|error| err(error.to_string()))?;
            let digest = inventory::put(context.store, &bytes).map_err(err)?;
            context.snapshot_objects.insert(digest.clone(), bytes);

            let stem_if_new = policy_id::derive_policy_id(&policy.bytes);
            let entry_name = format!(
                "{stem}.{extension}",
                stem = policy.alias.as_deref().unwrap_or(&stem_if_new)
            );
            let path_key = format!("{logical_path}/{entry_name}");
            let by_path: Vec<&str> = context
                .previous_by_path
                .get(&path_key)
                .map(|id| vec![id.as_str()])
                .unwrap_or_default();
            let by_alias: Vec<&str> = policy
                .alias
                .as_deref()
                .and_then(|alias| context.previous_by_alias.get(alias))
                .map(|id| vec![id.as_str()])
                .unwrap_or_default();
            let resolved =
                match policy_id::resolve_id(&path_key, &by_path, &by_alias, &policy.bytes) {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        context.problems.push(format!("{child_fs}: {error}"));
                        continue;
                    }
                };
            let id = resolved.id().to_owned();

            if let Some(other) = context.ids_seen.insert(id.clone(), child_fs.clone()) {
                context.problems.push(format!(
                    "the same policy ({id}) appears in both {other} and {child_fs}: one policy, one place"
                ));
                continue;
            }
            if let Some(alias) = &policy.alias
                && let Some(other) = context.aliases_seen.insert(alias.clone(), child_fs.clone())
            {
                context.problems.push(format!(
                    "the alias `{alias}` is declared in both {other} and {child_fs}: aliases are unique"
                ));
                continue;
            }

            let mut annotations = BTreeMap::new();
            annotations.insert(ANNOTATION_POLICY_ID.to_owned(), id.clone());
            annotations.insert(ANNOTATION_POLICY_KIND.to_owned(), "policy".to_owned());
            if let Some(alias) = &policy.alias {
                annotations.insert(ANNOTATION_POLICY_ALIAS.to_owned(), alias.clone());
            }
            insert_entry(
                &mut entries,
                TreeEntry {
                    kind: Kind::Blob,
                    digest: digest.clone(),
                    name: entry_name.clone(),
                    annotations,
                },
                &child_fs,
            )?;
            context.policies.push(PolicyRecord {
                partition: logical_path
                    .split('/')
                    .next()
                    .unwrap_or(logical_path)
                    .to_owned(),
                name: path_key
                    .split_once('/')
                    .map(|(_, rest)| rest)
                    .unwrap_or(&entry_name)
                    .to_owned(),
                id,
                alias: policy.alias.clone(),
                digest,
                source: child_fs.clone(),
            });
        }
    }

    let tree = Tree {
        entries: entries.into_values().collect(),
    };
    let bytes = tree.encode().map_err(|error| err(error.to_string()))?;
    let digest = inventory::put(context.store, &bytes).map_err(err)?;
    context.snapshot_objects.insert(digest.clone(), bytes);
    Ok(digest)
}

fn insert_entry(
    entries: &mut BTreeMap<String, TreeEntry>,
    entry: TreeEntry,
    source: &str,
) -> Result<()> {
    let name = entry.name.clone();
    if entries.insert(name.clone(), entry).is_some() {
        return Err(err(format!(
            "two policies resolve to the entry `{name}` (last seen in {source}): identical anonymous policies?"
        )));
    }
    Ok(())
}

fn read_ignores(store: &dyn Store) -> Result<Vec<String>> {
    let Some(bytes) = store.read(".permguardignore").map_err(err)? else {
        return Ok(Vec::new());
    };
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}
