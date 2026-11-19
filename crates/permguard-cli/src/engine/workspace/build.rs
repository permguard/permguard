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
use permguard_client::Store;

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

/// `bytes` without a leading UTF-8 byte order mark (`EF BB BF`): every file a workspace holds is
/// read as a Windows editor writes it, as the token file already is (BUG-0295, DEC-0031).
pub(crate) fn without_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)
}

/// The authored bytes of a workspace file (6-contract-ledger-notp, Policy identity): every `\r\n`
/// made `\n`, and nothing else changed. Read here, before anything is extracted, hashed or stored,
/// so the blob, its digest and the derived id come from the same bytes, and a Windows checkout,
/// where git writes CRLF by default, derives what a Linux or macOS one does. Every registered
/// artifact type is text, so artifacts are read the same way.
pub(crate) fn authored(bytes: Vec<u8>) -> Vec<u8> {
    // A UTF-8 byte order mark, which Windows editors write by default, is not part of what was
    // authored (BUG-0295, DEC-0031): the same policy with and without it is one policy.
    let bytes = match without_bom(&bytes) {
        rest if rest.len() < bytes.len() => rest.to_vec(),
        _ => bytes,
    };
    if !bytes.windows(2).any(|pair| pair == b"\r\n") {
        return bytes;
    }
    let mut normalised = Vec::with_capacity(bytes.len());
    let mut rest = bytes.iter().peekable();
    while let Some(&byte) = rest.next() {
        if byte == b'\r' && rest.peek() == Some(&&b'\n') {
            continue;
        }
        normalised.push(byte);
    }
    normalised
}

/// Where the second of a file's policies begins, 1-based: searched after the first, as the
/// splitter keeps each policy's bytes verbatim; the file's start when it cannot be found.
fn place_of(source: &[u8], first: &[u8], second: &[u8]) -> (usize, usize) {
    let text = String::from_utf8_lossy(source);
    let first = String::from_utf8_lossy(first);
    let second = String::from_utf8_lossy(second);
    let after = text
        .find(first.trim())
        .map_or(0, |at| at + first.trim().len());
    let at = text[after..]
        .find(second.trim())
        .map_or(0, |found| after + found);
    let line = text[..at].matches('\n').count() + 1;
    let column = at - text[..at].rfind('\n').map_or(0, |newline| newline + 1) + 1;
    (line, column)
}

/// Builds the snapshot of the working tree.
pub(crate) fn build_snapshot(
    store: &dyn Store,
    manifest: &Manifest,
    one_policy_per_file: bool,
) -> Result<Snapshot> {
    let ignores = read_ignores(store)?;

    // The previous snapshot's hooks, for the identity cascade: entry path →
    // id, and alias → id across the whole snapshot.
    let (previous_by_path, previous_by_alias) = sync::previous_identity_maps(store)?;

    let mut snapshot_objects: BTreeMap<Digest, Vec<u8>> = BTreeMap::new();
    let mut policies: Vec<PolicyRecord> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    // What a workspace is: the manifest, the partitions it declares, `.permguardignore` and
    // `.permguard/`. Anything else at the root is refused, not walked past: a policy in a folder
    // nobody compiles is a policy nobody enforces, and the author who put it there believes
    // otherwise. `.permguardignore` is where the neighbours that are not policy are excused.
    problems.extend(root_dirt(store, manifest, &ignores)?);
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
            one_policy_per_file,
        };
        // A partition the manifest declares is compiled: an entry hiding it whole would publish
        // an empty partition while its author believes their policies are enforced (BUG-0205).
        if let Some(entry) = hiding_entry(&ignores, partition_name, true) {
            context.problems.push(format!(
                "the partition `{partition_name}` the manifest declares is hidden by the \
                 `.permguardignore` entry `{entry}`: a declared partition is compiled, so remove \
                 or anchor the entry, or rename the partition"
            ));
        }
        refuse_links(&mut context, partition_name)?;
        let (digest, _) = build_directory(&mut context, partition_name, partition_name, 1)?;
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
        data: manifest.encode().map_err(|error| err(error.to_string()))?,
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
    /// Whether a policy file must hold one policy (`workspace.one_policy_per_file`).
    one_policy_per_file: bool,
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
/// Answers the tree's digest and whether it holds anything.
fn build_directory(
    context: &mut PartitionContext<'_>,
    logical_path: &str,
    fs_path: &str,
    depth: usize,
) -> Result<(Digest, bool)> {
    if depth > permguard_objects::limits::MAX_TREE_DEPTH {
        return Err(err(format!("{fs_path}: deeper than the model allows")));
    }
    let mut entries: BTreeMap<String, TreeEntry> = BTreeMap::new();

    for (name, is_dir) in context.store.list(fs_path).map_err(err)? {
        let child_fs = format!("{fs_path}/{name}");
        let child_logical = format!("{logical_path}/{name}");
        if !is_dir && os_noise(&name) {
            continue;
        }
        if let Some(entry) = hiding_entry(context.ignores, &child_fs, is_dir) {
            // A name entry reaches into every partition: one written for the folders beside the
            // manifest (`tests/`) also hides `cedar/tests/<policy>`, which a fresh clone then
            // never sees and its next `apply` deletes from the ledger. A path entry is the
            // author's own choice of this place, and stands (BUG-0015, DEC-0002).
            if name_entry(entry) {
                for hidden in readable_under(context, &child_fs, is_dir)? {
                    context.problems.push(format!(
                        "`{hidden}` is a file of the partition `{}` and the `.permguardignore` \
                         entry `{entry}` hides it: a hidden policy is one nobody enforces, so \
                         anchor the entry to the root (`/{}`), move the file, or remove it",
                        context.partition,
                        entry.trim_start_matches('/')
                    ));
                }
            }
            continue;
        }
        if is_dir {
            refuse_links(context, &child_fs)?;
            let (digest, holds) = build_directory(context, &child_logical, &child_fs, depth + 1)?;
            // An empty folder is not part of the snapshot: a clone never recreates one, so
            // publishing it showed every clone a phantom change and two workspaces of one content
            // traded empty commits (BUG-0049, DEC-0003).
            if !holds {
                continue;
            }
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
            // Not a policy this runtime reads, not an artifact this partition may hold: refused,
            // not walked past. `documents.cedr` beside `documents.cedar` is a policy nobody
            // enforces, and the author who wrote it thinks otherwise. `.gitkeep` is the one file
            // that only means "this folder exists".
            if name != ".gitkeep" {
                context.problems.push(format!(
                    "`{child_fs}` is not a `{}` policy nor an artifact the partition `{}` \
                     declares: move it, remove it, or list it in `.permguardignore`",
                    context.plugin.name(),
                    context.partition
                ));
            }
            continue;
        }
        let source = authored(
            context
                .store
                .read(&child_fs)
                .map_err(err)?
                .ok_or_else(|| err(format!("{child_fs} vanished mid-read")))?,
        );

        if let Some(artifact) = artifact {
            if let Err(error) = permguard_languages::registry::validate_artifact(artifact, &source)
            {
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
        // A team that keeps one policy per file asks for it: the file is refused whole, where the
        // second policy begins, rather than split.
        if context.one_policy_per_file && extracted.len() > 1 {
            let (line, column) = place_of(&source, &extracted[0].bytes, &extracted[1].bytes);
            context.problems.push(format!(
                "{child_fs}: holds {} policies, the second at line {line} column {column}: a policy \
                 file holds one policy when workspace.one_policy_per_file is on; move each other \
                 policy to a file of its own",
                extracted.len()
            ));
            continue;
        }
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
                context.problems.push(if other == child_fs {
                    format!("{child_fs}: the same policy ({id}) appears twice in it: one policy, one place")
                } else {
                    format!(
                        "the same policy ({id}) appears in both {other} and {child_fs}: one policy, one place"
                    )
                });
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

    let holds = !entries.is_empty();
    let tree = Tree {
        entries: entries.into_values().collect(),
    };
    let bytes = tree.encode().map_err(|error| err(error.to_string()))?;
    let digest = inventory::put(context.store, &bytes).map_err(err)?;
    context.snapshot_objects.insert(digest.clone(), bytes);
    Ok((digest, holds))
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

/// The files an operating system drops into a folder on its own: never read, never dirt, and
/// never something a `.permguardignore` has to name. `checkout` removes them with the partition
/// they sit in rather than keeping the folder alive for them.
pub(crate) const OS_NOISE: &[&str] = &[".DS_Store", "Thumbs.db", "desktop.ini"];

/// Whether this is the name of a file an operating system drops on its own. Only a **file** of
/// that name is noise: a folder named `desktop.ini` is an ordinary folder, walked or refused like
/// any other, never a place a policy disappears into (BUG-0048, DEC-0002).
pub(crate) fn os_noise(name: &str) -> bool {
    OS_NOISE.contains(&name)
}

/// The refusal of a symbolic link: it is never followed or read, so what it points at is never
/// published, and it is never dropped in silence either — the next `apply` would delete from the
/// ledger the policy the author linked in (BUG-0030, DEC-0002).
fn link_refusal(path: &str) -> String {
    format!(
        "`{path}` is a symbolic link, and links are not followed: put the file itself there, \
         remove the link, or list it in `.permguardignore`"
    )
}

/// Refuses every link directly under `path` that `.permguardignore` does not excuse.
fn refuse_links(context: &mut PartitionContext<'_>, path: &str) -> Result<()> {
    for name in context.store.links(path).map_err(err)? {
        let child = format!("{path}/{name}");
        if !ignored(context.ignores, &child, false) {
            context.problems.push(link_refusal(&child));
        }
    }
    Ok(())
}

/// The files under `path` (or `path` itself, a file) the partition would read: its policy files
/// and the artifacts its language knows. What an ignore entry would hide from the build.
fn readable_under(context: &PartitionContext<'_>, path: &str, is_dir: bool) -> Result<Vec<String>> {
    let readable = |name: &str| {
        let extension = name.rsplit('.').next().unwrap_or_default();
        context.authoring.file_extensions().contains(&extension)
            || permguard_languages::artifact::classify(context.plugin.artifacts(), name).is_some()
    };
    if !is_dir {
        let name = path.rsplit('/').next().unwrap_or(path);
        return Ok(if readable(name) {
            vec![path.to_owned()]
        } else {
            Vec::new()
        });
    }
    let mut found = Vec::new();
    for (name, child_is_dir) in context.store.list(path).map_err(err)? {
        found.extend(readable_under(
            context,
            &format!("{path}/{name}"),
            child_is_dir,
        )?);
    }
    Ok(found)
}

/// Whether `entry` is a name entry, matching at any depth, rather than a path anchored to the
/// workspace root.
fn name_entry(entry: &str) -> bool {
    let entry = entry.strip_suffix('/').unwrap_or(entry);
    !entry.starts_with('/') && !entry.contains('/')
}

/// Whether `.permguardignore` excuses this path.
///
/// Two kinds of entry, the way `.gitignore` reads them: a name with no `/` in it matches a file
/// or folder of that name at any depth, and everything under such a folder — `.DS_Store` is
/// dropped by the Finder into every folder it opens, and `README.md` is no more a policy inside a
/// partition than beside one; a path with a `/` in it is a prefix from the workspace root. A
/// trailing `/` says the entry names a folder, never a file of that name.
pub(crate) fn ignored(ignores: &[String], path: &str, is_dir: bool) -> bool {
    hiding_entry(ignores, path, is_dir).is_some()
}

/// The first `.permguardignore` entry that excuses this path.
///
/// A path entry — one with a `/` inside it, or one starting with `/` — is anchored to the root and
/// matches whole segments: the path itself and what is under it, never a longer name that merely
/// starts alike (`cedar/doc` is not `cedar/documents.cedar`, BUG-0010, DEC-0002).
pub(crate) fn hiding_entry<'a>(ignores: &'a [String], path: &str, is_dir: bool) -> Option<&'a str> {
    let segments: Vec<&str> = path.split('/').collect();
    let (last, ancestors) = segments.split_last().unwrap_or((&path, &[]));
    ignores
        .iter()
        .find(|entry| {
            let (entry, folder_only) = match entry.strip_suffix('/') {
                Some(folder) => (folder, true),
                None => (entry.as_str(), false),
            };
            let (entry, anchored) = match entry.strip_prefix('/') {
                Some(rooted) => (rooted, true),
                None => (entry, entry.contains('/')),
            };
            if is_pattern(entry) {
                return pattern_hides(entry, anchored, folder_only, &segments, is_dir);
            }
            if anchored {
                (path == entry && (!folder_only || is_dir))
                    || path.starts_with(&format!("{entry}/"))
            } else {
                ancestors.contains(&entry) || (*last == entry && (!folder_only || is_dir))
            }
        })
        .map(String::as_str)
}

/// Whether an entry is a pattern, with a wildcard or a class in it, rather than an exact name or
/// path.
fn is_pattern(entry: &str) -> bool {
    entry.contains(['*', '?', '['])
}

/// A pattern, compiled as `.gitignore` reads one: `*` and `?` stay inside one segment, `**` spans
/// any number of them (BUG-0296, DEC-0002).
fn pattern(entry: &str) -> std::result::Result<globset::GlobMatcher, globset::Error> {
    globset::GlobBuilder::new(entry)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .map(|glob| glob.compile_matcher())
}

/// Whether a pattern entry hides the path `segments`: an anchored one matches the path or one of
/// the folders above it, from the root; a name one matches the path's own name or the name of a
/// folder above it, at any depth. A folder-only entry matches folders, and what is under them.
fn pattern_hides(
    entry: &str,
    anchored: bool,
    folder_only: bool,
    segments: &[&str],
    is_dir: bool,
) -> bool {
    // Checked when the file is read: an entry that does not compile never gets here.
    let Ok(matcher) = pattern(entry) else {
        return false;
    };
    let count = segments.len();
    (1..=count).any(|depth| {
        // The path itself, or a folder above it: a folder above is always a folder.
        let whole = depth == count;
        if whole && folder_only && !is_dir {
            return false;
        }
        if anchored {
            matcher.is_match(segments[..depth].join("/"))
        } else {
            matcher.is_match(segments[depth - 1])
        }
    })
}

/// The root entries that are not part of this workspace.
///
/// A workspace is the manifest, the partitions it declares, `.permguardignore` and `.permguard/`.
/// Everything else is refused rather than skipped: a `.cedar` file beside the partitions, or a
/// folder named like a partition the manifest does not declare, is content the author can see
/// and no build reads, and the worst outcome is the one where nothing says so. The three ways out
/// are named, because each is right somewhere: into a partition, away, or excused by name.
fn root_dirt(store: &dyn Store, manifest: &Manifest, ignores: &[String]) -> Result<Vec<String>> {
    let mut dirt = Vec::new();
    // A link is never followed, and never dropped in silence either (BUG-0030).
    for name in store.links("").map_err(err)? {
        if !ignored(ignores, &name, false) {
            dirt.push(link_refusal(&name));
        }
    }
    for (name, is_dir) in store.list("").map_err(err)? {
        let known = name == ".permguard"
            || name == ".permguardignore"
            || name == super::manifest_file::MANIFEST_YML
            || name == super::manifest_file::MANIFEST_YAML
            || (is_dir && manifest.partitions.contains_key(&name));
        if known || (!is_dir && os_noise(&name)) || ignored(ignores, &name, is_dir) {
            continue;
        }
        dirt.push(format!(
            "`{name}{}` is not part of this workspace: move it into a partition, remove it, or \
             list it in `.permguardignore`",
            if is_dir { "/" } else { "" }
        ));
    }

    Ok(dirt)
}

pub(crate) fn read_ignores(store: &dyn Store) -> Result<Vec<String>> {
    let Some(bytes) = store.read(".permguardignore").map_err(err)? else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for (number, line) in String::from_utf8_lossy(without_bom(&bytes))
        .lines()
        .enumerate()
    {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        // What this file cannot read is refused by its line, never matched as something else
        // (BUG-0296): an exclusion that silently excludes nothing puts a draft in the ledger.
        if entry.starts_with('!') {
            return Err(err(format!(
                "`.permguardignore` line {} `{entry}`: a negated entry is not supported, so \
                 nothing would be re-included; list only what is excluded",
                number + 1
            )));
        }
        if is_pattern(entry) {
            let bare = entry.trim_start_matches('/').trim_end_matches('/');
            if let Err(error) = pattern(bare) {
                return Err(err(format!(
                    "`.permguardignore` line {} `{entry}` is not a pattern: {error}",
                    number + 1
                )));
            }
        }
        entries.push(entry.to_owned());
    }
    Ok(entries)
}

#[cfg(test)]
mod ignore_tests {
    use super::ignored;

    fn entries(list: &[&str]) -> Vec<String> {
        list.iter().map(|entry| (*entry).to_owned()).collect()
    }

    /// What the Finder and Explorer leave behind is known without being named, and nothing else
    /// is: a policy is never noise.
    #[test]
    fn what_an_operating_system_drops_is_known_without_being_named() {
        assert!(super::os_noise(".DS_Store"));
        assert!(super::os_noise("Thumbs.db"));
        assert!(super::os_noise("desktop.ini"));
        assert!(!super::os_noise("documents.cedar"));
        assert!(!super::os_noise(".gitkeep"));
    }

    /// BUG-0296, DEC-0002: a pattern matches as `.gitignore` reads it — `*` and `?` inside one
    /// segment, `**` across any number of them, a name pattern at any depth, a path pattern from
    /// the root — and never a file the same pattern would not match there.
    #[test]
    fn a_pattern_matches_what_gitignore_would_and_nothing_else() {
        let drafts = entries(&["cedar/drafts/*.cedar"]);
        assert!(ignored(&drafts, "cedar/drafts/wip-open-all.cedar", false));
        assert!(
            !ignored(&drafts, "cedar/drafts/deep/wip.cedar", false),
            "`*` stays in one segment"
        );
        assert!(!ignored(&drafts, "cedar/read.cedar", false));

        let any = entries(&["*.cedar"]);
        assert!(ignored(&any, "read.cedar", false));
        assert!(
            ignored(&any, "cedar/deep/read.cedar", false),
            "a name pattern at any depth"
        );
        assert!(!ignored(&any, "cedar/read.rego", false));

        let rooted = entries(&["cedar/*.cedar"]);
        assert!(ignored(&rooted, "cedar/read.cedar", false));
        assert!(!ignored(&rooted, "cedar/sub/read.cedar", false));
        assert!(
            !ignored(&rooted, "other/cedar/read.cedar", false),
            "a path pattern is rooted"
        );

        let stem = entries(&["cedar/drop.*"]);
        assert!(ignored(&stem, "cedar/drop.cedar", false));
        assert!(!ignored(&stem, "cedar/keep.cedar", false));

        let deep = entries(&["**/drop.cedar"]);
        assert!(ignored(&deep, "drop.cedar", false));
        assert!(ignored(&deep, "cedar/a/b/drop.cedar", false));
        assert!(!ignored(&deep, "cedar/a/b/keep.cedar", false));

        // A folder pattern hides the folders it matches and what is under them, never a file.
        let folders = entries(&["draft-*/"]);
        assert!(ignored(&folders, "cedar/draft-1/read.cedar", false));
        assert!(ignored(&folders, "cedar/draft-1", true));
        assert!(!ignored(&folders, "cedar/draft-1", false));

        // `?` is one character, and a class is a class.
        assert!(ignored(&entries(&["v?.cedar"]), "cedar/v1.cedar", false));
        assert!(!ignored(&entries(&["v?.cedar"]), "cedar/v10.cedar", false));
        assert!(ignored(
            &entries(&["v[0-9].cedar"]),
            "cedar/v7.cedar",
            false
        ));
        assert!(!ignored(
            &entries(&["v[0-9].cedar"]),
            "cedar/vx.cedar",
            false
        ));
    }

    #[test]
    fn a_name_matches_at_any_depth_and_a_path_is_a_prefix_from_the_root() {
        let ignores = entries(&["notes.md", "tests/", "README.md", "cedar/drafts/"]);
        // A name, wherever it turns up.
        assert!(ignored(&ignores, "notes.md", false));
        assert!(ignored(&ignores, "cedar/notes.md", false));
        assert!(ignored(&ignores, "cedar/deep/notes.md", false));
        // A folder entry names folders, at the root and below, what is under them, and never a
        // file of that name.
        assert!(ignored(&ignores, "tests", true));
        assert!(ignored(&ignores, "cedar/tests", true));
        assert!(ignored(&ignores, "tests/cases.yml", false));
        assert!(!ignored(&ignores, "tests", false));
        // A path is anchored: `cedar/drafts/` excuses the folder and what is under it, and
        // nothing named alike elsewhere.
        assert!(ignored(&ignores, "cedar/drafts", true));
        assert!(ignored(&ignores, "cedar/drafts/old.cedar", false));
        assert!(!ignored(&ignores, "rego/drafts", true));
        assert!(!ignored(&ignores, "cedar/drafts.cedar", false));
        // A name is exact: `README.md` is not `README.md.bak`, and a policy is never excused by
        // a name it does not have.
        assert!(ignored(&ignores, "README.md", false));
        assert!(!ignored(&ignores, "README.md.bak", false));
        assert!(!ignored(&ignores, "cedar/documents.cedar", false));
    }

    /// BUG-0010: a path entry matches whole segments, never a name that merely starts alike; a
    /// leading `/` anchors an entry to the root.
    #[test]
    fn a_path_entry_matches_whole_segments_and_a_leading_slash_anchors() {
        let ignores = entries(&["cedar/doc", "/tests/", "/notes.md"]);
        assert!(ignored(&ignores, "cedar/doc", false));
        assert!(ignored(&ignores, "cedar/doc", true));
        assert!(ignored(&ignores, "cedar/doc/old.cedar", false));
        assert!(!ignored(&ignores, "cedar/documents.cedar", false));
        assert!(!ignored(&ignores, "cedar/document-owners.cedar", false));
        assert!(ignored(&ignores, "tests", true));
        assert!(ignored(&ignores, "tests/cases.yml", false));
        assert!(
            !ignored(&ignores, "cedar/tests", true),
            "anchored to the root"
        );
        assert!(ignored(&ignores, "notes.md", false));
        assert!(!ignored(&ignores, "cedar/notes.md", false));
        assert!(!super::name_entry("/tests/"));
        assert!(!super::name_entry("cedar/doc"));
        assert!(super::name_entry("tests/"));
    }
}

#[cfg(test)]
mod tests {
    use super::authored;

    /// BUG-0295, DEC-0031: a leading UTF-8 byte order mark is not part of what was authored, so
    /// the same policy with and without it is the same bytes, the same digest and the same id;
    /// a mark anywhere else is kept.
    #[test]
    fn a_leading_byte_order_mark_is_not_authored() {
        let plain = b"permit(principal, action, resource);\n".to_vec();
        let mut marked = vec![0xEF, 0xBB, 0xBF];
        marked.extend_from_slice(&plain);
        assert_eq!(authored(marked), plain);
        let mut crlf = vec![0xEF, 0xBB, 0xBF];
        crlf.extend_from_slice(b"a\r\nb");
        assert_eq!(authored(crlf), b"a\nb");
        let inside = b"a\xEF\xBB\xBFb".to_vec();
        assert_eq!(authored(inside.clone()), inside);
    }

    #[test]
    fn only_crlf_becomes_lf() {
        assert_eq!(authored(b"a\r\nb\r\n".to_vec()), b"a\nb\n");
        // A lone carriage return, white space and every other byte stay as written.
        assert_eq!(authored(b"a\rb \t\n".to_vec()), b"a\rb \t\n");
        assert_eq!(authored(b"a\r\r\nb".to_vec()), b"a\r\nb");
        let lf = b"permit(principal, action, resource);\n".to_vec();
        assert_eq!(authored(lf.clone()), lf);
    }
}
