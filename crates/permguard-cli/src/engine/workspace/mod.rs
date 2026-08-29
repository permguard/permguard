// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The workspace operations, layered exactly as the documentation promises:
//! `apply ⊃ plan ⊃ validate ⊃ refresh` — one code path, exercised at four
//! depths. Everything here speaks the two traits and nothing else.

pub mod build;
pub mod cases;
pub mod config;
pub mod inventory;
pub mod lock;
pub mod manifest_file;
pub mod prune;
pub mod sync;

use std::collections::BTreeMap;

use permguard_objects::digest::Digest;
use permguard_objects::manifest::Manifest;

use config::WorkspaceConfig;
use permguard_control_client::Store;

pub use build::Snapshot;
pub use sync::{ApplyOutcome, PullOutcome};

/// The default ref a workspace starts on.
pub const DEFAULT_REF: &str = "main";

/// One policy of a snapshot, as plans and reports show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRecord {
    pub partition: String,
    /// The canonical entry name: `<alias|id>.<ext>`.
    pub name: String,
    pub id: String,
    pub alias: Option<String>,
    pub digest: Digest,
    /// The source file it was read from.
    pub source: String,
}

/// One step of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanAction {
    Create(PolicyRecord),
    Update(PolicyRecord),
    Delete {
        partition: String,
        name: String,
        id: String,
    },
}

impl PlanAction {
    /// Which partition this action is in.
    pub fn partition(&self) -> &str {
        match self {
            Self::Create(policy) | Self::Update(policy) => &policy.partition,
            Self::Delete { partition, .. } => partition,
        }
    }
}

/// The full plan: what apply would do.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// The policies to create, update or delete — each named by its identity.
    pub actions: Vec<PlanAction>,
    /// How many tracked policies the plan leaves alone — the context that
    /// says whether "2 to update" is most of the ledger or a rounding error.
    pub unchanged: usize,
    /// Whether the manifest itself differs from the tracked head's.
    pub manifest_changed: bool,
    /// Partitions whose content differs beyond the policies above: a schema,
    /// in practice, since a policy would have an action of its own.
    pub other_changes: Vec<String>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && !self.manifest_changed && self.other_changes.is_empty()
    }
}

/// Everything a workspace operation can say when it refuses.
#[derive(Debug)]
pub struct WorkspaceError {
    pub message: String,
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WorkspaceError {}

impl From<String> for WorkspaceError {
    fn from(message: String) -> Self {
        Self { message }
    }
}

pub(crate) fn err(message: impl Into<String>) -> WorkspaceError {
    WorkspaceError {
        message: message.into(),
    }
}

pub(crate) type Result<T> = std::result::Result<T, WorkspaceError>;

/// One workspace, over whatever storage the caller brought.
pub struct Workspace<'a> {
    pub(crate) store: &'a dyn Store,
}

impl<'a> Workspace<'a> {
    /// Opens a workspace over a store. Nothing is read until asked.
    pub fn open(store: &'a dyn Store) -> Self {
        Self { store }
    }

    /// Initializes a new workspace: the manifest (mandatory from birth),
    /// the hidden state, and one directory per language partition.
    ///
    /// `languages` are language names; every one must be built in, or the
    /// whole init refuses — a manifest naming an engine this build does not
    /// carry would only fail later and further from the cause.
    pub fn init(&self, name: &str, languages: &[&str]) -> Result<()> {
        if self.store.exists(config::CONFIG_PATH) {
            return Err(err("this directory is already a workspace"));
        }
        if languages.is_empty() {
            return Err(err("at least one language is required"));
        }

        // A directory that already holds a manifest is adopted, not
        // overwritten: the manifest is the author's, init only adds the
        // workspace state around it.
        if manifest_file::find(self.store).map_err(err)?.is_some() {
            manifest_file::load(self.store).map_err(err)?;
            WorkspaceConfig::new().save(self.store).map_err(err)?;
            config::write_head(self.store, DEFAULT_REF).map_err(err)?;
            return Ok(());
        }

        let mut runtimes = String::new();
        let mut partitions = String::new();
        let mut profile_partitions = Vec::new();
        for language in languages {
            let plugin = permguard_languages::language(language).ok_or_else(|| {
                let known: Vec<&str> = permguard_languages::languages()
                    .iter()
                    .map(|p| p.name())
                    .collect();
                err(format!(
                    "`{language}` is not a built-in language: this build carries {}",
                    known.join(", ")
                ))
            })?;
            let floor = default_language_floor(plugin.language_version());
            runtimes.push_str(&format!(
                "  {name}:\n    language: {{ name: {name}, constraint: \">={floor}\" }}\n    engine:   {{ name: permguard, constraint: \">=0.1.0 <0.2.0\" }}\n",
                name = plugin.name(),
            ));
            partitions.push_str(&format!(
                "  {name}: {{ runtime: {name}, schema: false }}\n",
                name = plugin.name()
            ));
            profile_partitions.push(plugin.name().to_owned());
            // The partition directory exists from birth — a `.gitkeep`, the
            // one convention every VCS understands for an empty directory.
            self.store
                .write(&format!("{}/.gitkeep", plugin.name()), b"")
                .map_err(err)?;
        }

        let manifest = format!(
            "metadata:\n  kind: policy\n  name: {name}\nruntimes:\n{runtimes}partitions:\n{partitions}profiles:\n  default: {{ type: permguard.api.pdp.native.v1, partitions: [{profiles}] }}\n",
            profiles = profile_partitions.join(", "),
        );
        self.store
            .write(manifest_file::MANIFEST_YML, manifest.as_bytes())
            .map_err(err)?;
        self.store
            .write(
                ".permguardignore",
                b"# paths refresh never reads, one prefix per line\n",
            )
            .map_err(err)?;

        WorkspaceConfig::new().save(self.store).map_err(err)?;
        config::write_head(self.store, DEFAULT_REF).map_err(err)?;
        Ok(())
    }

    /// The loaded configuration; an error when this is not a workspace.
    pub fn config(&self) -> Result<WorkspaceConfig> {
        WorkspaceConfig::load(self.store)
            .map_err(err)?
            .ok_or_else(|| err("not a workspace: run `permguard init` first"))
    }

    /// Saves the configuration.
    pub fn save_config(&self, config: &WorkspaceConfig) -> Result<()> {
        config.save(self.store).map_err(err)
    }

    /// The manifest, loaded and validated — including the load gate: this
    /// build's engines must satisfy every declared runtime.
    pub fn manifest(&self) -> Result<Manifest> {
        let manifest = manifest_file::load(self.store).map_err(err)?;
        permguard_objects::manifest::check_load_gate(
            &manifest,
            &permguard_languages::registry::provided_runtimes(),
        )
        .map_err(|error| err(error.to_string()))?;
        Ok(manifest)
    }

    /// Refresh: build the snapshot from the sources. Everything `validate`
    /// checks happens here — building *is* validating, one code path.
    pub fn refresh(&self) -> Result<Snapshot> {
        let manifest = self.manifest()?;
        build::build_snapshot(self.store, &manifest)
    }

    /// The plan: refresh, then diff against the tracked remote head.
    pub fn plan(&self) -> Result<(Snapshot, Plan)> {
        let snapshot = self.refresh()?;
        let previous = sync::tracked_policies(self.store)?;
        let tracked = sync::tracked_shape(self.store)?;
        Ok((
            snapshot.clone(),
            diff(&previous, &snapshot, tracked.as_ref()),
        ))
    }

    /// The workspace at a glance — everything `.permguard` knows, without
    /// opening it: what is tracked, where it stands, what would change.
    /// Entirely offline: the diff runs against the locally stored head.
    pub fn status(&self) -> Result<Status> {
        let config = self.config()?;
        let r#ref = config::read_head(self.store)
            .map_err(err)?
            .unwrap_or_else(|| DEFAULT_REF.to_owned());
        let checkpoint = config::read_checkpoint(self.store, &r#ref).map_err(err)?;

        let (manifest_name, languages) = match self.manifest() {
            Ok(manifest) => (
                manifest.name.clone(),
                manifest
                    .runtimes
                    .values()
                    .map(|runtime| runtime.language.name.clone())
                    .collect(),
            ),
            Err(_) => (String::new(), Vec::new()),
        };

        let plan = self.plan().ok().map(|(_, plan)| plan);

        Ok(Status {
            manifest_name,
            languages,
            ledger: config.ledger.clone(),
            remote_url: config.ledger.as_ref().and_then(|ledger| {
                config
                    .remotes
                    .get(&ledger.remote)
                    .map(|remote| remote.url.clone())
            }),
            r#ref,
            checkpoint,
            plan,
        })
    }
}

/// What `status` answers: the tracked ledger, the checkpoint, the pending
/// changes — `.permguard`, read for you.
#[derive(Debug, Clone)]
pub struct Status {
    pub manifest_name: String,
    pub languages: Vec<String>,
    pub ledger: Option<crate::engine::workspace::config::LedgerConfig>,
    pub remote_url: Option<String>,
    pub r#ref: String,
    pub checkpoint: Option<crate::engine::workspace::config::Checkpoint>,
    /// `None` when the sources do not even build — status still answers.
    pub plan: Option<Plan>,
}

/// The floor `init` writes for a language constraint: the current major,
/// from zero — wide enough to not fight the author, narrow enough to mean
/// something.
fn default_language_floor(version: &str) -> String {
    let major = version.split('.').next().unwrap_or("0");
    format!("{major}.0.0")
}

/// Diffs two policy sets by id.
/// Compares the working tree with the tracked head.
///
/// Policies are compared one by one, because each has an identity and a report
/// has to name it. Everything **else** a commit carries — the manifest, and a
/// partition's schema — is compared by digest: the root tree covers the lot, so
/// a change nobody has a name for is still a change, and `apply` still has
/// something to do.
fn diff(
    previous: &BTreeMap<String, PolicyRecord>,
    snapshot: &Snapshot,
    tracked: Option<&sync::TrackedShape>,
) -> Plan {
    let mut actions = Vec::new();
    let mut unchanged = 0;
    for policy in &snapshot.policies {
        match previous.get(&policy.id) {
            None => actions.push(PlanAction::Create(policy.clone())),
            Some(old) if old.digest != policy.digest => {
                actions.push(PlanAction::Update(policy.clone()));
            }
            Some(_) => unchanged += 1,
        }
    }
    for (id, old) in previous {
        if !snapshot.policies.iter().any(|policy| policy.id == *id) {
            actions.push(PlanAction::Delete {
                partition: old.partition.clone(),
                name: old.name.clone(),
                id: id.clone(),
            });
        }
    }
    // What changed that no action above names: the manifest, and any partition
    // whose subtree moved without one of its policies moving — a schema, in
    // practice.
    let manifest_changed = tracked.is_some_and(|tracked| tracked.manifest != snapshot.manifest);
    let mut other_changes = Vec::new();
    if let Some(tracked) = tracked
        && tracked.root != snapshot.root
    {
        for (partition, digest) in snapshot_partitions(snapshot) {
            let moved = tracked.partitions.get(&partition) != Some(&digest);
            let named = actions.iter().any(|action| action.partition() == partition);
            if moved && !named {
                other_changes.push(partition);
            }
        }
    }

    Plan {
        actions,
        unchanged,
        manifest_changed,
        other_changes,
    }
}

/// The partition subtrees of a snapshot, read back out of the objects it built.
fn snapshot_partitions(snapshot: &Snapshot) -> BTreeMap<String, permguard_objects::digest::Digest> {
    let Some(bytes) = snapshot.objects.get(&snapshot.root) else {
        return BTreeMap::new();
    };
    let Ok(permguard_objects::object::Object::Tree(root)) =
        permguard_objects::object::decode(bytes)
    else {
        return BTreeMap::new();
    };

    root.entries
        .into_iter()
        .filter(|entry| entry.kind == permguard_objects::object::Kind::Tree)
        .map(|entry| (entry.name, entry.digest))
        .collect()
}
