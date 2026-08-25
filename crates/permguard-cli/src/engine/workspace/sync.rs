// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The synchronizing half: apply (the push), pull, checkout, history — the
//! transfer lifecycle of the specification, client side. Objects move
//! incrementally; the checkpoint and the working tree advance only when the
//! whole closure is present and verified. The head is logically atomic.

use std::collections::{BTreeMap, BTreeSet};

use permguard_notp::{CommitPushRequest, NegotiatePushRequest, ObjectClaim, UploadObjectsRequest};
use permguard_objects::digest::Digest;
use permguard_objects::object::{self, Kind, Object, Tree};
use permguard_objects::policy_id::{ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID};

use super::{PolicyRecord, Result, Workspace, err};
use crate::engine::remote::Remote;
use crate::engine::verify;
use crate::engine::workspace::config::{self, Checkpoint};
use crate::engine::workspace::inventory;
use crate::engine::workspace::manifest_file;
use permguard_control_client::Store;
use permguard_control_client::pull;

/// What an apply reports.
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub head: String,
    pub counter: u64,
    pub uploaded: usize,
}

/// What a verify reports.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub r#ref: String,
    pub head: String,
    pub counter: u64,
    pub local_closure_objects: Option<usize>,
}

/// What a pull reports.
#[derive(Debug, Clone)]
pub struct PullOutcome {
    pub head: String,
    pub counter: u64,
    pub fetched: usize,
    pub materialized: Vec<String>,
}

impl Workspace<'_> {
    /// Apply: plan, then push — negotiate once, upload the missing objects
    /// in batches, commit with compare-and-swap, verify the returned
    /// statement, advance the checkpoint.
    pub fn apply(&self, remote: &dyn Remote, author: &str, message: &str) -> Result<ApplyOutcome> {
        let (snapshot, plan) = self.plan()?;
        let config = self.config()?;
        let ledger = config
            .ledger
            .as_ref()
            .ok_or_else(|| err("no tracked ledger: run `permguard checkout` first"))?;
        let r#ref = config::read_head(self.store)
            .map_err(err)?
            .unwrap_or_else(|| super::DEFAULT_REF.to_owned());
        let checkpoint = config::read_checkpoint(self.store, &r#ref).map_err(err)?;

        if plan.is_empty()
            && let Some(checkpoint) = checkpoint.clone()
        {
            return Ok(ApplyOutcome {
                head: checkpoint.head,
                counter: checkpoint.counter,
                uploaded: 0,
            });
        }

        // The commit: client-determined fields only.
        let expected_old = match &checkpoint {
            Some(checkpoint) => Some(
                Digest::parse(&checkpoint.head).map_err(|_| err("the checkpoint is corrupt"))?,
            ),
            None => None,
        };
        let commit = object::Commit {
            tree: snapshot.root.clone(),
            manifest: snapshot.manifest.clone(),
            predecessors: expected_old.iter().cloned().collect(),
            author: author.to_owned(),
            author_at: now(),
            message: message.to_owned(),
        };
        let commit_bytes = commit.encode().map_err(|error| err(error.to_string()))?;
        let new_head = inventory::put(self.store, &commit_bytes).map_err(err)?;

        // The delta closure: reachable from the new head, minus the old one.
        let stop = match &expected_old {
            Some(old) => walk_local(self.store, old)?,
            None => BTreeSet::new(),
        };
        let region = walk_region_local(self.store, &new_head, &stop)?;
        let claims: Vec<ObjectClaim> = region
            .iter()
            .map(|digest| {
                let bytes = inventory::get(self.store, digest)
                    .map_err(err)?
                    .ok_or_else(|| err(format!("local object {digest} vanished")))?;
                Ok(ObjectClaim {
                    digest: digest.clone(),
                    size: bytes.len() as u64,
                })
            })
            .collect::<Result<_>>()?;

        // Negotiate ONCE; upload the missing set in batches within the
        // advertised limits; every batch independent and idempotent.
        let negotiated = remote
            .negotiate_push(&NegotiatePushRequest {
                r#ref: r#ref.clone(),
                new_head: new_head.clone(),
                expected_old: expected_old.clone(),
                closure: claims,
            })
            .map_err(err)?;
        let mut uploaded = 0usize;
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut batch_bytes = 0u64;
        for digest in &negotiated.missing {
            let bytes = inventory::get(self.store, digest)
                .map_err(err)?
                .ok_or_else(|| {
                    err(format!(
                        "the server misses {digest}, which is not local either"
                    ))
                })?;
            let size = bytes.len() as u64;
            let over = batch.len() as u64 + 1 > negotiated.max_batch_objects
                || batch_bytes + size > negotiated.max_batch_bytes;
            if over && !batch.is_empty() {
                uploaded += batch.len();
                remote
                    .upload(&UploadObjectsRequest {
                        objects: std::mem::take(&mut batch),
                        // Raw here: compression is the transport's concern.
                        compression: None,
                    })
                    .map_err(err)?;
                batch_bytes = 0;
            }
            batch_bytes += size;
            batch.push(bytes);
        }
        if !batch.is_empty() {
            uploaded += batch.len();
            remote
                .upload(&UploadObjectsRequest {
                    objects: batch,
                    compression: None,
                })
                .map_err(err)?;
        }

        // Finalize ONCE: the compare-and-swap commit.
        let committed = remote
            .commit_push(&CommitPushRequest {
                r#ref: r#ref.clone(),
                new_head: new_head.clone(),
                expected_old,
            })
            .map_err(err)?;

        // Verify the returned statement before trusting the new checkpoint.
        let jwks = remote.keyring().map_err(err)?;
        let statement = verify::verify_statement(
            &jwks,
            &committed.statement,
            &ledger.zone_id,
            &ledger.ledger_id,
            &r#ref,
            config::read_checkpoint(self.store, &r#ref)
                .map_err(err)?
                .as_ref(),
        )
        .map_err(err)?;

        let checkpoint = Checkpoint {
            head: statement.digest.to_string(),
            counter: statement.counter,
        };
        config::write_checkpoint(self.store, &r#ref, &checkpoint).map_err(err)?;
        config::write_head(self.store, &r#ref).map_err(err)?;
        Ok(ApplyOutcome {
            head: checkpoint.head,
            counter: checkpoint.counter,
            uploaded,
        })
    }

    /// Pull: the client's fetch-and-prove cycle, with the workspace's file
    /// materialization between the proof and the checkpoint — a failure
    /// writing sources can never leave the checkpoint claiming more than
    /// the disk holds.
    pub fn pull(&self, remote: &dyn Remote) -> Result<PullOutcome> {
        let config = self.config()?;
        let ledger = config
            .ledger
            .as_ref()
            .ok_or_else(|| err("no tracked ledger: run `permguard checkout` first"))?;
        let r#ref = config::read_head(self.store)
            .map_err(err)?
            .unwrap_or_else(|| super::DEFAULT_REF.to_owned());

        let tracked = pull::TrackedRef {
            zone_id: ledger.zone_id.clone(),
            ledger_id: ledger.ledger_id.clone(),
            r#ref: r#ref.clone(),
        };
        let verified = pull::fetch_closure(
            self.store,
            crate::engine::workspace::inventory::OBJECTS_DIR,
            &config::checkpoint_path(&r#ref),
            remote,
            &tracked,
        )
        .map_err(err)?;

        let materialized = self.materialize(&verified.head)?;

        pull::commit_checkpoint(self.store, &config::checkpoint_path(&r#ref), &verified)
            .map_err(err)?;
        config::write_head(self.store, &r#ref).map_err(err)?;
        Ok(PullOutcome {
            head: verified.head.to_string(),
            counter: verified.counter,
            fetched: verified.fetched,
            materialized,
        })
    }

    /// Binds this workspace to a ledger and pulls it.
    pub fn checkout(
        &self,
        remote: &dyn Remote,
        remote_name: &str,
        zone: &str,
        ledger: &str,
        r#ref: &str,
    ) -> Result<PullOutcome> {
        let (zone_id, ledger_id) = remote.resolve(zone, ledger).map_err(err)?;
        let mut config = self.config()?;
        config.ledger = Some(crate::engine::workspace::config::LedgerConfig {
            remote: remote_name.to_owned(),
            zone: zone.to_owned(),
            ledger: ledger.to_owned(),
            zone_id,
            ledger_id,
        });
        self.save_config(&config)?;
        config::write_head(self.store, r#ref).map_err(err)?;
        match self.pull(remote) {
            Ok(outcome) => Ok(outcome),
            // A ledger with no ref yet is not an error to bind to: the first
            // apply will create it. The binding stays; the pull found nothing.
            Err(error)
                if error.message.contains("not_found") || error.message.contains("no ref") =>
            {
                Ok(PullOutcome {
                    head: String::new(),
                    counter: 0,
                    fetched: 0,
                    materialized: Vec::new(),
                })
            }
            Err(error) => Err(error),
        }
    }

    /// History: the commit DAG of the current ref, newest first.
    pub fn history(&self) -> Result<Vec<(Digest, object::Commit)>> {
        let r#ref = config::read_head(self.store)
            .map_err(err)?
            .unwrap_or_else(|| super::DEFAULT_REF.to_owned());
        let Some(checkpoint) = config::read_checkpoint(self.store, &r#ref).map_err(err)? else {
            return Ok(Vec::new());
        };
        let mut commits = Vec::new();
        let mut queue =
            vec![Digest::parse(&checkpoint.head).map_err(|_| err("corrupt checkpoint"))?];
        let mut seen = BTreeSet::new();
        while let Some(digest) = queue.pop() {
            if !seen.insert(digest.clone()) {
                continue;
            }
            let Some(bytes) = inventory::get(self.store, &digest).map_err(err)? else {
                continue;
            };
            if let Ok(Object::Commit(commit)) = object::decode(&bytes) {
                queue.extend(commit.predecessors.iter().cloned());
                commits.push((digest, commit));
            }
        }
        Ok(commits)
    }

    /// Verifies the remote head statement against the key ring and the
    /// checkpoint, and the local closure by hash — reporting what it found.
    pub fn verify(&self, remote: &dyn Remote) -> Result<VerifyOutcome> {
        let config = self.config()?;
        let ledger = config
            .ledger
            .as_ref()
            .ok_or_else(|| err("no tracked ledger: run `permguard checkout` first"))?;
        let r#ref = config::read_head(self.store)
            .map_err(err)?
            .unwrap_or_else(|| super::DEFAULT_REF.to_owned());
        let checkpoint = config::read_checkpoint(self.store, &r#ref).map_err(err)?;
        let answer = remote
            .get_ref(&r#ref)
            .map_err(err)?
            .ok_or_else(|| err(format!("the remote has no ref `{ref}`", ref = r#ref)))?;
        let jwks = remote.keyring().map_err(err)?;
        let statement = verify::verify_statement(
            &jwks,
            &answer.statement,
            &ledger.zone_id,
            &ledger.ledger_id,
            &r#ref,
            checkpoint.as_ref(),
        )
        .map_err(err)?;
        let local_closure_objects = match checkpoint {
            Some(checkpoint) => {
                let head =
                    Digest::parse(&checkpoint.head).map_err(|_| err("corrupt checkpoint"))?;
                Some(walk_local(self.store, &head)?.len())
            }
            None => None,
        };
        Ok(VerifyOutcome {
            r#ref: r#ref.clone(),
            head: statement.digest.to_string(),
            counter: statement.counter,
            local_closure_objects,
        })
    }

    /// Materializes what the workspace lacks from a snapshot: the manifest
    /// file when there is none, and one new file per missing policy. Files
    /// the author already keeps are never touched.
    fn materialize(&self, head: &Digest) -> Result<Vec<String>> {
        let commit = load_commit(self.store, head)?;
        let root = load_tree(self.store, &commit.tree)?;
        let mut written = Vec::new();

        // The manifest: written as manifest.yml only when no manifest file
        // exists — the CLI never picks between two silently.
        if manifest_file::find(self.store).map_err(err)?.is_none() {
            let manifest_blob = load_blob_data(self.store, &commit.manifest)?;
            let manifest = permguard_objects::manifest::Manifest::decode(&manifest_blob)
                .map_err(|error| err(error.to_string()))?;
            let yaml = manifest_file::to_yaml(&manifest).map_err(err)?;
            self.store
                .write(manifest_file::MANIFEST_YML, yaml.as_bytes())
                .map_err(err)?;
            written.push(manifest_file::MANIFEST_YML.to_owned());
        }

        // Local ids: what the sources already hold, wherever they hold it.
        let local: BTreeMap<String, PolicyRecord> = match self.refresh() {
            Ok(snapshot) => snapshot
                .policies
                .into_iter()
                .map(|policy| (policy.id.clone(), policy))
                .collect(),
            // A fresh clone has no sources yet: everything materializes.
            Err(_) => BTreeMap::new(),
        };

        for entry in &root.entries {
            if entry.kind != Kind::Tree {
                continue;
            }
            self.materialize_tree(&entry.name, &entry.digest, &local, &mut written)?;
        }
        Ok(written)
    }
}

impl Workspace<'_> {
    /// Materializes one subtree, recursing — the folder structure of the
    /// snapshot (a Rego package tree, say) is rebuilt exactly: directory
    /// names are the subtree entry names.
    fn materialize_tree(
        &self,
        directory: &str,
        tree_digest: &Digest,
        local: &BTreeMap<String, PolicyRecord>,
        written: &mut Vec<String>,
    ) -> Result<()> {
        let tree = load_tree(self.store, tree_digest)?;
        for item in &tree.entries {
            match item.kind {
                Kind::Tree => {
                    self.materialize_tree(
                        &format!("{directory}/{}", item.name),
                        &item.digest,
                        local,
                        written,
                    )?;
                }
                Kind::Blob => match item.annotations.get(ANNOTATION_POLICY_ID) {
                    Some(id) => {
                        if local.contains_key(id) {
                            continue;
                        }
                        let stem = item
                            .annotations
                            .get(ANNOTATION_POLICY_ALIAS)
                            .cloned()
                            .unwrap_or_else(|| id.clone());
                        let extension = item.name.rsplit('.').next().unwrap_or("txt");
                        let path = format!("{directory}/{stem}.{extension}");
                        if !self.store.exists(&path) {
                            let data = load_blob_data(self.store, &item.digest)?;
                            self.store.write(&path, &data).map_err(err)?;
                            written.push(path);
                        }
                    }
                    None => {
                        // A schema or other non-policy blob: keep its name.
                        let path = format!("{directory}/{name}", name = item.name);
                        if !self.store.exists(&path) {
                            let data = load_blob_data(self.store, &item.digest)?;
                            self.store.write(&path, &data).map_err(err)?;
                            written.push(path);
                        }
                    }
                },
                Kind::Commit => {}
            }
        }
        Ok(())
    }
}

/// The identity hooks of the previous (tracked) snapshot: entry path → id,
/// and alias → id, for the cascade.
pub(crate) fn previous_identity_maps(
    store: &dyn Store,
) -> Result<(BTreeMap<String, String>, BTreeMap<String, String>)> {
    let mut by_path = BTreeMap::new();
    let mut by_alias = BTreeMap::new();
    for policy in tracked_policies(store)?.into_values() {
        by_path.insert(
            format!("{}/{}", policy.partition, policy.name),
            policy.id.clone(),
        );
        if let Some(alias) = policy.alias {
            by_alias.insert(alias, policy.id);
        }
    }
    Ok((by_path, by_alias))
}

/// What the tracked head *is*, beyond its policies: the shape a plan has to
/// compare against.
///
/// The root tree digest covers everything a commit carries — policies,
/// schemas, nested folders — and the manifest digest covers the manifest. A
/// plan that compared only policies would call a changed schema "no changes",
/// which is exactly the bug this exists to make impossible.
#[derive(Debug, Clone)]
pub(crate) struct TrackedShape {
    pub root: Digest,
    pub manifest: Digest,
    /// Each partition's subtree digest, so a report can name what changed.
    pub partitions: BTreeMap<String, Digest>,
}

/// The shape of the tracked head, or `None` when nothing is tracked yet.
pub(crate) fn tracked_shape(store: &dyn Store) -> Result<Option<TrackedShape>> {
    let r#ref = config::read_head(store)
        .map_err(err)?
        .unwrap_or_else(|| super::DEFAULT_REF.to_owned());
    let Some(checkpoint) = config::read_checkpoint(store, &r#ref).map_err(err)? else {
        return Ok(None);
    };
    let head = Digest::parse(&checkpoint.head).map_err(|_| err("corrupt checkpoint"))?;
    let commit = load_commit(store, &head)?;
    let root = load_tree(store, &commit.tree)?;
    let partitions = root
        .entries
        .iter()
        .filter(|entry| entry.kind == Kind::Tree)
        .map(|entry| (entry.name.clone(), entry.digest.clone()))
        .collect();

    Ok(Some(TrackedShape {
        root: commit.tree,
        manifest: commit.manifest,
        partitions,
    }))
}

/// The policies of the tracked remote head, id → record, from local objects.
pub(crate) fn tracked_policies(store: &dyn Store) -> Result<BTreeMap<String, PolicyRecord>> {
    let r#ref = config::read_head(store)
        .map_err(err)?
        .unwrap_or_else(|| super::DEFAULT_REF.to_owned());
    let Some(checkpoint) = config::read_checkpoint(store, &r#ref).map_err(err)? else {
        return Ok(BTreeMap::new());
    };
    let head = Digest::parse(&checkpoint.head).map_err(|_| err("corrupt checkpoint"))?;
    let commit = load_commit(store, &head)?;
    let root = load_tree(store, &commit.tree)?;
    let mut policies = BTreeMap::new();
    for entry in &root.entries {
        if entry.kind != Kind::Tree {
            continue;
        }
        collect_policies(store, &entry.name, "", &entry.digest, &mut policies)?;
    }
    Ok(policies)
}

/// Walks one partition subtree collecting its policies, folder names kept.
fn collect_policies(
    store: &dyn Store,
    partition: &str,
    prefix: &str,
    tree_digest: &Digest,
    policies: &mut BTreeMap<String, PolicyRecord>,
) -> Result<()> {
    let tree = load_tree(store, tree_digest)?;
    for item in &tree.entries {
        let name = if prefix.is_empty() {
            item.name.clone()
        } else {
            format!("{prefix}/{}", item.name)
        };
        match item.kind {
            Kind::Tree => collect_policies(store, partition, &name, &item.digest, policies)?,
            Kind::Blob => {
                if let Some(id) = item.annotations.get(ANNOTATION_POLICY_ID) {
                    policies.insert(
                        id.clone(),
                        PolicyRecord {
                            partition: partition.to_owned(),
                            name,
                            id: id.clone(),
                            alias: item.annotations.get(ANNOTATION_POLICY_ALIAS).cloned(),
                            digest: item.digest.clone(),
                            source: String::new(),
                        },
                    );
                }
            }
            Kind::Commit => {}
        }
    }
    Ok(())
}

/// Everything reachable from `start` in the local store — the client's walk,
/// rooted at the workspace's mirror.
pub(crate) fn walk_local(store: &dyn Store, start: &Digest) -> Result<BTreeSet<Digest>> {
    pull::walk_local(
        store,
        crate::engine::workspace::inventory::OBJECTS_DIR,
        start,
    )
    .map_err(err)
}

pub(crate) fn walk_region_local(
    store: &dyn Store,
    start: &Digest,
    stop: &BTreeSet<Digest>,
) -> Result<BTreeSet<Digest>> {
    pull::walk_region_local(
        store,
        crate::engine::workspace::inventory::OBJECTS_DIR,
        start,
        stop,
    )
    .map_err(err)
}

fn load_commit(store: &dyn Store, digest: &Digest) -> Result<object::Commit> {
    match decode_object(store, digest)? {
        Object::Commit(commit) => Ok(commit),
        _ => Err(err(format!("{digest} is not a commit"))),
    }
}

fn load_tree(store: &dyn Store, digest: &Digest) -> Result<Tree> {
    match decode_object(store, digest)? {
        Object::Tree(tree) => Ok(tree),
        _ => Err(err(format!("{digest} is not a tree"))),
    }
}

fn load_blob_data(store: &dyn Store, digest: &Digest) -> Result<Vec<u8>> {
    match decode_object(store, digest)? {
        Object::Blob(blob) => Ok(blob.data),
        _ => Err(err(format!("{digest} is not a blob"))),
    }
}

fn decode_object(store: &dyn Store, digest: &Digest) -> Result<Object> {
    let bytes = inventory::get(store, digest)
        .map_err(err)?
        .ok_or_else(|| err(format!("object {digest} is not local: pull first")))?;
    object::decode(&bytes).map_err(|error| err(format!("{digest}: {error}")))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}
