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

use super::{PlanAction, PolicyRecord, Result, Workspace, err};
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
    /// Files the incoming head moved forward that the author had not touched.
    pub updated: Vec<String>,
    /// Files the incoming head dropped that the author had not touched.
    pub removed: Vec<String>,
    /// The counter this workspace held before the pull, when it held one — so
    /// the report can tell a pull that moved the ref from one that found
    /// nothing to do, which the object count alone cannot: a refused pull
    /// leaves its objects in the store, so the retry fetches none.
    pub previous_counter: Option<u64>,
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
    pub fn pull(&self, remote: &dyn Remote, resolved: bool) -> Result<PullOutcome> {
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
        let previous_counter = config::read_checkpoint(self.store, &r#ref)
            .map_err(err)?
            .map(|held| held.counter);
        let verified = pull::fetch_closure(
            self.store,
            crate::engine::workspace::inventory::OBJECTS_DIR,
            &config::checkpoint_path(&r#ref),
            remote,
            &tracked,
        )
        .map_err(err)?;

        let landed = self.materialize(&verified.head, resolved)?;

        pull::commit_checkpoint(self.store, &config::checkpoint_path(&r#ref), &verified)
            .map_err(err)?;
        config::write_head(self.store, &r#ref).map_err(err)?;
        Ok(PullOutcome {
            head: verified.head.to_string(),
            counter: verified.counter,
            fetched: verified.fetched,
            materialized: landed.created(),
            updated: landed.updated(),
            removed: landed.removals,
            previous_counter,
        })
    }

    /// Binds this workspace to a ledger and pulls it.
    ///
    /// Like `git checkout`, not like a merge: the tree becomes the ledger's. A checkout that
    /// changes what is tracked — another ledger, or another ref of it — refuses while the tree
    /// holds changes not applied to what it tracks now, because a checkout must never carry work
    /// from one ledger into another, where the next `apply` would publish it under the wrong
    /// name. On a clean tree it removes what the tracked ledger materialised — the manifest and
    /// its partitions — and pulls the new one whole; what `.permguardignore` names was never the
    /// ledger's and stays. Towards a ledger with no history yet that leaves an empty workspace,
    /// which `init` gives a shape again without touching the binding. The first checkout of a
    /// workspace only binds and pulls: `init` leaves nothing tracked to compare against, and so
    /// does a workspace with no manifest.
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
        let current_ref = config::read_head(self.store)
            .map_err(err)?
            .unwrap_or_else(|| super::DEFAULT_REF.to_owned());
        // The checkpoint is kept per ref, and every ledger's default ref is `main`, so two
        // ledgers checked out in turn would share one checkpoint file. Left standing, the old
        // ledger's `(head, counter)` would be read as the new one's: `status` would report a
        // counter the new ledger never reached, `plan` would diff against a head it does not
        // hold, and an `apply` with nothing to send would return that stale checkpoint as a
        // success — a publication that never happened. A checkpoint belongs to the ledger it was
        // taken from, and goes when the binding does.
        let rebound = config.ledger.as_ref().is_some_and(|held| {
            if held.zone_id.is_empty() || held.ledger_id.is_empty() {
                // A binding written before the ids were recorded: the names are all there is.
                held.zone != zone || held.ledger != ledger
            } else {
                held.zone_id != zone_id || held.ledger_id != ledger_id
            }
        });
        // A workspace without a manifest holds nothing the tracked ledger materialised — a clone
        // before its first pull, or the empty tree a checkout of an empty ledger leaves — so there
        // is nothing to refuse over and nothing to clear.
        let switching = config.ledger.is_some()
            && (rebound || current_ref != r#ref)
            && manifest_file::find(self.store).map_err(err)?.is_some();
        if switching {
            let tracked = config
                .ledger
                .as_ref()
                .map(|held| format!("{}/{}/{}", held.remote, held.zone, held.ledger))
                .unwrap_or_default();
            // `plan` builds the tree first, so a workspace that does not validate — dirt
            // included — is refused here in the build's own words, before anything is touched.
            let (_, plan) = self.plan()?;
            if !plan.is_empty() {
                let (mut create, mut update, mut delete) = (0usize, 0usize, 0usize);
                for action in &plan.actions {
                    match action {
                        PlanAction::Create(_) => create += 1,
                        PlanAction::Update(_) => update += 1,
                        PlanAction::Delete { .. } => delete += 1,
                    }
                }
                let beyond = if plan.manifest_changed || !plan.other_changes.is_empty() {
                    ", and the manifest or a schema"
                } else {
                    ""
                };
                return Err(err(format!(
                    "the working tree has changes not applied to `{tracked}` ({create} to \
                     create, {update} to update, {delete} to delete{beyond}): `apply` them, or \
                     remove them, before checking out another ledger"
                )));
            }
        }
        // Whether the target has a history to pull, asked before anything is removed: towards a
        // ledger with no ref yet there is nothing to pull, and the pull's "not found" must not be
        // mistaken for a failure after the tree has already been cleared.
        let target_head = if switching {
            remote.get_ref(r#ref).map_err(err)?
        } else {
            None
        };
        if rebound {
            self.store
                .remove(&config::checkpoint_path(r#ref))
                .map_err(err)?;
        }
        config.ledger = Some(crate::engine::workspace::config::LedgerConfig {
            remote: remote_name.to_owned(),
            zone: zone.to_owned(),
            ledger: ledger.to_owned(),
            zone_id,
            ledger_id,
        });
        self.save_config(&config)?;
        config::write_head(self.store, r#ref).map_err(err)?;
        if switching {
            // The tree becomes the new ledger's. What the old one materialised goes: every
            // partition its manifest declared, then the manifest itself. What `.permguardignore`
            // names stays where it is, inside a partition too, as it would survive a clone.
            let previous = manifest_file::load(self.store).map_err(err)?;
            let ignores = super::build::read_ignores(self.store)?;
            let mut removed = Vec::new();
            for partition in previous.partitions.keys() {
                clear_tree(self.store, partition, &ignores, &mut removed)?;
            }
            if let Some(file) = manifest_file::find(self.store).map_err(err)? {
                self.store.remove(file).map_err(err)?;
                removed.push(file.to_owned());
            }
            if target_head.is_none() {
                // An empty ledger is an empty workspace: bound, with nothing to pull. `init`
                // gives it a shape again, and the first `apply` creates the ledger's history.
                return Ok(PullOutcome {
                    head: String::new(),
                    counter: 0,
                    fetched: 0,
                    materialized: Vec::new(),
                    updated: Vec::new(),
                    removed,
                    previous_counter: None,
                });
            }
            let mut outcome = self.pull(remote, false)?;
            removed.append(&mut outcome.removed);
            outcome.removed = removed;

            return Ok(outcome);
        }
        match self.pull(remote, false) {
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
                    updated: Vec::new(),
                    removed: Vec::new(),
                    previous_counter: None,
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

    /// The aliases of the tracked head's policies, identity → alias.
    ///
    /// A plane cites policies by identity and a person reads them by the alias their author
    /// wrote. `test` already names them that way; a `check` asked from inside a checkout can name
    /// them the same way from the head it tracks — without building the tree, and without
    /// pretending the plane cited anything but the identity.
    pub fn tracked_aliases(&self) -> Result<BTreeMap<String, String>> {
        Ok(tracked_policies(self.store)?
            .into_values()
            .filter_map(|policy| policy.alias.map(|alias| (policy.id, alias)))
            .collect())
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

    /// Materializes the incoming head into the working tree.
    ///
    /// Three-way, per policy: the tracked head is the base, the working tree
    /// is the author's, the incoming head is the remote's. A policy only one
    /// side moved follows that side — the remote's change lands, the author's
    /// stays pending for `apply`. A policy both sides moved is a conflict, and
    /// a conflict stops the pull before a byte is written.
    ///
    /// Advancing the checkpoint over content the tree does not hold is how a
    /// later `apply` silently reverts somebody else's commit: the diff is
    /// taken tree-against-checkpoint, so content the tree never received
    /// reads as a deliberate deletion. The checkpoint may only claim what
    /// the disk holds.
    fn materialize(&self, head: &Digest, resolved: bool) -> Result<Materialization> {
        let plan = self.plan_materialization(head)?;
        if !resolved && !plan.conflicts.is_empty() {
            return Err(err(plan.refusal()));
        }
        for (path, content) in plan.creates.iter().chain(&plan.updates) {
            self.store.write(path, content).map_err(err)?;
        }
        for path in &plan.removals {
            self.store.remove(path).map_err(err)?;
        }
        Ok(plan)
    }

    /// Decides what the incoming head does to the working tree, without
    /// touching it — so a conflict costs nothing and leaves nothing behind.
    fn plan_materialization(&self, head: &Digest) -> Result<Materialization> {
        let commit = load_commit(self.store, head)?;
        let incoming = head_contents(self.store, head)?;
        let tracked = tracked_head(self.store)?;

        // A manifest already in the tree is the author's, and it says which partitions the tree
        // has. A head carrying a partition the manifest does not declare cannot land on it: the
        // files would be written where no build reads them, and the next `plan` — the tracked
        // head against a tree that never declared them — would delete them from the ledger.
        // Refused before a byte is written, naming the partition and both ways out.
        if manifest_file::find(self.store).map_err(err)?.is_some() {
            let manifest = manifest_file::load(self.store).map_err(err)?;
            let root = load_tree(self.store, &commit.tree)?;
            let undeclared: Vec<String> = root
                .entries
                .iter()
                .filter(|entry| entry.kind == Kind::Tree)
                .filter(|entry| !manifest.partitions.contains_key(&entry.name))
                .map(|entry| format!("`{}`", entry.name))
                .collect();
            if !undeclared.is_empty() {
                return Err(err(format!(
                    "the incoming head holds the partition(s) {} and this workspace's manifest \
                     does not declare them: declare them in the manifest (`init` names its \
                     languages with --language), or remove the manifest so the checkout adopts \
                     the ledger's",
                    undeclared.join(", ")
                )));
            }

            // The same for what a declared partition holds. A schema the head carries lands in
            // a partition whose manifest says `schema: false`, and the build then refuses the
            // tree — after the checkout reported success. The head's own manifest says what each
            // partition declares, so the two are compared before anything is written: a contract
            // the ledger has and this manifest lacks is refused by name. The reverse — a contract
            // this manifest declares and the ledger does not yet — is the author being ahead, and
            // `plan` is where that shows.
            let theirs = permguard_objects::manifest::Manifest::decode(&load_blob_data(
                self.store,
                &commit.manifest,
            )?)
            .map_err(|error| err(error.to_string()))?;
            let mut lacking: Vec<String> = Vec::new();
            for (name, declared) in &theirs.partitions {
                let Some(ours) = manifest.partitions.get(name) else {
                    continue;
                };
                // The legacy `schema` flag and a typed `artifacts` list are two spellings, and
                // the registry is what says whether they name the same contract. Compared only
                // when both sides spell it the same way; a mixed pair is left to the build.
                if ours.artifacts.is_empty() != declared.artifacts.is_empty() {
                    continue;
                }
                let held = contracts_of(ours);
                for contract in contracts_of(declared) {
                    if !held.contains(&contract) {
                        lacking.push(format!("`{name}` declares no {contract}"));
                    }
                }
            }
            if !lacking.is_empty() {
                return Err(err(format!(
                    "the incoming head's manifest declares what this workspace's does not — {}: \
                     declare it in the manifest (a partition with a language schema is \
                     `schema: true`), or remove the manifest so the checkout adopts the ledger's",
                    lacking.join("; ")
                )));
            }
        }
        let base = match &tracked {
            Some(previous) => head_contents(self.store, previous)?,
            // Nothing tracked yet: a clone, where every file is a create.
            None => HeadContents::default(),
        };
        let mut plan = Materialization::default();

        // The manifest: written as manifest.yml only when no manifest file
        // exists — the CLI never picks between two silently, and it does not
        // three-way a generated document against a hand-written one either.
        if manifest_file::find(self.store).map_err(err)?.is_none() {
            let manifest_blob = load_blob_data(self.store, &commit.manifest)?;
            let manifest = permguard_objects::manifest::Manifest::decode(&manifest_blob)
                .map_err(|error| err(error.to_string()))?;
            let yaml = manifest_file::to_yaml(&manifest).map_err(err)?;
            plan.creates
                .push((manifest_file::MANIFEST_YML.to_owned(), yaml.into_bytes()));
        }

        // Local ids: what the sources already hold, wherever they hold it. A
        // fresh clone has no sources to compare, so everything is a create. A
        // tracked workspace whose sources do not build is another matter: the
        // pull cannot tell what the author changed, and advancing the
        // checkpoint over a tree it could not read is how the next `apply`,
        // once the tree builds again, reverts somebody else's commit.
        let local: BTreeMap<String, PolicyRecord> = match self.refresh() {
            Ok(snapshot) => snapshot
                .policies
                .into_iter()
                .map(|policy| (policy.id.clone(), policy))
                .collect(),
            Err(error) if tracked.is_some() => {
                return Err(err(format!(
                    "the working tree does not build, so the pull cannot tell what it changed: \
                     fix it, then pull again\n{error}"
                )));
            }
            Err(_) => BTreeMap::new(),
        };

        // A file may hold several policies, and each moves on its own: the
        // edits are gathered per file, and applied to the file's own text.
        let mut edits: BTreeMap<String, FileEdits> = BTreeMap::new();
        let mut policies_per_file: BTreeMap<&str, usize> = BTreeMap::new();
        for held in local.values() {
            *policies_per_file.entry(held.source.as_str()).or_default() += 1;
        }

        for (id, (digest, canonical)) in &incoming.policies {
            let Some(held) = local.get(id) else {
                // Not held here under any name: materialize it — unless the
                // name it would take is already in use. Writing over that
                // would clobber the author's file; skipping it would advance
                // the checkpoint over a policy the tree never received, and
                // the next `apply` would delete it from the ledger.
                if self.store.exists(canonical) {
                    plan.conflicts.push(Conflict {
                        path: canonical.clone(),
                        reason: Reason::NameTaken {
                            incoming: digest.clone(),
                        },
                    });
                } else {
                    plan.creates
                        .push((canonical.clone(), load_blob_data(self.store, digest)?));
                }
                continue;
            };
            if &held.digest == digest {
                continue;
            }
            let based = base.policies.get(id).map(|(digest, _)| digest);
            if based == Some(digest) {
                // Only the author moved it: that change is what `apply` sends.
                continue;
            }
            if based == Some(&held.digest) {
                // Only the remote moved it: its text advances inside the
                // author's file, whatever else that file holds.
                edits.entry(held.source.clone()).or_default().splices.push((
                    load_blob_data(self.store, &held.digest)?,
                    Some(load_blob_data(self.store, digest)?),
                ));
                continue;
            }
            plan.conflicts.push(Conflict {
                path: held.source.clone(),
                reason: Reason::BothChanged {
                    incoming: digest.clone(),
                },
            });
        }

        // Policies the incoming head dropped.
        for (id, (digest, _)) in &base.policies {
            if incoming.policies.contains_key(id) {
                continue;
            }
            let Some(held) = local.get(id) else {
                continue;
            };
            if &held.digest == digest {
                edits
                    .entry(held.source.clone())
                    .or_default()
                    .splices
                    .push((load_blob_data(self.store, digest)?, None));
            } else {
                plan.conflicts.push(Conflict {
                    path: held.source.clone(),
                    reason: Reason::DroppedThere,
                });
            }
        }

        // The edits, file by file. A file every policy of which was dropped
        // goes with them; any other is rewritten with each policy spliced in
        // place, so whatever else it holds — other policies, the author's
        // comments — is kept.
        for (path, edit) in edits {
            let held = policies_per_file.get(path.as_str()).copied().unwrap_or(0);
            let dropped = edit.splices.iter().filter(|(_, new)| new.is_none()).count();
            if dropped == held {
                plan.removals.push(path);
                continue;
            }
            let Some(mut content) = self.store.read(&path).map_err(err)? else {
                return Err(err(format!("{path} vanished mid-pull")));
            };
            for (old, new) in &edit.splices {
                content = splice(&content, old, new.as_deref()).ok_or_else(|| {
                    err(format!(
                        "{path}: the policy to advance is not where the last build read it: \
                         run `permguard refresh`, then pull again"
                    ))
                })?;
            }
            plan.updates.push((path, content));
        }

        // Schemas and every other non-policy blob: no identity to track them
        // by, so the path is the identity and the bytes are the comparison.
        for (path, digest) in &incoming.others {
            let theirs = load_blob_data(self.store, digest)?;
            let Some(ours) = self.store.read(path).map_err(err)? else {
                plan.creates.push((path.clone(), theirs));
                continue;
            };
            if ours == theirs {
                continue;
            }
            let based = match base.others.get(path) {
                Some(based) => load_blob_data(self.store, based)?,
                None => {
                    plan.conflicts.push(Conflict {
                        path: path.clone(),
                        reason: Reason::BothChanged {
                            incoming: digest.clone(),
                        },
                    });
                    continue;
                }
            };
            if based == theirs {
                continue;
            }
            if based == ours {
                plan.updates.push((path.clone(), theirs));
            } else {
                plan.conflicts.push(Conflict {
                    path: path.clone(),
                    reason: Reason::BothChanged {
                        incoming: digest.clone(),
                    },
                });
            }
        }

        for (path, digest) in &base.others {
            if incoming.others.contains_key(path) {
                continue;
            }
            let Some(ours) = self.store.read(path).map_err(err)? else {
                continue;
            };
            if ours == load_blob_data(self.store, digest)? {
                plan.removals.push(path.clone());
            } else {
                plan.conflicts.push(Conflict {
                    path: path.clone(),
                    reason: Reason::DroppedThere,
                });
            }
        }

        Ok(plan)
    }
}

/// Removes what a directory holds, keeping what `.permguardignore` names and the directories that
/// still hold something kept. Answers whether anything was kept.
fn clear_tree(
    store: &dyn Store,
    path: &str,
    ignores: &[String],
    removed: &mut Vec<String>,
) -> Result<bool> {
    let mut kept = false;
    for (name, is_dir) in store.list(path).map_err(err)? {
        let child = format!("{path}/{name}");
        if super::build::ignored(ignores, &child, is_dir) {
            kept = true;
            continue;
        }
        if is_dir {
            if clear_tree(store, &child, ignores, removed)? {
                kept = true;
            }
            continue;
        }
        store.remove(&child).map_err(err)?;
        removed.push(child);
    }
    if !kept {
        store.remove(path).map_err(err)?;
    }

    Ok(kept)
}

/// The artifact contracts a partition declares, by name: its typed `artifacts`, or the one
/// legacy `schema` — the same reading `build` gives the manifest, so the comparison above refuses
/// exactly what the build would have refused after the files had landed.
fn contracts_of(partition: &permguard_objects::manifest::Partition) -> Vec<String> {
    if !partition.artifacts.is_empty() {
        return partition
            .artifacts
            .iter()
            .map(|contract| format!("artifact `{}`", contract.r#type))
            .collect();
    }
    if partition.schema {
        return vec!["schema".to_owned()];
    }

    Vec::new()
}

/// What a pull does to the working tree, decided before anything is written.
#[derive(Debug, Default)]
pub(crate) struct Materialization {
    /// Files the tree does not hold: path and content.
    creates: Vec<(String, Vec<u8>)>,
    /// Files the incoming head moved and the author had not: path and content.
    updates: Vec<(String, Vec<u8>)>,
    /// Files the incoming head dropped and the author had not touched.
    removals: Vec<String>,
    /// Files the author has to reconcile. Non-empty means the pull does not
    /// happen.
    conflicts: Vec<Conflict>,
}

impl Materialization {
    /// The paths created, in the order they were written.
    fn created(&self) -> Vec<String> {
        self.creates.iter().map(|(path, _)| path.clone()).collect()
    }

    /// The paths advanced to the incoming head's content.
    fn updated(&self) -> Vec<String> {
        self.updates.iter().map(|(path, _)| path.clone()).collect()
    }

    /// The refusal: every file the author has to reconcile, and how to read
    /// what the remote holds so they can.
    fn refusal(&self) -> String {
        let mut message = String::from(
            "the incoming head cannot land on this working tree as it is: reconcile the files \
             below, then pull again",
        );
        for conflict in &self.conflicts {
            let path = &conflict.path;
            match &conflict.reason {
                Reason::BothChanged { incoming } => message.push_str(&format!(
                    "\n  - {path}: changed here and on the remote — read the remote's version \
                     with `permguard objects cat {incoming}`"
                )),
                Reason::DroppedThere => message.push_str(&format!(
                    "\n  - {path}: the remote dropped it and this workspace changed it — delete \
                     the file to accept the removal, or apply it back"
                )),
                Reason::NameTaken { incoming } => message.push_str(&format!(
                    "\n  - {path}: the remote adds a policy that would be written here, but the \
                     name is taken — move the file aside, or add the policy yourself from \
                     `permguard objects cat {incoming}`"
                )),
            }
        }
        message
    }
}

/// One file the pull cannot land without the author.
#[derive(Debug)]
struct Conflict {
    /// The local file, as the author knows it — or, for a policy the remote
    /// added, the file it would have been written to.
    path: String,
    reason: Reason,
}

/// Why a file is the author's to reconcile.
#[derive(Debug)]
enum Reason {
    /// Both sides moved it. The digest is what the remote holds, so
    /// `permguard objects cat` can show it.
    BothChanged { incoming: Digest },
    /// The remote dropped it, and this workspace changed it.
    DroppedThere,
    /// The remote adds a policy whose file name this workspace already uses
    /// for something else.
    NameTaken { incoming: Digest },
}

/// The edits one file receives from the incoming head, one per policy in it
/// that the remote moved: the policy's current text, and the text replacing
/// it — `None` when the remote dropped the policy.
#[derive(Debug, Default)]
struct FileEdits {
    splices: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

/// Replaces one policy's text inside a file, or cuts it out.
///
/// A policy's blob is the verbatim slice the build read from the file, so the
/// slice is found by its bytes. `None` when it is not there: the file moved
/// since the last build, and the pull does not guess.
fn splice(content: &[u8], old: &[u8], new: Option<&[u8]>) -> Option<Vec<u8>> {
    let at = find(content, old)?;
    let (before, after) = (&content[..at], &content[at + old.len()..]);
    Some(match new {
        Some(new) => [before, new, after].concat(),
        None => {
            // The policy goes, and the blank lines that set it apart go with
            // it; what is left is joined the way the file joined its policies.
            let before = trim_end(before);
            let after = trim_start(after);
            match (before.is_empty(), after.is_empty()) {
                (true, true) => Vec::new(),
                (true, false) => after.to_vec(),
                (false, true) => [before, b"\n".as_slice()].concat(),
                (false, false) => [before, b"\n\n".as_slice(), after].concat(),
            }
        }
    })
}

/// The first position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn trim_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

/// Every blob one head materializes, keyed the way the working tree keys it:
/// policies by identity, because the author may keep one under any file name;
/// everything else by the path it lands at.
#[derive(Debug, Default)]
struct HeadContents {
    /// Policy id → its blob, and the path a fresh materialization writes it to.
    policies: BTreeMap<String, (Digest, String)>,
    /// Non-policy blobs: path → blob.
    others: BTreeMap<String, Digest>,
}

/// Reads one head's contents from the local store.
fn head_contents(store: &dyn Store, head: &Digest) -> Result<HeadContents> {
    let commit = load_commit(store, head)?;
    let root = load_tree(store, &commit.tree)?;
    let mut contents = HeadContents::default();
    for entry in &root.entries {
        if entry.kind != Kind::Tree {
            continue;
        }
        read_tree_contents(store, &entry.name, &entry.digest, &mut contents)?;
    }
    Ok(contents)
}

/// Reads one subtree, recursing — the folder structure of the snapshot (a
/// Rego package tree, say) is keyed exactly: directory names are the subtree
/// entry names.
fn read_tree_contents(
    store: &dyn Store,
    directory: &str,
    tree_digest: &Digest,
    contents: &mut HeadContents,
) -> Result<()> {
    let tree = load_tree(store, tree_digest)?;
    for item in &tree.entries {
        match item.kind {
            Kind::Tree => read_tree_contents(
                store,
                &format!("{directory}/{name}", name = item.name),
                &item.digest,
                contents,
            )?,
            Kind::Blob => match item.annotations.get(ANNOTATION_POLICY_ID) {
                Some(id) => {
                    let stem = item
                        .annotations
                        .get(ANNOTATION_POLICY_ALIAS)
                        .cloned()
                        .unwrap_or_else(|| id.clone());
                    let extension = item.name.rsplit('.').next().unwrap_or("txt");
                    contents.policies.insert(
                        id.clone(),
                        (
                            item.digest.clone(),
                            format!("{directory}/{stem}.{extension}"),
                        ),
                    );
                }
                None => {
                    // A schema or other non-policy blob: keep its name.
                    contents.others.insert(
                        format!("{directory}/{name}", name = item.name),
                        item.digest.clone(),
                    );
                }
            },
            Kind::Commit => {}
        }
    }
    Ok(())
}

/// The commit this workspace last converged on, or `None` before the first.
fn tracked_head(store: &dyn Store) -> Result<Option<Digest>> {
    let r#ref = config::read_head(store)
        .map_err(err)?
        .unwrap_or_else(|| super::DEFAULT_REF.to_owned());
    let Some(checkpoint) = config::read_checkpoint(store, &r#ref).map_err(err)? else {
        return Ok(None);
    };
    Digest::parse(&checkpoint.head)
        .map(Some)
        .map_err(|_| err("corrupt checkpoint"))
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
